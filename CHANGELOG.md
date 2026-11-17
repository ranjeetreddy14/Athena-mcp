# Version History

## v1.3.1 - ThreatFox type codes
*Released: November 2026*

Bug fix. The response contracts are unchanged; `ti_query` output differs from v1.3.0 only where noted below.

**Fixed:**
- **ThreatFox `ioc_type` and `threat_type` were always `null`.** `tools/threatfox_tool.py` read `ioc_type_full` / `threat_type_full`, fields the ThreatFox API does not return (confirmed against the live API on 2026-11-17). It now reads `ioc_type` / `threat_type` and returns ThreatFox's codes, e.g. `sha256_hash`, `ip:port` / `payload`, `botnet_cc`. TriageLoop's post-check reads both fields ("any ThreatFox match → can't be FALSE_POSITIVE"), so with v1.3.0 the check never saw a ThreatFox match type.
  - **Effect on `ti_query`:** for a ThreatFox match, `observed_facts.ioc_type` and `observed_facts.threat_type` now have values instead of `null`. Nothing else changes. Golden diff against v1.3.0: 19 cases, 18 identical; the one ThreatFox-match case differs only in those two fields.
  - The bug has been present since ThreatFox support was added in v1.1.
- **`schemas/threatfox.json`** now requires both fields as non-empty strings on a match, so a regression to `null` fails validation. `fixtures/threatfox.json` was already correct: it stores ThreatFox's real `ioc_type` / `threat_type` values, so it was not re-recorded. Only the test assertion had encoded the bug.

**Docs:** README states the two deliberate agentic-mode design choices explicitly (`caller` is policy, not authentication; why `ti_lookup` omits VirusTotal's `verdict`). It also documents how Athena is verified, including the injected-bug check: 7 deliberate bugs, each failed the suite.

---

## v1.3.0 - Agentic Mode
*Released: November 2026*

Makes Athena callable by an autonomous pipeline (**TriageLoop**) without loosening what it refuses to do. `ti_query`, the persona and the three-lane output contract are unchanged. With the cache disabled, `ti_query` returns byte-identical results to v1.2.1 across a 17-case golden set, including input-validation errors.

**New:**
- **`ti_lookup(source, indicator_type, indicator, caller)` and `ti_lookup_batch(items)`** MCP tools. They take structured input and return structured output (MCP `structuredContent` with `outputSchema`), with no natural-language routing and no clarifying questions. They never load the embedding model.
- **Indicator validation.** IPv4, domain, http(s) URL and MD5/SHA-1/SHA-256, each checked against the source's accepted types. Private, loopback and link-local IPs are rejected with the same predicate `ti_query` uses. URLs whose host is such an IP or `localhost` are also rejected.
- **Approval from configuration** for agentic callers: `trusted_callers` and `medium_risk_requires_approval` in `config/athena.json` (or `$ATHENA_CONFIG`). Defaults are fail-safe: no trusted callers, approval required. An untrusted caller requesting a medium-risk source (VirusTotal) gets `{"ok": false, "reason": "approval_required"}`.
- **Non-interactive error contract.** Every agentic failure is exactly `{"ok": false, "reason": <code>, "source": <source|null>}` with 14 enumerated reason codes. Provider error text is never passed through.
- **Audit.** Every agentic call writes one entry (one per batch item) with `routing: "agentic"`, `caller`, `source`, `indicator_type`, `indicator`, `executed_tool`, `cache_hit`, `ok`, `reason`, `batch_id`/`batch_index`. If the entry cannot be written, the call fails closed with `internal_error`.
- **Response cache** keyed by `(source, indicator)`, on disk, TTL 3600 s by default (`ATHENA_CACHE_DIR`, `ATHENA_CACHE_TTL`, or config). Shared by `ti_query` and `ti_lookup`. Stores successful results only, never errors or pending VirusTotal scans. Cache hits are marked `cache_hit: true` in both audit-entry types and `cached: true` in `ti_lookup` output.
- **JSON Schemas** for each source's `observed_facts`: `schemas/{shodan,virustotal,abuseipdb,threatfox}.json` (Draft 2020-12, `additionalProperties: false`).
- **Recorded fixtures**: `fixtures/{source}.json`, each with one well-known benign and one well-known malicious public indicator, captured live by `scripts/record_fixtures.py` and sanitised. The recorder uses read-only lookups only, never submits a URL to VirusTotal, and writes no keys. Tool tests replay them offline.
- **`ti://capabilities`** lists all three MCP tools, reports `athena_version: "1.3.0"`, and has an `agentic_mode` block (contract version `1`, sources, indicator types, reason codes, approval rule, batch limit, cache, audit fields). Tests keep it in sync with the code and registry.

**Changed:**
- `ti_lookup` removes judgement keys (`verdict`, `severity`, `attribution`, `remediation`, `recommendation[s]`) from `observed_facts` at any depth. In practice this removes the `verdict` the VirusTotal tool derives from engine counts; the counts themselves remain. `ti_query` still emits VirusTotal's `verdict`, as in v1.2.
- **The MCP SDK's input validation is now done by Athena** (`@server.call_tool(validate_input=False)`).
  - **Why:** the SDK checks arguments against `inputSchema` *before* Athena sees the call, and answers a mismatch with plain text (`Input validation error: ...`, `isError: true`). A malformed `ti_lookup` call would then get free text instead of `{"ok": false, "reason": "invalid_request", "source": ...}`, which breaks the non-interactive error contract an unattended caller depends on. With SDK validation off, `ti_lookup` validates its own input and always answers in the contract.
  - **`ti_query` is unaffected:** it gets an identical copy of the SDK check, so its validation errors are byte-for-byte the same. This is verified by the 17-case golden diff against v1.2.1, which includes missing-argument, wrong-type and unknown-tool calls.
- `ti_query` audit entries gain `cache_hit`. `executed_tool` is `null` on a cache hit.
- `capabilities.json`: `data_freshness` now mentions the cache. VirusTotal `input_type` corrected from "URL/Domain/Hash" to "URL/Hash", which matches the registry; VirusTotal never received domains.
- New runtime dependency declared: `jsonschema` (already present via `mcp`).

**Known issues:**
- ~~ThreatFox `ioc_type` / `threat_type` always `null`~~: **fixed in v1.3.1**.

**Future items:**
- Migrate `server.py` to the `mcp` 2.x API (carried over from v1.2.1).
- `caller` is self-declared (by design: agentic mode assumes a local stdio parent process). If Athena is ever exposed over a network transport, add caller authentication.

---

## v1.2.1 - Stabilisation
*Released: November 2026*

Maintenance release: no new features, no change to `ti_query` responses, the output schema or the persona.

**Fixes:**
- **Server failed to start on a fresh install.** The unpinned `mcp` dependency resolved to 2.x, which removed the `Server.list_tools()` decorator API used by `server.py`. `mcp` is now pinned `>=1.25,<2`.
- **Hash routing is now deterministic.** Hashes skip the similarity router entirely (and never load the embedding model): ThreatFox by default, VirusTotal only when the user asks for or approves it. Previously VirusTotal's hash intents out-scored ThreatFox by 0.0014 for "search threatfox for hash ...", so the audit log could record `url_scan_virustotal` while ThreatFox actually ran.
- **Audit entries are accurate for hashes.** The audit log entry now includes `routing` (`hash_rule` | `semantic` | `entity_filter`) and `executed_tool` (the tool that actually ran, `null` if nothing ran). `persona_hash` is unchanged.
- **`ti://capabilities` is readable.** Reading it always failed with "Unknown resource": `server.py` compared `uri.path`, but `ti://capabilities` parses `capabilities` as the host. Downstream clients (TriageLoop) read this resource to record Athena's version.
- **`capabilities.json` reports `athena_version: "1.2.1"`** (was `"1.2"`), and a test keeps it equal to the `pyproject.toml` version. `output_contract.version` stays `"1.2"`: the response schema is unchanged.

**Build and tooling:**
- `pyproject.toml` + `uv.lock` replace `requirements.txt`. All direct imports are declared (previously `pydantic` was only transitive), and CPU-only PyTorch is pinned on Linux/Windows. Requires Python 3.11+ (only 3.11 and 3.13 were ever tested).
- pytest is the only supported runner (`pythonpath`/`testpaths` configured, so bare `pytest` works). `unittest discover` instructions removed; they silently skipped 8 tests.
- New `ATHENA_AUDIT_PATH` (default `logs/audit.jsonl`) and `ATHENA_ENV_FILE` (default `.env`) environment variables.
- Test isolation (`tests/conftest.py`): dummy API keys, temp audit log, no `.env`, no network, enforced with guards rather than convention. Tests that need the embedding model are marked `requires_model` and are skipped, with instructions, when the Hugging Face cache is empty.
- `.env.example` documents every variable. `generate_report_pdf.py` removed (hardcoded personal path, undeclared dependency).

**Future items:**
- **Migrate `server.py` to the `mcp` 2.x API** (`Server.add_request_handler` instead of the removed decorators) and lift the `<2` pin. Deliberately not done in 1.2.1.
- Add unit tests for the VirusTotal, AbuseIPDB and ThreatFox tool modules.

---

## v1.2 - Analyst-Augmented Output
*Released: February 2026*

**What's New:**
- **Three-Lane Output Schema:** Athena now separates `observed_facts` (tool-derived, authoritative), `analyst_interpretation` (LLM-rendered), and `recommended_next_steps` (LLM-rendered).
- **Senior CTI Persona Prompt:** Use the `senior_cti_analyst` MCP Prompt at session startup to inject the Senior CTI Analyst persona and guarantee authoritative behavior.
- **Audit Hashing:** Every response now includes a `persona_hash` (SHA256) in the audit block, proving which persona version governed the session.
- **Enhanced LLM Guardrails:** The persona explicitly prohibits the LLM from claiming execution authority, issuing autonomous verdicts, or fabricating technical details.
- **Verdict Leakage Hardening:** Updated `ti_query` tool description to strictly forbid authoritative verdicts.
- **Output Governance:** Added immutable `analysis_constraints` to the response schema.

**Schema Changes (Breaking):**
- `data` field renamed to `observed_facts` to emphasize authoritative nature
- Added `analyst_interpretation` field (always `null` from server)
- Added `recommended_next_steps` field (always `null` from server)

---

## v1.1 - Expanded Threat Intelligence
*Released: January 2026*

**What's New:**
- **New Threat Intelligence Sources:** Added full integration with **AbuseIPDB** for IP reputation and **ThreatFox** for IOC database lookups.
- **Hash Support:** You can now query MD5, SHA1, and SHA256 hashes directly.
- **Smart Workflows:** Added interactive confirmation flows for sensitive or credit-consuming tools.
- **Enhanced Detection:** Improved entity detection engine to automatically distinguish between IPs, URLs, Domains, and Hashes with higher accuracy.
- **Audit Logging:** Implemented structured audit logging for all queries and tool executions.

## v1.0 - Initial Release
*Released: December 2025*

**What's New:**
- **Athena Core:** Initial release of the Threat Intelligence MCP Server.
- **Shodan Integration:** Native support for IP geolocation and open port scanning.
- **VirusTotal Integration:** deep scanning capabilities for URLs and Domains.
- **Semantic Routing:** AI-powered intent matching to automatically select the right tool for your query.
- **MCP Compatibility:** Full support for the Model Context Protocol (stdio transport).
