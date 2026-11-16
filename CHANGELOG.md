# Version History

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
