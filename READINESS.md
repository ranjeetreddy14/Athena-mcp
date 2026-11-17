# READINESS — Athena (ti-mcp-server)

## Status after v1.3.1 (ThreatFox type codes)

**ThreatFox `ioc_type` / `threat_type` are fixed** (they were always `null`; TriageLoop's post-check reads them). From a brand-new Python 3.11.5 env built only from `uv.lock` (mcp 1.30.0), offline, dummy keys:

| Hugging Face cache | Result |
|---|---|
| model present | **268 passed** |
| model absent | **263 passed, 5 skipped** (nothing downloaded) |

- **`ti_query` golden diff vs v1.3.0:** 19 cases, 18 identical. Two cases were added this release that run the real ThreatFox tool against the recorded fixture. The single difference is the intended fix: `observed_facts.ioc_type` `null` → `"sha256_hash"` and `threat_type` `null` → `"payload"`.
- **Injected-bug check re-run on v1.3.1:** 7 of 7 caught, including reverting this fix (4 tests fail). The table is in README "How Athena is verified".
- **Fixture not re-recorded.** `fixtures/threatfox.json` already held ThreatFox's real `ioc_type` / `threat_type`; only the test assertion and the schema encoded the bug. Both are corrected, and the schema now rejects `null`.
- **Stdio check:** `ti://capabilities` reports `athena_version` 1.3.1; the model never loads.
- **Still open:** INTEGRATION_READINESS.md is not yet in the repo, so §5 still maps the Session 3 brief's bullet list.

---

## Status after v1.3.0 (agentic mode)

**Every Agentic-mode checklist item (§5) is done and every constraint held.** A1–A11, C1–C7 and R1–R5 are listed in §5. From a brand-new Python 3.11.5 environment built only from `uv.lock` (mcp 1.30.0), offline, with dummy keys only:

| Hugging Face cache | Result |
|---|---|
| model present | **263 passed** |
| model absent | **258 passed, 5 skipped** (only the 5 `requires_model` tests; nothing downloaded) |

How we know the tests bite: six deliberate bugs were injected, one per guarantee, and each failed the suite:

| Injected bug | Tests failed |
|---|---|
| ti_lookup leaks VT verdict | 6 |
| untrusted caller allowed a medium-risk source | 3 |
| private IPs accepted | 16 |
| agentic path touches the router (model) | 130 |
| MCP SDK input validation re-enabled | 13 |
| ti_query bypasses the cache | 2 |

`ti_query` is byte-identical to v1.2.1 across a 17-case golden set run through the real SDK handler, including input-validation and unknown-tool errors. A real MCP client over stdio received the error contract on every failure path, `athena_version` 1.3.0 from `ti://capabilities`, and never triggered a model load.

**Open (needs your decision):**
- **INTEGRATION_READINESS.md is still not in the repo.** §5 maps the brief's bullet list; if the real file has more items, they are not covered.
- **ThreatFox `ioc_type` / `threat_type` are always `null`.** Resolved: fixed in v1.3.1.
- **`caller` is self-declared.** Resolved: confirmed as the intended design and documented in the README ("policy, not authentication; agentic mode assumes a local stdio parent process that controls the server").
- **Shodan's "malicious" fixture is a 404.** The ThreatFox C2 IP is not in Shodan, so that fixture covers the not-found path rather than a malicious host record.
- **`v1.3.0` not pushed.** Resolved: pushed with `main`.

---

## Status after v1.2.1 (stabilisation)

**All findings from the original assessment (below) are resolved; see "Still open" for what remains.** From a brand-new Python 3.11.5 environment built only from `uv.lock`, bare `pytest` gives:

| Hugging Face cache | Result |
|---|---|
| model present, offline | **52 passed** |
| model absent, offline | **47 passed, 5 skipped** (the 5 `requires_model` tests, with an explanatory message; nothing downloaded) |

52 = the original 23 + 29 new tests (hash rule and audit entry: 12; isolation guards and lazy loading: 11; `ti://capabilities`: 6). The real `logs/audit.jsonl` was not touched by any run (46 lines before and after), and `.env` was never opened (an audit-hook tripwire in `tests/conftest.py` raises if it is).

| Original finding | Resolution |
|---|---|
| **F1** `mcp` 2.x broke `server.py`; no test runner config | `mcp>=1.25,<2` (locks to **1.30.0**, newer than the 1.25 I'd previously seen working; the suite and a real stdio session pass on it). `pythonpath`/`testpaths` set, so bare `pytest` works. 2.x migration logged in CHANGELOG as a future item |
| **F2** hash routing: VT beat ThreatFox by 0.0014 | Hashes now skip the similarity router (rule in `orchestrator/router.py`). Audit entry records `routing: "hash_rule"` and `executed_tool`. `test_multi_input_routing` asserts it; `tests/test_hash_routing.py` covers it without the model |
| Unpinned / undeclared deps | `pyproject.toml` declares every import (incl. `pydantic`) plus `pytest` in a dev group; `uv.lock` committed (79 packages); `requirements.txt` deleted. CPU-only torch pinned on Linux/Windows (lock contains 0 nvidia/triton packages) |
| `unittest` vs `pytest` | pytest only; CONTRIBUTING.md rewritten (also fixed its stale registry example) |
| Tests could read `.env`, write real audit log, hit network | `tests/conftest.py`: dummy keys for every `env_var_name` in `registry/tools.json`, `ATHENA_AUDIT_PATH` per-test temp file, `ATHENA_ENV_FILE` to a non-existent file, HF offline, non-loopback sockets blocked, plus an open() tripwire on the real `.env` and `logs/audit.jsonl` |
| Model needed by tests | Marked `requires_model`, skipped with a message when the cache is empty |
| `generate_report_pdf.py` | Deleted |
| `.env.example` | Rewritten: all 4 keys plus `ROUTER_THRESHOLD`, `ATHENA_AUDIT_PATH`, `ATHENA_ENV_FILE` |
| `ti://capabilities` unreadable (found in the v1.2.1 stdio smoke test) | Fixed: `server.py` matched `uri.path`, but `ti://capabilities` parses `capabilities` as the host. `athena_version` bumped `1.2` → `1.2.1` and tied to `pyproject.toml` by a test, because TriageLoop records it per case. Verified through a real MCP client on mcp 1.30; `tests/test_capabilities.py` fails 3/6 against the old line |

**Lazy loading holds.** The embedding model is constructed only on the first IP/URL/domain query that reaches the similarity router. These never construct it (each tested with a sentinel that fails if it is built): importing `server`, `list_tools`, `list_prompts`, `list_resources`, `get_prompt`, queries with no entity, and all hash queries. I also drove the real server over stdio and confirmed the model-load log line never appears. A first IP/URL/domain `ti_query` still loads the model, by design; I did not change `ti_query` behaviour.

**Deviations from the brief (please check):**
1. **5 tests are marked `requires_model`, not 8.** The 8 in my original count included the 3 hash-workflow tests, which called the router. After the hash rule they no longer load the model, so marking them would only hide coverage when the cache is empty. The empty-cache run confirms exactly the 5 marked tests need it and everything else passes.
2. **`torch` is declared as a direct dependency** though nothing imports it, solely so the CPU-only index applies on Linux.
3. **`requires-python` is `>=3.11`** (README said 3.10+). Only 3.11 and 3.13 were ever run; 3.10 is untested, so I did not claim it.
4. **README install/config block and Python badge were edited.** Deleting `requirements.txt` made the `pip install -r` instructions wrong, so they now use `uv sync`, and the config example lists all four keys.
5. **New env vars** `ATHENA_AUDIT_PATH` and `ATHENA_ENV_FILE` are read at runtime; `ATHENA_AUDIT_PATH` is resolved at write time, so it works from `.env` too. The `logs/` directory is now created on first write, not at import.
6. Audit-log entries for hashes now show `confidence: 1.0` and a `hash_rule` reason (was a meaningless similarity score). Entries gain two keys (`routing`, `executed_tool`). Response JSON from `ti_query` is unchanged.

**Still open:**
- **Section 5 (READINESS CHECKLIST)** still can't be assessed: `INTEGRATION_READINESS.md` is not in the repo or anywhere on this machine. It must be added before the §5 mapping is done.
- Not verified: install on Linux/macOS (the lock has the right wheels, but I only ran Windows), any live API call, and PyPI deprecation/CVE status. No CI exists yet. VirusTotal/AbuseIPDB/ThreatFox tool modules still have no unit tests.

---

## 5. Integration readiness: Agentic mode (INTEGRATION_READINESS.md §1) — v1.3.0

**Source of the checklist.** `INTEGRATION_READINESS.md` was referenced by the Session 3 brief but was never available on this machine (searched the repo, `c:\Repos`, Desktop, Documents, Downloads). The items below are taken verbatim from the bullet list in the Session 3 brief, which says to implement v1.3 "exactly as the checklist lists". **If the real file has items not listed here, they are not covered.** This mapping was written before any v1.3 code; the Status column was filled in after the final verification run.

Consumer: **TriageLoop**, an autonomous pipeline. It pins Athena by git tag and reads `ti://capabilities` to record the version per case.

### 5.1 Checklist items

| # | Checklist item | Implementation | Verified by | Status |
|---|---|---|---|---|
| A1 | `ti_lookup(source, indicator_type, indicator, caller)` as a new MCP tool beside `ti_query`; structured in, structured out; no NL routing; no clarifying questions | `orchestrator/agentic.py` (pure logic) + dispatch in `server.py`. Strict `inputSchema` (enums), `outputSchema`, returns MCP `structuredContent`. Never calls the router | `tests/test_agentic.py`, stdio end-to-end | **done**: stdio client gets `structuredContent`; SDK `outputSchema` validation passes on every test call |
| A2 | `ti_lookup_batch(items)` | Same validation/policy per item, sequential, results in input order, max items enforced | `tests/test_agentic.py` | **done**: order, per-item audit, `batch_id`, limit 25, in-batch duplicates hit cache |
| A3 | Validate `indicator_type` / `indicator` format | `ip` (IPv4), `domain`, `url` (http/https), `hash` (MD5/SHA1/SHA256); source must accept the type (from `registry/tools.json`) | `tests/test_agentic.py` (parametrised valid/invalid) | **done**: 19 invalid-format cases, 4 type-not-accepted cases, normalisation |
| A4 | Reject private / loopback / link-local IPs **exactly as `ti_query` does** | Reuses the same predicate `ti_query`'s tools use (`tools/shodan_tool.validate_ip`) | `tests/test_agentic.py` | **done**: same predicate; 14-address parity test vs `ti_query`'s rule; URL hosts too (interp. 5) |
| A5 | Approval from config for agentic callers: `trusted_callers`, `medium_risk_requires_approval`; untrusted caller + medium-risk source → `{"ok": false, "reason": "approval_required"}` | `orchestrator/config.py`; `$ATHENA_CONFIG` or `config/athena.json`, defaults fail-safe (`[]`, `true`). Risk tier from registry | `tests/test_agentic.py` | **done**: default, trusted, flag off, low risk, unknown tier, bad config → `config_error` |
| A6 | Every agentic call writes an audit entry: `caller`, `source`, `indicator_type`, `routing="agentic"`, `executed_tool` | Written for every outcome incl. rejections and each batch item | `tests/test_agentic.py` (every path) | **done**: one entry per call on every path incl. rejections, batch failures and audit-write failure (fails closed) |
| A7 | Non-interactive error contract: any failure → `{"ok": false, "reason": ..., "source": ...}`; never a question | Exactly those 3 keys; enumerated reason codes; all exceptions caught | `tests/test_agentic.py` + tripwire | **done**: exactly 3 keys, 14 codes; provider error text (even questions) never passes through; checked over real stdio |
| A8 | Response cache keyed by `(source, indicator)`, TTL default 3600 s, on disk, configurable path, used by **both** `ti_query` and `ti_lookup`; cache hits marked in the audit entry | `orchestrator/cache.py`; `$ATHENA_CACHE_DIR` / `$ATHENA_CACHE_TTL` or config; `cache_hit` in both audit entry types | `tests/test_cache.py` | **done**: shared both ways; hit/expiry/TTL 0/errors & pending not cached/corrupt entries/bad config; `cache_hit` in both audit types |
| A9 | JSON Schema per source's `observed_facts` → `schemas/{shodan,virustotal,abuseipdb,threatfox}.json`; test that each tool's output validates | Hand-written Draft 2020-12, `additionalProperties: false` so drift fails | `tests/test_tool_fixtures.py` | **done**: 4 schemas, meta-validated; all 8 fixture outputs + VT URL/no_result variants validate; extra fields rejected |
| A10 | One sanitised fixture per source under `fixtures/` (well-known benign + well-known malicious public indicators, no private data); tool tests use them | `scripts/record_fixtures.py` (read-only lookups, keys never written), recorded once live | `tests/test_tool_fixtures.py`, `tests/test_shodan_tool.py` | **done** (recorded 2026-11-17): 8 cases; read in full before commit; public data only; keys `<redacted>` |
| A11 | `ti://capabilities` lists the new tools and exposes a version string TriageLoop can read | `capabilities.json`: `athena_version`, `mcp_tools`, `agentic_mode` (sources, types, reason codes, limits) | `tests/test_capabilities.py` (drift tests vs code/registry) | **done**: `athena_version` 1.3.0, `mcp_tools`, `agentic_mode`; drift tests vs code, registry, config defaults and audit fields |

### 5.2 Constraints

| # | Constraint | How it is held | Verified by | Status |
|---|---|---|---|---|
| C1 | `ti_query` behaviour unchanged | Only additions: cache lookup around tool execution, `cache_hit` in its audit entry | Golden diff: identical `ti_query` responses from v1.2.1 and v1.3.0 code over a fixed query set | **held**: golden diff 17/17 identical (cache off); with cache on only the 2 repeat-indicator cases differ (served from cache) |
| C2 | Persona unchanged | `persona/` not touched | `git diff v1.2.1 -- persona` empty | **held**: `git diff v1.2.1 -- persona` empty |
| C3 | Three-lane output contract unchanged | `ThreatIntelResponse` not touched | golden diff (C1) | **held**: golden diff (C1) |
| C4 | Never emit verdict, severity, attribution, remediation; tripwire for `ti_lookup` | `ti_lookup` output carries only provider facts; forbidden keys/phrases checked recursively | `tests/test_agentic_tripwire.py` | **held**: judgement keys stripped in code at any depth; `tests/test_agentic_tripwire.py` (20 tests) incl. checker self-test |
| C5 | Agentic calls never load the embedding model | No router call on any agentic path | sentinel that fails if the model is constructed, on every agentic test | **held**: sentinel on every agentic/cache/tripwire test; router-use mutant fails 130 tests; stdio run never logs a model load |
| C6 | Keep conftest tripwires | Extended (config file, cache dir), not relaxed | `tests/test_isolation.py` | **held**: extended to `config/athena.json` and `cache/`; real audit log 46 → 46 lines |
| C7 | Build on v1.2.1 / mcp 1.30 | `mcp>=1.25,<2` unchanged | lockfile | **held**: lock still resolves mcp 1.30.0 |
| R1 | Tests for every new behaviour; green on fresh 3.11, offline, no real keys | | fresh `uv sync --frozen` env, both HF-cache states | **done**: fresh env from lock: 263 passed (model cached) / 258 passed + 5 skipped (empty cache), offline, dummy keys |
| R2–R5 | Tag v1.3.0; CHANGELOG; README "Agentic mode" naming TriageLoop; READINESS | | | **done**: tag `v1.3.0` (local); CHANGELOG; README "Agentic mode"; this file |

### 5.3 Interpretations (the brief leaves room; please check)

1. **`ti_query` input validation.** The MCP SDK validates `inputSchema` *before* Athena sees a call and answers with plain text (`Input validation error: ...`), which would break A7 for `ti_lookup`. SDK validation is therefore turned off and done by Athena: `ti_lookup` gets the A7 contract, and `ti_query` gets a byte-identical copy of the SDK's error result (part of the C1 golden diff).
2. **Failures are not MCP `isError`.** `{"ok": false, ...}` is returned as normal structured content; `ok` is the success signal.
3. **VirusTotal `verdict` is dropped from `ti_lookup`.** `tools/virustotal_tool.py` derives a `verdict` field (`malicious`/`suspicious`/`safe`) from engine counts; `ti_query` keeps emitting it (C1), but `ti_lookup` removes it to satisfy C4. The engine counts remain. The schema lists `verdict` as optional so both validate.
4. **IP format = IPv4 only**, matching what `ti_query` can detect. IPv6 → `invalid_indicator`.
5. **URLs whose host is a private/loopback/link-local IP literal or `localhost` are rejected** (`non_routable_ip`). Stricter than `ti_query`, which forwards such URLs to VirusTotal; for an unattended pipeline that would leak internal URLs to a third party.
6. **`caller` is self-asserted.** Over stdio, whoever launches Athena controls it; `trusted_callers` is policy, not authentication.
7. **Cache stores only successful results** (including "not found"/"no result"), never errors or VirusTotal `pending` scans. On a cache hit `executed_tool` is `null` and `cache_hit` is `true`.
8. **Fixtures are recorded live** with the keys in the local `.env`, read-only lookups only; VirusTotal is queried by hash only (URL submissions are public).

---

# Original assessment (before v1.2.1)

Assessment only. **Nothing in the repo was changed except this file.** Date: 2026-11-16, HEAD `4e5ffb5`, Windows 11. Kept as the baseline; the status section above supersedes it.

## 0. How this was run

- Read `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `requirements.txt`, `.env.example`, all source and all tests.
- `uv` was not installed. I bootstrapped uv 0.13.8 into a throwaway venv (pip, Python 3.11) and used it for everything below. Nothing was installed globally.
- Fresh venv: `uv venv --python 3.11` → CPython 3.11.5, at `C:\Users\ranje\AppData\Local\Temp\claude\29483da81418f058\f1a2ec59-cd4e-4db5-b047-186071de4571\scratchpad\venv311` (outside the repo). Your existing 3.13 `.venv` was left untouched.
- Install followed the README order: `torch` from the CPU index, then `requirements.txt`, then `pytest` (not declared anywhere, see §3).
- Resolved versions (everything unpinned → latest at install time): mcp 2.3.0, sentence-transformers 6.3.0, torch 2.15.0+cpu, numpy 2.4.6, requests 2.34.2, python-dotenv 1.2.4, pydantic 2.14.3, transformers 5.23.0, pytest 9.2.0.

## 1. Test results

The suite has **23 tests** in 5 files, plus `test_hash_workflow.py`, which currently can't be imported.

| Run | Command (Python 3.11 fresh venv unless noted) | Result |
|---|---|---|
| A | `pytest` (bare, as most people run it) | **0 tests run.** 20 collected, 1 collection error, session interrupted |
| B | `python -m pytest` | **0 tests run.** Same, different error (see §2) |
| C | `python -m pytest --continue-on-collection-errors` | **19 passed, 1 failed, 1 error** (the error hides 3 tests, so 3 not run) |
| D | `python -m unittest discover tests` (the command in CONTRIBUTING.md) | Ran 13: **11 pass, 1 fail, 1 import error**. The 8 pytest-style tripwire tests are silently never run |
| E (baseline) | `python -m pytest` in your existing 3.13 `.venv` (mcp 1.25.0, sentence-transformers 5.2.0) | **22 passed, 1 failed** |
| F | Run C with `HF_HUB_OFFLINE=1`, model cached | 19 passed, 1 failed (same as C, minus hash tests) |
| G | Offline and **empty** HF cache | The 2 router test files: **5 failed, 2 passed** |

Per-file, run C (fresh 3.11 venv):

| File | Tests | Result |
|---|---|---|
| `test_compliance_tripwire.py` | 8 | 8 pass |
| `test_shodan_tool.py` | 5 | 5 pass |
| `test_orchestrator.py` | 4 | 4 pass |
| `test_v1_1.py` | 3 | 2 pass, **1 fail** |
| `test_hash_workflow.py` | 3 | **not run, collection error** |

## 2. Every failure and its cause

### F1. `tests/test_hash_workflow.py` — collection error (3 tests blocked)
Two stacked causes:

1. **Bare `pytest`: `ModuleNotFoundError: No module named 'server'`.**
   There is no `conftest.py`, `pytest.ini`, `pyproject.toml` or `tests/__init__.py`, so the repo root isn't on `sys.path`. `test_orchestrator.py` and `test_shodan_tool.py` patch `sys.path` themselves. `test_hash_workflow.py` and `test_v1_1.py` don't, and `test_hash_workflow.py` is collected first. `python -m pytest` (adds cwd) gets past this.
2. **`AttributeError: 'Server' object has no attribute 'list_tools'`** at `server.py:104` (`@server.list_tools()`).
   Unpinned `mcp` resolved to **2.3.0**, which removed the decorator API (`list_tools`, `list_resources`, `read_resource`, `list_prompts`, `get_prompt`, `call_tool`). `Server` now exposes `add_request_handler` / `add_notification_handler`. `server.py` uses all six decorators.
   - **This is not just a test problem.** `server.py` fails at import, so the MCP server cannot start on a fresh install.
   - Control: in your existing `.venv` (mcp **1.25.0**) the same 3 tests pass.

### F2. `tests/test_v1_1.py::TestAthenaV11::test_multi_input_routing` — assertion failure
`AssertionError: 'url_scan_virustotal' != 'threatfox_ioc'`, on the **4th** case only (hash query).

Measured scores for `"search threatfox for hash 2cf24d…"`:

| Tool | Best score | Matching intent |
|---|---|---|
| `url_scan_virustotal` | 0.6493 | "check malware report for hash" |
| `threatfox_ioc` | 0.6479 | "search threatfox for ioc" |

- The margin is 0.0014. VirusTotal's hash intents (added to `registry/tools.json` in v1.1) outscore the ThreatFox intents even when the query says "threatfox".
- **Not version drift.** Scores are identical in the 3.13 env (ST 5.2.0) and the 3.11 env (ST 6.3.0). It fails in baseline run E too.
- Production impact: low for execution. `server.py` special-cases hashes and bypasses the router. But the router result is still computed and written to the audit log (`selected_tool`, `routing_reason`), so the log can record `url_scan_virustotal` while ThreatFox actually ran. I did not verify this against a real log entry.

No other test failures.

## 3. Dependencies: deprecated, unpinned, undeclared, install failures

**Install failures: none.** All three `uv pip install` steps exited 0 with no warnings. 58 packages from `requirements.txt` plus torch; pytest added 3 more.

**Unpinned.** `requirements.txt` has 5 bare names (`mcp`, `python-dotenv`, `sentence-transformers`, `numpy`, `requests`), with no versions, no lockfile and no `pyproject.toml`. This directly caused F1. Known-good set from your working `.venv`: mcp 1.25.0, sentence-transformers 5.2.0, torch 2.9.1+cpu, numpy 2.4.0, requests 2.32.5, python-dotenv 1.2.1, pydantic 2.12.5.

**Deprecated / removed API.**
- `mcp` low-level decorator API: removed in 2.x (see F1). A `mcp<2` ceiling, or a port to the 2.x handler API, is needed.
- mcp 2.x also pulls a different transitive set (e.g. `mcp-types`, `httpx2`, `httpcore2`). I didn't investigate it.
- At test time the only warning is huggingface_hub's Windows symlink notice (environmental, harmless). ST 6.3.0 also logs a benign `HEAD …/2_Normalize/config.json 404`.
- **Not checked:** PyPI deprecation/yank flags and CVEs (no `pip-audit` run).

**Used but not declared:**
| Package | Where | Status |
|---|---|---|
| `pydantic` | `server.py:13` (direct import) | Only arrives transitively via `mcp` |
| `pytest` | `tests/test_compliance_tripwire.py`, and the README/CONTRIBUTING test story | Not in any requirements file |
| `markdown2` (+ optional `weasyprint`) | `generate_report_pdf.py` | Not installed. The script isn't runnable as-is (I didn't run it). It also hardcodes `C:\Users\ranje\.gemini\antigravity\brain\…\security_audit_report.md`, so it looks like a stray artifact |
| `torch` (CPU) | README says to install separately | Not captured in `requirements.txt`. `sentence-transformers` will pull its own torch if the README step is skipped, so the lightweight CPU-only goal depends on install order |

**Python version.** README and badge claim 3.10+. Only 3.11 (fresh) and 3.13 (existing venv) were exercised. There is no `requires-python` declaration anywhere.

## 4. What needs a network call or API key

**Tests need no API keys and make no calls to the threat-intel APIs.** Shodan tests mock `os.getenv` and `requests.get`. Hash tests mock `tool.execute`. Nothing in the suite touches VirusTotal, AbuseIPDB or ThreatFox directly.

**Tests do need the Hugging Face model** `all-MiniLM-L6-v2` (downloaded from huggingface.co on first use and cached in `~/.cache/huggingface`).
- **8 tests** load it: 3 in `test_orchestrator`, 2 in `test_v1_1`, and the 3 hash-workflow tests (they call `router.route_query` before the hash branch).
- Offline with the model cached → fine (run F). Offline with an empty cache → `OSError: couldn't connect to huggingface.co` (run G). So a fresh clone or CI runner needs network once, or a pre-seeded cache.
- Even with a cache, ST 6.x makes HEAD requests to huggingface.co when online. `HF_HUB_OFFLINE=1` avoids that.

**Runtime (not exercised, no live call was made):**
| Tool | Endpoint | Env var |
|---|---|---|
| `ip_intel_shodan` | api.shodan.io | `SHODAN_API_KEY` |
| `url_scan_virustotal` | virustotal.com/api/v3 (URL path submits and polls with up to 5×2 s sleeps) | `VT_API_KEY` |
| `abuse_ip_db` | api.abuseipdb.com | `ABUSEIPDB_API_KEY` |
| `threatfox_ioc` | threatfox-api.abuse.ch | `THREATFOX_API_KEY` (sent as `Auth-Key`) |

- A local `.env` exists with all four keys plus `ROUTER_THRESHOLD`. Its values were not read or printed.
- **Hazard:** `server.py` calls `load_dotenv()` at import, so any test that imports `server` loads real keys into the process. Today everything is mocked, so no live call happens. One unmocked test would spend real quota.
- **Side effect of my runs:** importing `server` creates and appends to `logs/audit.jsonl`. Baseline run E added **3 entries (43 → 46 lines)**. The file is gitignored and `git status` is clean. Say so if you want those 3 lines removed.

## 5 (original). READINESS CHECKLIST: not assessed — superseded by §5 above

**The brief with the READINESS CHECKLIST was not in the message I received.** Your paste contained only the task instructions, and there is no checklist file in the repo (I searched). I did not guess at its items. Please paste it and I'll map each item to a status.

Gaps I observed that a checklist will probably touch (repo-derived, not the checklist):

- **Server can't start** on a fresh install (F1).
- **No pinned or locked dependencies**, no `pyproject.toml`, no `requires-python`.
- **No test runner config.** Bare `pytest` can't import the repo. There is no `conftest.py` or `pythonpath` setting, and the `sys.path` hacks are inconsistent.
- **No CI** (no `.github/`).
- **Test coverage gaps:** `virustotal_tool.py`, `abuseipdb_tool.py` and `threatfox_tool.py` have no unit tests. MCP handlers (`list_tools`, resources, prompts, `call_tool` success path, persona hash) are only partially covered (hash branch only).
- **Router tests depend on a live model download** and a score margin of 0.0014 (F2).
- **Docs drift:**
  - README's config block omits `ABUSEIPDB_API_KEY` and `THREATFOX_API_KEY`, and says threshold 0.20 vs 0.30 in `.env.example` and code.
  - README says "Shodan and/or VirusTotal"; there are 4 tools.
  - CONTRIBUTING's test command skips 8 tests and its registry example uses the old `input_type` schema.
  - README's `pip` flow vs the uv workflow you want.
- **Stray file:** `generate_report_pdf.py` (hardcoded personal path, undeclared dependency).
