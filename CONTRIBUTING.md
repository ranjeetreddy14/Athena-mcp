# Contributing to Athena

We love imagination and scalability! This project is designed so that anyone can add new capabilities without touching the core routing engine.

## Setup

Athena uses [uv](https://docs.astral.sh/uv/) and requires Python 3.11+.

```bash
uv sync          # creates .venv from uv.lock (CPU-only torch on Linux/Windows)
uv run pytest    # run the test suite
```

## Running the tests

Tests use **pytest** (the only supported runner) and run fully offline with no real API keys:

```bash
uv run pytest                      # everything
uv run pytest -m "not requires_model"   # skip tests that load the embedding model
```

- `tests/conftest.py` sets dummy values for every API-key variable, points `ATHENA_ENV_FILE` and
  `ATHENA_AUDIT_PATH` at temp locations, and blocks non-loopback network access. Tests must never read
  `.env` or write `logs/audit.jsonl`; both are enforced and will raise.
- Tests that route queries through the similarity router are marked `@pytest.mark.requires_model`.
  They need the `all-MiniLM-L6-v2` model in your local Hugging Face cache and are **skipped with a
  message** when it is absent. Populate the cache once (needs network):
  `uv run python -c "from sentence_transformers import SentenceTransformer as S; S('all-MiniLM-L6-v2')"`
- Mock tool network calls (`requests`, or the tool's `execute`); never let a test hit a live API.

## How to add a new Threat Intel Tool

### 1. Implement the Logic
Create a new file in `/tools/` (e.g., `tools/misp_tool.py`).
Your file should expose a single `execute(value)` function that returns a dictionary.

```python
def execute(value: str):
    # Your API logic here
    return {"status": "ok", "data": ...}
```

### 2. Register the Tool
Add your tool to `registry/tools.json`. List its API-key variable in `env_var_name`; the test
suite reads that field to inject a dummy key automatically.

```json
{
  "name": "my_new_tool",
  "input_types": ["domain"],
  "intents": [
    "check domain on my tool",
    "is this domain blocked"
  ],
  "risk_tier": "low",
  "requires_user_approval": false,
  "enabled": true,
  "requires_api_key": true,
  "env_var_name": "MY_TOOL_API_KEY"
}
```

### 3. Update the Server
In `server.py`, add your tool to the execution switch in `handle_call_tool`.

```python
if route.tool_name == "my_new_tool":
    tool_data = await asyncio.to_thread(my_tool.execute, entity.value)
```

### 4. Agentic mode, schema and fixture
- Add the tool to `SOURCES` in `orchestrator/agentic.py` (source name → registry tool + module) and to
  `agentic_mode.sources` in `capabilities.json`. `tests/test_capabilities.py` fails until both agree.
- Add `schemas/<source>.json` describing the tool's success output (`additionalProperties: false`).
- Add a recorder for the source in `scripts/record_fixtures.py` (read-only lookups, one benign and one
  malicious public indicator, sanitised) and commit `fixtures/<source>.json`. The fixture tests replay it
  offline and validate the tool's output against the schema.
- Make sure the tool's output carries no judgement (verdict, severity, attribution, remediation):
  `tests/test_agentic_tripwire.py` runs every fixture through `ti_lookup`.

Note: hashes are not routed by the similarity router; they follow a fixed rule
(ThreatFox by default, VirusTotal when the user asks for it) in `orchestrator/router.py`.

## Pull Request Guidelines
- Ensure `uv run pytest` passes.
- Document any new `.env` variables in `.env.example`.
- Commit `uv.lock` when you change dependencies in `pyproject.toml` (`uv lock`).
- Keep output JSON structured and flat where possible.
