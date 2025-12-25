# Contributing to Athena

We love imagination and scalability! This project is designed so that anyone can add new capabilities without touching the core routing engine.

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
Add your tool to `registry/tools.json`.

```json
{
  "name": "my_new_tool",
  "input_type": "domain",
  "intents": [
    "check domain on my tool",
    "is this domain blocked"
  ],
  "risk_tier": "low",
  "enabled": true
}
```

### 3. Update the Server
In `server.py`, add your tool to the execution switch in `handle_call_tool`.

```python
if route.tool_name == "my_new_tool":
    tool_data = await asyncio.to_thread(my_tool.execute, entity.value)
```

## Pull Request Guidelines
- Ensure `unittest discover tests` passes.
- Document any new `.env` variables required.
- Keep output JSON structured and flat where possible.
