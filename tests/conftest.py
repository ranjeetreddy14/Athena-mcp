"""
Test isolation for Athena.

Guarantees, enforced here rather than by convention:
  * No real API keys: every key env var named in registry/tools.json is overwritten with a dummy.
  * No .env: ATHENA_ENV_FILE points at a non-existent file, and an audit hook makes opening the
    repo's .env raise.
  * No real audit log: ATHENA_AUDIT_PATH points at a temp file (per test), and the audit hook makes
    opening the repo's logs/audit.jsonl raise.
  * No network: non-loopback socket connects raise, and Hugging Face runs in offline mode.
    (Tests that need the embedding model are marked `requires_model` and skipped if it is not
    already in the local HF cache.)

All of this runs at conftest import time, i.e. before any test module imports `server`.
"""
import json
import os
import socket
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_REPO = "sentence-transformers/all-MiniLM-L6-v2"

# --- 1. Environment (module level on purpose: must precede `import server`) ---------------------
_SESSION_TMP = tempfile.mkdtemp(prefix="athena-tests-")

# Hugging Face: never download during tests. Must be set before huggingface_hub is imported.
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# Overwrite (not setdefault) so a real key exported in the developer's shell can't leak in.
with open(os.path.join(REPO_ROOT, "registry", "tools.json"), encoding="utf-8") as _f:
    API_KEY_VARS = sorted(
        {t["env_var_name"] for t in json.load(_f)["tools"] if t.get("env_var_name")}
    )
for _var in API_KEY_VARS:
    os.environ[_var] = f"dummy-{_var.lower()}"

os.environ["ROUTER_THRESHOLD"] = "0.30"  # the documented default, independent of any local .env
os.environ["ATHENA_ENV_FILE"] = os.path.join(_SESSION_TMP, "no-such.env")
os.environ["ATHENA_AUDIT_PATH"] = os.path.join(_SESSION_TMP, "audit.jsonl")

# --- 2. Audit hook: tripwire on the two files tests must never touch ---------------------------
_FORBIDDEN = {
    os.path.normcase(os.path.abspath(os.path.join(REPO_ROOT, ".env"))): ".env",
    os.path.normcase(os.path.abspath(os.path.join(REPO_ROOT, "logs", "audit.jsonl"))): "logs/audit.jsonl",
}


def _open_guard(event, args):
    if event == "open" and isinstance(args[0], (str, os.PathLike)):
        name = _FORBIDDEN.get(os.path.normcase(os.path.abspath(os.fspath(args[0]))))
        if name:
            raise RuntimeError(f"Test suite attempted to open {name}; tests must not touch it.")


sys.addaudithook(_open_guard)

# --- 3. Model availability (item: requires_model) ----------------------------------------------
def _model_cached() -> bool:
    try:
        from huggingface_hub import snapshot_download

        path = snapshot_download(MODEL_REPO, local_files_only=True)
        return os.path.exists(os.path.join(path, "modules.json"))
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    if _model_cached():
        return
    skip = pytest.mark.skip(
        reason=(
            f"Embedding model '{MODEL_REPO}' is not in the local Hugging Face cache and tests run "
            "offline. Populate it once with network access: "
            "uv run python -c \"from sentence_transformers import SentenceTransformer as S; "
            "S('all-MiniLM-L6-v2')\""
        )
    )
    for item in items:
        if "requires_model" in item.keywords:
            item.add_marker(skip)


# --- 4. Fixtures --------------------------------------------------------------------------------
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


@pytest.fixture(scope="session", autouse=True)
def _no_network():
    """Fail loudly on any non-loopback socket connect."""
    original = socket.socket.connect

    def guarded(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0] if isinstance(address, tuple) else address
            if host not in _LOOPBACK:
                raise RuntimeError(f"Test suite attempted a network connection to {address!r}.")
        return original(self, address)

    socket.socket.connect = guarded
    yield
    socket.socket.connect = original


@pytest.fixture(autouse=True)
def audit_path(tmp_path, monkeypatch):
    """Fresh audit log per test; yields its path so tests can read what was logged."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ATHENA_AUDIT_PATH", str(path))
    return path


@pytest.fixture
def read_audit(audit_path):
    def _read():
        if not audit_path.exists():
            return []
        return [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]

    return _read
