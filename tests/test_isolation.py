"""
Guards for the test-suite's own guarantees (see conftest.py) and for lazy model loading.
No test here needs the embedding model.
"""
import asyncio
import json
import os

import pytest

import server
from conftest import API_KEY_VARS, REPO_ROOT


@pytest.fixture
def no_model(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("Embedding model was loaded; this code path must stay model-free.")
    monkeypatch.setattr("orchestrator.router.SentenceTransformer", boom)


# --- isolation ---------------------------------------------------------------------------------
def test_every_registry_key_is_a_dummy():
    assert API_KEY_VARS, "registry/tools.json should declare env vars"
    for var in API_KEY_VARS:
        assert os.environ[var] == f"dummy-{var.lower()}"


def test_audit_path_is_a_temp_file_not_the_real_log(audit_path):
    assert server.get_audit_path() == str(audit_path)
    assert not str(audit_path).startswith(os.path.join(REPO_ROOT, "logs"))


def test_audit_path_defaults_to_logs_dir(monkeypatch):
    monkeypatch.delenv("ATHENA_AUDIT_PATH")
    assert server.get_audit_path() == os.path.join(REPO_ROOT, "logs", "audit.jsonl")


def test_env_file_is_not_the_repo_dotenv():
    assert os.path.abspath(os.environ["ATHENA_ENV_FILE"]) != os.path.join(REPO_ROOT, ".env")
    assert not os.path.exists(os.environ["ATHENA_ENV_FILE"])


@pytest.mark.parametrize("rel", [".env", os.path.join("logs", "audit.jsonl"), os.path.join("config", "athena.json"),
                                 os.path.join("cache", "anything.json")])
def test_tripwire_blocks_real_dotenv_audit_log_config_and_cache(rel):
    with pytest.raises(RuntimeError, match="must not touch"):
        open(os.path.join(REPO_ROOT, rel))


def test_non_loopback_network_is_blocked():
    import socket
    # A routable literal IP: no DNS involved, so only the conftest guard can stop this.
    with pytest.raises(RuntimeError, match="network connection"):
        socket.create_connection(("93.184.216.34", 80), timeout=2)


def test_config_and_cache_are_temp_locations(cache_dir):
    from orchestrator.config import load_config
    assert not os.path.exists(os.environ["ATHENA_CONFIG"])
    assert load_config().cache_dir == str(cache_dir)
    assert not str(cache_dir).startswith(os.path.join(REPO_ROOT, "cache"))


def test_huggingface_is_offline():
    assert os.environ["HF_HUB_OFFLINE"] == "1"


# --- lazy model loading ------------------------------------------------------------------------
def test_importing_server_does_not_load_model():
    assert server.router._model is None


def test_mcp_discovery_calls_do_not_load_model(no_model):
    """list_tools / prompts / resources are what an agentic client calls on connect."""
    assert [t.name for t in asyncio.run(server.handle_list_tools())] == ["ti_query", "ti_lookup", "ti_lookup_batch"]
    assert [p.name for p in asyncio.run(server.handle_list_prompts())] == ["senior_cti_analyst"]
    assert len(asyncio.run(server.handle_list_resources())) == 1
    assert asyncio.run(server.handle_read_resource(server.types.AnyUrl("ti://capabilities")))
    prompt = asyncio.run(server.handle_get_prompt("senior_cti_analyst", None))
    assert prompt.messages


def test_queries_with_no_routable_entity_do_not_load_model(no_model):
    result = asyncio.run(server.handle_call_tool("ti_query", {"query": "hello world"}))
    data = json.loads(result[0].text)
    assert data["ok"] is False
    assert server.router._model is None
