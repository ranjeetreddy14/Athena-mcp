"""
Hash rule: hashes skip the similarity router entirely (no embedding model), and the audit entry
records routing="hash_rule" plus the tool that actually ran.

None of these tests need the embedding model; a sentinel makes any attempt to load it fail.
"""
import asyncio
import json

import pytest

import server
from orchestrator.entity import detect_entity, EntityType
from orchestrator.registry import ToolRegistry
from orchestrator.router import SemanticRouter

SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


@pytest.fixture
def no_model(monkeypatch):
    """Any attempt to construct the embedding model fails the test."""
    def boom(*args, **kwargs):
        raise AssertionError("Embedding model was loaded; this code path must stay model-free.")
    monkeypatch.setattr("orchestrator.router.SentenceTransformer", boom)


def _query(text):
    result = asyncio.run(server.handle_call_tool("ti_query", {"query": text}))
    return json.loads(result[0].text)


def test_hash_default_is_threatfox_by_rule(no_model):
    router = SemanticRouter(ToolRegistry("registry/tools.json"))
    query = f"check hash {SHA256}"
    entity = detect_entity(query)
    assert entity.type == EntityType.HASH

    route = router.route_query(query, entity)

    assert (route.tool_name, route.method, route.confidence) == ("threatfox_ioc", "hash_rule", 1.0)
    assert router._model is None


@pytest.mark.parametrize("phrase", ["virustotal", "vt", "yes", "approve", "confirm", "proceed", "scan vt"])
def test_hash_virustotal_only_on_explicit_request(no_model, phrase):
    router = SemanticRouter(ToolRegistry("registry/tools.json"))
    query = f"{phrase} {SHA256}"
    route = router.route_query(query, detect_entity(query))
    assert (route.tool_name, route.method) == ("url_scan_virustotal", "hash_rule")
    assert router._model is None


def test_hash_audit_entry_threatfox(no_model, monkeypatch, read_audit):
    monkeypatch.setattr(server.threatfox_tool, "execute", lambda ioc: {"malware_family": "Emotet"})

    data = _query(f"check hash {SHA256}")

    assert data["ok"] and data["audit"]["tool"] == "threatfox_ioc"
    entry = read_audit()[-1]["audit"]
    assert entry["routing"] == "hash_rule"
    assert entry["selected_tool"] == "threatfox_ioc"
    assert entry["executed_tool"] == "threatfox_ioc"
    assert entry["confidence"] == 1.0


def test_hash_audit_entry_virustotal(no_model, monkeypatch, read_audit):
    monkeypatch.setattr(server.virustotal_tool, "execute", lambda obs: {"verdict": "safe"})

    data = _query(f"yes check this hash on virustotal {SHA256}")

    assert data["ok"] and data["audit"]["tool"] == "url_scan_virustotal"
    entry = read_audit()[-1]["audit"]
    assert (entry["routing"], entry["selected_tool"], entry["executed_tool"]) == (
        "hash_rule", "url_scan_virustotal", "url_scan_virustotal")


def test_hash_no_result_still_records_executed_tool(no_model, monkeypatch, read_audit):
    monkeypatch.setattr(server.threatfox_tool, "execute", lambda ioc: {"status": "no_result"})

    data = _query(f"check hash {SHA256}")

    assert data["ok"] is False and "VirusTotal" in data["suggestions"][0]
    entry = read_audit()[-1]["audit"]
    assert (entry["routing"], entry["executed_tool"]) == ("hash_rule", "threatfox_ioc")


def test_persona_hash_still_in_audit_entry(no_model, monkeypatch, read_audit):
    monkeypatch.setattr(server.threatfox_tool, "execute", lambda ioc: {"malware_family": "X"})
    _query(f"check hash {SHA256}")
    entry = read_audit()[-1]["audit"]
    assert entry["persona"] == "senior_cti_v1_2"
    assert entry["persona_hash"] == server.PERSONA_HASH != "unknown"
