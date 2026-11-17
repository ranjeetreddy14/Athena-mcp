"""
ti://capabilities is read by downstream clients (e.g. TriageLoop) to record Athena's version per case.
"""
import asyncio
import json
import os
import tomllib

import pytest
from mcp import types

import server
from orchestrator import agentic
from orchestrator.config import DEFAULT_CACHE_TTL_SECONDS, AthenaConfig
from orchestrator.indicators import INDICATOR_TYPES
from orchestrator.version import AGENTIC_CONTRACT_VERSION, ATHENA_VERSION


def _read(uri):
    return asyncio.run(server.handle_read_resource(types.AnyUrl(uri)))


def test_capabilities_resource_is_readable():
    manifest = json.loads(_read("ti://capabilities"))
    assert manifest["athena_version"]
    assert manifest["output_contract"]["version"] == "1.2"  # response schema unchanged


def test_listed_resource_uri_is_readable():
    """Every URI advertised by list_resources must actually be readable."""
    for resource in asyncio.run(server.handle_list_resources()):
        assert json.loads(_read(str(resource.uri)))


def test_capabilities_version_matches_package_version():
    with open("pyproject.toml", "rb") as f:
        package_version = tomllib.load(f)["project"]["version"]
    manifest = json.loads(_read("ti://capabilities"))
    assert manifest["athena_version"] == package_version == ATHENA_VERSION


# --- v1.3 agentic mode: the manifest must describe the code exactly (TriageLoop reads it) -------
def _manifest():
    return json.loads(_read("ti://capabilities"))


def test_manifest_lists_every_mcp_tool():
    listed = [t.name for t in asyncio.run(server.handle_list_tools())]
    assert [t["name"] for t in _manifest()["mcp_tools"]] == listed == ["ti_query", "ti_lookup", "ti_lookup_batch"]
    assert _manifest()["agentic_mode"]["tools"] == ["ti_lookup", "ti_lookup_batch"]


def test_agentic_contract_version():
    assert _manifest()["agentic_mode"]["contract_version"] == AGENTIC_CONTRACT_VERSION


def test_agentic_sources_match_code_and_registry():
    sources = _manifest()["agentic_mode"]["sources"]
    assert list(sources) == list(agentic.SOURCES)
    for source, (tool_name, _) in agentic.SOURCES.items():
        tool = server.registry.get_tool(tool_name)
        assert sources[source]["tool"] == tool_name
        assert sources[source]["indicator_types"] == tool.input_types
        assert sources[source]["risk_tier"] == tool.risk_tier
        assert os.path.exists(sources[source]["observed_facts_schema"])


def test_agentic_constants_match_code():
    mode = _manifest()["agentic_mode"]
    assert mode["reason_codes"] == list(agentic.REASONS)
    assert mode["batch_max_items"] == agentic.MAX_BATCH_ITEMS
    assert mode["cache"]["default_ttl_seconds"] == DEFAULT_CACHE_TTL_SECONDS
    assert list(mode["indicator_types"]) == list(INDICATOR_TYPES)
    defaults = AthenaConfig()
    assert mode["approval"]["defaults"] == {"trusted_callers": sorted(defaults.trusted_callers),
                                             "medium_risk_requires_approval": defaults.medium_risk_requires_approval}


def test_agentic_audit_fields_are_really_written(read_audit):
    asyncio.run(server.handle_call_tool("ti_lookup", {"source": "misp", "indicator_type": "ip",
                                                      "indicator": "8.8.8.8", "caller": "triageloop"}))
    written = set(read_audit()[-1]["audit"])
    assert set(_manifest()["agentic_mode"]["audit"]["fields"]) <= written


def test_manifest_tool_input_types_match_registry():
    """available_tools.input_type is human-readable; check it names exactly the registry's types."""
    words = {"ip": "IP", "domain": "Domain", "url": "URL", "hash": "Hash"}
    for entry in _manifest()["available_tools"]:
        tool = server.registry.get_tool(entry["name"])
        named = {t for t, w in words.items() if w.lower() in entry["input_type"].lower()}
        assert named == set(tool.input_types), entry


@pytest.mark.parametrize("uri", ["ti://unknown", "ti://capabilities-x"])
def test_unknown_resource_still_rejected(uri):
    with pytest.raises(ValueError, match="Unknown resource"):
        _read(uri)


def test_wrong_scheme_rejected():
    with pytest.raises(ValueError, match="Unsupported URI scheme"):
        _read("https://capabilities")
