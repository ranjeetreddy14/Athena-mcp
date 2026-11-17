"""
Agentic mode: ti_lookup / ti_lookup_batch.

Every call goes through the real MCP SDK request handler (in-process), so the SDK's outputSchema
validation runs on every response. Every test runs with the embedding-model sentinel: any attempt
to load the model fails the test.
"""
import asyncio
import json

import jsonschema
import pytest
from mcp import types

import server
from fixture_replay import all_cases, case_id, load_fixture, load_schema, replay
from orchestrator import agentic as agentic_mod
from orchestrator.agentic import (MAX_BATCH_ITEMS, REASONS, TI_LOOKUP_BATCH_OUTPUT_SCHEMA,
                                  TI_LOOKUP_OUTPUT_SCHEMA)
from orchestrator.version import ATHENA_VERSION
from tools.shodan_tool import validate_ip as ti_query_ip_rule

pytestmark = pytest.mark.usefixtures("no_model")

SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
AUDIT_FIELDS = {"caller", "source", "indicator_type", "routing", "executed_tool", "cache_hit"}


def call(name, arguments):
    """Call a tool through the MCP SDK handler; return the structured result."""
    handler = server.server.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(method="tools/call",
                                params=types.CallToolRequestParams(name=name, arguments=arguments))
    result = asyncio.run(handler(req)).root
    assert result.isError is False, result.content[0].text  # SDK output validation passed
    assert json.loads(result.content[0].text) == result.structuredContent
    return result.structuredContent


def lookup(source="threatfox", indicator_type="hash", indicator=SHA, caller="triageloop", **extra):
    return call("ti_lookup", {"source": source, "indicator_type": indicator_type,
                              "indicator": indicator, "caller": caller, **extra})


def stub_tool(monkeypatch, source, result=None, exc=None):
    """Replace a source's tool with a stub; returns the list of indicators it was called with."""
    seen = []

    def execute(indicator):
        seen.append(indicator)
        if exc:
            raise exc
        return result if result is not None else {"ioc": indicator, "malware_family": "X"}

    monkeypatch.setattr(agentic_mod.SOURCES[source][1], "execute", execute)
    return seen


def assert_failure(response, reason, source):
    assert response == {"ok": False, "reason": reason, "source": source}
    jsonschema.validate(response, TI_LOOKUP_OUTPUT_SCHEMA)


# --- discovery ----------------------------------------------------------------------------------
def test_tools_listed_with_input_and_output_schemas():
    tools = {t.name: t for t in asyncio.run(server.handle_list_tools())}
    assert set(tools) == {"ti_query", "ti_lookup", "ti_lookup_batch"}
    for name in ("ti_lookup", "ti_lookup_batch"):
        assert tools[name].inputSchema["additionalProperties"] is False
        assert tools[name].outputSchema
    assert tools["ti_lookup"].inputSchema["properties"]["source"]["enum"] == list(agentic_mod.SOURCES)


# --- success, from recorded fixtures -------------------------------------------------------------
CASES = all_cases()


@pytest.mark.parametrize("source,case", CASES, ids=[case_id(c) for c in CASES])
def test_lookup_every_fixture(monkeypatch, athena_config, read_audit, source, case):
    athena_config(trusted_callers=["triageloop"])  # virustotal is medium risk
    replay(monkeypatch, source, case)

    r = lookup(source, case["indicator_type"], case["indicator"])

    assert set(r) == {"ok", "source", "indicator_type", "indicator", "observed_facts", "cached", "athena_version"}
    assert (r["ok"], r["source"], r["indicator_type"], r["cached"]) == (True, source, case["indicator_type"], False)
    assert r["athena_version"] == ATHENA_VERSION
    jsonschema.Draft202012Validator(load_schema(source)).validate(r["observed_facts"])
    assert "verdict" not in r["observed_facts"]

    [entry] = read_audit()
    audit = entry["audit"]
    assert AUDIT_FIELDS <= set(audit)
    assert audit["routing"] == "agentic"
    assert (audit["caller"], audit["source"], audit["indicator_type"]) == ("triageloop", source, case["indicator_type"])
    assert audit["executed_tool"] == agentic_mod.SOURCES[source][0]
    assert audit["cache_hit"] is False and audit["ok"] is True and audit["reason"] is None
    assert entry["response"] == r


# --- validation ---------------------------------------------------------------------------------
@pytest.mark.parametrize("arguments", [
    {"source": "threatfox", "indicator_type": "hash", "indicator": SHA},                        # no caller
    {"source": "threatfox", "indicator_type": "hash", "indicator": SHA, "caller": "t", "x": 1},  # extra field
    {"source": "threatfox", "indicator_type": "hash", "indicator": 123, "caller": "t"},          # wrong type
    {"source": "threatfox", "indicator_type": "hash", "indicator": SHA, "caller": ""},           # empty caller
    {"source": "threatfox", "indicator_type": "hash", "indicator": SHA, "caller": "has space"},
    {"source": "threatfox", "indicator_type": "hash", "indicator": SHA, "caller": "x" * 200},
    {},
])
def test_malformed_arguments_are_invalid_request(arguments):
    assert_failure(call("ti_lookup", arguments), "invalid_request", "threatfox" if arguments else None)


def test_non_object_arguments_are_invalid_request():
    assert_failure(server.agentic.lookup(None), "invalid_request", None)
    assert_failure(server.agentic.lookup(["threatfox"]), "invalid_request", None)


def test_unknown_source_echoes_null_source():
    assert_failure(lookup(source="misp"), "unknown_source", None)


def test_invalid_indicator_type():
    assert_failure(lookup(indicator_type="email"), "invalid_indicator_type", "threatfox")


@pytest.mark.parametrize("source,indicator_type,indicator", [
    ("shodan", "hash", SHA), ("abuseipdb", "domain", "example.com"),
    ("virustotal", "ip", "8.8.8.8"), ("shodan", "url", "https://example.com/"),
])
def test_type_not_accepted_by_source(source, indicator_type, indicator):
    assert_failure(lookup(source, indicator_type, indicator), "unsupported_indicator_type", source)


@pytest.mark.parametrize("indicator_type,indicator", [
    ("ip", "999.1.1.1"), ("ip", "8.8.8"), ("ip", "08.8.8.8"), ("ip", "2001:4860:4860::8888"), ("ip", "dns.google"),
    ("hash", "xyz"), ("hash", SHA[:-1]), ("hash", SHA + "a"),
    ("domain", "not a domain"), ("domain", "https://example.com"), ("domain", "localhost"),
    ("url", "ftp://example.com/x"), ("url", "https://"), ("url", "javascript:alert(1)"),
    ("url", "https://exa mple.com/"), ("url", "example.com/path"),
    ("hash", ""), ("hash", "   "), ("domain", "a" * 3000 + ".com"),
])
def test_invalid_indicator_format(indicator_type, indicator):
    assert_failure(lookup("threatfox", indicator_type, indicator), "invalid_indicator", "threatfox")


@pytest.mark.parametrize("indicator_type,indicator", [
    ("ip", "10.0.0.1"), ("ip", "172.16.5.4"), ("ip", "192.168.1.1"), ("ip", "127.0.0.1"),
    ("ip", "169.254.169.254"), ("ip", "0.0.0.0"),
    ("url", "http://10.0.0.1/admin"), ("url", "http://127.0.0.1:8080/"), ("url", "http://[::1]/"),
    ("url", "http://169.254.169.254/latest/meta-data"), ("url", "http://localhost/x"),
    ("url", "https://svc.localhost/"),
])
def test_non_routable_targets_rejected(indicator_type, indicator):
    assert_failure(lookup("threatfox", indicator_type, indicator), "non_routable_ip", "threatfox")


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "10.1.2.3", "172.31.255.255", "172.32.0.1",
                                "192.168.0.1", "127.0.0.2", "169.254.0.1", "100.64.0.1", "224.0.0.1",
                                "255.255.255.255", "0.0.0.0", "198.18.0.1", "203.0.113.5"])
def test_ip_rule_is_exactly_ti_querys(monkeypatch, ip):
    """Accept/reject must match the predicate ti_query's tools use, address by address."""
    stub_tool(monkeypatch, "threatfox")
    r = lookup("threatfox", "ip", ip)
    assert r["ok"] is ti_query_ip_rule(ip)
    if not r["ok"]:
        assert r["reason"] == "non_routable_ip"


@pytest.mark.parametrize("indicator_type,given,canonical", [
    ("hash", SHA.upper(), SHA), ("domain", "Example.COM.", "example.com"), ("ip", " 8.8.8.8 ", "8.8.8.8"),
])
def test_indicators_are_normalised(monkeypatch, indicator_type, given, canonical):
    seen = stub_tool(monkeypatch, "threatfox")
    r = lookup("threatfox", indicator_type, given)
    assert r["indicator"] == canonical and seen == [canonical]


# --- approval policy ----------------------------------------------------------------------------
def test_untrusted_caller_medium_risk_needs_approval_by_default(monkeypatch, read_audit):
    seen = stub_tool(monkeypatch, "virustotal")
    assert_failure(lookup("virustotal", "hash", SHA, caller="someone"), "approval_required", "virustotal")
    assert seen == []
    audit = read_audit()[-1]["audit"]
    assert (audit["reason"], audit["executed_tool"], audit["caller"]) == ("approval_required", None, "someone")


def test_trusted_caller_medium_risk_allowed(monkeypatch, athena_config):
    athena_config(trusted_callers=["triageloop"])
    seen = stub_tool(monkeypatch, "virustotal", result={"hash": SHA, "verdict": "malicious",
                                                       "malicious_count": 1, "suspicious_count": 0,
                                                       "harmless_count": 0, "total_engines": 1,
                                                       "reputation": 0, "permalink": "https://www.virustotal.com/gui/file/x"})
    r = lookup("virustotal", "hash", SHA)
    assert r["ok"] and seen == [SHA]
    assert_failure(lookup("virustotal", "hash", SHA, caller="other"), "approval_required", "virustotal")


def test_flag_off_allows_untrusted_medium_risk(monkeypatch, athena_config):
    athena_config(medium_risk_requires_approval=False)
    stub_tool(monkeypatch, "virustotal", result={"status": "no_result", "message": "m"})
    assert lookup("virustotal", "hash", SHA, caller="anyone")["ok"] is True


@pytest.mark.parametrize("source,indicator_type,indicator",
                         [("shodan", "ip", "8.8.8.8"), ("abuseipdb", "ip", "8.8.8.8"), ("threatfox", "hash", SHA)])
def test_low_risk_sources_never_need_approval(monkeypatch, source, indicator_type, indicator):
    stub_tool(monkeypatch, source, result={"status": "no_result", "message": "m"} if source != "shodan"
              else {"status": "not_found", "message": "m"})
    assert lookup(source, indicator_type, indicator, caller="untrusted")["ok"] is True


@pytest.mark.parametrize("flag", [True, False])
def test_unknown_or_high_tier_is_trusted_callers_only(monkeypatch, athena_config, flag):
    athena_config(trusted_callers=["triageloop"], medium_risk_requires_approval=flag)
    monkeypatch.setattr(server.registry.get_tool("threatfox_ioc"), "risk_tier", "high")
    stub_tool(monkeypatch, "threatfox")
    assert_failure(lookup(caller="other"), "approval_required", "threatfox")
    assert lookup(caller="triageloop")["ok"] is True


# --- error contract -----------------------------------------------------------------------------
def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("THREATFOX_API_KEY")
    seen = stub_tool(monkeypatch, "threatfox")
    assert_failure(lookup(), "missing_api_key", "threatfox")
    assert seen == []


def test_disabled_source(monkeypatch):
    monkeypatch.setattr(server.registry.get_tool("threatfox_ioc"), "enabled", False)
    assert_failure(lookup(), "source_disabled", "threatfox")


@pytest.mark.parametrize("tool_error,reason", [
    ("ThreatFox API Error: 500", "upstream_error"),
    ("Shodan API Error: 429 (Too Many Requests)", "upstream_rate_limited"),
    ("Execution failed: timeout", "upstream_error"),
])
def test_upstream_errors(monkeypatch, read_audit, tool_error, reason):
    stub_tool(monkeypatch, "threatfox", result={"error": tool_error, "details": "Would you like to retry?"})
    assert_failure(lookup(), reason, "threatfox")
    assert read_audit()[-1]["audit"]["executed_tool"] == "threatfox_ioc"


def test_real_http_429_maps_to_rate_limited(monkeypatch):
    case = load_fixture("shodan")["cases"][0]
    replay(monkeypatch, "shodan", case, status_code=429, body={"error": "rate"})
    assert_failure(lookup("shodan", "ip", "8.8.8.8"), "upstream_rate_limited", "shodan")


def test_tool_exception_is_upstream_error(monkeypatch):
    stub_tool(monkeypatch, "threatfox", exc=ConnectionError("boom"))
    assert_failure(lookup(), "upstream_error", "threatfox")


def test_tool_returning_non_dict_is_upstream_error(monkeypatch):
    monkeypatch.setattr(agentic_mod.SOURCES["threatfox"][1], "execute", lambda i: "not a dict")
    assert_failure(lookup(), "upstream_error", "threatfox")


@pytest.mark.parametrize("config", ['{"trusted_callers": "triageloop"}', '{"medium_risk_requires_approval": "no"}',
                                    "not json", '{"cache": {"ttl_seconds": -1}}', "[]"])
def test_bad_config_fails_closed(monkeypatch, tmp_path, config):
    path = tmp_path / "bad.json"
    path.write_text(config)
    monkeypatch.setenv("ATHENA_CONFIG", str(path))
    seen = stub_tool(monkeypatch, "threatfox")
    assert_failure(lookup(), "config_error", "threatfox")
    assert seen == []


def test_unexpected_exception_is_internal_error(monkeypatch, read_audit):
    def boom(*a, **k):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(agentic_mod, "normalize_indicator", boom)
    assert_failure(lookup(), "internal_error", "threatfox")
    assert read_audit()[-1]["audit"]["reason"] == "internal_error"


def test_audit_write_failure_fails_closed(monkeypatch):
    stub_tool(monkeypatch, "threatfox")

    def broken(entry):
        raise OSError("disk full")
    monkeypatch.setattr(server, "log_audit", broken)
    assert_failure(lookup(), "internal_error", "threatfox")


# --- audit: one entry per call, every path ------------------------------------------------------
@pytest.mark.parametrize("arguments", [
    {"source": "threatfox", "indicator_type": "hash", "indicator": SHA, "caller": "triageloop"},
    {"source": "virustotal", "indicator_type": "hash", "indicator": SHA, "caller": "untrusted"},
    {"source": "nope", "indicator_type": "hash", "indicator": SHA, "caller": "triageloop"},
    {"source": "threatfox", "indicator_type": "ip", "indicator": "10.0.0.1", "caller": "triageloop"},
    {"bogus": True},
])
def test_every_call_writes_exactly_one_agentic_audit_entry(monkeypatch, read_audit, arguments):
    stub_tool(monkeypatch, "threatfox")
    call("ti_lookup", arguments)
    [entry] = read_audit()
    assert AUDIT_FIELDS <= set(entry["audit"]) and entry["audit"]["routing"] == "agentic"
    assert entry["audit"]["mcp_tool"] == "ti_lookup" and entry["timestamp"]


def test_audit_clips_oversized_values(read_audit):
    lookup(caller="ok", indicator="a" * 5000, indicator_type="hash")
    assert len(read_audit()[-1]["audit"]["indicator"]) < 600


# --- batch --------------------------------------------------------------------------------------
def item(source="threatfox", indicator_type="hash", indicator=SHA, caller="triageloop"):
    return {"source": source, "indicator_type": indicator_type, "indicator": indicator, "caller": caller}


def test_batch_results_in_order_with_per_item_contract(monkeypatch, read_audit):
    seen = stub_tool(monkeypatch, "threatfox")
    items = [item(), item(indicator_type="ip", indicator="10.0.0.1"), item(source="virustotal", caller="x"),
             item(indicator_type="domain", indicator="example.com")]
    r = call("ti_lookup_batch", {"items": items})

    jsonschema.validate(r, TI_LOOKUP_BATCH_OUTPUT_SCHEMA)
    assert r["ok"] is True and r["athena_version"] == ATHENA_VERSION
    assert [x["ok"] for x in r["results"]] == [True, False, False, True]
    assert [x.get("reason") for x in r["results"]] == [None, "non_routable_ip", "approval_required", None]
    assert seen == [SHA, "example.com"]

    entries = [e["audit"] for e in read_audit()]
    assert len(entries) == 4 and len({e["batch_id"] for e in entries}) == 1
    assert [e["batch_index"] for e in entries] == [0, 1, 2, 3]
    assert all(e["routing"] == "agentic" and e["mcp_tool"] == "ti_lookup_batch" for e in entries)


def test_batch_duplicate_items_hit_cache(monkeypatch):
    seen = stub_tool(monkeypatch, "threatfox")
    r = call("ti_lookup_batch", {"items": [item(), item(indicator=SHA.upper())]})
    assert [x["cached"] for x in r["results"]] == [False, True]
    assert seen == [SHA]


@pytest.mark.parametrize("arguments,reason", [
    ({"items": []}, "invalid_request"),
    ({"items": "x"}, "invalid_request"),
    ({}, "invalid_request"),
    ({"items": [item()], "extra": 1}, "invalid_request"),
    ({"items": [item()] * (MAX_BATCH_ITEMS + 1)}, "batch_too_large"),
])
def test_batch_level_failures(monkeypatch, read_audit, arguments, reason):
    seen = stub_tool(monkeypatch, "threatfox")
    r = call("ti_lookup_batch", arguments)
    assert r == {"ok": False, "reason": reason, "source": None}
    jsonschema.validate(r, TI_LOOKUP_BATCH_OUTPUT_SCHEMA)
    assert seen == []
    [entry] = read_audit()
    assert entry["audit"]["routing"] == "agentic" and entry["audit"]["reason"] == reason


def test_batch_at_limit_is_accepted(monkeypatch):
    stub_tool(monkeypatch, "threatfox")
    r = call("ti_lookup_batch", {"items": [item()] * MAX_BATCH_ITEMS})
    assert r["ok"] and len(r["results"]) == MAX_BATCH_ITEMS


# --- the embedding model is never loaded --------------------------------------------------------
def test_agentic_calls_never_touch_the_router(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("router used by an agentic call")
    monkeypatch.setattr(server.router, "route_query", forbidden)
    stub_tool(monkeypatch, "threatfox")
    assert lookup()["ok"]
    assert call("ti_lookup_batch", {"items": [item(), item(indicator_type="ip", indicator="8.8.8.8")]})["ok"]
    assert server.router._model is None
