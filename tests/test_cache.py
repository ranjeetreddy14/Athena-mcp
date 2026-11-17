"""
Response cache (orchestrator/cache.py) and config (orchestrator/config.py), plus the cache's use by
both ti_query and ti_lookup. No model needed: ti_query is exercised with hash queries (rule-routed).
"""
import asyncio
import json
import os

import pytest

import server
from orchestrator import agentic as agentic_mod
from orchestrator.cache import ResponseCache, is_cacheable
from orchestrator.config import (BASE_DIR, DEFAULT_CACHE_TTL_SECONDS, AthenaConfig, ConfigError,
                                 load_config)

pytestmark = pytest.mark.usefixtures("no_model")

SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# --- ResponseCache unit -------------------------------------------------------------------------
def test_round_trip(tmp_path):
    c = ResponseCache(str(tmp_path), 3600)
    assert c.get("threatfox", SHA) is None
    assert c.put("threatfox", SHA, {"ioc": SHA}) is True
    assert c.get("threatfox", SHA) == {"ioc": SHA}


def test_key_is_source_and_indicator(tmp_path):
    c = ResponseCache(str(tmp_path), 3600)
    c.put("threatfox", SHA, {"from": "threatfox"})
    assert c.get("virustotal", SHA) is None
    assert c.get("threatfox", SHA[:-1] + "0") is None


def test_ttl_expiry(tmp_path):
    clock = Clock()
    c = ResponseCache(str(tmp_path), 60, clock=clock)
    c.put("shodan", "8.8.8.8", {"ip": "8.8.8.8"})
    clock.t += 59
    assert c.get("shodan", "8.8.8.8") is not None
    clock.t += 1
    assert c.get("shodan", "8.8.8.8") is None


def test_ttl_zero_disables_cache(tmp_path):
    c = ResponseCache(str(tmp_path), 0)
    assert c.put("shodan", "8.8.8.8", {"ip": "8.8.8.8"}) is False
    assert c.get("shodan", "8.8.8.8") is None
    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize("data,cacheable", [
    ({"ioc": "x"}, True), ({"status": "no_result", "message": "m"}, True),
    ({"status": "not_found", "message": "m"}, True), ({"error": "boom"}, False),
    ({"status": "pending", "message": "m"}, False), ("str", False),
])
def test_only_successful_results_are_cached(tmp_path, data, cacheable):
    assert is_cacheable(data) is cacheable
    assert ResponseCache(str(tmp_path), 3600).put("virustotal", "x", data) is cacheable


def test_corrupt_entry_is_a_miss(tmp_path):
    c = ResponseCache(str(tmp_path), 3600)
    c.put("threatfox", SHA, {"ioc": SHA})
    [entry] = list(tmp_path.glob("*.json"))
    entry.write_text("{not json")
    assert c.get("threatfox", SHA) is None
    c.put("threatfox", SHA, {"ioc": SHA})  # recovers
    assert c.get("threatfox", SHA) == {"ioc": SHA}


def test_put_never_raises_on_unwritable_dir(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    c = ResponseCache(str(blocker / "cache"), 3600)  # parent is a file
    assert c.put("threatfox", SHA, {"ioc": SHA}) is False
    assert c.get("threatfox", SHA) is None


def test_entries_hold_no_credentials(tmp_path):
    c = ResponseCache(str(tmp_path), 3600)
    c.put("threatfox", SHA, {"ioc": SHA})
    text = next(tmp_path.glob("*.json")).read_text()
    assert set(json.loads(text)) == {"source", "indicator", "stored_at", "data"}
    assert "dummy-" not in text


# --- config -------------------------------------------------------------------------------------
def test_defaults_are_fail_safe(monkeypatch):
    monkeypatch.delenv("ATHENA_CACHE_DIR")
    cfg = load_config()  # ATHENA_CONFIG points at a non-existent file
    assert cfg == AthenaConfig()
    assert cfg.trusted_callers == frozenset() and cfg.medium_risk_requires_approval is True
    assert cfg.cache_ttl_seconds == DEFAULT_CACHE_TTL_SECONDS == 3600
    assert cfg.cache_dir == os.path.join(BASE_DIR, "cache")


def test_config_file_values(athena_config, monkeypatch, tmp_path):
    monkeypatch.delenv("ATHENA_CACHE_DIR")
    athena_config(trusted_callers=["triageloop"], medium_risk_requires_approval=False,
                  cache={"dir": "var/athena-cache", "ttl_seconds": 120})
    cfg = load_config()
    assert cfg.trusted_callers == {"triageloop"} and cfg.medium_risk_requires_approval is False
    assert cfg.cache_dir == os.path.join(BASE_DIR, "var/athena-cache")  # relative -> repo root
    assert cfg.cache_ttl_seconds == 120


def test_env_overrides_file(athena_config, monkeypatch, tmp_path):
    athena_config(cache={"dir": "ignored", "ttl_seconds": 120})
    monkeypatch.setenv("ATHENA_CACHE_DIR", str(tmp_path / "c"))
    monkeypatch.setenv("ATHENA_CACHE_TTL", "7")
    cfg = load_config()
    assert (cfg.cache_dir, cfg.cache_ttl_seconds) == (str(tmp_path / "c"), 7)


@pytest.mark.parametrize("values", [
    {"trusted_callers": "triageloop"}, {"trusted_callers": [""]}, {"trusted_callers": [1]},
    {"medium_risk_requires_approval": "yes"}, {"cache": []}, {"cache": {"ttl_seconds": -5}},
    {"cache": {"ttl_seconds": True}}, {"cache": {"ttl_seconds": 1.5}},
])
def test_invalid_config_raises(athena_config, values):
    athena_config(**values)
    with pytest.raises(ConfigError):
        load_config()


def test_invalid_ttl_env_raises(monkeypatch):
    monkeypatch.setenv("ATHENA_CACHE_TTL", "soon")
    with pytest.raises(ConfigError):
        load_config()


# --- shared by ti_lookup and ti_query -----------------------------------------------------------
def _ti_query(text):
    return json.loads(asyncio.run(server.handle_call_tool("ti_query", {"query": text}))[0].text)


def _ti_lookup(indicator=SHA):
    return asyncio.run(server.handle_call_tool("ti_lookup", {
        "source": "threatfox", "indicator_type": "hash", "indicator": indicator, "caller": "triageloop"}))


@pytest.fixture
def threatfox_calls(monkeypatch):
    calls = []

    def execute(ioc):
        calls.append(ioc)
        return {"ioc": ioc, "malware_family": "Mirai", "confidence": 90}

    monkeypatch.setattr(server.threatfox_tool, "execute", execute)
    return calls


def test_ti_lookup_second_call_is_cache_hit(threatfox_calls, read_audit):
    first, second = _ti_lookup(), _ti_lookup(SHA.upper())
    assert (first["cached"], second["cached"]) == (False, True)
    assert first["observed_facts"] == second["observed_facts"]
    assert threatfox_calls == [SHA]
    hit = read_audit()[-1]["audit"]
    assert (hit["cache_hit"], hit["executed_tool"], hit["tool"]) == (True, None, "threatfox_ioc")


def test_ti_query_second_call_is_cache_hit_with_identical_response(threatfox_calls, read_audit):
    first, second = _ti_query(f"check hash {SHA}"), _ti_query(f"check hash {SHA}")
    assert first == second  # ti_query's response contract is unaffected by a cache hit
    assert len(threatfox_calls) == 1
    audits = [e["audit"] for e in read_audit()]
    assert [(a["cache_hit"], a["executed_tool"]) for a in audits] == [(False, "threatfox_ioc"), (True, None)]


def test_cache_shared_lookup_then_query(threatfox_calls, read_audit):
    _ti_lookup()
    data = _ti_query(f"check hash {SHA.upper()}")
    assert data["ok"] and data["observed_facts"]["malware_family"] == "Mirai"
    assert threatfox_calls == [SHA]
    assert read_audit()[-1]["audit"]["cache_hit"] is True


def test_cache_shared_query_then_lookup(threatfox_calls):
    _ti_query(f"check hash {SHA}")
    assert _ti_lookup()["cached"] is True
    assert threatfox_calls == [SHA]


def test_errors_are_not_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(server.threatfox_tool, "execute",
                        lambda ioc: calls.append(ioc) or {"error": "ThreatFox API Error: 500"})
    _ti_lookup(), _ti_lookup()
    _ti_query(f"check hash {SHA}")
    assert len(calls) == 3


def test_expiry_through_ti_lookup(threatfox_calls, monkeypatch):
    import orchestrator.cache as cache_mod
    now = [1_000_000.0]
    monkeypatch.setattr(cache_mod.time, "time", lambda: now[0])
    _ti_lookup()
    now[0] += DEFAULT_CACHE_TTL_SECONDS - 1
    assert _ti_lookup()["cached"] is True
    now[0] += 1
    assert _ti_lookup()["cached"] is False
    assert len(threatfox_calls) == 2


def test_ttl_zero_disables_for_both(threatfox_calls, monkeypatch):
    monkeypatch.setenv("ATHENA_CACHE_TTL", "0")
    _ti_lookup(), _ti_lookup(), _ti_query(f"check hash {SHA}")
    assert len(threatfox_calls) == 3


def test_ti_query_survives_bad_config(threatfox_calls, monkeypatch, tmp_path):
    """ti_query must not fail because of agentic config; it runs uncached instead."""
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    monkeypatch.setenv("ATHENA_CONFIG", str(bad))
    assert _ti_query(f"check hash {SHA}")["ok"] is True
    assert _ti_query(f"check hash {SHA}")["ok"] is True
    assert len(threatfox_calls) == 2


def test_cache_lives_under_configured_dir(threatfox_calls, cache_dir):
    _ti_lookup()
    assert len(list(cache_dir.glob("*.json"))) == 1
