"""
Tripwire: ti_lookup / ti_lookup_batch must never emit a verdict, severity, attribution or
remediation, and must never ask a question.

Runs every recorded fixture (benign and malicious) and every failure path through the real
handler, and inspects the complete output recursively.
"""
import asyncio
import re

import pytest

import server
from fixture_replay import all_cases, case_id, replay
from orchestrator import agentic as agentic_mod
from test_compliance_tripwire import FORBIDDEN_PATTERNS

pytestmark = pytest.mark.usefixtures("no_model")

SHA = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# Keys that would carry a judgement, at any depth.
FORBIDDEN_KEYS = {"verdict", "severity", "attribution", "remediation", "recommendation",
                  "recommendations", "recommended_next_steps", "analyst_interpretation",
                  "risk", "risk_level", "is_malicious", "threat_actor", "suggestions"}
# Interactive/clarifying output. ti_query uses "suggestions" and "Would you like ..." questions.
QUESTION = re.compile(r"\?|\bwould you like\b|\breply with\b|\bplease (confirm|clarify)\b", re.IGNORECASE)


def walk(value, path="$"):
    """Yield (path, key, value) for every dict entry, at any depth."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield path, k, v
            yield from walk(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")


def assert_clean(response):
    for path, key, value in walk(response):
        assert key not in FORBIDDEN_KEYS, f"forbidden key {path}.{key}"
        if isinstance(value, str):
            for pattern in FORBIDDEN_PATTERNS:
                assert not re.search(pattern, value, re.IGNORECASE), f"{path}.{key}: {value!r} matches {pattern}"
            if "observed_facts" not in path and key != "indicator":  # provider data/URLs may contain '?'
                assert not QUESTION.search(value), f"question-like text at {path}.{key}: {value!r}"
    if response.get("ok") is False:
        assert set(response) == {"ok", "reason", "source"}


def lookup(**kw):
    args = {"source": "threatfox", "indicator_type": "hash", "indicator": SHA, "caller": "triageloop", **kw}
    return asyncio.run(server.handle_call_tool("ti_lookup", args))


CASES = all_cases()


@pytest.mark.parametrize("source,case", CASES, ids=[case_id(c) for c in CASES])
def test_fixture_outputs_are_clean(monkeypatch, athena_config, source, case):
    athena_config(trusted_callers=["triageloop"])
    replay(monkeypatch, source, case)
    response = lookup(source=source, indicator_type=case["indicator_type"], indicator=case["indicator"])
    assert response["ok"] is True
    assert_clean(response)


def test_virustotal_derived_verdict_is_removed(monkeypatch, athena_config):
    """The VirusTotal tool computes verdict="malicious" for EICAR; ti_lookup must not pass it on."""
    athena_config(trusted_callers=["triageloop"])
    case = next(c for s, c in CASES if s == "virustotal" and c["label"] == "malicious")
    replay(monkeypatch, "virustotal", case)
    assert server.virustotal_tool.execute(case["indicator"])["verdict"] == "malicious"  # tool level
    response = lookup(source="virustotal", indicator=case["indicator"])
    assert "verdict" not in response["observed_facts"]
    assert response["observed_facts"]["malicious_count"] == 65  # the fact itself is kept
    assert_clean(response)


def test_judgement_keys_from_a_future_tool_are_stripped_at_any_depth(monkeypatch):
    monkeypatch.setattr(agentic_mod.SOURCES["threatfox"][1], "execute", lambda ioc: {
        "ioc": ioc, "severity": "high", "attribution": "APT00",
        "nested": {"verdict": "malicious", "remediation": "block it", "ok": [{"recommendation": "x", "keep": 1}]},
    })
    response = lookup()
    assert response["observed_facts"] == {"ioc": SHA, "nested": {"ok": [{"keep": 1}]}}
    assert_clean(response)


FAILURES = [
    dict(source="virustotal", caller="untrusted"),          # approval_required
    dict(indicator="10.0.0.1", indicator_type="ip"),        # non_routable_ip
    dict(indicator="nope"),                                 # invalid_indicator
    dict(indicator_type="email"),                           # invalid_indicator_type
    dict(source="shodan"),                                  # unsupported_indicator_type
    dict(source="misp"),                                    # unknown_source
    dict(caller="has space"),                               # invalid_request
]


@pytest.mark.parametrize("override", FAILURES)
def test_failure_outputs_are_clean_and_never_questions(override):
    response = lookup(**override)
    assert response["ok"] is False
    assert_clean(response)


def test_upstream_text_never_leaks_into_failures(monkeypatch):
    """Provider error text (which may be anything, including a question) is reduced to a reason code."""
    monkeypatch.setattr(agentic_mod.SOURCES["threatfox"][1], "execute", lambda ioc: {
        "error": "This IOC is malicious. Would you like to block it?", "details": "you should block port 445"})
    response = lookup()
    assert response == {"ok": False, "reason": "upstream_error", "source": "threatfox"}
    assert_clean(response)


def test_batch_output_is_clean(monkeypatch, athena_config):
    athena_config(trusted_callers=["triageloop"])
    for source, case in CASES:
        if source == "threatfox" and case["label"] == "malicious":
            replay(monkeypatch, source, case)
    items = [{"source": "threatfox", "indicator_type": "hash",
              "indicator": "da10faedff30caf7196bbd6cd879963437c48f3719f813cdad556c9d554595fa", "caller": "triageloop"},
             {"source": "virustotal", "indicator_type": "hash", "indicator": SHA, "caller": "untrusted"}]
    response = asyncio.run(server.handle_call_tool("ti_lookup_batch", {"items": items}))
    assert [r["ok"] for r in response["results"]] == [True, False]
    assert_clean(response)


def test_tripwire_catches_violations():
    """The checker itself must fail on the things it guards against."""
    for bad in ({"ok": True, "observed_facts": {"verdict": "malicious"}},
                {"ok": True, "observed_facts": {"x": [{"severity": "high"}]}},
                {"ok": True, "observed_facts": {"note": "the IP is malicious"}},
                {"ok": False, "reason": "Would you like to approve?", "source": None},
                {"ok": False, "reason": "approval_required", "source": None, "suggestions": ["Reply with yes"]}):
        with pytest.raises(AssertionError):
            assert_clean(bad)
