"""
Tool tests driven by the recorded fixtures (fixtures/*.json), and schema validation of every
tool's observed_facts against schemas/*.json. Offline; no model.
"""
import copy

import jsonschema
import pytest

from fixture_replay import SOURCES, all_cases, case_id, load_fixture, load_schema, replay
from tools import abuseipdb_tool, shodan_tool, threatfox_tool, virustotal_tool

MODULES = {"shodan": shodan_tool, "virustotal": virustotal_tool,
           "abuseipdb": abuseipdb_tool, "threatfox": threatfox_tool}
CASES = all_cases()


def _case(source, label):
    return next(c for c in load_fixture(source)["cases"] if c["label"] == label)


def _validate(source, facts):
    jsonschema.Draft202012Validator(load_schema(source)).validate(facts)


# --- fixtures themselves ------------------------------------------------------------------------
@pytest.mark.parametrize("source", SOURCES)
def test_fixture_has_benign_and_malicious_public_cases(source):
    doc = load_fixture(source)
    assert doc["source"] == source and doc["recorded_at"] and doc["sanitisation"]
    assert sorted(c["label"] for c in doc["cases"]) == ["benign", "malicious"]
    for case in doc["cases"]:
        assert case["why"]
        if case["indicator_type"] == "ip":
            assert shodan_tool.validate_ip(case["indicator"]), "fixtures must use public IPs only"


@pytest.mark.parametrize("source", SOURCES)
def test_fixture_contains_no_credentials(source):
    text = repr(load_fixture(source))
    for case in load_fixture(source)["cases"]:
        for section in ("params", "headers"):
            for name, value in case["request"].get(section, {}).items():
                if name.lower() in ("key", "x-apikey", "auth-key"):
                    assert value == "<redacted>"
    assert "dummy-" not in text


# --- schemas ------------------------------------------------------------------------------------
@pytest.mark.parametrize("source", SOURCES)
def test_schema_is_valid_draft_2020_12(source):
    jsonschema.Draft202012Validator.check_schema(load_schema(source))


@pytest.mark.parametrize("source,case", CASES, ids=[case_id(c) for c in CASES])
def test_tool_output_from_fixture_validates_against_schema(monkeypatch, source, case):
    calls = replay(monkeypatch, source, case)
    facts = MODULES[source].execute(case["indicator"])
    assert "error" not in facts, facts
    assert len(calls) == 1
    _validate(source, facts)


@pytest.mark.parametrize("source,extra", [("shodan", "severity"), ("abuseipdb", "verdict"),
                                          ("threatfox", "attribution"), ("virustotal", "remediation")])
def test_schema_rejects_unexpected_fields(monkeypatch, source, extra):
    """additionalProperties=false: a tool that starts emitting a new field fails validation."""
    case = _case(source, "benign")
    replay(monkeypatch, source, case)
    facts = MODULES[source].execute(case["indicator"])
    facts[extra] = "x"
    with pytest.raises(jsonschema.ValidationError):
        _validate(source, facts)


# --- per-source facts (what the tool extracts from the recorded payload) -----------------------
def test_shodan_benign_host_facts(monkeypatch):
    case = _case("shodan", "benign")
    raw = case["response"]["json"]
    replay(monkeypatch, "shodan", case)
    facts = shodan_tool.execute(case["indicator"])
    assert facts["ip"] == "8.8.8.8"
    assert (facts["country"], facts["org"], facts["asn"]) == (raw["country_name"], raw["org"], raw["asn"])
    assert facts["ports"] == raw["ports"] and facts["hostnames"] == raw["hostnames"]
    assert facts["last_seen"] == raw["last_update"]


def test_shodan_unknown_ip_is_not_found(monkeypatch):
    case = _case("shodan", "malicious")
    assert case["response"]["status_code"] == 404
    replay(monkeypatch, "shodan", case)
    assert shodan_tool.execute(case["indicator"])["status"] == "not_found"


@pytest.mark.parametrize("label,malicious,verdict", [("benign", 0, "safe"), ("malicious", 65, "malicious")])
def test_virustotal_hash_facts(monkeypatch, label, malicious, verdict):
    case = _case("virustotal", label)
    stats = case["response"]["json"]["data"]["attributes"]["last_analysis_stats"]
    replay(monkeypatch, "virustotal", case)
    facts = virustotal_tool.execute(case["indicator"])
    assert facts["hash"] == case["indicator"]
    assert facts["malicious_count"] == stats["malicious"] == malicious
    assert facts["total_engines"] == sum(stats.values())
    assert facts["verdict"] == verdict  # tool-level field; ti_lookup strips it (see test_agentic_tripwire)
    assert facts["permalink"] == f"https://www.virustotal.com/gui/file/{case['indicator']}"


def test_virustotal_url_report_validates_against_schema(monkeypatch):
    """URL mode, using the recorded EICAR attributes as the cached URL report (no submission)."""
    case = copy.deepcopy(_case("virustotal", "malicious"))
    url = "https://example.com/eicar.com"
    case["request"]["url"] = f"https://www.virustotal.com/api/v3/urls/{virustotal_tool.url_to_id(url)}"
    replay(monkeypatch, "virustotal", case)
    facts = virustotal_tool.execute(url)
    assert facts["url"] == url and "hash" not in facts
    _validate("virustotal", facts)


def test_virustotal_unknown_hash_is_no_result(monkeypatch):
    case = _case("virustotal", "benign")
    replay(monkeypatch, "virustotal", case, status_code=404, body={"error": {"code": "NotFoundError"}})
    facts = virustotal_tool.execute(case["indicator"])
    assert facts["status"] == "no_result"
    _validate("virustotal", facts)


@pytest.mark.parametrize("label", ["benign", "malicious"])
def test_abuseipdb_facts(monkeypatch, label):
    case = _case("abuseipdb", label)
    raw = case["response"]["json"]["data"]
    replay(monkeypatch, "abuseipdb", case)
    facts = abuseipdb_tool.execute(case["indicator"])
    assert facts == {
        "ip": case["indicator"], "abuse_confidence_score": raw["abuseConfidenceScore"],
        "total_reports": raw["totalReports"], "distinct_users": raw["numDistinctUsers"],
        "last_reported_at": raw["lastReportedAt"], "usage_type": raw["usageType"],
        "isp": raw["isp"], "country": raw["countryCode"],
    }


def test_threatfox_malicious_hash_facts(monkeypatch):
    case = _case("threatfox", "malicious")
    raw = case["response"]["json"]["data"][0]
    replay(monkeypatch, "threatfox", case)
    facts = threatfox_tool.execute(case["indicator"])
    assert facts["ioc"] == case["indicator"]
    assert facts["malware_family"] == raw["malware_printable"] == "Mirai"
    assert facts["confidence"] == raw["confidence_level"] and facts["tags"] == raw["tags"]
    # Known issue (unchanged in v1.3.0): the tool reads ioc_type_full/threat_type_full, which
    # ThreatFox does not return, so these are always null.
    assert facts["ioc_type"] is None and facts["threat_type"] is None


def test_threatfox_benign_ip_is_no_result(monkeypatch):
    case = _case("threatfox", "benign")
    replay(monkeypatch, "threatfox", case)
    assert threatfox_tool.execute(case["indicator"])["status"] == "no_result"


# --- error paths (no fixture body needed; these never become observed_facts) -------------------
@pytest.mark.parametrize("source,status", [("shodan", 403), ("shodan", 429), ("abuseipdb", 429),
                                           ("virustotal", 500), ("threatfox", 500)])
def test_http_errors_return_error_dicts(monkeypatch, source, status):
    case = _case(source, "benign")
    replay(monkeypatch, source, case, status_code=status, body={"errors": ["x"]})
    facts = MODULES[source].execute(case["indicator"])
    assert "error" in facts and str(status) in facts["error"]
