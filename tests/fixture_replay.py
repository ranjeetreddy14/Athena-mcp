"""
Offline replay of the recorded provider fixtures in fixtures/{source}.json.

`replay(monkeypatch, source, case)` patches requests.get/post so the real tool code receives the
recorded HTTP response. It asserts the tool calls the same endpoint that was recorded, so a fixture
can't silently go stale against the tool's URL. Nothing touches the network.
"""
import json
import os

import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = ("shodan", "virustotal", "abuseipdb", "threatfox")


def load_fixture(source):
    with open(os.path.join(REPO_ROOT, "fixtures", f"{source}.json"), encoding="utf-8") as f:
        return json.load(f)


def load_schema(source):
    with open(os.path.join(REPO_ROOT, "schemas", f"{source}.json"), encoding="utf-8") as f:
        return json.load(f)


def all_cases():
    """[(source, case), ...] for every recorded case, for parametrisation."""
    return [(source, case) for source in SOURCES for case in load_fixture(source)["cases"]]


def case_id(param):
    source, case = param
    return f"{source}-{case['label']}"


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.ok = 200 <= status_code < 300
        self.text = json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return json.loads(json.dumps(self._body))  # fresh copy per call


def replay(monkeypatch, source, case, status_code=None, body=None):
    """Serve `case`'s recorded response (optionally overridden) to the tool. Returns the call log."""
    recorded = case["request"]
    calls = []
    response = FakeResponse(status_code or case["response"]["status_code"],
                            case["response"]["json"] if body is None else body)

    def fake(url, *args, **kwargs):
        calls.append({"url": url, **kwargs})
        assert url == recorded["url"], f"tool called {url!r}, fixture recorded {recorded['url']!r}"
        if "json" in recorded:
            assert kwargs.get("json") == recorded["json"]
        return response

    monkeypatch.setattr(requests, "get" if recorded["method"] == "GET" else "post", fake)
    return calls
