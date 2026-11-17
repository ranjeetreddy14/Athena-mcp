#!/usr/bin/env python3
"""
Record one sanitised fixture per source into fixtures/{shodan,virustotal,abuseipdb,threatfox}.json.

Each fixture holds a well-known benign and a well-known malicious *public* indicator, captured from
the live API with the same endpoints/parameters the tools use. Tests replay them offline.

    uv run python scripts/record_fixtures.py            # uses API keys from .env

Safety:
  * Read-only lookups only. VirusTotal is queried by file hash; URLs are never submitted
    (VirusTotal URL submissions are public).
  * Keys are read from .env into this process only and are never written: request auth is stored as
    "<redacted>", and the script aborts if any key value appears in a fixture.
  * Responses are reduced to the fields Athena's tools read plus identifying metadata. Banners,
    per-engine results, reporter handles and sample lists are dropped.
"""
import datetime as dt
import json
import os
import sys
import time

import requests
from dotenv import dotenv_values

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "fixtures")
TIMEOUT = 20

BENIGN_IP = ("8.8.8.8", "Google Public DNS resolver")
EMPTY_FILE_SHA256 = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                     "SHA-256 of the empty file (well-known, benign)")
EICAR_SHA256 = ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EICAR anti-malware test file (industry-standard 'malicious' test sample)")

keys = {k: v for k, v in dotenv_values(os.path.join(ROOT, ".env")).items() if k.endswith("_API_KEY") and v}


def need(name):
    if name not in keys:
        sys.exit(f"{name} not set in .env; cannot record this source.")
    return keys[name]


def pick(d, fields):
    return {k: d[k] for k in fields if k in d}


# --- sanitisers: keep what the tools read, plus identifying metadata ---------------------------
def clean_shodan(j):
    return pick(j, ["ip_str", "country_code", "country_name", "city", "org", "isp", "asn",
                    "ports", "hostnames", "tags", "last_update"])


def clean_virustotal(j):
    attrs = j.get("data", {}).get("attributes", {})
    return {"data": {"id": j["data"].get("id"), "type": j["data"].get("type"),
                     "attributes": pick(attrs, ["last_analysis_stats", "reputation", "type_description",
                                                "size", "md5", "sha1", "sha256"])}}


def clean_abuseipdb(j):
    return {"data": pick(j.get("data", {}), [
        "ipAddress", "isPublic", "ipVersion", "isWhitelisted", "abuseConfidenceScore", "countryCode",
        "usageType", "isp", "domain", "hostnames", "isTor", "totalReports", "numDistinctUsers",
        "lastReportedAt"])}


def clean_threatfox(j):
    if j.get("query_status") != "ok" or not isinstance(j.get("data"), list):
        return pick(j, ["query_status", "data"])
    entry = pick(j["data"][0], [
        "id", "ioc", "threat_type", "threat_type_desc", "ioc_type", "ioc_type_desc", "malware",
        "malware_printable", "malware_alias", "malware_malpedia", "confidence_level", "first_seen",
        "last_seen", "reference", "tags"])
    return {"query_status": "ok", "data": [entry]}


# --- live calls (same endpoints/params as tools/*.py) ------------------------------------------
def shodan(ip):
    r = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": need("SHODAN_API_KEY")}, timeout=TIMEOUT)
    return {"method": "GET", "url": f"https://api.shodan.io/shodan/host/{ip}", "params": {"key": "<redacted>"}}, r, clean_shodan


def virustotal(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    r = requests.get(url, headers={"x-apikey": need("VT_API_KEY")}, timeout=TIMEOUT)
    return {"method": "GET", "url": url, "headers": {"x-apikey": "<redacted>"}}, r, clean_virustotal


def abuseipdb(ip):
    url, params = "https://api.abuseipdb.com/api/v2/check", {"ipAddress": ip, "maxAgeInDays": "90"}
    r = requests.get(url, headers={"Accept": "application/json", "Key": need("ABUSEIPDB_API_KEY")}, params=params, timeout=TIMEOUT)
    return {"method": "GET", "url": url, "params": params, "headers": {"Key": "<redacted>"}}, r, clean_abuseipdb


def threatfox_post(payload):
    return requests.post("https://threatfox-api.abuse.ch/api/v1/", json=payload,
                         headers={"Auth-Key": need("THREATFOX_API_KEY")}, timeout=TIMEOUT)


def threatfox(ioc):
    payload = {"query": "search_ioc", "search_term": ioc}
    r = threatfox_post(payload)
    return {"method": "POST", "url": "https://threatfox-api.abuse.ch/api/v1/", "json": payload,
            "headers": {"Auth-Key": "<redacted>"}}, r, clean_threatfox


def recent_threatfox_iocs():
    """Pick public, high-confidence IOCs from ThreatFox's recent feed to serve as 'malicious' cases."""
    r = threatfox_post({"query": "get_iocs", "days": 1})
    r.raise_for_status()
    data = r.json().get("data") or []
    good = [d for d in data if (d.get("confidence_level") or 0) >= 75]
    ip = next((d for d in good if d.get("ioc_type") == "ip:port"), None)
    sha = next((d for d in good if d.get("ioc_type") == "sha256_hash"), None)
    if not ip or not sha:
        sys.exit("ThreatFox recent feed had no high-confidence ip:port and sha256 IOCs; try again later.")
    return ip, sha


def case(label, indicator_type, indicator, why, call):
    request, resp, clean = call(indicator)
    try:
        body = resp.json()
    except ValueError:
        body = None
    print(f"  {label:9s} {indicator_type:5s} {indicator[:20]:20s} HTTP {resp.status_code}")
    return {"label": label, "indicator_type": indicator_type, "indicator": indicator, "why": why,
            "request": request,
            "response": {"status_code": resp.status_code, "json": clean(body) if isinstance(body, dict) and resp.ok else body}}


def write(source, cases, note):
    doc = {
        "source": source,
        "recorded_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "recorder": "scripts/record_fixtures.py",
        "sanitisation": note,
        "cases": cases,
    }
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    for value in keys.values():
        if value and value in text:
            sys.exit(f"ABORT: an API key value appeared in the {source} fixture; nothing written.")
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"{source}.json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"  -> fixtures/{source}.json")


def main():
    print("ThreatFox recent feed (to choose public malicious indicators)")
    ip_ioc, sha_ioc = recent_threatfox_iocs()
    bad_ip = ip_ioc["ioc"].rsplit(":", 1)[0]
    bad_ip_why = (f"ThreatFox IOC #{ip_ioc.get('id')} ({ip_ioc.get('malware_printable')}, "
                  f"{ip_ioc.get('threat_type')}, confidence {ip_ioc.get('confidence_level')})")
    bad_sha = sha_ioc["ioc"]
    bad_sha_why = (f"ThreatFox IOC #{sha_ioc.get('id')} ({sha_ioc.get('malware_printable')}, "
                   f"{sha_ioc.get('threat_type')}, confidence {sha_ioc.get('confidence_level')})")

    print("shodan")
    write("shodan", [case("benign", "ip", BENIGN_IP[0], BENIGN_IP[1], shodan),
                     case("malicious", "ip", bad_ip, bad_ip_why, shodan)],
          "Top-level host fields only; service banners ('data'), vulns and other keys dropped.")

    print("virustotal")
    benign = case("benign", "hash", EMPTY_FILE_SHA256[0], EMPTY_FILE_SHA256[1], virustotal)
    time.sleep(16)  # public API: 4 requests/minute
    write("virustotal", [benign, case("malicious", "hash", EICAR_SHA256[0], EICAR_SHA256[1], virustotal)],
          "data.attributes reduced to last_analysis_stats, reputation, type_description, size and hashes; "
          "per-engine results, file names and all other attributes dropped. Hash lookups only.")

    print("abuseipdb")
    write("abuseipdb", [case("benign", "ip", BENIGN_IP[0], BENIGN_IP[1], abuseipdb),
                        case("malicious", "ip", bad_ip, bad_ip_why, abuseipdb)],
          "Summary 'data' fields only (no individual reports).")

    print("threatfox")
    write("threatfox", [case("benign", "ip", BENIGN_IP[0], BENIGN_IP[1], threatfox),
                        case("malicious", "hash", bad_sha, bad_sha_why, threatfox)],
          "First match only; reporter, credits and malware_samples dropped.")


if __name__ == "__main__":
    main()
