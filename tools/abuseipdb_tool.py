"""
AbuseIPDB Tool Implementation
Responsibility: Check IP reputation via AbuseIPDB API.
"""
import os
import requests
import ipaddress
from typing import Dict, Any

def is_public_ip(ip: str) -> bool:
    """Validates if an IP is public-facing."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except ValueError:
        return False

def execute(ip: str) -> Dict[str, Any]:
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        return {"error": "Missing ABUSEIPDB_API_KEY environment variable."}

    if not is_public_ip(ip):
        return {"error": f"IP {ip} is private/internal and cannot be checked on AbuseIPDB."}

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()["data"]
            return {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "distinct_users": data.get("numDistinctUsers"),
                "last_reported_at": data.get("lastReportedAt"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "country": data.get("countryCode")
            }
        else:
            return {"error": f"AbuseIPDB API Error: {resp.status_code}", "details": resp.text}
    except Exception as e:
        return {"error": f"Execution failed: {str(e)}"}
