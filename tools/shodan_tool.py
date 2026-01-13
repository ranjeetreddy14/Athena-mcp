"""
Shodan Tool Implementation
Responsibility: Execute IP lookup via Shodan API and normalize output.
"""
import os
import requests
import ipaddress
from typing import Dict, Any

def validate_ip(ip: str) -> bool:
    """Rejects RFC1918, Loopback, Link-Local."""
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local:
            return False
        return True
    except ValueError:
        return False

def execute(ip: str) -> Dict[str, Any]:
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        return {"error": "Missing SHODAN_API_KEY environment variable."}

    if not validate_ip(ip):
        return {"error": f"IP {ip} is private/internal/invalid and cannot be scanned."}

    try:
        # NOTE: Shodan API only supports query parameter auth (not headers).
        # Using params dict prevents key from appearing in log string representations.
        url = f"https://api.shodan.io/shodan/host/{ip}"
        resp = requests.get(url, params={"key": api_key}, timeout=10)
        
        if resp.status_code == 404:
            return {"status": "not_found", "message": "No information available for this IP in Shodan database."}
        
        if resp.status_code == 403:
            return {
                "error": "Shodan API Error: 403 (Forbidden)", 
                "details": "This usually means your API key has zero query credits or your account tier (Free/OSS) does not allow host lookups for this specific IP. Shodan's free tier resets monthly."
            }
        
        if resp.status_code == 429:
            return {
                "error": "Shodan API Error: 429 (Too Many Requests)",
                "details": "Rate limit exceeded. Please wait a few seconds before retrying."
            }

        if resp.status_code != 200:
            return {"error": f"Shodan API Error: {resp.status_code}", "details": resp.text}

        data = resp.json()
        
        # Normalize Output
        return {
            "ip": ip,
            "country": data.get("country_name"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "last_seen": data.get("last_update")
        }

    except Exception as e:
        return {"error": f"Execution failed: {str(e)}"}
