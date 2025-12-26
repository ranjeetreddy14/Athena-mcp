import os
import requests
from typing import Dict, Any

def execute(ioc: str) -> Dict[str, Any]:
    api_key = os.getenv('THREATFOX_API_KEY')
    if not api_key:
        return {"error": "Missing THREATFOX_API_KEY environment variable."}

    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "Auth-Key": api_key
    }
    payload = {
        "query": "search_ioc",
        "search_term": ioc
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("data"):
                # ThreatFox returns a list of matches, we'll take the most recent/relevant one
                # For simplicity in v1.1, we take the first match.
                ioc_data = data["data"][0]
                return {
                    "ioc": ioc,
                    "ioc_type": ioc_data.get("ioc_type_full"),
                    "threat_type": ioc_data.get("threat_type_full"),
                    "malware_family": ioc_data.get("malware_printable", "Unknown"),
                    "confidence": ioc_data.get("confidence_level"),
                    "first_seen": ioc_data.get("first_seen"),
                    "last_seen": ioc_data.get("last_seen"),
                    "tags": ioc_data.get("tags", []),
                    "reference": ioc_data.get("reference")
                }
            elif data.get("query_status") == "no_result":
                return {"status": "no_result", "message": f"No IOC matches found for {ioc} on ThreatFox."}
            else:
                return {"error": "ThreatFox API reported an issue", "details": data.get("query_status")}
        else:
            return {"error": f"ThreatFox API Error: {resp.status_code}", "details": resp.text}
    except Exception as e:
        return {"error": f"Execution failed: {str(e)}"}
