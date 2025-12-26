"""
VirusTotal Tool Implementation
Responsibility: Scan URL via VT API and normalize verdict.
Optimized: Handles pending scans and provides better feedback for slow URL analysis.
"""
import os
import requests
import time
import base64
import logging
from typing import Dict, Any

import re

logger = logging.getLogger("ti-mcp-server")

def url_to_id(url: str) -> str:
    """Encodes URL to VT-compatible ID (Base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def is_hash(value: str) -> bool:
    """Detects if a string is an MD5 (32), SHA1 (40), or SHA256 (64) hash."""
    return bool(re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', value))

def execute(observable: str) -> Dict[str, Any]:
    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        return {"error": "Missing VT_API_KEY environment variable."}

    headers = {"x-apikey": api_key}
    
    # Mode Detection
    type_mode = "hash" if is_hash(observable) else "url"

    try:
        if type_mode == "hash":
            # Step A: File/Hash Lookup
            report_url = f"https://www.virustotal.com/api/v3/files/{observable}"
            logger.info(f"Checking VT File report for Hash: {observable}")
            resp = requests.get(report_url, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                return _normalize_vt_response(resp.json(), observable, "hash")
            elif resp.status_code == 404:
                return {"status": "no_result", "message": f"Hash {observable} not found in VirusTotal database."}
            else:
                return {"error": f"VT API Error: {resp.status_code}", "details": resp.text}

        else:
            # Step B: URL Lookup (Existing Logic)
            vt_id = url_to_id(observable)
            report_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
            logger.info(f"Checking VT report for URL: {observable}")
            resp = requests.get(report_url, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                data = resp.json()
                if "last_analysis_stats" in data["data"]["attributes"]:
                    return _normalize_vt_response(data, observable, "url")
            
            # Submission/Polling for URLs
            submit_url = "https://www.virustotal.com/api/v3/urls"
            submit_resp = requests.post(submit_url, headers=headers, data={"url": observable}, timeout=10)
            if submit_resp.status_code != 200:
                return {"error": f"VT Submission Error: {submit_resp.status_code}", "details": submit_resp.text}
            
            analysis_id = submit_resp.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            
            for i in range(5):
                time.sleep(2)
                poll_resp = requests.get(analysis_url, headers=headers)
                if poll_resp.status_code == 200:
                    analysis_data = poll_resp.json()
                    if analysis_data["data"]["attributes"]["status"] == "completed":
                        final_resp = requests.get(report_url, headers=headers)
                        if final_resp.status_code == 200:
                            return _normalize_vt_response(final_resp.json(), observable, "url")
            
            return {
                "status": "pending", 
                "message": "Scan is taking longer than expected.",
                "observable": observable,
                "vt_link": f"https://www.virustotal.com/gui/url/{vt_id}"
            }

    except Exception as e:
        logger.error(f"VT Execution failed: {str(e)}")
        return {"error": f"Execution failed: {str(e)}"}

def _normalize_vt_response(data: Dict[str, Any], observable: str, mode: str) -> Dict[str, Any]:
    """Helper to extract consistent fields from VT report."""
    attr = data["data"]["attributes"]
    stats = attr.get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    
    verdict = "safe"
    if malicious > 0: verdict = "malicious"
    elif suspicious > 0: verdict = "suspicious"
    
    vt_id = observable if mode == "hash" else url_to_id(observable)
    path_segment = "file" if mode == "hash" else "url"

    return {
        mode: observable,
        "verdict": verdict,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": stats.get("harmless", 0),
        "total_engines": total,
        "reputation": attr.get("reputation", 0),
        "permalink": f"https://www.virustotal.com/gui/{path_segment}/{vt_id}"
    }
