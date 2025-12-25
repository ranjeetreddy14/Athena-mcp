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

logger = logging.getLogger("ti-mcp-server")

def url_to_id(url: str) -> str:
    """Encodes URL to VT-compatible ID (Base64 without padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def execute(url: str) -> Dict[str, Any]:
    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        return {"error": "Missing VT_API_KEY environment variable."}

    headers = {
        "x-apikey": api_key
    }

    try:
        # Step 1: Check for existing report
        vt_id = url_to_id(url)
        report_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
        logger.info(f"Checking VT report for URL: {url} (ID: {vt_id})")
        resp = requests.get(report_url, headers=headers, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            # Check if this report has actual analysis results
            if "last_analysis_stats" in data["data"]["attributes"]:
                logger.info(f"Found existing VT report for {url}")
                return _normalize_vt_response(data, url)
            else:
                logger.info(f"VT report exists but has no stats yet for {url}. Polling for update...")
                # Report exists but might be "queued" or "in_progress"
                # We'll treat this as if we just submitted it and poll.
                pass 

        # Step 2: Submit for scan if 404 OR if report exists but has no stats
        submit_url = "https://www.virustotal.com/api/v3/urls"
        # VT returns 200 even if already submitted, giving us a new analysis ID
        submit_resp = requests.post(submit_url, headers=headers, data={"url": url}, timeout=10)
        
        if submit_resp.status_code != 200:
            return {"error": f"VT Submission Error: {submit_resp.status_code}", "details": submit_resp.text}
        
        analysis_id = submit_resp.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        logger.info(f"Submitted {url} to VT. Analysis ID: {analysis_id}")
        
        # Step 3: Poll for results (Higher count, 2s wait)
        # Total wait time: ~10 seconds
        for i in range(5):
            time.sleep(2)
            poll_resp = requests.get(analysis_url, headers=headers)
            if poll_resp.status_code == 200:
                analysis_data = poll_resp.json()
                status = analysis_data["data"]["attributes"]["status"]
                logger.info(f"VT Poll {i+1}: Status = {status}")
                
                if status == "completed":
                    final_resp = requests.get(report_url, headers=headers)
                    if final_resp.status_code == 200:
                        return _normalize_vt_response(final_resp.json(), url)
        
        return {
            "status": "pending", 
            "message": "Scan is taking longer than expected. VirusTotal is still analyzing this URL. Please check again in a minute.",
            "url": url,
            "vt_link": f"https://www.virustotal.com/gui/url/{vt_id}"
        }

    except Exception as e:
        logger.error(f"VT Execution failed: {str(e)}")
        return {"error": f"Execution failed: {str(e)}"}

def _normalize_vt_response(data: Dict[str, Any], url: str) -> Dict[str, Any]:
    """Helper to extract consistent fields from VT report."""
    attr = data["data"]["attributes"]
    stats = attr.get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    
    verdict = "safe"
    if malicious > 0: verdict = "malicious"
    elif suspicious > 0: verdict = "suspicious"
    
    return {
        "url": url,
        "verdict": verdict,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": stats.get("harmless", 0),
        "total_engines": total,
        "reputation": attr.get("reputation", 0),
        "permalink": f"https://www.virustotal.com/gui/url/{url_to_id(url)}"
    }
