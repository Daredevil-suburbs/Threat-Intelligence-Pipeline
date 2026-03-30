"""
enricher/virustotal.py — Enrich IOCs using VirusTotal API
Free tier: 4 requests/minute, 500/day
Get key at: https://www.virustotal.com/gui/join-us
"""

import requests
import time
import logging
from config import VIRUSTOTAL_API_KEY

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# Rate limiting: 4 req/min on free tier
REQUEST_DELAY = 15  # seconds between requests


def _get_endpoint(ioc_type: str, ioc_value: str) -> str | None:
    if ioc_type == "ip":
        return f"{BASE_URL}/ip_addresses/{ioc_value}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
        return f"{BASE_URL}/urls/{url_id}"
    elif ioc_type == "domain":
        return f"{BASE_URL}/domains/{ioc_value}"
    elif ioc_type == "hash":
        return f"{BASE_URL}/files/{ioc_value}"
    return None


def enrich(ioc_value: str, ioc_type: str) -> dict:
    """
    Returns enrichment dict: {vt_score, vt_malicious}
    Returns empty dict if no API key or on error.
    """
    if not VIRUSTOTAL_API_KEY:
        return {}

    endpoint = _get_endpoint(ioc_type, ioc_value)
    if not endpoint:
        return {}

    try:
        resp = requests.get(endpoint, headers=HEADERS, timeout=15)

        if resp.status_code == 404:
            return {"vt_score": "not found", "vt_malicious": 0}

        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit, sleeping 60s...")
            time.sleep(60)
            return {}

        resp.raise_for_status()
        data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        score = f"{malicious}/{total}" if total else "0/0"

        time.sleep(REQUEST_DELAY)  # Respect free-tier rate limit

        return {
            "vt_score":    score,
            "vt_malicious": malicious,
        }

    except requests.RequestException as e:
        logger.warning("VirusTotal lookup failed for %s: %s", ioc_value, e)
        return {}
