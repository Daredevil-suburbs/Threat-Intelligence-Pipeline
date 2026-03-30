"""
enricher/abuseipdb.py — Enrich IP IOCs using AbuseIPDB
Free tier: 1000 checks/day
Get key at: https://www.abuseipdb.com/register
"""

import requests
import logging
from config import ABUSEIPDB_API_KEY

logger = logging.getLogger(__name__)

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich(ip_address: str) -> dict:
    """
    Returns enrichment dict: {abuse_score, country}
    Returns empty dict if no API key or on error.
    Only works for IP type IOCs.
    """
    if not ABUSEIPDB_API_KEY:
        return {}

    try:
        resp = requests.get(
            CHECK_URL,
            headers={
                "Key":    ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress":   ip_address,
                "maxAgeInDays": 90,
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country":     data.get("countryCode", ""),
        }

    except requests.RequestException as e:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip_address, e)
        return {}
