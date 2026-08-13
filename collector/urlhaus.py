"""
collector/urlhaus.py — Pulls malicious URLs from URLhaus (abuse.ch)
No API key required.
Docs: https://urlhaus-api.abuse.ch/
"""

import requests
import logging
from datetime import datetime
from config import MAX_IOCS_PER_SOURCE

logger = logging.getLogger(__name__)

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{}/"


def fetch() -> list[dict]:
    """
    Returns a list of IOC dicts from URLhaus.
    Each dict is ready to be passed to storage.database.insert_ioc()
    """
    iocs = []
    url = API_URL.format(MAX_IOCS_PER_SOURCE)

    try:
        logger.info("Fetching URLhaus feed...")
        headers = {"User-Agent": "ThreatIntelPipeline/1.0"}
        resp = requests.post(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "is_recent":
            logger.warning("URLhaus returned unexpected status: %s", data.get("query_status"))
            return []

        for entry in data.get("urls", []):
            if entry.get("url_status") not in ("online", "unknown"):
                continue  # Skip taken-down URLs

            iocs.append({
                "ioc_value":  entry.get("url", "").strip(),
                "ioc_type":   "url",
                "source":     "urlhaus",
                "threat_type": entry.get("threat", "malware"),
                "confidence": 75,
                "tags":       ",".join(entry.get("tags") or []),
                "first_seen": entry.get("date_added"),
                "last_seen":  datetime.utcnow().isoformat(),
                "country":    entry.get("country", ""),
                "reporter":   entry.get("reporter", ""),
            })

        logger.info("URLhaus: fetched %d active IOCs", len(iocs))

    except requests.RequestException as e:
        logger.error("URLhaus fetch failed: %s", e)

    return iocs
