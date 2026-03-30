"""
collector/feodo.py — Botnet Command & Control IPs from Feodo Tracker (abuse.ch)
No API key required.
Docs: https://feodotracker.abuse.ch/
"""

import requests
import logging
from datetime import datetime
from config import MAX_IOCS_PER_SOURCE

logger = logging.getLogger(__name__)

BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch() -> list[dict]:
    """
    Returns a list of IOC dicts for known botnet C2 IPs.
    """
    iocs = []

    try:
        logger.info("Fetching Feodo Tracker IP blocklist...")
        resp = requests.get(BLOCKLIST_URL, timeout=30)
        resp.raise_for_status()
        entries = resp.json()

        for entry in entries[:MAX_IOCS_PER_SOURCE]:
            iocs.append({
                "ioc_value":  entry.get("ip_address", "").strip(),
                "ioc_type":   "ip",
                "source":     "feodo",
                "threat_type": "botnet_c2",
                "confidence": 90,
                "tags":       entry.get("malware", ""),
                "first_seen": entry.get("first_seen"),
                "last_seen":  entry.get("last_online") or datetime.utcnow().isoformat(),
                "country":    entry.get("country", ""),
                "reporter":   "Feodo Tracker",
            })

        logger.info("Feodo Tracker: fetched %d C2 IPs", len(iocs))

    except requests.RequestException as e:
        logger.error("Feodo Tracker fetch failed: %s", e)

    return iocs
