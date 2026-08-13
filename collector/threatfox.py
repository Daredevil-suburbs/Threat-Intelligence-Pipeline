"""
collector/threatfox.py — IOCs from ThreatFox (abuse.ch): IPs, domains, URLs, hashes
No API key required.
Docs: https://threatfox.abuse.ch/api/
"""

import requests
import logging
from datetime import datetime
from config import MAX_IOCS_PER_SOURCE

logger = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox ioc_type → our ioc_type
TYPE_MAP = {
    "ip:port":  "ip",
    "domain":   "domain",
    "url":      "url",
    "md5_hash": "hash",
    "sha256_hash": "hash",
}


def fetch() -> list[dict]:
    """
    Fetches recent IOCs from ThreatFox (last 7 days).
    """
    iocs = []

    try:
        logger.info("Fetching ThreatFox IOCs...")
        payload = {"query": "get_iocs", "days": 3}
        headers = {"User-Agent": "ThreatIntelPipeline/1.0"}
        resp = requests.post(API_URL, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            logger.warning("ThreatFox: unexpected status %s", data.get("query_status"))
            return []

        for entry in (data.get("data") or [])[:MAX_IOCS_PER_SOURCE]:
            raw_type = entry.get("ioc_type", "")
            our_type = TYPE_MAP.get(raw_type, "url")

            # For ip:port, strip the port
            ioc_value = entry.get("ioc", "").strip()
            if raw_type == "ip:port" and ":" in ioc_value:
                ioc_value = ioc_value.split(":")[0]

            iocs.append({
                "ioc_value":  ioc_value,
                "ioc_type":   our_type,
                "source":     "threatfox",
                "threat_type": entry.get("threat_type", ""),
                "confidence": int(entry.get("confidence_level", 0)),
                "tags":       ",".join(entry.get("tags") or []),
                "first_seen": entry.get("first_seen"),
                "last_seen":  entry.get("last_seen") or datetime.utcnow().isoformat(),
                "country":    "",
                "reporter":   entry.get("reporter", ""),
            })

        logger.info("ThreatFox: fetched %d IOCs", len(iocs))

    except requests.RequestException as e:
        logger.error("ThreatFox fetch failed: %s", e)

    return iocs
