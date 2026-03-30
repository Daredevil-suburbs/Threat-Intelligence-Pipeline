"""
enricher/__init__.py — Enriches IOCs with VT and AbuseIPDB data.
Gracefully skips if API keys are not set.
"""

import logging
from enricher import virustotal, abuseipdb
from storage import database
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

logger = logging.getLogger(__name__)


def enrich_batch(iocs: list) -> int:
    """
    Enrich a list of IOC dicts. Updates the database.
    Returns the count of successfully enriched IOCs.
    """
    if not VIRUSTOTAL_API_KEY and not ABUSEIPDB_API_KEY:
        logger.info("No API keys set — skipping enrichment. Add keys to .env to enable.")
        return 0

    enriched_count = 0

    for ioc in iocs:
        ioc_value = ioc["ioc_value"]
        ioc_type  = ioc["ioc_type"]

        vt_data     = {}
        abuse_data  = {}

        # VirusTotal works for all IOC types
        if VIRUSTOTAL_API_KEY:
            vt_data = virustotal.enrich(ioc_value, ioc_type)

        # AbuseIPDB only for IPs
        if ABUSEIPDB_API_KEY and ioc_type == "ip":
            abuse_data = abuseipdb.enrich(ioc_value)

        if vt_data or abuse_data:
            database.update_enrichment(
                ioc_value=ioc_value,
                vt_score=vt_data.get("vt_score", ""),
                vt_malicious=vt_data.get("vt_malicious", 0),
                abuse_score=abuse_data.get("abuse_score", 0),
            )
            enriched_count += 1

    logger.info("Enriched %d / %d IOCs", enriched_count, len(iocs))
    return enriched_count
