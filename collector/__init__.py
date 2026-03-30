"""
collector/__init__.py — Runs all feed collectors and returns combined IOC list
"""

import logging
from collector import urlhaus, feodo, threatfox, malwarebazaar

logger = logging.getLogger(__name__)


def collect_all() -> list:
    """Run every collector and return a flat list of all IOC dicts."""
    all_iocs = []
    collectors = [
        ("URLhaus",       urlhaus.fetch),
        ("Feodo",         feodo.fetch),
        ("ThreatFox",     threatfox.fetch),
        ("MalwareBazaar", malwarebazaar.fetch),
    ]
    for name, fn in collectors:
        try:
            results = fn()
            all_iocs.extend(results)
            logger.info("[%s] returned %d IOCs", name, len(results))
        except Exception as e:
            logger.error("[%s] collector crashed: %s", name, e)
    logger.info("Total collected: %d IOCs", len(all_iocs))
    return all_iocs
