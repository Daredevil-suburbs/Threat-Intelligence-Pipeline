"""
elastic/ingest.py — Indexes IOCs into Elasticsearch
"""

import logging
import json
from datetime import datetime
from config import ES_HOST, ES_INDEX

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch, helpers
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    logger.warning("elasticsearch package not installed. Run: pip install elasticsearch")


def get_client():
    if not ES_AVAILABLE:
        return None
    return Elasticsearch(ES_HOST, request_timeout=30)


def ensure_index(es):
    """Create index with proper mappings if it doesn't exist."""
    if es.indices.exists(index=ES_INDEX):
        return

    mapping = {
        "mappings": {
            "properties": {
                "ioc_value":   {"type": "keyword"},
                "ioc_type":    {"type": "keyword"},
                "source":      {"type": "keyword"},
                "threat_type": {"type": "keyword"},
                "confidence":  {"type": "integer"},
                "tags":        {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "first_seen":  {"type": "date", "ignore_malformed": True},
                "last_seen":   {"type": "date", "ignore_malformed": True},
                "country":     {"type": "keyword"},
                "reporter":    {"type": "keyword"},
                "vt_score":    {"type": "keyword"},
                "vt_malicious":{"type": "integer"},
                "abuse_score": {"type": "integer"},
                "enriched":    {"type": "boolean"},
                "@timestamp":  {"type": "date"},
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }

    es.indices.create(index=ES_INDEX, body=mapping)
    logger.info("Created Elasticsearch index: %s", ES_INDEX)


def index_iocs(iocs: list) -> int:
    """
    Bulk-index a list of IOC dicts into Elasticsearch.
    Returns count of successfully indexed docs.
    """
    if not ES_AVAILABLE:
        return 0

    es = get_client()
    if es is None:
        return 0

    try:
        if not es.ping():
            logger.warning("Elasticsearch not reachable at %s — is Docker running?", ES_HOST)
            return 0

        ensure_index(es)

        actions = []
        for ioc in iocs:
            doc = dict(ioc)
            doc["@timestamp"] = datetime.utcnow().isoformat()
            doc["enriched"]   = bool(doc.get("enriched"))
            actions.append({
                "_index": ES_INDEX,
                "_id":    f"{ioc['source']}_{ioc['ioc_value']}",
                "_source": doc,
            })

        if not actions:
            return 0

        success, errors = helpers.bulk(es, actions, raise_on_error=False)

        if errors:
            logger.warning("Elasticsearch bulk errors: %d", len(errors))

        logger.info("Indexed %d IOCs to Elasticsearch (%s)", success, ES_INDEX)
        return success

    except Exception as e:
        logger.error("Elasticsearch indexing failed: %s", e)
        return 0


def check_connection() -> bool:
    """Returns True if Elasticsearch is reachable."""
    if not ES_AVAILABLE:
        return False
    try:
        es = get_client()
        return es.ping()
    except Exception:
        return False
