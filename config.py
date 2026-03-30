"""
config.py — Central configuration loader
"""

import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

# Elasticsearch
ES_HOST  = os.getenv("ES_HOST", "http://localhost:9200")
ES_INDEX = os.getenv("ES_INDEX", "threat-intel-iocs")

# Database
DB_PATH = os.getenv("DB_PATH", "data/threat_intel.db")

# Pipeline
MAX_IOCS_PER_SOURCE   = int(os.getenv("MAX_IOCS_PER_SOURCE", "500"))
RUN_INTERVAL_HOURS    = int(os.getenv("RUN_INTERVAL_HOURS", "6"))
LOG_LEVEL             = os.getenv("LOG_LEVEL", "INFO")

# IOC Types
IOC_TYPES = ["url", "ip", "domain", "hash"]

# Threat feed source names
SOURCES = {
    "urlhaus":       "URLhaus (abuse.ch)",
    "feodo":         "Feodo Tracker (abuse.ch)",
    "threatfox":     "ThreatFox (abuse.ch)",
    "malwarebazaar": "MalwareBazaar (abuse.ch)",
}
