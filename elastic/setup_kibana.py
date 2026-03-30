"""
elastic/setup_kibana.py — Auto-configures Kibana with index pattern and dashboard
Run this ONCE after docker compose is up and Elasticsearch has data.

Usage: python elastic/setup_kibana.py
"""

import requests
import time
import sys

KIBANA_URL = "http://localhost:5601"
ES_URL     = "http://localhost:9200"
INDEX_NAME = "threat-intel-iocs"
HEADERS    = {"kbn-xsrf": "true", "Content-Type": "application/json"}


def wait_for_kibana(timeout=120):
    print("[*] Waiting for Kibana to be ready...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=5)
            if r.status_code == 200:
                print("[OK] Kibana is ready")
                return True
        except Exception:
            pass
        time.sleep(5)
        print("    Still waiting...")
    return False


def create_index_pattern():
    print("[*] Creating index pattern...")
    payload = {
        "attributes": {
            "title": f"{INDEX_NAME}*",
            "timeFieldName": "@timestamp"
        }
    }
    r = requests.post(
        f"{KIBANA_URL}/api/saved_objects/index-pattern/{INDEX_NAME}-pattern",
        json=payload,
        headers=HEADERS,
        timeout=15
    )
    if r.status_code in (200, 409):
        print(f"[OK] Index pattern created (or already exists)")
    else:
        print(f"[WARN] Index pattern status: {r.status_code} — {r.text[:200]}")


def set_default_index():
    print("[*] Setting default index pattern...")
    payload = {"value": f"{INDEX_NAME}-pattern"}
    r = requests.post(
        f"{KIBANA_URL}/api/kibana/settings/defaultIndex",
        json=payload,
        headers=HEADERS,
        timeout=15
    )
    if r.status_code == 200:
        print("[OK] Default index set")
    else:
        print(f"[WARN] Could not set default index: {r.status_code}")


def print_next_steps():
    print()
    print("=" * 55)
    print("  Kibana Setup Complete!")
    print("=" * 55)
    print()
    print("  Open Kibana: http://localhost:5601")
    print()
    print("  Recommended visualizations to build manually:")
    print("  ┌─────────────────────────────────────────────┐")
    print("  │  1. Pie chart    → ioc_type.keyword          │")
    print("  │  2. Bar chart    → source.keyword            │")
    print("  │  3. Data table   → ioc_value, threat_type    │")
    print("  │  4. Metric       → Count of documents        │")
    print("  │  5. Map          → country.keyword           │")
    print("  └─────────────────────────────────────────────┘")
    print()
    print("  In Kibana: Analytics → Discover")
    print("  Filter:    ioc_type : ip AND abuse_score > 50")
    print()


def main():
    if not wait_for_kibana():
        print("[ERROR] Kibana not reachable at http://localhost:5601")
        print("        Make sure Docker is running: docker compose up -d")
        sys.exit(1)

    create_index_pattern()
    set_default_index()
    print_next_steps()


if __name__ == "__main__":
    main()
