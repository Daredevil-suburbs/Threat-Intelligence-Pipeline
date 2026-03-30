# 🛡️ Threat Intelligence Pipeline

A fully automated cybersecurity project that collects IOCs (Indicators of Compromise) from open-source threat feeds, enriches them with OSINT APIs, stores them in SQLite, indexes them into Elasticsearch, and displays them in a Kibana dashboard — with automated HTML report generation.

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     THREAT FEEDS                        │
│   URLhaus  │  Feodo Tracker  │  ThreatFox  │  MalwareBazaar │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP (no auth needed)
                       ▼
┌─────────────────────────────────────────────────────────┐
│               COLLECTOR  (collector/)                    │
│   Fetches URLs, IPs, Domains, Hashes                    │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│               STORAGE  (SQLite)                         │
│   Deduplication · Persistence · Querying                │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│               ENRICHER  (enricher/)                     │
│   VirusTotal API (optional)                             │
│   AbuseIPDB API  (optional)                             │
└──────────────────────┬──────────────────────────────────┘
                       │
              ┌────────┴────────┐
              ▼                 ▼
┌─────────────────┐   ┌──────────────────────┐
│  ELASTICSEARCH  │   │   HTML REPORT         │
│  + KIBANA       │   │   reports/output/     │
│  localhost:5601 │   │   (auto-generated)    │
└─────────────────┘   └──────────────────────┘
```

---

## 📂 Project Structure

```
threat-intel-pipeline/
│
├── main.py                  ← Entry point (run this)
├── config.py                ← All settings loaded from .env
├── requirements.txt
├── docker-compose.yml       ← Elasticsearch + Kibana
├── .env.example             ← Copy to .env and fill in
│
├── collector/               ← Feed fetchers (no API keys needed)
│   ├── urlhaus.py           ← Malicious URLs (URLhaus)
│   ├── feodo.py             ← Botnet C2 IPs (Feodo Tracker)
│   ├── threatfox.py         ← Multi-type IOCs (ThreatFox)
│   └── malwarebazaar.py     ← Malware hashes (MalwareBazaar)
│
├── enricher/                ← API enrichment (optional keys)
│   ├── virustotal.py        ← VT scores for all IOC types
│   └── abuseipdb.py        ← IP reputation scores
│
├── storage/
│   └── database.py          ← SQLite: insert, dedup, query
│
├── elastic/
│   ├── ingest.py            ← Bulk-index IOCs to Elasticsearch
│   ├── setup_kibana.py      ← Auto-create index pattern in Kibana
│   └── kibana_objects.json  ← Saved objects for import
│
├── pipeline/
│   └── runner.py            ← Orchestrates all 5 stages
│
├── reports/
│   ├── generator.py         ← HTML report builder
│   └── output/              ← Generated reports saved here
│
├── data/
│   └── threat_intel.db      ← SQLite database (auto-created)
│
└── logs/
    └── pipeline.log         ← Log file (auto-created)
```

---

## 🚀 Quick Start

### Windows

```cmd
git clone <this repo>
cd threat-intel-pipeline
setup_windows.bat
```

Then activate the venv and run:
```cmd
venv\Scripts\activate
python main.py
```

---

### Linux / WSL

```bash
git clone <this repo>
cd threat-intel-pipeline
chmod +x setup_linux.sh
./setup_linux.sh
```

Then run:
```bash
source venv/bin/activate
python3 main.py
```

---

## 🔑 API Keys (Optional but recommended)

The pipeline works **without any API keys** using abuse.ch feeds.
Adding keys unlocks enrichment (VT scores, abuse confidence scores).

### VirusTotal (Free)
1. Go to https://www.virustotal.com/gui/join-us
2. Create a free account
3. Go to your profile → API Key
4. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key_here`
5. Free tier: 4 requests/minute, 500/day

### AbuseIPDB (Free)
1. Go to https://www.abuseipdb.com/register
2. Create a free account
3. Go to Account → API → Create Key
4. Add to `.env`: `ABUSEIPDB_API_KEY=your_key_here`
5. Free tier: 1,000 IP checks/day

---

## 🖥️ Usage

```bash
# Run the full pipeline once
python main.py

# Run once every 6 hours automatically
python main.py --watch

# Generate an HTML report from existing data (no fetching)
python main.py --report

# Show database stats
python main.py --stats
```

---

## 📊 Kibana Dashboard Setup

1. Make sure Docker is running:
   ```bash
   docker compose up -d
   ```

2. Run the pipeline at least once to populate data:
   ```bash
   python main.py
   ```

3. Auto-configure Kibana:
   ```bash
   python elastic/setup_kibana.py
   ```

4. Open Kibana: **http://localhost:5601**

5. Build visualizations in **Analytics → Visualize Library**:
   - **Pie chart**: split by `ioc_type.keyword`
   - **Bar chart**: split by `source.keyword`
   - **Metric**: total count
   - **Data table**: `ioc_value`, `threat_type`, `confidence`
   - **Map**: aggregate by `country.keyword`

---

## 🗃️ Data Sources

| Source | Type | IOCs Provided | Requires Auth |
|--------|------|---------------|---------------|
| URLhaus (abuse.ch) | URLs | Malicious/phishing URLs | ❌ Free |
| Feodo Tracker (abuse.ch) | IPs | Botnet C2 servers | ❌ Free |
| ThreatFox (abuse.ch) | Mixed | IPs, domains, URLs, hashes | ❌ Free |
| MalwareBazaar (abuse.ch) | Hashes | Malware SHA256 hashes | ❌ Free |
| VirusTotal | Enrichment | Detection scores | ✅ Free key |
| AbuseIPDB | Enrichment | IP reputation | ✅ Free key |

---

## 🔧 Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | _(empty)_ | Optional VT API key |
| `ABUSEIPDB_API_KEY` | _(empty)_ | Optional AbuseIPDB key |
| `ES_HOST` | `http://localhost:9200` | Elasticsearch URL |
| `ES_INDEX` | `threat-intel-iocs` | Index name |
| `DB_PATH` | `data/threat_intel.db` | SQLite database path |
| `MAX_IOCS_PER_SOURCE` | `500` | IOCs fetched per source per run |
| `RUN_INTERVAL_HOURS` | `6` | Watch mode interval |
| `LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |

---

## 🧠 Concepts You'll Learn From This Project

- **IOC collection** via public OSINT threat feeds
- **API integration** with VirusTotal and AbuseIPDB
- **SQLite** for local storage and deduplication
- **Elasticsearch** indexing and full-text search
- **Kibana** for SIEM-style dashboards
- **Docker Compose** for running production-grade services locally
- **Python project architecture** with modular collectors/enrichers
- **Scheduled automation** with the `schedule` library

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**.
All IOC feeds are sourced from public, community-maintained, free threat intelligence platforms.
Do not use IOCs to scan or probe systems you do not own.

---

*Built to learn Blue Team / Threat Intelligence fundamentals.*
