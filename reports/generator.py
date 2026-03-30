"""
reports/generator.py — Generates an HTML intelligence report from SQLite data
"""

import os
import logging
from datetime import datetime
from storage.database import get_stats, get_connection

logger = logging.getLogger(__name__)

REPORT_DIR = "reports/output"


def generate() -> str:
    """Generates an HTML report and returns the file path."""
    os.makedirs(REPORT_DIR, exist_ok=True)

    stats = get_stats()
    conn  = get_connection()

    # Top malicious IPs by abuse score
    top_ips = conn.execute("""
        SELECT ioc_value, country, abuse_score, vt_score, tags
        FROM iocs WHERE ioc_type='ip' AND (abuse_score > 0 OR vt_malicious > 0)
        ORDER BY abuse_score DESC LIMIT 20
    """).fetchall()

    # Recent high-confidence IOCs
    recent = conn.execute("""
        SELECT ioc_value, ioc_type, source, threat_type, confidence, first_seen
        FROM iocs ORDER BY created_at DESC LIMIT 50
    """).fetchall()

    # Source breakdown
    by_source = conn.execute(
        "SELECT source, COUNT(*) as cnt FROM iocs GROUP BY source ORDER BY cnt DESC"
    ).fetchall()

    conn.close()

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    filename  = f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    filepath  = os.path.join(REPORT_DIR, filename)

    html = _build_html(stats, top_ips, recent, by_source, timestamp)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("Report generated: %s", filepath)
    return filepath


def _build_html(stats, top_ips, recent, by_source, timestamp) -> str:
    def rows(data, cols):
        html = ""
        for row in data:
            html += "<tr>" + "".join(f"<td>{row[c] or ''}</td>" for c in cols) + "</tr>"
        return html or "<tr><td colspan='99'>No data yet</td></tr>"

    by_type_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in (stats.get("by_type") or {}).items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Intelligence Report — {timestamp}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --danger: #f85149; --warn: #d29922; --ok: #3fb950;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: .25rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .card .label {{ font-size: .8rem; color: var(--muted); margin-top: .3rem; }}
  section {{ margin-bottom: 2.5rem; }}
  h2 {{ font-size: 1.1rem; border-bottom: 1px solid var(--border); padding-bottom: .5rem; margin-bottom: 1rem; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ background: var(--surface); color: var(--muted); text-align: left; padding: .6rem .8rem; border-bottom: 1px solid var(--border); }}
  td {{ padding: .5rem .8rem; border-bottom: 1px solid var(--border); word-break: break-all; }}
  tr:hover {{ background: var(--surface); }}
  .tag {{ display: inline-block; background: #1f3354; color: var(--accent); border-radius: 4px; padding: 1px 6px; font-size: .75rem; margin: 1px; }}
  .badge-url {{ color: #79c0ff; }} .badge-ip {{ color: var(--danger); }}
  .badge-domain {{ color: var(--warn); }} .badge-hash {{ color: var(--ok); }}
</style>
</head>
<body>
<h1>🛡️ Threat Intelligence Report</h1>
<p class="meta">Generated: {timestamp} | Source: Automated Pipeline (URLhaus · Feodo · ThreatFox · MalwareBazaar)</p>

<div class="grid">
  <div class="card"><div class="num">{stats.get('total', 0)}</div><div class="label">Total IOCs</div></div>
  <div class="card"><div class="num">{stats.get('by_type', {}).get('ip', 0)}</div><div class="label">Malicious IPs</div></div>
  <div class="card"><div class="num">{stats.get('by_type', {}).get('url', 0)}</div><div class="label">Malicious URLs</div></div>
  <div class="card"><div class="num">{stats.get('by_type', {}).get('domain', 0)}</div><div class="label">Malicious Domains</div></div>
  <div class="card"><div class="num">{stats.get('by_type', {}).get('hash', 0)}</div><div class="label">Malware Hashes</div></div>
  <div class="card"><div class="num">{stats.get('enriched', 0)}</div><div class="label">Enriched</div></div>
  <div class="card"><div class="num">{stats.get('indexed', 0)}</div><div class="label">In Elasticsearch</div></div>
</div>

<section>
  <h2>📊 IOCs by Source</h2>
  <table>
    <tr><th>Source</th><th>IOC Count</th></tr>
    {"".join(f"<tr><td>{r['source']}</td><td>{r['cnt']}</td></tr>" for r in by_source) or "<tr><td colspan='2'>No data yet</td></tr>"}
  </table>
</section>

<section>
  <h2>🔴 Top Malicious IPs (by Abuse Score)</h2>
  <table>
    <tr><th>IP Address</th><th>Country</th><th>Abuse Score</th><th>VT Score</th><th>Tags</th></tr>
    {"".join(f"<tr><td class='badge-ip'>{r['ioc_value']}</td><td>{r['country'] or '—'}</td><td>{r['abuse_score'] or 0}</td><td>{r['vt_score'] or '—'}</td><td>{''.join(f'<span class=tag>{t}</span>' for t in (r['tags'] or '').split(',') if t)}</td></tr>" for r in top_ips) or "<tr><td colspan='5'>No enriched IPs yet — add AbuseIPDB key to .env</td></tr>"}
  </table>
</section>

<section>
  <h2>🕒 Recent IOCs (Latest 50)</h2>
  <table>
    <tr><th>Value</th><th>Type</th><th>Source</th><th>Threat Type</th><th>Confidence</th><th>First Seen</th></tr>
    {"".join(f"<tr><td class='badge-{r['ioc_type']}'>{r['ioc_value'][:80]}{'...' if len(r['ioc_value'])>80 else ''}</td><td>{r['ioc_type']}</td><td>{r['source']}</td><td>{r['threat_type'] or '—'}</td><td>{r['confidence']}%</td><td>{(r['first_seen'] or '')[:10]}</td></tr>" for r in recent) or "<tr><td colspan='6'>Run the pipeline first</td></tr>"}
  </table>
</section>

<p style="color:var(--muted);font-size:.75rem;margin-top:2rem;">
  ⚡ Threat Intel Pipeline | For educational/research purposes only
</p>
</body>
</html>"""
