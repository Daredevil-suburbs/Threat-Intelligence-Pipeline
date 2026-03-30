"""
pipeline/runner.py — Orchestrates the full pipeline:
  1. Collect IOCs from all feeds
  2. Store new ones in SQLite (dedup)
  3. Enrich with VirusTotal / AbuseIPDB (if keys set)
  4. Index into Elasticsearch
  5. Generate HTML report
"""

import logging
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

import collector
import enricher
from storage import database
from elastic import ingest
from reports import generator

logger  = logging.getLogger(__name__)
console = Console()


def run_pipeline():
    console.print(Panel.fit(
        "[bold cyan]🛡️  Threat Intelligence Pipeline[/bold cyan]\n"
        f"[dim]Started at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]",
        border_style="cyan"
    ))

    run_id = database.start_run()

    # ── Stage 1: Collect ─────────────────────────────────────
    console.print("\n[bold yellow]Stage 1:[/bold yellow] Collecting IOCs from feeds...")
    all_iocs = collector.collect_all()
    console.print(f"  ✅ Collected [bold]{len(all_iocs)}[/bold] raw IOCs")

    # ── Stage 2: Store (deduplicate) ──────────────────────────
    console.print("\n[bold yellow]Stage 2:[/bold yellow] Storing & deduplicating...")
    new_count = 0
    for ioc in all_iocs:
        if ioc.get("ioc_value"):
            is_new = database.insert_ioc(ioc)
            if is_new:
                new_count += 1
    console.print(f"  ✅ [bold]{new_count}[/bold] new IOCs stored ({len(all_iocs) - new_count} duplicates skipped)")

    # ── Stage 3: Enrich ───────────────────────────────────────
    console.print("\n[bold yellow]Stage 3:[/bold yellow] Enriching with threat intelligence APIs...")
    unenriched = database.get_unenriched(limit=50)  # Limit to avoid burning API quota
    enriched_count = enricher.enrich_batch(unenriched)
    console.print(f"  ✅ Enriched [bold]{enriched_count}[/bold] IOCs")

    # ── Stage 4: Index to Elasticsearch ───────────────────────
    console.print("\n[bold yellow]Stage 4:[/bold yellow] Indexing to Elasticsearch...")
    if ingest.check_connection():
        unindexed = database.get_unindexed(limit=500)
        indexed_count = ingest.index_iocs(unindexed)
        for ioc in unindexed[:indexed_count]:
            database.mark_indexed(ioc["ioc_value"])
        console.print(f"  ✅ Indexed [bold]{indexed_count}[/bold] IOCs → Elasticsearch")
        console.print("  📊 View dashboard: [link=http://localhost:5601]http://localhost:5601[/link]")
    else:
        indexed_count = 0
        console.print("  [yellow]⚠️  Elasticsearch not reachable. Is Docker running?[/yellow]")
        console.print("     Run: [bold]docker compose up -d[/bold]")

    # ── Stage 5: Report ───────────────────────────────────────
    console.print("\n[bold yellow]Stage 5:[/bold yellow] Generating HTML report...")
    report_path = generator.generate()
    console.print(f"  ✅ Report saved: [bold]{report_path}[/bold]")

    # ── Summary ───────────────────────────────────────────────
    database.finish_run(run_id, len(all_iocs), new_count, enriched_count, indexed_count)
    stats = database.get_stats()

    table = Table(title="Pipeline Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric",  style="dim")
    table.add_column("Value",   style="bold green")
    table.add_row("Fetched this run",   str(len(all_iocs)))
    table.add_row("New IOCs stored",    str(new_count))
    table.add_row("Enriched",           str(enriched_count))
    table.add_row("Indexed to ES",      str(indexed_count))
    table.add_row("Total IOCs in DB",   str(stats["total"]))
    table.add_row("Report",             report_path)

    console.print()
    console.print(table)
    console.print()
