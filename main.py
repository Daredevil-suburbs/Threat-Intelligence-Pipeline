"""
main.py — Entry point for the Threat Intelligence Pipeline

Usage:
  python main.py           → Run pipeline once
  python main.py --watch   → Run continuously on schedule
  python main.py --report  → Generate report from existing data only
  python main.py --stats   → Show database stats
"""

import sys
import logging
import argparse
import schedule
import time
from rich.console import Console
from rich.table import Table
from rich import box

from config import LOG_LEVEL, RUN_INTERVAL_HOURS
from storage.database import init_db, get_stats
from pipeline.runner import run_pipeline
from reports.generator import generate

# ── Logging Setup ─────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("logs/pipeline.log"),
        logging.StreamHandler(),
    ]
)
logger  = logging.getLogger(__name__)
console = Console()


def cmd_stats():
    stats = get_stats()
    table = Table(title="📊 Threat Intel Database Stats", box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric")
    table.add_column("Value", style="bold green")

    table.add_row("Total IOCs",         str(stats["total"]))
    table.add_row("Enriched",           str(stats["enriched"]))
    table.add_row("Indexed to ES",      str(stats["indexed"]))
    table.add_section()

    for ioc_type, count in (stats.get("by_type") or {}).items():
        table.add_row(f"  → {ioc_type}", str(count))
    table.add_section()

    for source, count in (stats.get("by_source") or {}).items():
        table.add_row(f"  [{source}]", str(count))

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Pipeline")
    parser.add_argument("--watch",  action="store_true", help="Run on schedule continuously")
    parser.add_argument("--report", action="store_true", help="Generate HTML report only")
    parser.add_argument("--stats",  action="store_true", help="Show database stats")
    args = parser.parse_args()

    # Always initialize DB
    init_db()

    if args.stats:
        cmd_stats()

    elif args.report:
        path = generate()
        console.print(f"[green]✅ Report generated:[/green] {path}")

    elif args.watch:
        console.print(f"[cyan]🔄 Watch mode: running every {RUN_INTERVAL_HOURS}h[/cyan]")
        run_pipeline()  # Run immediately
        schedule.every(RUN_INTERVAL_HOURS).hours.do(run_pipeline)
        while True:
            schedule.run_pending()
            time.sleep(60)

    else:
        run_pipeline()


if __name__ == "__main__":
    main()
