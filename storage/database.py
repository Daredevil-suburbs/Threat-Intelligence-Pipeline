"""
storage/database.py — SQLite layer for deduplication and persistence
"""

import sqlite3
import os
import logging
from datetime import datetime
from config import DB_PATH

logger = logging.getLogger(__name__)


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS iocs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_value     TEXT NOT NULL,
            ioc_type      TEXT NOT NULL,           -- url | ip | domain | hash
            source        TEXT NOT NULL,
            threat_type   TEXT,
            confidence    INTEGER DEFAULT 0,        -- 0-100
            tags          TEXT,                     -- JSON array as text
            first_seen    TEXT,
            last_seen     TEXT,
            country       TEXT,
            reporter      TEXT,
            vt_score      TEXT,                     -- e.g. "15/72"
            vt_malicious  INTEGER DEFAULT 0,
            abuse_score   INTEGER DEFAULT 0,        -- AbuseIPDB confidence score
            enriched      INTEGER DEFAULT 0,        -- 0=no, 1=yes
            indexed_to_es INTEGER DEFAULT 0,        -- 0=no, 1=yes
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ioc_value, source)
        );

        CREATE TABLE IF NOT EXISTS pipeline_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at  TEXT,
            finished_at TEXT,
            total_fetched   INTEGER DEFAULT 0,
            total_new       INTEGER DEFAULT 0,
            total_enriched  INTEGER DEFAULT 0,
            total_indexed   INTEGER DEFAULT 0,
            status      TEXT DEFAULT 'running'
        );

        CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(ioc_value);
        CREATE INDEX IF NOT EXISTS idx_ioc_type  ON iocs(ioc_type);
        CREATE INDEX IF NOT EXISTS idx_source    ON iocs(source);
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized at %s", DB_PATH)


def insert_ioc(ioc: dict) -> bool:
    """
    Insert an IOC. Returns True if new, False if duplicate.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO iocs
                (ioc_value, ioc_type, source, threat_type, confidence,
                 tags, first_seen, last_seen, country, reporter)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ioc.get("ioc_value"),
            ioc.get("ioc_type"),
            ioc.get("source"),
            ioc.get("threat_type"),
            ioc.get("confidence", 0),
            ioc.get("tags", ""),
            ioc.get("first_seen"),
            ioc.get("last_seen"),
            ioc.get("country"),
            ioc.get("reporter"),
        ))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Duplicate
    finally:
        conn.close()


def update_enrichment(ioc_value: str, vt_score: str, vt_malicious: int,
                       abuse_score: int):
    conn = get_connection()
    conn.execute("""
        UPDATE iocs
        SET vt_score=?, vt_malicious=?, abuse_score=?, enriched=1
        WHERE ioc_value=?
    """, (vt_score, vt_malicious, abuse_score, ioc_value))
    conn.commit()
    conn.close()


def mark_indexed(ioc_value: str):
    conn = get_connection()
    conn.execute("UPDATE iocs SET indexed_to_es=1 WHERE ioc_value=?", (ioc_value,))
    conn.commit()
    conn.close()


def get_unenriched(limit: int = 100) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM iocs WHERE enriched=0 LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_unindexed(limit: int = 500) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM iocs WHERE indexed_to_es=0 LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = get_connection()
    stats = {}
    stats["total"]    = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    stats["by_type"]  = dict(conn.execute(
        "SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type").fetchall())
    stats["by_source"] = dict(conn.execute(
        "SELECT source, COUNT(*) FROM iocs GROUP BY source").fetchall())
    stats["enriched"] = conn.execute(
        "SELECT COUNT(*) FROM iocs WHERE enriched=1").fetchone()[0]
    stats["indexed"]  = conn.execute(
        "SELECT COUNT(*) FROM iocs WHERE indexed_to_es=1").fetchone()[0]
    conn.close()
    return stats


def start_run() -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO pipeline_runs (started_at) VALUES (?)",
        (datetime.utcnow().isoformat(),)
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finish_run(run_id: int, fetched: int, new: int, enriched: int, indexed: int):
    conn = get_connection()
    conn.execute("""
        UPDATE pipeline_runs
        SET finished_at=?, total_fetched=?, total_new=?, total_enriched=?,
            total_indexed=?, status='completed'
        WHERE id=?
    """, (datetime.utcnow().isoformat(), fetched, new, enriched, indexed, run_id))
    conn.commit()
    conn.close()
