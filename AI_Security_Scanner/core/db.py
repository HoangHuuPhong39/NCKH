# -*- coding: utf-8 -*-
"""
core/db.py - Database layer for AI Security Scanner
Manages SQLite persistence for scan results and findings.
"""

import os
import sqlite3
from datetime import datetime

from core.config import cfg

_raw_db_path = cfg.get("storage.database_path", "data/scanner.db")
if os.path.isabs(_raw_db_path):
    DB_PATH = _raw_db_path
else:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DB_PATH = os.path.join(PROJECT_ROOT, _raw_db_path)


def _get_conn() -> sqlite3.Connection:
    """Return an optimized connection with WAL mode and row_factory."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create tables and migrate schema if columns are missing (handles old DBs)."""
    conn = _get_conn()
    cursor = conn.cursor()

    # ── Create scans table (new) ──────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url     TEXT    NOT NULL,
            model_name     TEXT    NOT NULL,
            started_at     TEXT    NOT NULL,
            completed_at   TEXT,
            total_findings INTEGER DEFAULT 0
        )
    """)

    # ── Create findings table (new schema) ───────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id),
            target_url  TEXT    NOT NULL,
            module_name TEXT    NOT NULL,
            payload     TEXT,
            response    TEXT,
            severity    TEXT,
            risk_score  REAL    DEFAULT 0.0,
            owasp_code  TEXT,
            mitre_code  TEXT,
            timestamp   TEXT    NOT NULL DEFAULT ''
        )
    """)

    # ── Migrate old schema: add missing columns if they don't exist ───────
    existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(findings)")}
    migrations = [
        ("scan_id",    "INTEGER REFERENCES scans(id)"),
        ("risk_score", "REAL DEFAULT 0.0"),
        ("timestamp",  "TEXT NOT NULL DEFAULT ''"),
    ]
    for col_name, col_def in migrations:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def save_finding(
    scan_id: int,
    target_url: str,
    module_name: str,
    payload: str,
    response: str,
    severity: str,
    risk_score: float,
    owasp: str,
    mitre: str,
) -> int:
    """
    Insert a single finding into the database.

    Returns:
        The row ID of the newly inserted finding.
    """
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO findings
            (scan_id, target_url, module_name, payload, response,
             severity, risk_score, owasp_code, mitre_code, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            target_url,
            module_name,
            payload,
            response,
            severity,
            risk_score,
            owasp,
            mitre,
            datetime.now().isoformat(),
        ),
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_findings(
    severity: str | None = None,
    module_name: str | None = None,
    date: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """
    Retrieve findings, optionally filtered by severity, module, and/or date (YYYY-MM-DD).

    Args:
        severity:    Filter by severity level (e.g. 'HIGH', 'CRITICAL').
        module_name: Filter by module (e.g. 'jailbreak').
        date:        Filter by date string prefix (e.g. '2026-09-25').
        limit:       Maximum number of rows to return.

    Returns:
        List of dicts containing all finding fields.
    """
    conn = _get_conn()
    cursor = conn.cursor()

    query = "SELECT * FROM findings WHERE 1=1"
    params: list = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if module_name:
        query += " AND module_name = ?"
        params.append(module_name)
    if date:
        query += " AND timestamp LIKE ?"
        params.append(f"{date}%")

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def clear_findings() -> None:
    """Delete all findings and scans from the database."""
    conn = _get_conn()
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def start_scan(target_url: str, model_name: str) -> int:
    """
    Record the start of a new scan.

    Returns:
        The new scan's ID.
    """
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (target_url, model_name, started_at)
        VALUES (?, ?, ?)
        """,
        (target_url, model_name, datetime.now().isoformat()),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def complete_scan(scan_id: int) -> None:
    """
    Mark a scan as completed and update its total_findings count.

    Args:
        scan_id: The ID of the scan to finalise.
    """
    conn = _get_conn()
    conn.execute(
        """
        UPDATE scans
        SET completed_at   = ?,
            total_findings = (
                SELECT COUNT(*) FROM findings WHERE scan_id = ?
            )
        WHERE id = ?
        """,
        (datetime.now().isoformat(), scan_id, scan_id),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def get_stats() -> dict:
    """
    Return aggregated statistics about all findings and recent scans.

    Returns:
        {
            'total_findings': int,
            'by_severity':    {severity: count, ...},
            'by_module':      {module_name: count, ...},
            'recent_scans':   [scan_dict, ...]   # last 5 scans
        }
    """
    conn = _get_conn()
    cursor = conn.cursor()

    # Total
    cursor.execute("SELECT COUNT(*) AS cnt FROM findings")
    total_findings = cursor.fetchone()["cnt"]

    # By severity
    cursor.execute(
        "SELECT severity, COUNT(*) AS cnt FROM findings GROUP BY severity"
    )
    by_severity = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

    # By module
    cursor.execute(
        "SELECT module_name, COUNT(*) AS cnt FROM findings GROUP BY module_name"
    )
    by_module = {row["module_name"]: row["cnt"] for row in cursor.fetchall()}

    # Recent scans (last 5)
    cursor.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT 5"
    )
    recent_scans = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "total_findings": total_findings,
        "by_severity": by_severity,
        "by_module": by_module,
        "recent_scans": recent_scans,
    }


def get_scans(date: str | None = None, limit: int = 50) -> list[dict]:
    """
    Retrieve scans, optionally filtered by date (YYYY-MM-DD).
    """
    conn = _get_conn()
    cursor = conn.cursor()
    query = "SELECT * FROM scans WHERE 1=1"
    params: list = []
    if date:
        query += " AND started_at LIKE ?"
        params.append(f"{date}%")
    query += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_dates() -> list[str]:
    """
    Return a distinct list of dates (YYYY-MM-DD) that have scans recorded.
    """
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT DISTINCT substr(started_at, 1, 10) as s_date
        FROM scans
        WHERE started_at IS NOT NULL AND started_at != ''
        ORDER BY s_date DESC
        """
    )
    dates = [row["s_date"] for row in cursor.fetchall() if row["s_date"]]
    conn.close()
    return dates


def get_finding_dates() -> list[str]:
    """
    Return a distinct list of dates (YYYY-MM-DD) that have findings recorded.
    """
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT DISTINCT substr(timestamp, 1, 10) as f_date
        FROM findings
        WHERE timestamp IS NOT NULL AND timestamp != ''
        ORDER BY f_date DESC
        """
    )
    dates = [row["f_date"] for row in cursor.fetchall() if row["f_date"]]
    conn.close()
    return dates