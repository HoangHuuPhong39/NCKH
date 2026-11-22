# -*- coding: utf-8 -*-
"""
core/db.py - Database layer for AI Security Scanner
Manages SQLite persistence for scans, findings (with verification & remediation
lifecycle), and regression test runs.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.config import cfg

_raw_db_path = cfg.get("storage.database_path", "data/scanner.db")
if os.path.isabs(_raw_db_path):
    DB_PATH = _raw_db_path
else:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DB_PATH = os.path.join(PROJECT_ROOT, _raw_db_path)

VALID_VERIFICATION_STATUSES = {
    "CONFIRMED",
    "NEEDS_VERIFICATION",
    "FALSE_POSITIVE",
    "UNREPRODUCIBLE",
}

VALID_REMEDIATION_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
    "FIXED",
    "ACCEPTED_RISK",
    "REGRESSED",
}

VALID_ROOT_CAUSE_TYPES = {
    "MODEL",
    "APPLICATION",
    "CONFIGURATION",
    "DATA",
    "INFRASTRUCTURE",
}

_DEFAULT_ROOT_CAUSE_BY_MODULE: Dict[str, str] = {
    "code_scanner": "APPLICATION",
    "output_handling": "APPLICATION",
    "oss_security": "INFRASTRUCTURE",
    "port_scan": "INFRASTRUCTURE",
    "model_fingerprint": "CONFIGURATION",
    "rag_security": "DATA",
    "sensitive_disclosure": "DATA",
    "prompt_leak": "CONFIGURATION",
    "excessive_agency": "APPLICATION",
    "agent_testing": "APPLICATION",
}


def infer_root_cause(module_name: str) -> str:
    return _DEFAULT_ROOT_CAUSE_BY_MODULE.get((module_name or "").lower(), "MODEL")


def _get_conn() -> sqlite3.Connection:
    """Return an optimized connection with foreign_keys enabled and row_factory."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Schema & Migrations
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create tables, indexes, WAL journal mode (once), and migrate schema if needed."""
    conn = _get_conn()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()

        # ── Scans table ───────────────────────────────────────────────────────
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

        # ── Findings table (with lifecycle columns) ───────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id             INTEGER REFERENCES scans(id),
                target_url          TEXT    NOT NULL,
                module_name         TEXT    NOT NULL,
                payload             TEXT,
                response            TEXT,
                severity            TEXT,
                risk_score          REAL    DEFAULT 0.0,
                owasp_code          TEXT,
                mitre_code          TEXT,
                timestamp           TEXT    NOT NULL DEFAULT '',
                verification_status TEXT    NOT NULL DEFAULT 'NEEDS_VERIFICATION',
                remediation_status  TEXT    NOT NULL DEFAULT 'OPEN',
                root_cause_type     TEXT    NOT NULL DEFAULT 'MODEL',
                confidence_score    REAL    DEFAULT 0.0,
                verified_at         TEXT    DEFAULT '',
                notes               TEXT    DEFAULT ''
            )
        """)

        # ── Idempotent migrations for existing findings tables ────────────────
        existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(findings)")}
        migrations = [
            ("scan_id",             "INTEGER REFERENCES scans(id)"),
            ("risk_score",          "REAL DEFAULT 0.0"),
            ("timestamp",           "TEXT NOT NULL DEFAULT ''"),
            ("verification_status", "TEXT NOT NULL DEFAULT 'NEEDS_VERIFICATION'"),
            ("remediation_status",  "TEXT NOT NULL DEFAULT 'OPEN'"),
            ("root_cause_type",     "TEXT NOT NULL DEFAULT 'MODEL'"),
            ("confidence_score",    "REAL DEFAULT 0.0"),
            ("verified_at",         "TEXT DEFAULT ''"),
            ("notes",               "TEXT DEFAULT ''"),
        ]
        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")

        # ── Performance indexes ───────────────────────────────────────────────
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings(owasp_code)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_remediation ON findings(remediation_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module_name)")

        # ── Regression runs table ─────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS regression_runs (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                baseline_scan_id       INTEGER,
                target_url             TEXT    NOT NULL,
                model_name             TEXT    NOT NULL,
                started_at             TEXT    NOT NULL,
                completed_at           TEXT,
                total_tested           INTEGER DEFAULT 0,
                fixed_count            INTEGER DEFAULT 0,
                still_vulnerable_count INTEGER DEFAULT 0,
                skipped_count          INTEGER DEFAULT 0,
                error_count            INTEGER DEFAULT 0,
                fix_rate               REAL    DEFAULT 0.0,
                baseline_avg_risk      REAL    DEFAULT 0.0,
                retest_avg_risk        REAL    DEFAULT 0.0,
                risk_reduction_pct     REAL    DEFAULT 0.0,
                details_json           TEXT    DEFAULT '[]'
            )
        """)

        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Findings CRUD & Lifecycle
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
    verification_status: Optional[str] = None,
    remediation_status: str = "OPEN",
    root_cause_type: Optional[str] = None,
    confidence_score: float = 0.0,
    notes: str = "",
) -> int:
    """
    Insert a single finding into the database.

    Returns:
        The row ID of the newly inserted finding.
    """
    ver_status = (verification_status or "NEEDS_VERIFICATION").upper()
    if ver_status not in VALID_VERIFICATION_STATUSES:
        ver_status = "NEEDS_VERIFICATION"

    rem_status = (remediation_status or "OPEN").upper()
    if rem_status not in VALID_REMEDIATION_STATUSES:
        rem_status = "OPEN"

    rc_type = (root_cause_type or infer_root_cause(module_name)).upper()
    if rc_type not in VALID_ROOT_CAUSE_TYPES:
        rc_type = "MODEL"

    verified_at = datetime.now().isoformat() if ver_status == "CONFIRMED" else ""

    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO findings
            (scan_id, target_url, module_name, payload, response,
             severity, risk_score, owasp_code, mitre_code, timestamp,
             verification_status, remediation_status, root_cause_type,
             confidence_score, verified_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ver_status,
            rem_status,
            rc_type,
            float(confidence_score or 0.0),
            verified_at,
            notes or "",
        ),
    )
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_finding_by_id(finding_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single finding by its primary key ID."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (int(finding_id),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_findings_by_scan(scan_id: int) -> List[Dict[str, Any]]:
    """Retrieve all findings belonging to a specific scan_id."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY risk_score DESC, id ASC",
        (int(scan_id),),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def update_finding_lifecycle(
    finding_id: int,
    verification_status: Optional[str] = None,
    remediation_status: Optional[str] = None,
    root_cause_type: Optional[str] = None,
    notes: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Update verification_status, remediation_status, root_cause_type, and/or notes
    for an existing finding. Returns the updated finding dict, or None if not found.
    Raises ValueError if an invalid enum value is provided.
    """
    updates: List[str] = []
    params: List[Any] = []

    if verification_status is not None:
        v = verification_status.strip().upper()
        if v not in VALID_VERIFICATION_STATUSES:
            raise ValueError(
                f"Invalid verification_status '{verification_status}'. "
                f"Allowed: {sorted(VALID_VERIFICATION_STATUSES)}"
            )
        updates.append("verification_status = ?")
        params.append(v)
        updates.append("verified_at = ?")
        params.append(datetime.now().isoformat())

    if remediation_status is not None:
        r = remediation_status.strip().upper()
        if r not in VALID_REMEDIATION_STATUSES:
            raise ValueError(
                f"Invalid remediation_status '{remediation_status}'. "
                f"Allowed: {sorted(VALID_REMEDIATION_STATUSES)}"
            )
        updates.append("remediation_status = ?")
        params.append(r)

    if root_cause_type is not None:
        rc = root_cause_type.strip().upper()
        if rc not in VALID_ROOT_CAUSE_TYPES:
            raise ValueError(
                f"Invalid root_cause_type '{root_cause_type}'. "
                f"Allowed: {sorted(VALID_ROOT_CAUSE_TYPES)}"
            )
        updates.append("root_cause_type = ?")
        params.append(rc)

    if notes is not None:
        updates.append("notes = ?")
        params.append(str(notes))

    if not updates:
        return get_finding_by_id(finding_id)

    conn = _get_conn()
    cursor = conn.cursor()
    params.append(int(finding_id))
    cursor.execute(f"UPDATE findings SET {', '.join(updates)} WHERE id = ?", params)
    conn.commit()
    changed = cursor.rowcount
    conn.close()
    if changed == 0:
        return None
    return get_finding_by_id(finding_id)


def get_findings(
    severity: str | None = None,
    module_name: str | None = None,
    date: str | None = None,
    limit: int = 100,
    scan_id: int | None = None,
    verification_status: str | None = None,
    remediation_status: str | None = None,
) -> list[dict]:
    """
    Retrieve findings, optionally filtered by severity, module, date (YYYY-MM-DD),
    scan_id, verification_status, or remediation_status.
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
    if scan_id is not None:
        query += " AND scan_id = ?"
        params.append(int(scan_id))
    if verification_status:
        query += " AND verification_status = ?"
        params.append(verification_status.upper())
    if remediation_status:
        query += " AND remediation_status = ?"
        params.append(remediation_status.upper())

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def clear_findings() -> None:
    """Delete all findings, scans, and regression runs from DB and reset sequences."""
    conn = _get_conn()
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM scans")
    try:
        conn.execute("DELETE FROM regression_runs")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN ('findings', 'scans', 'regression_runs')"
        )
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

    try:
        from core.evidence_store import EvidenceStore
        EvidenceStore().clear_all()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def start_scan(target_url: str, model_name: str) -> int:
    """Record the start of a new scan and return its ID."""
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
    """Mark a scan as completed and update its total_findings count."""
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


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single scan record by ID."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Regression Runs Persistence
# ---------------------------------------------------------------------------

def save_regression_run(
    baseline_scan_id: Optional[int],
    target_url: str,
    model_name: str,
    started_at: str,
    completed_at: str,
    total_tested: int,
    fixed_count: int,
    still_vulnerable_count: int,
    skipped_count: int,
    error_count: int,
    fix_rate: float,
    baseline_avg_risk: float,
    retest_avg_risk: float,
    risk_reduction_pct: float,
    details: List[Dict[str, Any]],
) -> int:
    """Persist a regression retest campaign summary and per-finding diff."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO regression_runs
            (baseline_scan_id, target_url, model_name, started_at, completed_at,
             total_tested, fixed_count, still_vulnerable_count, skipped_count,
             error_count, fix_rate, baseline_avg_risk, retest_avg_risk,
             risk_reduction_pct, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            baseline_scan_id,
            target_url,
            model_name,
            started_at,
            completed_at,
            int(total_tested),
            int(fixed_count),
            int(still_vulnerable_count),
            int(skipped_count),
            int(error_count),
            round(float(fix_rate), 4),
            round(float(baseline_avg_risk), 2),
            round(float(retest_avg_risk), 2),
            round(float(risk_reduction_pct), 2),
            json.dumps(details, ensure_ascii=False),
        ),
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return run_id


def get_regression_runs(
    baseline_scan_id: Optional[int] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Retrieve historical regression retest runs."""
    conn = _get_conn()
    cursor = conn.cursor()
    query = "SELECT * FROM regression_runs WHERE 1=1"
    params: List[Any] = []
    if baseline_scan_id is not None:
        query += " AND baseline_scan_id = ?"
        params.append(int(baseline_scan_id))
    query += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows: List[Dict[str, Any]] = []
    for row in cursor.fetchall():
        d = dict(row)
        try:
            d["details"] = json.loads(d.pop("details_json", "[]") or "[]")
        except json.JSONDecodeError:
            d["details"] = []
        rows.append(d)
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def get_lifecycle_stats() -> Dict[str, Dict[str, int]]:
    """Return counts grouped by verification_status, remediation_status, and root_cause_type."""
    conn = _get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT verification_status, COUNT(*) AS cnt FROM findings GROUP BY verification_status"
    )
    by_verification = {
        (row["verification_status"] or "NEEDS_VERIFICATION"): row["cnt"]
        for row in cursor.fetchall()
    }

    cursor.execute(
        "SELECT remediation_status, COUNT(*) AS cnt FROM findings GROUP BY remediation_status"
    )
    by_remediation = {
        (row["remediation_status"] or "OPEN"): row["cnt"]
        for row in cursor.fetchall()
    }

    cursor.execute(
        "SELECT root_cause_type, COUNT(*) AS cnt FROM findings GROUP BY root_cause_type"
    )
    by_root_cause = {
        (row["root_cause_type"] or "MODEL"): row["cnt"]
        for row in cursor.fetchall()
    }

    conn.close()
    return {
        "by_verification": by_verification,
        "by_remediation": by_remediation,
        "by_root_cause": by_root_cause,
    }


def get_stats() -> dict:
    """
    Return aggregated statistics about all findings, lifecycle states, and recent scans.
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

    # By module and severity (for stacked bar analytics)
    cursor.execute(
        "SELECT module_name, severity, COUNT(*) AS cnt FROM findings GROUP BY module_name, severity"
    )
    by_module_severity = {}
    for row in cursor.fetchall():
        m_name = row["module_name"]
        sev_name = row["severity"]
        if m_name not in by_module_severity:
            by_module_severity[m_name] = {}
        by_module_severity[m_name][sev_name] = row["cnt"]

    # Recent scans (last 5)
    cursor.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT 5"
    )
    recent_scans = [dict(row) for row in cursor.fetchall()]

    conn.close()

    lifecycle = get_lifecycle_stats()
    return {
        "total_findings": total_findings,
        "by_severity": by_severity,
        "by_module": by_module,
        "by_module_severity": by_module_severity,
        "by_verification": lifecycle["by_verification"],
        "by_remediation": lifecycle["by_remediation"],
        "by_root_cause": lifecycle["by_root_cause"],
        "recent_scans": recent_scans,
    }


def get_scans(date: str | None = None, limit: int = 50) -> list[dict]:
    """Retrieve scans, optionally filtered by date (YYYY-MM-DD)."""
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
    """Return a distinct list of dates (YYYY-MM-DD) that have scans recorded."""
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
    """Return a distinct list of dates (YYYY-MM-DD) that have findings recorded."""
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
