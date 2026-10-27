# -*- coding: utf-8 -*-
"""
core/evidence_store.py - Evidence & Replay Store for AI Security Scanner

Lưu trữ bằng chứng (evidence) của các lỗ hổng đã phát hiện vào SQLite,
hỗ trợ tái lập (replay) và xuất bundle để reproducibility trong nghiên cứu.

Cách dùng::

    store = EvidenceStore()
    eid = store.record_evidence(
        finding_id="find_001",
        payload="Ignore all instructions...",
        response="I AM HACKED",
        module_name="prompt_injection",
        detector_result=True,
        score=8.5,
    )
    bundle_path = store.export_evidence_bundle([eid], "output/bundle.json")
    report = store.generate_reproducibility_report("run_20260930")
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Project root resolution (allows standalone import)
# ---------------------------------------------------------------------------
_MODULE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _MODULE_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Default database path
# ---------------------------------------------------------------------------
_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "evidence.db"


# ===========================================================================
# Data class
# ===========================================================================


@dataclass
class EvidenceRecord:
    """
    Immutable record capturing all information needed to reproduce a finding.

    Attributes:
        id:              Unique evidence UUID.
        finding_id:      External finding reference (e.g. DB row id or custom label).
        timestamp:       ISO-8601 creation time.
        payload:         The exact prompt/payload that triggered the vulnerability.
        response:        The LLM response that was flagged.
        module_name:     Security module that detected the issue.
        score:           Risk score (0.0 – 10.0).
        severity:        Severity label derived from score.
        model_version:   LLM model identifier used during the test.
        config_hash:     SHA-256 hash of the scanner configuration at test time.
        seed:            Random seed used (for reproducibility).
        is_reproducible: Whether a replay has confirmed the same outcome.
        metadata:        Additional arbitrary key-value pairs.
    """

    id: str
    finding_id: str
    timestamp: str
    payload: str
    response: str
    module_name: str
    score: float
    severity: str
    model_version: str
    config_hash: str
    seed: int
    is_reproducible: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


# ===========================================================================
# EvidenceStore
# ===========================================================================


class EvidenceStore:
    """
    Manages SQLite-backed evidence storage for AI Security Scanner findings.

    Supports:
    - Recording evidence with full context for reproducibility
    - Retrieving individual evidence records
    - Replaying test cases against a live LLM to verify reproducibility
    - Exporting JSON bundles suitable for publication / peer review
    - Generating reproducibility reports per scan run

    Args:
        db_path: Path to the SQLite evidence database.
                 Defaults to ``data/evidence.db`` in the project root.
    """

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            self.db_path = _DEFAULT_DB_PATH
        else:
            self.db_path = Path(db_path)

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return an optimised SQLite connection with WAL journal mode."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create the evidence table if it does not exist, with migration support."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id              TEXT PRIMARY KEY,
                finding_id      TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                payload         TEXT NOT NULL,
                response        TEXT NOT NULL,
                module_name     TEXT NOT NULL,
                score           REAL NOT NULL DEFAULT 0.0,
                severity        TEXT NOT NULL DEFAULT 'INFO',
                model_version   TEXT NOT NULL DEFAULT 'unknown',
                config_hash     TEXT NOT NULL DEFAULT '',
                seed            INTEGER NOT NULL DEFAULT 0,
                is_reproducible INTEGER NOT NULL DEFAULT 0,
                metadata_json   TEXT NOT NULL DEFAULT '{}'
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS run_metadata (
                run_id          TEXT NOT NULL,
                evidence_id     TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                PRIMARY KEY (run_id, evidence_id)
            )
        """)

        # Migration: add missing columns gracefully
        existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(evidence)")}
        migrations = [
            ("seed", "INTEGER NOT NULL DEFAULT 0"),
            ("is_reproducible", "INTEGER NOT NULL DEFAULT 0"),
            ("config_hash", "TEXT NOT NULL DEFAULT ''"),
        ]
        for col_name, col_def in migrations:
            if col_name not in existing_cols:
                cursor.execute(f"ALTER TABLE evidence ADD COLUMN {col_name} {col_def}")

        conn.commit()
        conn.close()

    @staticmethod
    def _compute_config_hash(metadata: Dict[str, Any]) -> str:
        """Compute a deterministic SHA-256 hash of the configuration dict."""
        try:
            serialised = json.dumps(metadata, sort_keys=True, ensure_ascii=False)
            return hashlib.sha256(serialised.encode("utf-8")).hexdigest()[:16]
        except Exception:
            return "unknown"

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Map numeric score to severity label."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 2.0:
            return "LOW"
        return "INFO"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_evidence(
        self,
        finding_id: str,
        payload: str,
        response: str,
        module_name: str,
        detector_result: bool,
        score: float,
        metadata: Optional[Dict[str, Any]] = None,
        model_version: str = "unknown",
        seed: int = 0,
        run_id: Optional[str] = None,
    ) -> str:
        """
        Record a single vulnerability finding with all reproducibility context.

        Args:
            finding_id:       External reference ID for the finding.
            payload:          The exact prompt that triggered the issue.
            response:         The LLM response that was flagged.
            module_name:      Security module name (e.g. ``'jailbreak'``).
            detector_result:  ``True`` if the detector flagged as vulnerable.
            score:            Risk score 0.0 – 10.0.
            metadata:         Additional key-value pairs (scanner config, etc.).
            model_version:    LLM model identifier.
            seed:             Random seed used during generation.
            run_id:           Optional run identifier; links evidence to a run.

        Returns:
            The UUID string of the newly created evidence record.
        """
        if metadata is None:
            metadata = {}

        evidence_id = str(uuid.uuid4())
        severity = self._score_to_severity(score)
        config_hash = self._compute_config_hash(metadata)
        ts = datetime.now().isoformat()

        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO evidence
                (id, finding_id, timestamp, payload, response, module_name,
                 score, severity, model_version, config_hash, seed,
                 is_reproducible, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                finding_id,
                ts,
                payload,
                response,
                module_name,
                score,
                severity,
                model_version,
                config_hash,
                seed,
                1 if detector_result else 0,
                json.dumps(metadata, ensure_ascii=False),
            ),
        )

        # Link to run if provided
        if run_id:
            cursor.execute(
                "INSERT OR IGNORE INTO run_metadata (run_id, evidence_id, created_at) VALUES (?, ?, ?)",
                (run_id, evidence_id, ts),
            )

        conn.commit()
        conn.close()
        return evidence_id

    def get_evidence(self, finding_id: str) -> Optional[EvidenceRecord]:
        """
        Retrieve an evidence record by its finding_id (external reference).

        Args:
            finding_id: The external finding reference ID.

        Returns:
            :class:`EvidenceRecord` if found, otherwise ``None``.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY timestamp DESC LIMIT 1",
            (finding_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        return EvidenceRecord(
            id=row["id"],
            finding_id=row["finding_id"],
            timestamp=row["timestamp"],
            payload=row["payload"],
            response=row["response"],
            module_name=row["module_name"],
            score=row["score"],
            severity=row["severity"],
            model_version=row["model_version"],
            config_hash=row["config_hash"],
            seed=row["seed"],
            is_reproducible=bool(row["is_reproducible"]),
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def get_evidence_by_uuid(self, evidence_uuid: str) -> Optional[EvidenceRecord]:
        """
        Retrieve an evidence record by its internal UUID.

        Args:
            evidence_uuid: The UUID assigned at record time.

        Returns:
            :class:`EvidenceRecord` or ``None``.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence WHERE id = ?", (evidence_uuid,))
        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        return EvidenceRecord(
            id=row["id"],
            finding_id=row["finding_id"],
            timestamp=row["timestamp"],
            payload=row["payload"],
            response=row["response"],
            module_name=row["module_name"],
            score=row["score"],
            severity=row["severity"],
            model_version=row["model_version"],
            config_hash=row["config_hash"],
            seed=row["seed"],
            is_reproducible=bool(row["is_reproducible"]),
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def replay_test(
        self,
        evidence_id: str,
        llm_client: Any = None,
    ) -> Dict[str, Any]:
        """
        Replay a previously recorded test case to verify reproducibility.

        The original payload is re-sent to the LLM (or a mock if no client
        is provided). The detector result is compared to the stored outcome.

        Args:
            evidence_id: UUID of the evidence record to replay.
            llm_client:  An object with a ``send_prompt(payload) -> str``
                         method. If ``None``, the stored response is used
                         as the replay response.

        Returns:
            Dict with keys: ``evidence_id``, ``original_response``,
            ``replay_response``, ``is_reproducible``, ``delta``.
        """
        record = self.get_evidence_by_uuid(evidence_id)
        if record is None:
            return {"error": f"Evidence not found: {evidence_id}"}

        # Attempt to re-run against the LLM
        if llm_client is not None:
            try:
                t0 = time.perf_counter()
                replay_response = llm_client.send_prompt(record.payload)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
            except Exception as exc:  # noqa: BLE001
                replay_response = f"[REPLAY ERROR] {exc}"
                elapsed_ms = 0.0
        else:
            # Offline mode: use stored response as baseline
            replay_response = record.response
            elapsed_ms = 0.0

        # Naive reproducibility check: compare key tokens/patterns
        original_lower = record.response.lower()
        replay_lower = replay_response.lower()

        # Check for overlapping significant n-grams (simple heuristic)
        orig_words = set(original_lower.split())
        replay_words = set(replay_lower.split())
        overlap = len(orig_words & replay_words)
        total = max(len(orig_words | replay_words), 1)
        similarity = overlap / total

        is_reproducible = similarity >= 0.4  # threshold: ≥40% word overlap

        # Update reproducibility flag in DB
        conn = self._get_conn()
        conn.execute(
            "UPDATE evidence SET is_reproducible = ? WHERE id = ?",
            (1 if is_reproducible else 0, evidence_id),
        )
        conn.commit()
        conn.close()

        return {
            "evidence_id": evidence_id,
            "finding_id": record.finding_id,
            "module_name": record.module_name,
            "payload": record.payload,
            "original_response": record.response,
            "replay_response": replay_response,
            "similarity_score": round(similarity, 4),
            "is_reproducible": is_reproducible,
            "elapsed_ms": round(elapsed_ms, 2),
            "delta": {
                "original_length": len(record.response),
                "replay_length": len(replay_response),
                "length_delta": abs(len(record.response) - len(replay_response)),
            },
        }

    def export_evidence_bundle(
        self,
        finding_ids: List[str],
        output_path: str | Path,
    ) -> Path:
        """
        Export a JSON bundle of evidence records for reproducibility / sharing.

        Args:
            finding_ids: List of evidence UUIDs to include in the bundle.
            output_path: Path where the JSON bundle will be written.

        Returns:
            Resolved :class:`pathlib.Path` of the written bundle file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        records: List[Dict[str, Any]] = []
        for eid in finding_ids:
            record = self.get_evidence_by_uuid(eid)
            if record is not None:
                rec_dict = asdict(record)
                records.append(rec_dict)

        bundle: Dict[str, Any] = {
            "bundle_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "AI Security Scanner – Evidence Store",
                "version": "1.0.0",
                "total_records": len(records),
                "requested_ids": finding_ids,
                "found_records": len(records),
            },
            "evidence_records": records,
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, ensure_ascii=False, indent=2)

        return output_path.resolve()

    def generate_reproducibility_report(self, run_id: str) -> Dict[str, Any]:
        """
        Generate a reproducibility report for all evidence linked to a run.

        Args:
            run_id: The run identifier string (e.g. ``'run_20260930_120000'``).

        Returns:
            Dict containing reproducibility statistics and per-record details.
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Fetch all evidence IDs linked to this run
        cursor.execute(
            """
            SELECT e.* FROM evidence e
            INNER JOIN run_metadata r ON e.id = r.evidence_id
            WHERE r.run_id = ?
            ORDER BY e.timestamp ASC
            """,
            (run_id,),
        )
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            # Fallback: all evidence if no run metadata exists
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence ORDER BY timestamp ASC LIMIT 100")
            rows = cursor.fetchall()
            conn.close()

        total = len(rows)
        reproducible = sum(1 for r in rows if r["is_reproducible"])
        by_severity: Dict[str, int] = {}
        by_module: Dict[str, int] = {}
        records_summary: List[Dict[str, Any]] = []

        for row in rows:
            sev = row["severity"]
            mod = row["module_name"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_module[mod] = by_module.get(mod, 0) + 1
            records_summary.append(
                {
                    "id": row["id"],
                    "finding_id": row["finding_id"],
                    "module_name": mod,
                    "severity": sev,
                    "score": row["score"],
                    "model_version": row["model_version"],
                    "config_hash": row["config_hash"],
                    "seed": row["seed"],
                    "is_reproducible": bool(row["is_reproducible"]),
                    "timestamp": row["timestamp"],
                }
            )

        return {
            "run_id": run_id,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_evidence": total,
                "reproducible": reproducible,
                "not_reproducible": total - reproducible,
                "reproducibility_rate": round(reproducible / total, 4) if total > 0 else 0.0,
            },
            "by_severity": by_severity,
            "by_module": by_module,
            "evidence_records": records_summary,
        }

    def list_all(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        List all evidence records (up to *limit*), newest first.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of dicts with summary fields.
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, finding_id, timestamp, module_name, score, severity, "
            "model_version, is_reproducible FROM evidence ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows


# ===========================================================================
# Convenience CLI
# ===========================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evidence Store CLI")
    parser.add_argument("--list", action="store_true", help="List all evidence")
    parser.add_argument("--report", default=None, help="Generate report for run_id")
    parser.add_argument("--export", nargs="+", default=None, help="Export evidence UUIDs to bundle.json")
    args = parser.parse_args()

    store = EvidenceStore()

    if args.list:
        records = store.list_all()
        print(f"Total evidence records: {len(records)}")
        for r in records[:20]:
            print(f"  [{r['severity']:8s}] {r['module_name']:25s} | score={r['score']} | {r['id'][:8]}...")
    elif args.report:
        report = store.generate_reproducibility_report(args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.export:
        path = store.export_evidence_bundle(args.export, "evidence_bundle.json")
        print(f"Bundle exported to: {path}")
    else:
        parser.print_help()
