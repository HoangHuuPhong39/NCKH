# -*- coding: utf-8 -*-
"""
core/path_security.py - Centralized Filesystem Path Confinement & CLI Argument Safety

Prevents Arbitrary Local File Read/Write (Path Traversal) and CLI Flag Injection
across SAST, OSS, Data Hygiene, Trivy, Evidence Store, and Report modules.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional

from core.config import cfg

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Strict OCI container image reference regex (rejects leading '-' and shell metachars)
_SAFE_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]{0,254}(?:@sha256:[a-fA-F0-9]{64})?$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$")


def get_allowed_scan_roots(extra_roots: Optional[Iterable[str | Path]] = None) -> List[Path]:
    """
    Return the list of canonical directories permitted for local filesystem scans.

    Defaults to:
    - Configured ``storage.allowed_scan_roots`` (or ``SCANNER_ALLOWED_SCAN_ROOTS`` env var)
    - Project root (``AI_Security_Scanner/``)
    - System temporary directory (to allow uploaded file scans & pytest tmp_path)
    """
    roots: List[Path] = []
    configured = cfg.get("storage.allowed_scan_roots", None)
    if isinstance(configured, str):
        configured = [p.strip() for p in configured.split(os.pathsep) if p.strip()]
    if isinstance(configured, list) and configured:
        for item in configured:
            p = Path(item)
            if not p.is_absolute():
                p = _PROJECT_ROOT / p
            roots.append(p.expanduser().resolve())
    else:
        roots.append(_PROJECT_ROOT.resolve())

    # Always permit temp directory for secure upload staging and automated tests
    roots.append(Path(tempfile.gettempdir()).resolve())

    if extra_roots:
        for item in extra_roots:
            roots.append(Path(item).expanduser().resolve())

    # Deduplicate preserving order
    unique: List[Path] = []
    seen = set()
    for r in roots:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


def resolve_safe_path(
    user_path: str | Path,
    allowed_roots: Optional[Iterable[str | Path]] = None,
    must_exist: bool = True,
) -> Path:
    """
    Canonicalize *user_path* and verify it resides strictly inside *allowed_roots*.

    Raises:
        ValueError: if *user_path* is empty or contains null bytes.
        PermissionError: if the resolved path escapes all allowed roots.
        FileNotFoundError: if *must_exist* is True and the path does not exist.
    """
    if user_path is None:
        raise ValueError("Path must not be empty.")
    raw_str = str(user_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Invalid path value.")

    candidate = Path(raw_str)
    if not candidate.is_absolute():
        candidate = _PROJECT_ROOT / candidate
    resolved = candidate.expanduser().resolve()

    roots = (
        [Path(r).expanduser().resolve() for r in allowed_roots]
        if allowed_roots is not None
        else get_allowed_scan_roots()
    )

    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        raise PermissionError(
            f"Access denied: path '{raw_str}' is outside allowed scan roots."
        )

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Target path does not exist: {raw_str}")

    return resolved


def resolve_safe_output_path(
    output_path: str | Path,
    base_dir: Optional[Path] = None,
    allow_temp: bool = True,
) -> Path:
    """
    Confine output file writes (reports, evidence bundles) to *base_dir* (and temp dir if allowed).
    """
    raw_str = str(output_path or "").strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Invalid output path.")

    default_base = (base_dir or (_PROJECT_ROOT / cfg.get("storage.reports_dir", "reports"))).resolve()
    candidate = Path(raw_str)
    if not candidate.is_absolute():
        candidate = default_base / candidate
    resolved = candidate.expanduser().resolve()

    allowed = [default_base, (_PROJECT_ROOT / "data").resolve()]
    if allow_temp:
        allowed.append(Path(tempfile.gettempdir()).resolve())

    if not any(resolved == root or resolved.is_relative_to(root) for root in allowed):
        raise PermissionError(
            f"Access denied: output path '{raw_str}' escapes allowed output directories."
        )
    return resolved


def validate_no_cli_flag(value: str, field_name: str = "argument") -> str:
    """Reject strings starting with '-' or containing control/newline characters."""
    if not isinstance(value, str):
        raise ValueError(f"Invalid {field_name}: must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Invalid {field_name}: must not be empty.")
    if cleaned.startswith("-") or any(c in cleaned for c in ("\n", "\r", "\x00")):
        raise ValueError(f"Invalid {field_name}: leading '-' or control characters are not allowed.")
    return cleaned


def validate_container_image_ref(image_name: str) -> str:
    """Strictly validate an OCI/Docker container image name against flag/command injection."""
    cleaned = validate_no_cli_flag(image_name, "image_name")
    if not _SAFE_IMAGE_REF_RE.match(cleaned):
        raise ValueError(f"Invalid container image reference: '{cleaned}'.")
    return cleaned


def validate_safe_identifier(value: str, field_name: str = "identifier") -> str:
    """Strictly validate model/probe identifiers passed to external tools or configs."""
    cleaned = validate_no_cli_flag(value, field_name)
    if not _SAFE_IDENTIFIER_RE.match(cleaned):
        raise ValueError(f"Invalid {field_name}: contains disallowed characters.")
    return cleaned
