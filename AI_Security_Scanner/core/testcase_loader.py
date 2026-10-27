# -*- coding: utf-8 -*-
"""
core/testcase_loader.py - Test DSL / Testcase Loader

Load và validate testcases từ file YAML/JSON với schema validation.
Hỗ trợ ``!include`` directive trong YAML để import testcase từ file khác.

Usage::

    from core.testcase_loader import load_testcases, load_testcase_library

    testcases = load_testcases("data/testcases/prompt_injection.yaml")
    library = load_testcase_library("data/testcases/")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

# ---------------------------------------------------------------------------
# Optional dependencies — dùng try/except để không crash nếu thiếu
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    from pydantic import BaseModel, Field, validator, ValidationError as _PydanticValidationError
    _HAS_PYDANTIC = True
except ImportError:
    _HAS_PYDANTIC = False


# ---------------------------------------------------------------------------
# Schema definition — dùng Pydantic nếu có, fallback sang dataclass
# ---------------------------------------------------------------------------

if _HAS_PYDANTIC:
    class TestcaseSchema(BaseModel):
        """Pydantic model for a single testcase entry.

        Attributes:
            name:               Unique identifier name for this testcase.
            payload:            The actual attack payload string.
            expected_vulnerable: Whether this payload should trigger a vulnerability.
            module_name:        Scanner module to run (e.g. ``'prompt_injection'``).
            description:        Human-readable description of what this testcase tests.
            owasp_code:         OWASP LLM Top 10 category code (e.g. ``'LLM01'``).
            mitre_code:         MITRE ATLAS technique ID (e.g. ``'AML.T0051'``).
            language:           Language of the payload (ISO 639-1 code, e.g. ``'en'``, ``'vi'``).
            tags:               List of descriptive tags for filtering.
            mock_response:      Optional expected/example model response for offline testing.
        """

        name: str = Field(..., description="Unique testcase identifier")
        payload: str = Field(..., description="Attack payload string")
        expected_vulnerable: bool = Field(
            True, description="Whether this payload should detect a vulnerability"
        )
        module_name: Optional[str] = Field(
            None, description="Scanner module to run against"
        )
        description: Optional[str] = Field(
            None, description="Human-readable description"
        )
        owasp_code: Optional[str] = Field(
            None, description="OWASP LLM Top 10 code (e.g. LLM01)"
        )
        mitre_code: Optional[str] = Field(
            None, description="MITRE ATLAS technique ID (e.g. AML.T0051)"
        )
        language: str = Field("en", description="ISO 639-1 language code")
        tags: List[str] = Field(default_factory=list, description="Descriptive tags")
        mock_response: Optional[str] = Field(
            None, description="Example model response for offline testing"
        )

        @validator("owasp_code")
        @classmethod
        def validate_owasp_code(cls, v: Optional[str]) -> Optional[str]:
            """Validate OWASP LLM Top 10 code format."""
            if v is not None and not v.upper().startswith("LLM"):
                raise ValueError(f"owasp_code must start with 'LLM', got: {v!r}")
            return v

        class Config:
            extra = "allow"  # Allow extra fields for forward-compatibility

else:
    @dataclass
    class TestcaseSchema:  # type: ignore[no-redef]
        """Dataclass fallback for a single testcase entry (when pydantic is unavailable).

        Attributes:
            name:               Unique identifier name for this testcase.
            payload:            The actual attack payload string.
            expected_vulnerable: Whether this payload should trigger a vulnerability.
            module_name:        Scanner module to run.
            description:        Human-readable description.
            owasp_code:         OWASP LLM Top 10 category code.
            mitre_code:         MITRE ATLAS technique ID.
            language:           Language of the payload.
            tags:               List of descriptive tags.
            mock_response:      Optional expected model response for offline testing.
        """

        name: str
        payload: str
        expected_vulnerable: bool = True
        module_name: Optional[str] = None
        description: Optional[str] = None
        owasp_code: Optional[str] = None
        mitre_code: Optional[str] = None
        language: str = "en"
        tags: List[str] = field(default_factory=list)
        mock_response: Optional[str] = None

        def dict(self) -> Dict[str, Any]:
            """Return testcase as a dictionary."""
            return {
                "name": self.name,
                "payload": self.payload,
                "expected_vulnerable": self.expected_vulnerable,
                "module_name": self.module_name,
                "description": self.description,
                "owasp_code": self.owasp_code,
                "mitre_code": self.mitre_code,
                "language": self.language,
                "tags": self.tags,
                "mock_response": self.mock_response,
            }


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = {"name", "payload"}
_EXPECTED_FIELD_TYPES: Dict[str, type] = {
    "name": str,
    "payload": str,
    "expected_vulnerable": bool,
    "language": str,
    "tags": list,
}


def _validate_raw_testcase(raw: Dict[str, Any], source: str = "") -> List[str]:
    """Validate a raw testcase dict against required fields and types.

    Args:
        raw:    Raw testcase dictionary.
        source: Source file path (for error messages).

    Returns:
        List of validation error messages (empty if valid).
    """
    errors: List[str] = []
    prefix = f"[{source}] " if source else ""

    # Required fields check
    for req in _REQUIRED_FIELDS:
        if req not in raw:
            errors.append(f"{prefix}Missing required field: '{req}'")

    # Type checking
    for field_name, expected_type in _EXPECTED_FIELD_TYPES.items():
        if field_name in raw:
            val = raw[field_name]
            if not isinstance(val, expected_type):
                errors.append(
                    f"{prefix}Field '{field_name}': expected {expected_type.__name__}, "
                    f"got {type(val).__name__}"
                )

    # Name uniqueness check skipped at this level (done at library level)
    return errors


def _raw_to_schema(raw: Dict[str, Any]) -> TestcaseSchema:
    """Convert a raw dict to a :class:`TestcaseSchema` instance.

    Args:
        raw: Raw testcase dictionary.

    Returns:
        :class:`TestcaseSchema` instance.

    Raises:
        ValueError: If required fields are missing or types are invalid.
    """
    if _HAS_PYDANTIC:
        return TestcaseSchema(**raw)  # type: ignore[call-arg]
    else:
        return TestcaseSchema(  # type: ignore[call-arg]
            name=raw["name"],
            payload=raw["payload"],
            expected_vulnerable=raw.get("expected_vulnerable", True),
            module_name=raw.get("module_name"),
            description=raw.get("description"),
            owasp_code=raw.get("owasp_code"),
            mitre_code=raw.get("mitre_code"),
            language=raw.get("language", "en"),
            tags=raw.get("tags", []),
            mock_response=raw.get("mock_response"),
        )


# ---------------------------------------------------------------------------
# YAML !include directive support
# ---------------------------------------------------------------------------

class _IncludeLoader:
    """Custom YAML loader that supports ``!include`` directive.

    Cho phép YAML file import testcases từ file khác::

        testcases:
          - !include other_file.yaml
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir

    def make_loader(self):
        """Create a yaml.SafeLoader subclass with !include support."""
        if not _HAS_YAML:
            return None

        base_dir = self._base_dir

        class IncludeLoader(_yaml.SafeLoader):
            pass

        def _include_constructor(loader: IncludeLoader, node: Any) -> Any:
            # Resolve relative path
            include_path = base_dir / loader.construct_scalar(node)
            if include_path.exists():
                with open(include_path, encoding="utf-8") as inc_fh:
                    return _yaml.load(inc_fh, Loader=IncludeLoader)
            return {}

        IncludeLoader.add_constructor("!include", _include_constructor)
        return IncludeLoader


# ---------------------------------------------------------------------------
# Core loading functions
# ---------------------------------------------------------------------------

def load_testcases(
    path: Union[str, Path],
    strict: bool = False,
    as_dict: bool = False,
) -> List[Union[TestcaseSchema, Dict[str, Any]]]:
    """Load testcases from a YAML or JSON file.

    Args:
        path:    Path to the testcase file (``.yaml``, ``.yml``, or ``.json``).
        strict:  If ``True``, raises :class:`ValueError` on validation errors.
                 If ``False``, skips invalid testcases and logs warnings.
        as_dict: If ``True``, returns raw dicts instead of :class:`TestcaseSchema`.

    Returns:
        List of :class:`TestcaseSchema` instances (or raw dicts if ``as_dict=True``).

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If ``strict=True`` and any testcase fails validation.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Testcase file not found: {path}")

    suffix = path.suffix.lower()
    raw_data: Dict[str, Any] = {}

    if suffix in (".yaml", ".yml"):
        raw_data = _load_yaml_file(path)
    elif suffix == ".json":
        raw_data = _load_json_file(path)
    else:
        raise ValueError(f"Unsupported file extension: {suffix!r}. Use .yaml/.yml or .json")

    # Metadata extraction (file-level fields)
    raw_testcases: List[Dict[str, Any]] = raw_data.get("testcases", [])
    file_owasp = raw_data.get("owasp")
    file_mitre = raw_data.get("mitre")
    file_module = raw_data.get("module_name")

    results: List[Union[TestcaseSchema, Dict[str, Any]]] = []
    for i, raw_tc in enumerate(raw_testcases):
        if not isinstance(raw_tc, dict):
            if strict:
                raise ValueError(f"Testcase #{i} in {path.name} is not a dict: {raw_tc!r}")
            continue

        # Inherit file-level metadata if not set at testcase level
        if file_owasp and "owasp_code" not in raw_tc:
            raw_tc["owasp_code"] = file_owasp
        if file_mitre and "mitre_code" not in raw_tc:
            raw_tc["mitre_code"] = file_mitre
        if file_module and "module_name" not in raw_tc:
            raw_tc["module_name"] = file_module

        # Validation
        errors = _validate_raw_testcase(raw_tc, source=path.name)
        if errors:
            if strict:
                raise ValueError(f"Testcase #{i} validation failed:\n" + "\n".join(errors))
            else:
                # Soft fail — skip and warn
                print(f"[WARN] Skipping invalid testcase #{i} in {path.name}: {errors}")
                continue

        if as_dict:
            results.append(raw_tc)
        else:
            try:
                results.append(_raw_to_schema(raw_tc))
            except Exception as exc:
                if strict:
                    raise ValueError(f"Testcase #{i} schema error: {exc}") from exc
                print(f"[WARN] Schema error for testcase #{i} in {path.name}: {exc}")

    return results


def load_testcase_library(
    directory: Union[str, Path],
    strict: bool = False,
    as_dict: bool = False,
    recursive: bool = False,
) -> Dict[str, List[Union[TestcaseSchema, Dict[str, Any]]]]:
    """Load all YAML/JSON testcase files from a directory.

    Args:
        directory:  Path to directory containing testcase files.
        strict:     If ``True``, raises on any validation error.
        as_dict:    If ``True``, returns raw dicts instead of schema objects.
        recursive:  If ``True``, search subdirectories recursively.

    Returns:
        Dict mapping filename (stem) to list of testcases.

    Raises:
        FileNotFoundError: If the directory does not exist.
    """
    directory = Path(directory)
    if not directory.exists() or not directory.is_dir():
        raise FileNotFoundError(f"Testcase directory not found: {directory}")

    pattern = "**/*.yaml" if recursive else "*.yaml"
    patterns = [pattern, pattern.replace(".yaml", ".yml"), pattern.replace(".yaml", ".json")]

    library: Dict[str, List] = {}
    seen_names: Dict[str, str] = {}  # name → source file, for uniqueness warning

    for pat in patterns:
        for tc_file in sorted(directory.glob(pat)):
            try:
                testcases = load_testcases(tc_file, strict=strict, as_dict=as_dict)
                file_key = tc_file.stem

                # Check for name uniqueness across files
                for tc in testcases:
                    tc_name = (tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "?"))
                    if tc_name in seen_names:
                        print(
                            f"[WARN] Duplicate testcase name '{tc_name}' "
                            f"in {tc_file.name} (also in {seen_names[tc_name]})"
                        )
                    else:
                        seen_names[tc_name] = tc_file.name

                library[file_key] = testcases
            except (FileNotFoundError, ValueError) as exc:
                if strict:
                    raise
                print(f"[WARN] Failed to load {tc_file.name}: {exc}")

    return library


def iter_testcases(
    directory: Union[str, Path],
    module_filter: Optional[str] = None,
    tag_filter: Optional[List[str]] = None,
) -> Iterator[TestcaseSchema]:
    """Iterate over all testcases in a directory, with optional filtering.

    Args:
        directory:     Path to testcase directory.
        module_filter: If set, only yield testcases with this ``module_name``.
        tag_filter:    If set, only yield testcases that have ALL of these tags.

    Yields:
        :class:`TestcaseSchema` instances matching the filters.
    """
    library = load_testcase_library(directory)
    for testcases in library.values():
        for tc in testcases:
            # Apply filters
            if module_filter:
                tc_module = tc.get("module_name") if isinstance(tc, dict) else getattr(tc, "module_name", None)
                if tc_module != module_filter:
                    continue
            if tag_filter:
                tc_tags = tc.get("tags", []) if isinstance(tc, dict) else getattr(tc, "tags", [])
                if not all(t in tc_tags for t in tag_filter):
                    continue
            yield tc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_yaml_file(path: Path) -> Dict[str, Any]:
    """Load a YAML file with !include directive support.

    Args:
        path: Path to YAML file.

    Returns:
        Parsed YAML data as dict.

    Raises:
        ImportError: If PyYAML is not installed.
        ValueError: If YAML parsing fails.
    """
    if not _HAS_YAML:
        raise ImportError(
            "PyYAML is required to load YAML testcases. "
            "Install it with: pip install pyyaml"
        )
    try:
        loader_factory = _IncludeLoader(path.parent)
        loader_cls = loader_factory.make_loader()
        with open(path, encoding="utf-8") as fh:
            data = _yaml.load(fh, Loader=loader_cls)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        raise ValueError(f"YAML parse error in {path.name}: {exc}") from exc


def _load_json_file(path: Path) -> Dict[str, Any]:
    """Load a JSON testcase file.

    Args:
        path: Path to JSON file.

    Returns:
        Parsed JSON data as dict.

    Raises:
        ValueError: If JSON parsing fails.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON parse error in {path.name}: {exc}") from exc
