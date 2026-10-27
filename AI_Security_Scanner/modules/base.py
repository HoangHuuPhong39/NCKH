# -*- coding: utf-8 -*-
"""
modules/base.py - Abstract Base Class for Security Testing Modules

Provides a standard interface that all exploit and auxiliary modules
must implement.  This enforces consistency, enables the plugin registry
(modules/registry.py), and simplifies module discovery.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseExploitModule(ABC):
    """
    Base class for all security testing modules.

    Subclasses **must** define the class-level attributes ``name``,
    ``description``, ``owasp``, ``mitre`` and implement the ``run()``
    method.

    Example::

        class PromptInjection(BaseExploitModule):
            name = "Prompt Injection"
            description = "LLM01 ..."
            owasp = "LLM01"
            mitre = "AML.T0051"

            def __init__(self):
                self._payloads = [...]

            def run(self, llm_client):
                ...
    """

    # ── Class-level metadata (override in subclasses) ──────────────
    name: str = ""
    description: str = ""
    owasp: str = "N/A"
    mitre: str = "N/A"
    severity: str = "MEDIUM"
    category: str = "exploits"  # or "auxiliary"

    # ── Payload access ─────────────────────────────────────────────

    @property
    def payloads(self) -> List[Dict[str, Any]]:
        """Return the list of attack payloads."""
        return getattr(self, "_payloads", [])

    @payloads.setter
    def payloads(self, value: List[Dict[str, Any]]) -> None:
        self._payloads = value

    # ── Abstract interface ─────────────────────────────────────────

    @abstractmethod
    def run(self, llm_client: Any) -> List[Dict[str, Any]]:
        """Execute all payloads against the target LLM.

        Args:
            llm_client: Object with a ``send_prompt(prompt: str) -> str`` method.

        Returns:
            List of result dicts, each containing at least
            ``name``, ``payload``, ``response``, ``category``, ``owasp``, ``mitre``.
        """
        ...

    # ── Helpers ────────────────────────────────────────────────────

    def get_module_key(self) -> str:
        """Return a snake_case registry key derived from the class name."""
        import re

        name = self.__class__.__name__
        # CamelCase -> snake_case
        s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()

    def validate_payloads(self) -> bool:
        """Check that every payload has the minimum required fields."""
        required = {"name", "payload"}
        for p in self.payloads:
            if not isinstance(p, dict) or not required.issubset(p.keys()):
                return False
        return True

    def payload_count(self) -> int:
        """Return the number of payloads in this module."""
        return len(self.payloads)

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"name={self.name!r} payloads={self.payload_count()}>"
        )
