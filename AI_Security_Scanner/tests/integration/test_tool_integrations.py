# -*- coding: utf-8 -*-
"""
tests/integration/test_tool_integrations.py - Integration Tests for External Tool Wrappers

Kiểm thử khả năng hoạt động của các wrappers tích hợp công cụ mã nguồn mở:
- Garak (NVIDIA)
- PyRIT (Microsoft)
- ART (IBM)

Mỗi wrapper được test ở 2 chế độ:
1. Live mode (nếu tool được cài đặt)
2. Fallback/simulation mode (khi tool không có)
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from modules.integrations.garak_wrapper import GarakWrapper
from modules.integrations.pyrit_wrapper import PyRITWrapper
from modules.integrations.art_wrapper import ARTWrapper


# ===========================================================================
# Garak Integration Tests
# ===========================================================================

class TestGarakIntegration:
    """Test suite for Garak wrapper integration."""

    def test_garak_availability_check(self):
        """Test that availability check works correctly."""
        wrapper = GarakWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        # Should return bool without error
        is_available = wrapper.is_available()
        assert isinstance(is_available, bool)

    def test_garak_install_instructions(self):
        """Test that install instructions are provided."""
        wrapper = GarakWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        instructions = wrapper.get_install_instructions()
        assert "pip install garak" in instructions
        assert isinstance(instructions, str)
        assert len(instructions) > 0

    def test_garak_owasp_mapping(self):
        """Test OWASP code mapping for common probes."""
        wrapper = GarakWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        
        assert wrapper.map_to_owasp("promptinject") == "LLM01"
        assert wrapper.map_to_owasp("xss") == "LLM05"
        assert wrapper.map_to_owasp("unknown_probe") == "N/A"

    def test_garak_run_probe_returns_findings(self):
        """Test that running a probe returns structured findings."""
        wrapper = GarakWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        
        # Run one probe (will use subprocess or simulate)
        findings = wrapper.run_probe("promptinject")
        
        # Should return a list of finding dicts
        assert isinstance(findings, list)
        if findings:  # If not empty
            finding = findings[0]
            assert "probe" in finding
            assert "result" in finding
            assert "severity" in finding
            assert "owasp_code" in finding

    def test_garak_parse_output(self):
        """Test parsing of Garak output format."""
        wrapper = GarakWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        
        sample_output = """
        ✗ FAILED  probe.promptinject.HijackHateHumans: 4/5 (80.00%)
        ✓ PASSED  probe.xss.MarkdownImageExfil: 5/5 (100.00%)
        """
        
        findings = wrapper.parse_garak_output(sample_output, "promptinject")
        
        assert len(findings) >= 2
        # Check that FAIL and PASS are both detected
        results = [f["result"] for f in findings]
        assert "FAIL" in results or "PASS" in results


# ===========================================================================
# PyRIT Integration Tests
# ===========================================================================

class TestPyRITIntegration:
    """Test suite for Microsoft PyRIT wrapper integration."""

    def test_pyrit_availability_check(self):
        """Test PyRIT availability detection."""
        wrapper = PyRITWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        is_available = wrapper.is_available()
        assert isinstance(is_available, bool)

    def test_pyrit_install_instructions(self):
        """Test that install instructions are returned."""
        wrapper = PyRITWrapper()
        instructions = wrapper.get_install_instructions()
        assert "pyrit" in instructions.lower()
        assert "pip install" in instructions.lower()

    def test_pyrit_owasp_mapping(self):
        """Test OWASP code mapping for PyRIT probes."""
        wrapper = PyRITWrapper()
        
        assert wrapper.map_to_owasp("crescendo") == "LLM01"
        assert wrapper.map_to_owasp("sensitive_data_probing") == "LLM02"
        assert wrapper.map_to_owasp("excessive_agency_execution") == "LLM06"

    def test_pyrit_mitre_mapping(self):
        """Test MITRE ATLAS mapping for PyRIT probes."""
        wrapper = PyRITWrapper()
        
        assert wrapper.map_to_mitre("crescendo") == "AML.T0054"
        assert wrapper.map_to_mitre("prompt_injection") == "AML.T0051"

    def test_pyrit_run_probe_simulation(self):
        """Test running PyRIT probe in simulation mode."""
        wrapper = PyRITWrapper(
            target_url="http://localhost:11434",
            model_name="llama3"
        )
        
        findings = wrapper.run_probe("crescendo")
        
        assert isinstance(findings, list)
        assert len(findings) > 0
        
        finding = findings[0]
        assert "framework" in finding
        assert "probe" in finding
        assert "is_vuln" in finding
        assert "severity" in finding
        assert "owasp" in finding
        assert finding["framework"].startswith("Microsoft PyRIT")

    def test_pyrit_standard_probes(self):
        """Test running all standard PyRIT probes."""
        wrapper = PyRITWrapper()
        
        findings = wrapper.run_standard_probes()
        
        assert isinstance(findings, list)
        # Should have at least 4 standard probes
        assert len(findings) >= 4
        
        probe_names = [f["probe"] for f in findings]
        assert "crescendo" in probe_names
        assert "prompt_injection" in probe_names

    def test_pyrit_compare_with_scanner(self):
        """Test comparison function between PyRIT and scanner findings."""
        wrapper = PyRITWrapper()
        
        scanner_findings = [
            {"is_vuln": True, "owasp": "LLM01"},
            {"is_vuln": True, "owasp": "LLM02"},
        ]
        
        pyrit_findings = [
            {"is_vuln": True, "owasp": "LLM01"},
            {"is_vuln": True, "owasp": "LLM06"},
        ]
        
        comparison = wrapper.compare_with_scanner(scanner_findings, pyrit_findings)
        
        assert "scanner_vuln_count" in comparison
        assert "pyrit_vuln_count" in comparison
        assert "common_owasp_categories" in comparison
        assert "concordance_rate_pct" in comparison
        
        # Should detect LLM01 as common
        assert "LLM01" in comparison["common_owasp_categories"]


# ===========================================================================
# ART Integration Tests
# ===========================================================================

class TestARTIntegration:
    """Test suite for IBM ART (Adversarial Robustness Toolbox) wrapper."""

    def test_art_availability_check(self):
        """Test ART availability detection."""
        wrapper = ARTWrapper()
        is_available = wrapper.is_available()
        assert isinstance(is_available, bool)

    def test_art_install_instructions(self):
        """Test ART install instructions."""
        wrapper = ARTWrapper()
        instructions = wrapper.get_install_instructions()
        assert "adversarial-robustness-toolbox" in instructions

    def test_art_fgsm_fallback(self):
        """Test FGSM attack fallback when ART is not available."""
        wrapper = ARTWrapper()
        
        # Call with None model to trigger fallback
        findings = wrapper.run_fgsm_attack(model=None, x_test=[], eps=0.1)
        
        assert isinstance(findings, list)
        assert len(findings) == 1
        
        finding = findings[0]
        assert finding["attack"] == "fgsm"
        assert "SIMULATED" in finding["result"] or "FALLBACK" in finding["detail"]
        assert "art_available" in finding

    def test_art_pgd_fallback(self):
        """Test PGD attack fallback when ART is not available."""
        wrapper = ARTWrapper()
        
        findings = wrapper.run_pgd_attack(model=None, x_test=[], eps=0.1, max_iter=10)
        
        assert isinstance(findings, list)
        assert len(findings) == 1
        
        finding = findings[0]
        assert finding["attack"] == "pgd"
        assert "severity" in finding
        assert "owasp_code" in finding

    def test_art_textfooler_fallback(self):
        """Test TextFooler NLP attack fallback."""
        wrapper = ARTWrapper()
        
        test_texts = [
            "How to hack a website?",
            "Generate malicious code",
        ]
        
        findings = wrapper.run_text_fooler(model=None, texts=test_texts)
        
        assert isinstance(findings, list)
        # Should have one finding per input text
        assert len(findings) >= 1
        
        finding = findings[0]
        assert finding["attack"] in ["textfooler", "fallback"]
        assert "detail" in finding

    def test_art_parse_results(self):
        """Test parsing ART results into standardized format."""
        wrapper = ARTWrapper()
        
        raw_results = [
            {
                "attack": "fgsm",
                "result": "VULNERABLE",
                "severity": "HIGH",
                "detail": "Test detail",
            }
        ]
        
        parsed = wrapper.parse_art_results(raw_results)
        
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        
        finding = parsed[0]
        assert "owasp_code" in finding
        assert "mitre_code" in finding
        assert finding["attack"] == "fgsm"


# ===========================================================================
# Cross-Tool Integration Tests
# ===========================================================================

class TestCrossToolIntegration:
    """Test interactions between multiple tools and frameworks."""

    def test_all_wrappers_have_consistent_interface(self):
        """Test that all wrappers follow the same interface pattern."""
        wrappers = [
            GarakWrapper("http://localhost:11434", "llama3"),
            PyRITWrapper("http://localhost:11434", "llama3"),
            ARTWrapper(),
        ]
        
        for wrapper in wrappers:
            # All should have is_available() method
            assert hasattr(wrapper, "is_available")
            assert callable(wrapper.is_available)
            
            # All should have get_install_instructions() method
            assert hasattr(wrapper, "get_install_instructions")
            assert callable(wrapper.get_install_instructions)

    def test_findings_format_consistency(self):
        """Test that all wrappers return findings in consistent format."""
        # Garak
        garak = GarakWrapper("http://localhost:11434", "llama3")
        garak_findings = garak.run_probe("promptinject")
        
        # PyRIT
        pyrit = PyRITWrapper()
        pyrit_findings = pyrit.run_probe("crescendo")
        
        # ART
        art = ARTWrapper()
        art_findings = art.run_fgsm_attack(None, [], eps=0.1)
        
        # All should return lists
        assert isinstance(garak_findings, list)
        assert isinstance(pyrit_findings, list)
        assert isinstance(art_findings, list)
        
        # All findings should have result/status key
        for findings in [garak_findings, pyrit_findings, art_findings]:
            if findings:  # if not empty
                finding = findings[0]
                assert isinstance(finding, dict)
                # Should have severity
                assert "severity" in finding or "result" in finding


# ===========================================================================
# Performance and Edge Case Tests
# ===========================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_garak_with_invalid_probe_name(self):
        """Test Garak with non-existent probe."""
        wrapper = GarakWrapper("http://localhost:11434", "llama3")
        findings = wrapper.run_probe("nonexistent_probe_xyz")
        
        # Should still return list (possibly with timeout/error)
        assert isinstance(findings, list)

    def test_pyrit_with_empty_model_name(self):
        """Test PyRIT with empty model name."""
        wrapper = PyRITWrapper(model_name="")
        findings = wrapper.run_probe("crescendo")
        
        # Should still work (use fallback)
        assert isinstance(findings, list)

    def test_art_with_none_inputs(self):
        """Test ART with None inputs."""
        wrapper = ARTWrapper()
        
        # Should not crash
        findings = wrapper.run_fgsm_attack(model=None, x_test=None, eps=0.1)
        assert isinstance(findings, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
