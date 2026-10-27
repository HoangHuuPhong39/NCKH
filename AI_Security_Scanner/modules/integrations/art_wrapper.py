# -*- coding: utf-8 -*-
"""
modules/integrations/art_wrapper.py - Adversarial Robustness Toolbox (ART) Integration

Wrapper cho IBM Adversarial Robustness Toolbox (ART):
https://github.com/Trusted-AI/adversarial-robustness-toolbox

ART cung cấp các gradient-based adversarial attacks (FGSM, PGD)
và NLP attacks (TextFooler) để kiểm thử robustness của ML/DL models.

ART License: MIT
Install: pip install adversarial-robustness-toolbox
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ART import — graceful fallback nếu không được cài
# ---------------------------------------------------------------------------

try:
    import art  # noqa: F401
    _ART_AVAILABLE = True
    _ART_VERSION = getattr(art, "__version__", "unknown")
    logger.info("ART (Adversarial Robustness Toolbox) v%s detected.", _ART_VERSION)
except ImportError:
    _ART_AVAILABLE = False
    _ART_VERSION = None
    logger.warning(
        "ART is not installed. Gradient-based attacks will be unavailable. "
        "Run: pip install adversarial-robustness-toolbox"
    )

# ---------------------------------------------------------------------------
# OWASP / MITRE mappings for ART attack types
# ---------------------------------------------------------------------------

_ATTACK_OWASP_MAP: Dict[str, str] = {
    "fgsm":        "LLM-AI-SEC",
    "pgd":         "LLM-AI-SEC",
    "textfooler":  "LLM01",
    "fallback":    "LLM01",
}

_ATTACK_MITRE_MAP: Dict[str, str] = {
    "fgsm":        "AML.T0015",
    "pgd":         "AML.T0015",
    "textfooler":  "AML.T0015",
    "fallback":    "AML.T0015",
}


class ARTWrapper:
    """
    Integration wrapper around the IBM Adversarial Robustness Toolbox (ART).

    Provides:
    - FGSM (Fast Gradient Sign Method)
    - PGD (Projected Gradient Descent)
    - TextFooler (NLP adversarial attack)
    - Automatic fallback to ``ml_adversarial`` approach when ART is unavailable.

    Results are returned in the framework's standardised findings dict format.

    Example::

        wrapper = ARTWrapper()
        if wrapper.is_available():
            results = wrapper.run_fgsm_attack(model, x_test, eps=0.1)
        else:
            print(wrapper.get_install_instructions())
            results = wrapper.run_text_fooler(None, ["How to hack?"])
    """

    def __init__(self):
        """Initialise the ART wrapper."""
        self._available: Optional[bool] = None  # cached after first check

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether the ``art`` package is importable in the current environment.

        The result is cached after the first call.

        Returns:
            bool: ``True`` if ART is installed and importable.
        """
        if self._available is not None:
            return self._available

        try:
            import importlib.util
            spec = importlib.util.find_spec("art")
            self._available = spec is not None
        except Exception:
            self._available = False

        if not self._available:
            logger.warning("ART not available. Run: %s", self.get_install_instructions())
        return self._available

    @staticmethod
    def get_install_instructions() -> str:
        """
        Return the pip install command for ART.

        Returns:
            str: Shell command string.
        """
        return "pip install adversarial-robustness-toolbox"

    # ------------------------------------------------------------------
    # FGSM Attack
    # ------------------------------------------------------------------

    def run_fgsm_attack(
        self,
        model: Any,
        x_test: Any,
        eps: float = 0.1,
    ) -> List[Dict[str, Any]]:
        """
        Run Fast Gradient Sign Method (FGSM) adversarial attack.

        Requires ART and a compatible classifier model (e.g. scikit-learn,
        TensorFlow, or PyTorch wrapped in an ART estimator).

        Args:
            model: ART-compatible classifier or raw ML model.
            x_test: Input samples to perturb (numpy array or list).
            eps (float): Perturbation magnitude ε (default: 0.1).

        Returns:
            list[dict]: Findings, each containing ``attack``, ``eps``,
                ``result``, ``owasp_code``, ``mitre_code``, ``detail``.
        """
        if not self.is_available():
            logger.warning("ART not available — running FGSM fallback simulation.")
            return self._fgsm_fallback(eps)

        try:
            from art.attacks.evasion import FastGradientMethod
            from art.estimators.classification import SklearnClassifier

            # Wrap model nếu chưa là ART estimator
            if not hasattr(model, "predict"):
                return self._fgsm_fallback(eps, reason="Model không tương thích với ART estimator")

            attack = FastGradientMethod(estimator=model, eps=eps)
            x_adv = attack.generate(x=x_test)

            # Tính tỉ lệ thay đổi prediction
            orig_preds = model.predict(x_test)
            adv_preds  = model.predict(x_adv)

            changed = int(sum(
                1 for o, a in zip(orig_preds, adv_preds) if str(o) != str(a)
            ))
            total = len(list(orig_preds))
            attack_success_rate = round(changed / max(total, 1), 4)

            return [self._build_finding(
                attack="fgsm",
                result="VULNERABLE" if attack_success_rate > 0 else "ROBUST",
                severity="HIGH" if attack_success_rate > 0.5 else "MEDIUM",
                detail=(
                    f"FGSM ε={eps}: {changed}/{total} samples changed prediction. "
                    f"Attack success rate: {attack_success_rate * 100:.1f}%"
                ),
            )]

        except Exception as exc:
            logger.error("FGSM attack failed: %s", exc)
            return self._fgsm_fallback(eps, reason=str(exc))

    def _fgsm_fallback(self, eps: float, reason: str = "ART not installed") -> List[Dict[str, Any]]:
        """Fallback simulation when ART FGSM is unavailable."""
        return [self._build_finding(
            attack="fgsm",
            result="SIMULATED",
            severity="INFO",
            detail=(
                f"FGSM fallback (ε={eps}): ART not available ({reason}). "
                "Simulated: gradient-based perturbations would test model boundary decisions. "
                "Install ART for actual gradient-based attacks."
            ),
        )]

    # ------------------------------------------------------------------
    # PGD Attack
    # ------------------------------------------------------------------

    def run_pgd_attack(
        self,
        model: Any,
        x_test: Any,
        eps: float = 0.1,
        max_iter: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Run Projected Gradient Descent (PGD) adversarial attack.

        PGD is a stronger iterative variant of FGSM that finds stronger
        adversarial examples within an ε-ball around the input.

        Args:
            model: ART-compatible classifier.
            x_test: Input samples to perturb.
            eps (float): Perturbation magnitude ε (default: 0.1).
            max_iter (int): Maximum number of PGD iterations (default: 10).

        Returns:
            list[dict]: Findings in framework format.
        """
        if not self.is_available():
            logger.warning("ART not available — running PGD fallback simulation.")
            return self._pgd_fallback(eps, max_iter)

        try:
            from art.attacks.evasion import ProjectedGradientDescent

            attack = ProjectedGradientDescent(estimator=model, eps=eps, max_iter=max_iter)
            x_adv = attack.generate(x=x_test)

            orig_preds = model.predict(x_test)
            adv_preds  = model.predict(x_adv)

            changed = int(sum(
                1 for o, a in zip(orig_preds, adv_preds) if str(o) != str(a)
            ))
            total = len(list(orig_preds))
            attack_success_rate = round(changed / max(total, 1), 4)

            return [self._build_finding(
                attack="pgd",
                result="VULNERABLE" if attack_success_rate > 0 else "ROBUST",
                severity="CRITICAL" if attack_success_rate > 0.5 else "HIGH",
                detail=(
                    f"PGD ε={eps} iter={max_iter}: {changed}/{total} samples changed. "
                    f"Attack success rate: {attack_success_rate * 100:.1f}%"
                ),
            )]

        except Exception as exc:
            logger.error("PGD attack failed: %s", exc)
            return self._pgd_fallback(eps, max_iter, reason=str(exc))

    def _pgd_fallback(self, eps: float, max_iter: int, reason: str = "ART not installed") -> List[Dict[str, Any]]:
        """Fallback simulation when ART PGD is unavailable."""
        return [self._build_finding(
            attack="pgd",
            result="SIMULATED",
            severity="INFO",
            detail=(
                f"PGD fallback (ε={eps}, iter={max_iter}): ART not available ({reason}). "
                "Simulated: iterative gradient projection would find stronger adversarial examples. "
                "Install ART for actual gradient-based attacks."
            ),
        )]

    # ------------------------------------------------------------------
    # TextFooler Attack (NLP)
    # ------------------------------------------------------------------

    def run_text_fooler(
        self,
        model: Any,
        texts: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Run TextFooler adversarial attack on NLP/text classification models.

        TextFooler generates semantically similar but adversarial text by
        substituting important words with synonyms that fool the classifier.

        If ART's NLP module is unavailable, falls back to built-in
        character-level perturbations from ``ml_adversarial``.

        Args:
            model: Text classifier with ``predict(texts: list) -> list`` method,
                or an LLM client with ``send_prompt(text: str) -> str`` method.
            texts (list[str]): Input text strings to attack.

        Returns:
            list[dict]: Findings for each input text.
        """
        findings: List[Dict[str, Any]] = []

        # Nếu ART có NLP module, thử dùng
        if self.is_available():
            try:
                # ART TextFooler chỉ có trong art.attacks.evasion.text cho một số version
                from art.attacks.evasion import TextFooler  # type: ignore
                classifier = model  # Assume already wrapped
                attack = TextFooler(classifier=classifier)
                adv_texts = attack.generate(x=texts)
                for orig, adv in zip(texts, adv_texts):
                    findings.append(self._build_finding(
                        attack="textfooler",
                        result="GENERATED",
                        severity="HIGH",
                        detail=f"Original: {orig[:100]!r} → Adversarial: {adv[:100]!r}",
                    ))
                return findings
            except (ImportError, AttributeError, Exception) as exc:
                logger.info("ART TextFooler unavailable (%s) — using built-in fallback.", exc)

        # Fallback: dùng ml_adversarial perturbations
        return self._text_fooler_fallback(model, texts)

    def _text_fooler_fallback(self, model: Any, texts: List[str]) -> List[Dict[str, Any]]:
        """
        Fallback TextFooler using built-in character-level perturbations.

        Args:
            model: LLM client or callable.
            texts (list[str]): Input texts.

        Returns:
            list[dict]: Findings.
        """
        try:
            from modules.exploits.ml_adversarial import _generate_perturbations, _safe_call
        except ImportError:
            # Ultra-simple fallback nếu không import được
            findings = []
            for text in texts:
                findings.append(self._build_finding(
                    attack="fallback",
                    result="SIMULATED",
                    severity="INFO",
                    detail=f"Fallback: cannot import ml_adversarial. Text: {text[:80]!r}",
                ))
            return findings

        findings: List[Dict[str, Any]] = []
        for text in texts:
            perturbations = _generate_perturbations(text)
            perturbed_results = []
            for ptype, perturbed in perturbations:
                if model is not None:
                    resp = _safe_call(model, perturbed)
                else:
                    resp = f"[SANDBOX] Perturbed input: {perturbed[:80]}"
                perturbed_results.append({"type": ptype, "perturbed": perturbed[:80], "response": resp[:80]})

            findings.append(self._build_finding(
                attack="textfooler",
                result="SIMULATED",
                severity="MEDIUM",
                detail=(
                    f"TextFooler fallback on: {text[:80]!r}. "
                    f"Generated {len(perturbations)} perturbations. "
                    "Install ART for semantic synonym-based attacks."
                ),
                extra={"perturbations": perturbed_results},
            ))
        return findings

    # ------------------------------------------------------------------
    # Result parser
    # ------------------------------------------------------------------

    def parse_art_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Convert raw ART attack output into the framework's standardised findings format.

        Args:
            results (list[dict]): Raw ART result dicts.

        Returns:
            list[dict]: Standardised findings with ``attack``, ``result``,
                ``severity``, ``owasp_code``, ``mitre_code``, ``detail``.
        """
        parsed: List[Dict[str, Any]] = []
        for r in results:
            attack_type = r.get("attack", "unknown").lower()
            parsed.append({
                "attack": attack_type,
                "result": r.get("result", "UNKNOWN"),
                "severity": r.get("severity", "MEDIUM"),
                "owasp_code": _ATTACK_OWASP_MAP.get(attack_type, "N/A"),
                "mitre_code": _ATTACK_MITRE_MAP.get(attack_type, "N/A"),
                "detail": r.get("detail", ""),
                **{k: v for k, v in r.items() if k not in ("attack", "result", "severity", "detail")},
            })
        return parsed

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        attack: str,
        result: str,
        severity: str,
        detail: str,
        extra: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Build a standardised finding dict."""
        finding = {
            "attack": attack,
            "result": result,
            "severity": severity,
            "owasp_code": _ATTACK_OWASP_MAP.get(attack, "N/A"),
            "mitre_code": _ATTACK_MITRE_MAP.get(attack, "N/A"),
            "art_available": self.is_available(),
            "art_version": _ART_VERSION,
            "detail": detail,
        }
        if extra:
            finding.update(extra)
        return finding

    def __repr__(self) -> str:
        return f"<ARTWrapper available={self.is_available()} art_version={_ART_VERSION!r}>"
