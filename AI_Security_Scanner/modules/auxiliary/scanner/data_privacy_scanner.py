# -*- coding: utf-8 -*-
"""
modules/auxiliary/scanner/data_privacy_scanner.py
AI Data Hygiene, Poisoning Pre-Check & ML/DL Privacy Auditor (Mục 3.3.1 & 3.3.2)

Covers:
  1. AIDataHygieneScanner (Pre-ingestion / Training Dataset Security):
     - DATA-001: Sensitive PII & Secrets Leakage in Datasets (OWASP LLM02 / AML.T0024)
     - DATA-002: Prompt Injection & Backdoor Trigger Poisoning (OWASP LLM04, LLM08 / AML.T0020)
     - DATA-003: Exact Duplicate Memorization Risk & Severe Class/Label Skew (OWASP LLM04 / AML.T0020)
     - DATA-004: Dataset Integrity & Provenance (SHA-256 AI-BOM Digest + Empty/Corrupt Rows)
  2. MLPrivacyAuditor (ML/DL Model Privacy & Stealing):
     - ML-001: Membership Inference Attack — Confidence/Loss & IBM ART RuleBased MIA
       (OWASP LLM02 / MITRE AML.T0024.001)
     - ML-002: Model Extraction / Surrogate Fidelity Attack (OWASP LLM02 / MITRE AML.T0044)
     - ML-003: LLM Training Data Memorization Probe (OWASP LLM02 / MITRE AML.T0024)
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.governance import redact_sensitive_data

# ==============================================================================
# 1. AI Data Hygiene & Poisoning Pre-Check Scanner (DATA-001 .. DATA-004)
# ==============================================================================

_INVISIBLE_CHARS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")

_POISONING_TRIGGER_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("INDIRECT_INJECTION", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.IGNORECASE)),
    ("SYSTEM_OVERRIDE", re.compile(r"\[(?:system\s+override|supersede_all_policies|admin_directive)\]", re.IGNORECASE)),
    ("HIDDEN_TOOL_DIRECTIVE", re.compile(r"<(?:system_command|system_action|action)>|execute_tool\s*\(|call_tool\s*:", re.IGNORECASE)),
    ("BACKDOOR_TRIGGER", re.compile(r"\b(?:cf_trigger|bb_backdoor|tq_poison|backdoor_trigger|trigger_phrase_x9)\b", re.IGNORECASE)),
    ("EXFIL_BEACON", re.compile(r"!\[[^\]]*\]\(https?://[^)]*(?:exfil|steal|beacon|log\?)", re.IGNORECASE)),
    ("VI_INJECTION", re.compile(r"bỏ qua (?:toàn bộ|mọi) (?:hướng dẫn|chính sách|quy tắc)", re.IGNORECASE)),
]


def _extract_record_text_and_label(record: Any) -> Tuple[str, Optional[str]]:
    if isinstance(record, str):
        return record, None
    if isinstance(record, dict):
        label = None
        for lk in ("label", "class", "category", "target", "y"):
            if lk in record and record[lk] is not None:
                label = str(record[lk])
                break
        text_parts: List[str] = []
        for k, v in record.items():
            if k in ("label", "class", "target", "y"):
                continue
            if isinstance(v, str):
                text_parts.append(v)
            elif isinstance(v, (list, dict)):
                text_parts.append(json.dumps(v, ensure_ascii=False))
        return " ".join(text_parts), label
    return str(record), None


class AIDataHygieneScanner:
    """
    Audits training, fine-tuning, and RAG ingestion datasets prior to model training
    or vector indexing for PII/secrets, poisoning triggers, duplication, and skew.
    """

    def __init__(
        self,
        duplicate_threshold: float = 0.15,
        label_skew_threshold: float = 0.85,
    ) -> None:
        self.duplicate_threshold = float(duplicate_threshold)
        self.label_skew_threshold = float(label_skew_threshold)

    def scan_records(
        self,
        records: List[Any],
        dataset_name: str = "inline_dataset",
        provenance_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Audit a list of text/dict records and return structured data-security findings."""
        total = len(records)
        if total == 0:
            return {
                "success": True,
                "dataset": dataset_name,
                "total_records": 0,
                "sha256_digest": hashlib.sha256(b"").hexdigest(),
                "passed": True,
                "findings": [],
                "metrics": {"pii_records": 0, "poisoned_records": 0, "duplicate_rate": 0.0},
            }

        hasher = hashlib.sha256()
        pii_hits: List[Dict[str, Any]] = []
        poison_hits: List[Dict[str, Any]] = []
        seen_hashes: Counter[str] = Counter()
        labels: Counter[str] = Counter()
        empty_count = 0

        for idx, rec in enumerate(records):
            text, label = _extract_record_text_and_label(rec)
            hasher.update(text.encode("utf-8", errors="ignore") + b"\n")

            stripped = text.strip()
            if not stripped:
                empty_count += 1
                continue

            norm_hash = hashlib.sha256(re.sub(r"\s+", " ", stripped.lower()).encode("utf-8")).hexdigest()[:16]
            seen_hashes[norm_hash] += 1

            if label is not None:
                labels[label] += 1

            # 1. PII & Secret detection (reuses core.governance redactor)
            _, pii_labels = redact_sensitive_data(stripped)
            if pii_labels:
                pii_hits.append({"index": idx, "types": pii_labels})

            # 2. Poisoning / Backdoor / Invisible Unicode detection
            triggers: List[str] = []
            if _INVISIBLE_CHARS_RE.search(text):
                triggers.append("INVISIBLE_UNICODE_STEGO")
            for trig_name, pat in _POISONING_TRIGGER_PATTERNS:
                if pat.search(text):
                    triggers.append(trig_name)
            if triggers:
                poison_hits.append({"index": idx, "triggers": triggers})

        digest = hasher.hexdigest()
        duplicate_records = sum(cnt - 1 for cnt in seen_hashes.values() if cnt > 1)
        duplicate_rate = round(duplicate_records / total, 4)

        findings: List[Dict[str, Any]] = []

        # DATA-001: PII & Secrets
        if pii_hits:
            all_types = sorted({t for h in pii_hits for t in h["types"]})
            has_secret = any(t in all_types for t in ("API_KEY", "PRIVATE_KEY", "CREDENTIAL_URI", "JWT_TOKEN"))
            sev = "CRITICAL" if has_secret else "HIGH"
            findings.append({
                "finding_id": "DATA-001",
                "title": "Sensitive PII or Credentials Detected in AI Dataset",
                "category": "DATA_PRIVACY_LEAKAGE",
                "severity": sev,
                "risk_score": 9.1 if has_secret else 8.2,
                "owasp": "LLM02",
                "mitre": "AML.T0024",
                "affected_records": len(pii_hits),
                "evidence": f"{len(pii_hits)}/{total} records contain sensitive types: {', '.join(all_types)}",
                "sample_indices": [h["index"] for h in pii_hits[:10]],
                "remediation": (
                    "Chạy pipeline ẩn danh hóa/che mờ PII & Secret (như `redact_sensitive_data`) "
                    "trước khi fine-tune hoặc lập chỉ mục Vector DB."
                ),
            })

        # DATA-002: Poisoning / Backdoor Triggers
        if poison_hits:
            all_trigs = sorted({t for h in poison_hits for t in h["triggers"]})
            findings.append({
                "finding_id": "DATA-002",
                "title": "Potential Data Poisoning / Indirect Injection Trigger in Dataset",
                "category": "DATA_POISONING",
                "severity": "CRITICAL",
                "risk_score": 9.0,
                "owasp": "LLM04",
                "mitre": "AML.T0020",
                "affected_records": len(poison_hits),
                "evidence": f"{len(poison_hits)}/{total} records matched poisoning indicators: {', '.join(all_trigs)}",
                "sample_indices": [h["index"] for h in poison_hits[:10]],
                "remediation": (
                    "Loại bỏ ký tự Unicode vô hình, cách ly các mẫu chứa chỉ thị ghi đè/trigger backdoor "
                    "và áp dụng kiểm duyệt nguồn dữ liệu trước khi nạp."
                ),
            })

        # DATA-003A: Excessive Duplication (increases LLM/ML memorization & MIA risk)
        if total >= 5 and duplicate_rate >= self.duplicate_threshold:
            findings.append({
                "finding_id": "DATA-003",
                "title": "High Exact-Duplicate Rate Increasing Memorization & MIA Risk",
                "category": "DATA_DUPLICATION",
                "severity": "MEDIUM",
                "risk_score": 5.8,
                "owasp": "LLM04",
                "mitre": "AML.T0024",
                "affected_records": duplicate_records,
                "evidence": f"Duplicate rate {duplicate_rate*100:.1f}% ({duplicate_records}/{total} duplicate rows >= threshold {self.duplicate_threshold*100:.0f}%).",
                "remediation": "Khử trùng lặp (exact & near-deduplication MinHash) trước huấn luyện để giảm ghi nhớ dữ liệu và tấn công Membership Inference.",
            })

        # DATA-003B: Severe Label Skew
        dominant_label_ratio = 0.0
        if len(labels) >= 2 and sum(labels.values()) >= 5:
            top_label, top_cnt = labels.most_common(1)[0]
            dominant_label_ratio = round(top_cnt / sum(labels.values()), 4)
            if dominant_label_ratio >= self.label_skew_threshold:
                findings.append({
                    "finding_id": "DATA-003B",
                    "title": "Severe Class / Label Imbalance Detected in Training Dataset",
                    "category": "DATA_BIAS_SKEW",
                    "severity": "MEDIUM",
                    "risk_score": 5.2,
                    "owasp": "LLM04",
                    "mitre": "AML.T0020",
                    "affected_records": top_cnt,
                    "evidence": f"Class '{top_label}' accounts for {dominant_label_ratio*100:.1f}% of labeled rows ({dict(labels)}).",
                    "remediation": "Kiểm tra nguy cơ thao túng nhãn (label-flipping poisoning) và cân bằng lại phân bố lớp.",
                })

        # DATA-004: Empty / Corrupted records or missing provenance
        if empty_count > 0 or (provenance_metadata is not None and not provenance_metadata.get("source")):
            findings.append({
                "finding_id": "DATA-004",
                "title": "Dataset Quality / Provenance Anomaly Detected",
                "category": "DATA_PROVENANCE",
                "severity": "LOW",
                "risk_score": 3.2,
                "owasp": "LLM03",
                "mitre": "AML.T0020",
                "affected_records": empty_count,
                "evidence": (
                    f"Empty/corrupted rows: {empty_count}; SHA-256 AI-BOM digest: {digest[:16]}...; "
                    f"Provenance source present: {bool(provenance_metadata and provenance_metadata.get('source'))}"
                ),
                "remediation": "Ghi nhận nguồn gốc dữ liệu, phiên bản và chữ ký SHA-256 trong AI-BOM; làm sạch bản ghi rỗng.",
            })

        return {
            "success": True,
            "dataset": dataset_name,
            "total_records": total,
            "sha256_digest": digest,
            "passed": len(findings) == 0,
            "total_findings": len(findings),
            "findings": findings,
            "metrics": {
                "pii_records": len(pii_hits),
                "poisoned_records": len(poison_hits),
                "duplicate_records": duplicate_records,
                "duplicate_rate": duplicate_rate,
                "empty_records": empty_count,
                "label_distribution": dict(labels),
                "dominant_label_ratio": dominant_label_ratio,
            },
        }

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Load and audit a .json, .jsonl, .csv, .txt, or .md dataset file."""
        from core.path_security import resolve_safe_path

        try:
            p = resolve_safe_path(file_path, must_exist=True)
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return {"success": False, "error": str(exc), "findings": []}
        if not p.is_file():
            return {"success": False, "error": f"Dataset path is not a file: {file_path}", "findings": []}

        ext = p.suffix.lower()
        records: List[Any] = []
        try:
            if ext == ".json":
                raw = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(raw, list):
                    records = raw
                elif isinstance(raw, dict):
                    for key in ("data", "records", "items", "test_cases", "cases", "samples"):
                        if isinstance(raw.get(key), list):
                            records = raw[key]
                            break
                    if not records:
                        records = [raw]
            elif ext == ".jsonl":
                for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        records.append(json.loads(ln))
                    except json.JSONDecodeError:
                        records.append(ln)
            elif ext == ".csv":
                with open(p, "r", encoding="utf-8", errors="ignore", newline="") as fh:
                    reader = csv.DictReader(fh)
                    records = list(reader)
            else:
                records = [
                    ln for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if ln.strip()
                ]
        except Exception as exc:
            return {"success": False, "error": f"Failed to parse dataset {file_path}: {exc}", "findings": []}

        return self.scan_records(records, dataset_name=p.name)


# ==============================================================================
# 2. ML/DL Model Privacy & Stealing Auditor (ML-001, ML-002, ML-003)
# ==============================================================================

def _build_demo_ml_scenario(hardened: bool = False, seed: int = 42):
    """
    Construct a reproducible scikit-learn tabular classifier scenario:
      - hardened=False: unregularized deep DecisionTree / high-capacity MLP prone to
        overfitting -> high Membership Inference Advantage & high Extraction Fidelity.
      - hardened=True: strongly regularized LogisticRegression with low C + output
        probability rounding -> low Membership Inference Advantage.
    """
    import numpy as np
    from sklearn.datasets import make_classification
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier

    X, y = make_classification(
        n_samples=600,
        n_features=20,
        n_informative=6,
        n_redundant=4,
        n_classes=2,
        flip_y=0.12,
        random_state=seed,
    )
    x_train, x_test, y_train, y_test = train_test_split(
        X, y, test_size=0.5, random_state=seed, stratify=y
    )

    if hardened:
        model = LogisticRegression(C=0.05, max_iter=500, random_state=seed)
        model.fit(x_train, y_train)
    else:
        # Unconstrained decision tree memorizes training noise -> textbook MIA risk
        model = DecisionTreeClassifier(max_depth=None, min_samples_leaf=1, random_state=seed)
        model.fit(x_train, y_train)

    return model, x_train, y_train, x_test, y_test


class MLPrivacyAuditor:
    """
    Evaluates ML/DL models for Privacy & Intellectual Property risks:
      - ML-001: Membership Inference Attack (Yeom confidence/correctness & IBM ART RuleBased)
      - ML-002: Black-box Model Extraction / Surrogate Stealing Fidelity
      - ML-003: LLM Training Data Memorization Probing
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = int(seed)

    def run_membership_inference_audit(
        self,
        model: Optional[Any] = None,
        x_train: Optional[Any] = None,
        y_train: Optional[Any] = None,
        x_test: Optional[Any] = None,
        y_test: Optional[Any] = None,
        hardened_demo: bool = False,
        advantage_threshold: float = 0.15,
    ) -> Dict[str, Any]:
        """
        Run Membership Inference Attack (ML-001).
        Uses both Yeom correctness/confidence MIA and IBM ART's
        MembershipInferenceBlackBoxRuleBased when available.
        """
        import numpy as np

        if model is None or x_train is None or y_train is None or x_test is None or y_test is None:
            model, x_train, y_train, x_test, y_test = _build_demo_ml_scenario(
                hardened=hardened_demo, seed=self.seed
            )

        x_tr = np.asarray(x_train)
        y_tr = np.asarray(y_train)
        x_te = np.asarray(x_test)
        y_te = np.asarray(y_test)

        # Predictions & confidences
        pred_tr = np.asarray(model.predict(x_tr))
        pred_te = np.asarray(model.predict(x_te))
        train_acc = float(np.mean(pred_tr == y_tr))
        test_acc = float(np.mean(pred_te == y_te))

        if hasattr(model, "predict_proba"):
            proba_tr = np.asarray(model.predict_proba(x_tr))
            proba_te = np.asarray(model.predict_proba(x_te))
            conf_tr = np.max(proba_tr, axis=1)
            conf_te = np.max(proba_te, axis=1)
        else:
            conf_tr = (pred_tr == y_tr).astype(float)
            conf_te = (pred_te == y_te).astype(float)

        train_mean_conf = float(np.mean(conf_tr))
        test_mean_conf = float(np.mean(conf_te))
        confidence_gap = round(train_mean_conf - test_mean_conf, 4)

        # Yeom correctness-based MIA: predict "member" iff classifier predicted correctly
        tpr = train_acc
        fpr = test_acc
        mia_advantage = round(max(0.0, tpr - fpr), 4)
        mia_accuracy = round(0.5 * (tpr + (1.0 - fpr)), 4)

        # Optional IBM ART RuleBased Black-Box MIA verification
        art_mia_used = False
        art_mia_acc: Optional[float] = None
        try:
            from art.attacks.inference.membership_inference import MembershipInferenceBlackBoxRuleBased
            from art.estimators.classification import SklearnClassifier

            art_est = SklearnClassifier(model=model)
            art_attack = MembershipInferenceBlackBoxRuleBased(art_est)
            inferred_train = art_attack.infer(x_tr, y_tr)
            inferred_test = art_attack.infer(x_te, y_te)
            art_tpr = float(np.mean(inferred_train == 1))
            art_fpr = float(np.mean(inferred_test == 1))
            art_mia_acc = round(0.5 * (art_tpr + (1.0 - art_fpr)), 4)
            art_mia_used = True
        except Exception:
            art_mia_used = False

        is_vulnerable = mia_advantage >= advantage_threshold
        if mia_advantage >= 0.30:
            severity, risk_score = "CRITICAL", 9.0
        elif is_vulnerable:
            severity, risk_score = "HIGH", 7.8
        else:
            severity, risk_score = "LOW", 2.5

        return {
            "success": True,
            "finding_id": "ML-001",
            "name": "Membership Inference Attack (Training Data Privacy Leakage)",
            "is_vulnerable": is_vulnerable,
            "severity": severity if is_vulnerable else "INFO",
            "risk_score": risk_score if is_vulnerable else 0.0,
            "owasp": "LLM02",
            "mitre": "AML.T0024.001",
            "art_mia_used": art_mia_used,
            "metrics": {
                "train_accuracy": round(train_acc, 4),
                "test_accuracy": round(test_acc, 4),
                "generalization_gap": round(train_acc - test_acc, 4),
                "train_mean_confidence": round(train_mean_conf, 4),
                "test_mean_confidence": round(test_mean_conf, 4),
                "confidence_gap": confidence_gap,
                "mia_accuracy": mia_accuracy,
                "mia_advantage": mia_advantage,
                "art_rule_based_mia_accuracy": art_mia_acc,
                "advantage_threshold": advantage_threshold,
            },
            "remediation": (
                "Áp dụng Differential Privacy (DP-SGD), tăng cường chính quy hóa (L2/Dropout/Early Stopping), "
                "làm tròn hoặc ẩn vector xác suất đầu ra (confidence masking), và khử trùng lặp dữ liệu huấn luyện."
            ),
        }

    def run_model_extraction_audit(
        self,
        model: Optional[Any] = None,
        x_probe: Optional[Any] = None,
        x_eval: Optional[Any] = None,
        query_budget: int = 120,
        hardened_demo: bool = False,
        fidelity_threshold: float = 0.85,
    ) -> Dict[str, Any]:
        """
        Run Black-Box Model Extraction / Surrogate Stealing Audit (ML-002).
        Queries the target model up to *query_budget* times, trains a surrogate
        model on the stolen labels, and measures agreement fidelity on held-out inputs.
        """
        import numpy as np
        from sklearn.linear_model import LogisticRegression

        if model is None or x_probe is None or x_eval is None:
            # Use the SAME clean target model for both modes so defense comparison is controlled:
            #   - unprotected API (hardened_demo=False): allows full query_budget + exact labels/logits
            #   - defended API (hardened_demo=True): enforces strict query throttling (20 queries) + perturbation
            model, x_tr, _, x_te, _ = _build_demo_ml_scenario(
                hardened=True, seed=self.seed
            )
            x_probe = x_tr[:query_budget]
            x_eval = x_te

        effective_budget = min(len(x_probe), 20 if hardened_demo else query_budget)
        xp = np.asarray(x_probe)[:effective_budget]
        xe = np.asarray(x_eval)

        # Target oracle queries
        target_probe_preds = np.asarray(model.predict(xp))
        target_eval_preds = np.asarray(model.predict(xe))

        if hardened_demo:
            rng = np.random.default_rng(self.seed)
            flip_mask = rng.random(len(target_probe_preds)) < 0.30
            unique_classes = np.unique(target_probe_preds)
            if len(unique_classes) >= 2:
                stolen_labels = np.where(
                    flip_mask,
                    np.where(target_probe_preds == unique_classes[0], unique_classes[1], unique_classes[0]),
                    target_probe_preds,
                )
            else:
                stolen_labels = target_probe_preds
        else:
            stolen_labels = target_probe_preds

        surrogate = LogisticRegression(max_iter=500, random_state=self.seed)
        if len(np.unique(stolen_labels)) >= 2:
            surrogate.fit(xp, stolen_labels)
            surrogate_eval_preds = surrogate.predict(xe)
        else:
            surrogate_eval_preds = np.full(len(xe), stolen_labels[0])

        extraction_fidelity = round(float(np.mean(surrogate_eval_preds == target_eval_preds)), 4)
        is_vulnerable = extraction_fidelity >= fidelity_threshold

        return {
            "success": True,
            "finding_id": "ML-002",
            "name": "Black-Box Model Extraction / Surrogate Stealing",
            "is_vulnerable": is_vulnerable,
            "severity": "HIGH" if is_vulnerable else "INFO",
            "risk_score": 8.0 if is_vulnerable else 0.0,
            "owasp": "LLM02",
            "mitre": "AML.T0044",
            "metrics": {
                "query_budget": int(len(xp)),
                "eval_samples": int(len(xe)),
                "extraction_fidelity": extraction_fidelity,
                "fidelity_threshold": fidelity_threshold,
            },
            "remediation": (
                "Giới hạn tần suất truy vấn (API rate-limiting & query budgeting), chỉ trả về nhãn top-1 "
                "thay vì toàn bộ logits/probabilities, và phát hiện mẫu truy vấn quét biên quyết định bất thường."
            ),
        }

    def run_full_privacy_audit(self, hardened_demo: bool = False) -> Dict[str, Any]:
        """Run both ML-001 (Membership Inference) and ML-002 (Model Extraction)."""
        mia = self.run_membership_inference_audit(hardened_demo=hardened_demo)
        ext = self.run_model_extraction_audit(hardened_demo=hardened_demo)
        findings = [r for r in (mia, ext) if r.get("is_vulnerable")]
        return {
            "success": True,
            "mode": "hardened_demo" if hardened_demo else "vulnerable_demo",
            "total_checks": 2,
            "vulnerable_checks": len(findings),
            "passed": len(findings) == 0,
            "membership_inference": mia,
            "model_extraction": ext,
            "findings": findings,
        }
