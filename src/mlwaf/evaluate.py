"""Metrics.

Accuracy is deliberately not reported. The corpus is roughly 72% benign, so a
model that blocks nothing scores 72% and looks respectable while being useless.
What matters for a firewall is: how many attacks do we catch, at how much
collateral damage to real users.
"""

from __future__ import annotations

from itertools import pairwise

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

from mlwaf.model import CLASSES, attack_score

# A WAF that blocks 1% of real traffic is unusable, so the operating point is
# chosen by how much false blocking we can tolerate, not by argmax.
FPR_BUDGETS = (0.001, 0.005, 0.01)


def calibration(y_true: np.ndarray, scores: np.ndarray, bins: int = 10) -> dict:
    """Do the probabilities mean what they say?

    The whole threshold argument -- "block above 0.96, and 0.1% of real users pay
    for it" -- assumes a score of 0.9 corresponds to roughly a 90% chance of being
    an attack. Expected calibration error is the average gap between predicted
    confidence and observed frequency; Brier score is the mean squared error of the
    probability itself. Both are reported because a model can rank well (good
    PR-AUC) while being badly calibrated, and a badly calibrated model makes the
    chosen operating point mean something other than what it claims.
    """
    is_attack = (y_true != "benign").astype(float)
    brier = float(np.mean((scores - is_attack) ** 2))

    edges = np.linspace(0.0, 1.0, bins + 1)
    ece, buckets = 0.0, []
    for lo, hi in pairwise(edges):
        mask = (scores >= lo) & (scores < hi if hi < 1.0 else scores <= hi)
        if not mask.any():
            continue
        confidence = float(scores[mask].mean())
        observed = float(is_attack[mask].mean())
        weight = float(mask.mean())
        ece += weight * abs(confidence - observed)
        buckets.append({
            "range": [round(float(lo), 2), round(float(hi), 2)],
            "n": int(mask.sum()),
            "mean_score": round(confidence, 4),
            "observed_attack_rate": round(observed, 4),
        })

    return {
        "brier_score": round(brier, 4),
        "expected_calibration_error": round(ece, 4),
        "buckets": buckets,
    }


def threshold_at_fpr(y_true: np.ndarray, scores: np.ndarray, budget: float) -> float:
    """Lowest threshold whose false-positive rate on benign traffic stays within budget."""
    benign_scores = np.sort(scores[y_true == "benign"])[::-1]
    if len(benign_scores) == 0:
        return 0.5
    allowed = int(np.floor(budget * len(benign_scores)))
    # Sit just above the (allowed+1)-th highest benign score.
    idx = min(allowed, len(benign_scores) - 1)
    return float(np.nextafter(benign_scores[idx], 1.0))


def binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    is_attack = y_true != "benign"
    flagged = scores >= threshold

    tp = int((flagged & is_attack).sum())
    fp = int((flagged & ~is_attack).sum())
    fn = int((~flagged & is_attack).sum())
    tn = int((~flagged & ~is_attack).sum())

    return {
        "threshold": round(threshold, 6),
        "recall": round(tp / max(tp + fn, 1), 4),
        "precision": round(tp / max(tp + fp, 1), 4),
        "fpr": round(fp / max(fp + tn, 1), 5),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def evaluate(
    name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    proba: np.ndarray,
    thresholds: dict[float, float] | None = None,
) -> dict:
    """Score a split.

    `thresholds` supplies operating points chosen elsewhere -- pass the ones fitted
    on validation when scoring the test set. Without it the thresholds are fitted
    on the split being scored, which is fine for model selection on validation but
    would be a leak on test: the cut would be chosen using the answers.
    """
    scores = attack_score(proba)
    is_attack = (y_true != "benign").astype(int)

    report = classification_report(
        y_true, y_pred, labels=CLASSES, output_dict=True, zero_division=0
    )

    result = {
        "model": name,
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "per_class": {
            c: {
                "precision": round(report[c]["precision"], 4),
                "recall": round(report[c]["recall"], 4),
                "f1": round(report[c]["f1-score"], 4),
                "support": int(report[c]["support"]),
            }
            for c in CLASSES
        },
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=CLASSES).tolist(),
        "binary_pr_auc": round(float(average_precision_score(is_attack, scores)), 4),
        "binary_roc_auc": round(float(roc_auc_score(is_attack, scores)), 4),
        "at_fpr": {},
        "calibration": calibration(y_true, scores),
    }

    for budget in FPR_BUDGETS:
        thr = (thresholds or {}).get(budget)
        if thr is None:
            thr = threshold_at_fpr(y_true, scores, budget)
        result["at_fpr"][f"{budget:.3f}"] = binary_metrics(y_true, scores, thr)

    return result


def unseen_attack_recall(proba: np.ndarray, threshold: float) -> dict:
    """Share of never-trained-on attack types the model still flags as non-benign."""
    scores = attack_score(proba)
    caught = int((scores >= threshold).sum())
    return {
        "n": len(scores),
        "caught": caught,
        "recall": round(caught / max(len(scores), 1), 4),
        "threshold": round(threshold, 6),
    }
