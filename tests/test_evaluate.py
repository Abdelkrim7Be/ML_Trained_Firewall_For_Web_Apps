"""Metric behaviour, especially the ones that gate the operating point."""

import numpy as np

from mlwaf.evaluate import binary_metrics, calibration, threshold_at_fpr


def _labels(n_benign, n_attack):
    return np.array(["benign"] * n_benign + ["sqli"] * n_attack)


def test_perfect_scores_are_perfectly_calibrated():
    y = _labels(80, 20)
    scores = np.concatenate([np.zeros(80), np.ones(20)])
    c = calibration(y, scores)
    assert c["brier_score"] == 0.0
    assert c["expected_calibration_error"] == 0.0


def test_miscalibrated_scores_are_penalised():
    y = _labels(80, 20)
    # Every request scored 0.5 regardless of label: ranks nothing, calibrated badly.
    c = calibration(y, np.full(100, 0.5))
    assert c["expected_calibration_error"] > 0.25


def test_threshold_respects_fpr_budget():
    y = _labels(1000, 100)
    rng = np.random.default_rng(0)
    scores = np.concatenate([rng.random(1000) * 0.5, 0.5 + rng.random(100) * 0.5])
    thr = threshold_at_fpr(y, scores, 0.01)
    assert binary_metrics(y, scores, thr)["fpr"] <= 0.011


def test_binary_metrics_counts_add_up():
    y = _labels(10, 10)
    scores = np.concatenate([np.zeros(10), np.ones(10)])
    m = binary_metrics(y, scores, 0.5)
    assert m["tp"] + m["fp"] + m["fn"] + m["tn"] == 20
    assert m["recall"] == 1.0
    assert m["fpr"] == 0.0
