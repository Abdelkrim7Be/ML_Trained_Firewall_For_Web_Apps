"""How much of a difference between two models is real?

Every number elsewhere in this project comes from one 60/20/20 split. Across
re-runs the macro-F1 of an unchanged model moved by roughly 0.005, which means any
comparison decided by less than that was decided by the split, not by the model.

This module refits each candidate on several seeds and reports mean and standard
deviation, so a claimed improvement has to clear the noise floor before it is
believed. It is slower than `mlwaf.train` and is meant to be run when choosing
between designs, not on every change.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from mlwaf.evaluate import evaluate, threshold_at_fpr, unseen_attack_recall
from mlwaf.features import build_matrix
from mlwaf.model import (
    RuleBaseline,
    attack_score,
    lightgbm_model,
    lightgbm_split_model,
    logistic_model,
)
from mlwaf.train import SHIP_FPR_BUDGET, _split

REPORTS = Path("reports")
SEEDS = [42, 43, 44, 45, 46]

CANDIDATES = {
    "rule_baseline": RuleBaseline,
    "logreg": logistic_model,
    "lightgbm": lightgbm_model,
    "lightgbm_split_regions": lightgbm_split_model,
}

TRACKED = ["macro_f1", "binary_pr_auc", "sqli_recall", "xss_recall",
           "recall_at_budget", "unseen_recall"]


def _metrics(name, model, X_val, y_val, X_unseen) -> dict[str, float]:
    res = evaluate(name, y_val, model.predict(X_val), model.predict_proba(X_val))
    scores = attack_score(model.predict_proba(X_val))
    threshold = threshold_at_fpr(y_val, scores, float(SHIP_FPR_BUDGET))
    unseen = unseen_attack_recall(model.predict_proba(X_unseen), threshold)
    return {
        "macro_f1": res["macro_f1"],
        "binary_pr_auc": res["binary_pr_auc"],
        "sqli_recall": res["per_class"]["sqli"]["recall"],
        "xss_recall": res["per_class"]["xss"]["recall"],
        "recall_at_budget": res["at_fpr"][SHIP_FPR_BUDGET]["recall"],
        "unseen_recall": unseen["recall"],
    }


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    labelled = pd.read_parquet("data/processed/ecml_labelled.parquet")
    unseen = pd.read_parquet("data/processed/ecml_unseen.parquet")
    X_unseen = build_matrix(unseen)

    runs: dict[str, list[dict]] = {name: [] for name in CANDIDATES}

    for seed in SEEDS:
        train, val, _ = _split(labelled, seed=seed)
        X_train, y_train = build_matrix(train), train["label"].to_numpy()
        X_val, y_val = build_matrix(val), val["label"].to_numpy()

        for name, factory in CANDIDATES.items():
            t0 = time.perf_counter()
            model = factory()
            model.fit(X_train, y_train)
            runs[name].append(_metrics(name, model, X_val, y_val, X_unseen))
            print(f"  seed={seed} {name:<24} {time.perf_counter() - t0:5.1f}s")

    summary = {}
    for name, results in runs.items():
        summary[name] = {
            metric: {
                "mean": round(float(np.mean([r[metric] for r in results])), 4),
                "std": round(float(np.std([r[metric] for r in results])), 4),
            }
            for metric in TRACKED
        }

    print(f"\n{len(SEEDS)} seeds, mean +/- std\n")
    header = f"{'model':<24}" + "".join(f"{m:>22}" for m in TRACKED)
    print(header)
    for name, stats in summary.items():
        row = f"  {name:<22}"
        for metric in TRACKED:
            row += f"{stats[metric]['mean']:>15.4f} +/-{stats[metric]['std']:.3f}"
        print(row)

    # The decision this module exists to settle.
    a, b = summary["lightgbm"], summary["lightgbm_split_regions"]
    print("\nlightgbm vs lightgbm_split_regions:")
    for metric in TRACKED:
        delta = b[metric]["mean"] - a[metric]["mean"]
        noise = max(a[metric]["std"], b[metric]["std"])
        verdict = "real" if abs(delta) > 2 * noise else "within noise"
        print(f"  {metric:<20} delta={delta:+.4f}  noise={noise:.4f}  -> {verdict}")

    (REPORTS / "stability.json").write_text(
        json.dumps({"seeds": SEEDS, "summary": summary, "runs": runs}, indent=2)
    )
    print("\nwrote reports/stability.json")


if __name__ == "__main__":
    main()
