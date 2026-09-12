"""What the model gets wrong, and whether the mistakes have a shape.

A single recall number says how much is missed but nothing about what. If the
misses cluster -- short payloads, one attack family, requests with no body -- that
is a lead on the next improvement rather than a reason to add trees.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd

from mlwaf.features import build_matrix, numeric_features
from mlwaf.model import attack_score
from mlwaf.train import _split

REPORTS = Path("reports")
EXAMPLES = 8


def _profile(df: pd.DataFrame, feats: pd.DataFrame) -> dict:
    if df.empty:
        return {}
    return {
        "n": len(df),
        "median_length": int(feats["length"].median()),
        "median_decode_depth": float(feats["decode_depth"].median()),
        "has_body": round(float((df["body"].str.len() > 0).mean()), 3),
        "median_sql_keywords": float(feats["sql_keywords"].median()),
        "median_xss_keywords": float(feats["xss_keywords"].median()),
    }


def main(model_path: str = "models/model.joblib") -> None:
    bundle = joblib.load(model_path)
    pipeline, threshold = bundle["pipeline"], bundle["threshold"]

    labelled = pd.read_parquet("data/processed/ecml_labelled.parquet")
    _, _, test = _split(labelled)
    test = test.reset_index(drop=True)

    scores = attack_score(pipeline.predict_proba(build_matrix(test)))
    feats = numeric_features(test)
    is_attack = test["label"] != "benign"
    flagged = scores >= threshold

    false_neg = test[is_attack & ~flagged]
    false_pos = test[~is_attack & flagged]
    true_pos = test[is_attack & flagged]

    report = {
        "threshold": round(threshold, 6),
        "false_negatives": _profile(false_neg, feats.loc[false_neg.index]),
        "true_positives": _profile(true_pos, feats.loc[true_pos.index]),
        "false_positives": _profile(false_pos, feats.loc[false_pos.index]),
        "missed_by_class": false_neg["label"].value_counts().to_dict(),
        "miss_rate_by_class": {
            c: round(float((~flagged)[is_attack & (test["label"] == c)].mean()), 4)
            for c in ["sqli", "xss"]
        },
    }

    print(f"threshold {threshold:.4f}")
    print(f"false negatives: {len(false_neg)}   false positives: {len(false_pos)}")
    print(f"missed by class: {report['missed_by_class']}")
    print(f"miss rate by class: {report['miss_rate_by_class']}\n")

    print("caught vs missed attacks:")
    tp_p, fn_p = report["true_positives"], report["false_negatives"]
    for key in ["median_length", "median_decode_depth", "has_body",
                "median_sql_keywords", "median_xss_keywords"]:
        print(f"  {key:<22} caught={tp_p.get(key)!s:<8} missed={fn_p.get(key)}")

    print(f"\nlowest-scoring missed attacks (up to {EXAMPLES}):")
    worst = false_neg.assign(score=scores[false_neg.index]).nsmallest(EXAMPLES, "score")
    samples = []
    for r in worst.itertuples(index=False):
        snippet = r.text.replace("\n", " ")[:150]
        print(f"  [{r.label}] {r.score:.4f}  {snippet}")
        samples.append({"label": r.label, "score": round(float(r.score), 4),
                        "text": snippet})
    report["examples"] = samples

    (REPORTS / "errors.json").write_text(json.dumps(report, indent=2))
    print("\nwrote reports/errors.json")


if __name__ == "__main__":
    main()
