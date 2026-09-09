"""Measure recall decay under obfuscation.

Procedure: take the attack requests the model catches when they are clean, rewrite
each one with a transform, and count how many are still caught. Anything the model
lets through after rewriting is a payload that still works against the application
but no longer trips the detector.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd

from mlwaf.decode import decode, request_text
from mlwaf.evasion import HANDLED_BY_NORMALISER, TRANSFORMS, Transform
from mlwaf.features import build_matrix
from mlwaf.model import attack_score
from mlwaf.train import _split

REPORTS = Path("reports")


def mutate(df: pd.DataFrame, transform: Transform) -> pd.DataFrame:
    """Rewrite each request's payload, then push it back through normalisation.

    The transform is applied to the *decoded* payload and the result is treated as
    the new raw input, so encoding-based transforms genuinely exercise the decode
    chain rather than being cancelled out before it runs.
    """
    rows = []
    for r in df.itertuples(index=False):
        decoded_query, _ = decode(r.query)
        decoded_body, _ = decode(r.body)
        query = transform(decoded_query) if decoded_query else ""
        body = transform(decoded_body) if decoded_body else ""
        text, depth = request_text(r.method, r.path, query, body)
        rows.append({"text": text, "query": query, "path": r.path, "decode_depth": depth})
    return pd.DataFrame(rows)


def run(model_path: str = "models/model.joblib") -> dict:
    bundle = joblib.load(model_path)
    pipeline, threshold = bundle["pipeline"], bundle["threshold"]

    labelled = pd.read_parquet("data/processed/ecml_labelled.parquet")
    _, _, test = _split(labelled)
    attacks = test[test["label"] != "benign"].reset_index(drop=True)

    # Only payloads the model already catches can be evaded; the rest were missed
    # for reasons that have nothing to do with obfuscation.
    caught_clean = attack_score(pipeline.predict_proba(build_matrix(attacks))) >= threshold
    baseline = attacks[caught_clean].reset_index(drop=True)

    print(f"attacks in test set:      {len(attacks)}")
    print(f"caught before obfuscation: {len(baseline)} ({caught_clean.mean():.3f})\n")

    results = {}
    for name, transform in TRANSFORMS.items():
        mutated = mutate(baseline, transform)
        scores = attack_score(pipeline.predict_proba(build_matrix(mutated)))
        still_caught = int((scores >= threshold).sum())
        recall = still_caught / max(len(baseline), 1)

        results[name] = {
            "still_caught": still_caught,
            "n": len(baseline),
            "recall": round(recall, 4),
            "bypass_rate": round(1 - recall, 4),
            "mean_score": round(float(scores.mean()), 4),
            "normaliser_should_handle": name in HANDLED_BY_NORMALISER,
        }

        flag = ""
        if name in HANDLED_BY_NORMALISER and recall < 0.98:
            flag = "  <-- normalisation gap"
        elif name != "none" and recall < 0.5:
            flag = "  <-- major bypass"
        print(f"  {name:<20} recall={recall:.3f}  bypass={1 - recall:.3f}{flag}")

    return results


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    results = run()
    (REPORTS / "robustness.json").write_text(json.dumps(results, indent=2))

    worst = sorted(results.items(), key=lambda kv: kv[1]["recall"])[:3]
    print("\nweakest against:", ", ".join(f"{k} ({v['recall']:.3f})" for k, v in worst))
    print("wrote reports/robustness.json")


if __name__ == "__main__":
    main()
