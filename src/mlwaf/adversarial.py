"""Adversarial training: teach the model the obfuscations it failed against.

Normalisation is the first line of defence -- it rewrites a payload back to a
canonical form. But no normaliser is complete, and the robustness run shows
exactly where ours leaks. The second line is to put obfuscated payloads into the
training set itself.

The transforms are split in two. The model is trained on one half and evaluated on
the other, so the result answers "does this generalise to obfuscations it has never
seen" rather than "has it memorised the ones we showed it". Training on all of them
and reporting robustness against all of them would be a leak, and would look far
better than it deserved.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd

from mlwaf.evaluate import evaluate, threshold_at_fpr
from mlwaf.evasion import TRANSFORMS
from mlwaf.features import build_matrix
from mlwaf.model import attack_score, lightgbm_model
from mlwaf.robustness import mutate
from mlwaf.train import SHIP_FPR_BUDGET, _split

REPORTS = Path("reports")
MODELS_DIR = Path("models")

# One from each obfuscation family, so the held-out half is never a near-duplicate
# of something in the training half.
TRAIN_TRANSFORMS = ["case_flip", "url_encode", "space_to_tab", "char_function"]
HELD_OUT_TRANSFORMS = [
    "double_url_encode", "html_entity_encode", "js_unicode_escape", "fullwidth",
    "mysql_version_comment", "space_to_comment", "space_to_newline",
    "hex_literal", "concat_quotes",
]


def augment(train: pd.DataFrame) -> pd.DataFrame:
    """Add an obfuscated copy of every attack row, one per training transform."""
    attacks = train[train["label"] != "benign"]
    extra = []
    for name in TRAIN_TRANSFORMS:
        mutated = mutate(attacks, TRANSFORMS[name])
        mutated["label"] = attacks["label"].to_numpy()
        mutated["source"] = f"aug:{name}"
        extra.append(mutated)

    combined = pd.concat([train, *extra], ignore_index=True)
    print(f"augmented train: {len(train)} -> {len(combined)} rows")
    return combined


def _robustness(pipeline, threshold: float, attacks: pd.DataFrame) -> dict:
    out = {}
    for name in ["none", *TRAIN_TRANSFORMS, *HELD_OUT_TRANSFORMS]:
        mutated = mutate(attacks, TRANSFORMS[name])
        scores = attack_score(pipeline.predict_proba(build_matrix(mutated)))
        recall = float((scores >= threshold).mean())
        out[name] = {
            "recall": round(recall, 4),
            "bypass_rate": round(1 - recall, 4),
            "seen_in_training": name in TRAIN_TRANSFORMS,
        }
    return out


def main() -> None:
    labelled = pd.read_parquet("data/processed/ecml_labelled.parquet")
    train, val, test = _split(labelled)

    augmented = augment(train)
    X_aug, y_aug = build_matrix(augmented), augmented["label"].to_numpy()
    X_val, y_val = build_matrix(val), val["label"].to_numpy()
    X_test, y_test = build_matrix(test), test["label"].to_numpy()

    print("fitting on augmented data...")
    model = lightgbm_model()
    model.fit(X_aug, y_aug)

    threshold = threshold_at_fpr(
        y_val, attack_score(model.predict_proba(X_val)), float(SHIP_FPR_BUDGET)
    )
    clean = evaluate("lightgbm_adversarial", y_test, model.predict(X_test),
                     model.predict_proba(X_test))

    attacks = test[test["label"] != "benign"].reset_index(drop=True)
    robustness = _robustness(model, threshold, attacks)

    baseline = joblib.load(MODELS_DIR / "model.joblib")
    base_robustness = _robustness(baseline["pipeline"], baseline["threshold"], attacks)

    print(f"\nclean test: macro_f1={clean['macro_f1']}  "
          f"recall@fpr={clean['at_fpr'][SHIP_FPR_BUDGET]['recall']}  "
          f"fpr={clean['at_fpr'][SHIP_FPR_BUDGET]['fpr']}\n")
    print(f"{'transform':<24}{'seen':<7}{'before':<9}{'after':<9}change")
    for name, m in robustness.items():
        before, after = base_robustness[name]["recall"], m["recall"]
        seen = "yes" if m["seen_in_training"] else "no"
        print(f"  {name:<22}{seen:<7}{before:<9.3f}{after:<9.3f}{after - before:+.3f}")

    payload = {
        "clean_test": clean,
        "threshold": round(threshold, 6),
        "train_transforms": TRAIN_TRANSFORMS,
        "held_out_transforms": HELD_OUT_TRANSFORMS,
        "robustness_before": base_robustness,
        "robustness_after": robustness,
    }
    (REPORTS / "adversarial.json").write_text(json.dumps(payload, indent=2))
    joblib.dump({"pipeline": model, "threshold": threshold},
                MODELS_DIR / "model_adversarial.joblib")
    print("\nwrote reports/adversarial.json and models/model_adversarial.joblib")


if __name__ == "__main__":
    main()
