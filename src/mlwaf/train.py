"""Train, compare, and persist the detector."""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from mlwaf.evaluate import evaluate, threshold_at_fpr, unseen_attack_recall
from mlwaf.features import build_matrix
from mlwaf.model import MODELS, attack_score

PROCESSED = Path("data/processed")
REPORTS = Path("reports")
MODELS_DIR = Path("models")
SEED = 42
SHIP_MODEL = "lightgbm"
SHIP_FPR_BUDGET = "0.001"


def _split(df: pd.DataFrame):
    """60/20/20 stratified. The test split is scored once, at the very end."""
    train, rest = train_test_split(
        df, test_size=0.4, stratify=df["label"], random_state=SEED
    )
    val, test = train_test_split(
        rest, test_size=0.5, stratify=rest["label"], random_state=SEED
    )
    return train, val, test


def _source_leakage_check(ecml: pd.DataFrame, csic: pd.DataFrame) -> dict:
    """Can a model tell which corpus a request came from?

    If yes, cross-corpus scores must be read with care: the two datasets differ in
    ways that have nothing to do with attacks, so a drop on CSIC is partly domain
    shift rather than genuine failure. Reporting this beats quietly hoping.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import make_pipeline

    n = min(4000, len(ecml), len(csic))
    text = pd.concat(
        [ecml["text"].sample(n, random_state=SEED), csic["text"].sample(n, random_state=SEED)]
    )
    y = np.array(["ecml"] * n + ["csic"] * n)
    pipe = make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=50_000),
        LogisticRegression(max_iter=1000),
    )
    acc = float(cross_val_score(pipe, text, y, cv=3, scoring="accuracy").mean())
    return {"source_discrimination_accuracy": round(acc, 4)}


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    MODELS_DIR.mkdir(exist_ok=True)

    labelled = pd.read_parquet(PROCESSED / "ecml_labelled.parquet")
    unseen = pd.read_parquet(PROCESSED / "ecml_unseen.parquet")
    csic = pd.read_parquet(PROCESSED / "csic.parquet")

    train, val, test = _split(labelled)
    print(f"split  train={len(train)}  val={len(val)}  test={len(test)}")
    print(f"train dist {train['label'].value_counts().to_dict()}\n")

    X_train, y_train = build_matrix(train), train["label"].to_numpy()
    X_val, y_val = build_matrix(val), val["label"].to_numpy()
    X_test, y_test = build_matrix(test), test["label"].to_numpy()
    X_unseen = build_matrix(unseen)
    X_csic, y_csic = build_matrix(csic), csic["label"].to_numpy()

    results, fitted = {}, {}

    for name, factory in MODELS.items():
        print(f"[{name}] fitting...")
        model = factory()
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        fit_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        proba_val = model.predict_proba(X_val)
        predict_ms = (time.perf_counter() - t0) / len(X_val) * 1000

        res = evaluate(name, y_val, model.predict(X_val), proba_val)
        res["fit_seconds"] = round(fit_s, 2)
        res["predict_ms_per_request"] = round(predict_ms, 4)
        results[name] = res
        fitted[name] = model

        pc = res["per_class"]
        at = res["at_fpr"][SHIP_FPR_BUDGET]
        print(
            f"  macro_f1={res['macro_f1']}  pr_auc={res['binary_pr_auc']}  "
            f"sqli_recall={pc['sqli']['recall']}  xss_recall={pc['xss']['recall']}  "
            f"recall@0.1%fpr={at['recall']}  {predict_ms:.3f} ms/req\n"
        )

    # --- final scoring of the shipping model, on data touched once -------------
    model = fitted[SHIP_MODEL]
    proba_test = model.predict_proba(X_test)
    final = evaluate(SHIP_MODEL, y_test, model.predict(X_test), proba_test)

    # Operating threshold is chosen on validation, never on test.
    threshold = threshold_at_fpr(y_val, attack_score(fitted[SHIP_MODEL].predict_proba(X_val)),
                                 float(SHIP_FPR_BUDGET))

    final["generalisation"] = {
        "unseen_attack_types": unseen_attack_recall(model.predict_proba(X_unseen), threshold),
        "csic_cross_corpus": _cross_corpus(model, X_csic, y_csic, threshold),
    }
    final["leakage_check"] = _source_leakage_check(labelled, csic)
    final["operating_threshold"] = round(threshold, 6)

    results["FINAL_TEST"] = final

    (REPORTS / "metrics.json").write_text(json.dumps(results, indent=2))
    joblib.dump({"pipeline": model, "threshold": threshold}, MODELS_DIR / "model.joblib")

    print("=" * 68)
    print(f"FINAL ({SHIP_MODEL}, held-out test, threshold={threshold:.4f})")
    for c, m in final["per_class"].items():
        print(f"  {c:<7} precision={m['precision']:.4f} recall={m['recall']:.4f} n={m['support']}")
    at = final["at_fpr"][SHIP_FPR_BUDGET]
    print(f"  binary: recall={at['recall']}  fpr={at['fpr']}  pr_auc={final['binary_pr_auc']}")
    g = final["generalisation"]
    print(f"  unseen attack types: {g['unseen_attack_types']['recall']} "
          f"({g['unseen_attack_types']['caught']}/{g['unseen_attack_types']['n']})")
    print(f"  csic cross-corpus:   recall={g['csic_cross_corpus']['recall']} "
          f"fpr={g['csic_cross_corpus']['fpr']}")
    print(f"  source leakage acc:  {final['leakage_check']['source_discrimination_accuracy']}")
    print("=" * 68)
    print("wrote reports/metrics.json and models/model.joblib")


def _cross_corpus(model, X, y, threshold: float) -> dict:
    from mlwaf.evaluate import binary_metrics

    scores = attack_score(model.predict_proba(X))
    y_binary = np.where(y == "benign", "benign", "attack")
    return binary_metrics(y_binary, scores, threshold)


if __name__ == "__main__":
    main()
