"""Render the report figures from a trained model."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import precision_recall_curve

from mlwaf.features import build_matrix
from mlwaf.model import CLASSES, attack_score
from mlwaf.train import _split

REPORTS = Path("reports")


def confusion(metrics: dict) -> None:
    cm = np.array(metrics["FINAL_TEST"]["confusion_matrix"])
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False,
                xticklabels=CLASSES, yticklabels=CLASSES, ax=axes[0])
    axes[0].set(xlabel="predicted", ylabel="actual", title="Counts")

    norm = cm / cm.sum(axis=1, keepdims=True)
    sns.heatmap(norm, annot=True, fmt=".3f", cmap="Blues", vmin=0, vmax=1, cbar=False,
                xticklabels=CLASSES, yticklabels=CLASSES, ax=axes[1])
    axes[1].set(xlabel="predicted", ylabel="actual", title="Row-normalised (recall)")

    fig.suptitle("LightGBM — held-out test set", fontweight="bold")
    fig.tight_layout()
    fig.savefig(REPORTS / "confusion_matrix.png", dpi=140)
    plt.close(fig)


def pr_curve(bundle: dict) -> None:
    labelled = pd.read_parquet("data/processed/ecml_labelled.parquet")
    _, _, test = _split(labelled)
    scores = attack_score(bundle["pipeline"].predict_proba(build_matrix(test)))
    y = (test["label"].to_numpy() != "benign").astype(int)

    precision, recall, _ = precision_recall_curve(y, scores)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(recall, precision, lw=2)
    ax.axhline(y.mean(), ls="--", c="grey", lw=1, label=f"no-skill ({y.mean():.2f})")
    ax.set(xlabel="recall", ylabel="precision", title="Attack vs benign — precision/recall",
           xlim=(0, 1.01), ylim=(0, 1.02))
    ax.legend()
    fig.tight_layout()
    fig.savefig(REPORTS / "pr_curve.png", dpi=140)
    plt.close(fig)


def calibration_curve(metrics: dict) -> None:
    """Predicted confidence against observed attack rate.

    The operating point is quoted as "block above t, and 0.1% of real users pay for
    it". That only means anything if a score of 0.9 really does correspond to a 90%
    chance of being an attack, which is what this plot checks.
    """
    cal = metrics["FINAL_TEST"].get("calibration")
    if not cal or not cal.get("buckets"):
        return
    buckets = cal["buckets"]
    x = [b["mean_score"] for b in buckets]
    y = [b["observed_attack_rate"] for b in buckets]
    n = [b["n"] for b in buckets]

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot([0, 1], [0, 1], ls="--", c="grey", lw=1, label="perfect calibration")
    ax.plot(x, y, "o-", lw=2, label="model")
    for xi, yi, ni in zip(x, y, n):
        ax.annotate(str(ni), (xi, yi), textcoords="offset points", xytext=(5, -10),
                    fontsize=7, color="grey")
    ax.set(xlabel="mean predicted attack score", ylabel="observed attack rate",
           xlim=(-0.02, 1.02), ylim=(-0.02, 1.02),
           title=(f"Calibration  (ECE {cal['expected_calibration_error']:.3f}, "
                  f"Brier {cal['brier_score']:.3f})"))
    ax.legend(loc="upper left")
    fig.tight_layout()
    fig.savefig(REPORTS / "calibration.png", dpi=140)
    plt.close(fig)


def feature_importance(bundle: dict) -> None:
    pipe = bundle["pipeline"]
    names = pipe.named_steps["features"].get_feature_names_out()
    if "select" in pipe.named_steps:
        names = names[pipe.named_steps["select"].get_support()]
    imp = pipe.named_steps["clf"].feature_importances_
    top = pd.Series(imp, index=names).sort_values(ascending=False).head(25).sort_values()

    fig, ax = plt.subplots(figsize=(7, 8))
    top.plot.barh(ax=ax)
    ax.set(xlabel="gain", title="Top 25 features")
    fig.tight_layout()
    fig.savefig(REPORTS / "feature_importance.png", dpi=140)
    plt.close(fig)


def main() -> None:
    sns.set_theme(style="whitegrid")
    metrics = json.loads((REPORTS / "metrics.json").read_text())
    bundle = joblib.load("models/model.joblib")

    confusion(metrics)
    pr_curve(bundle)
    calibration_curve(metrics)
    feature_importance(bundle)
    print("wrote reports/{confusion_matrix,pr_curve,calibration,feature_importance}.png")


if __name__ == "__main__":
    main()
