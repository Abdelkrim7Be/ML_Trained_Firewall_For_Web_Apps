"""Render the README results tables from reports/metrics.json.

Generated rather than hand-typed, so the numbers in the README cannot drift away
from the numbers the run actually produced.
"""

from __future__ import annotations

import json
from pathlib import Path

REPORTS = Path("reports")
MODEL_ORDER = ["rule_baseline", "logreg", "lightgbm"]
LABELS = {
    "rule_baseline": "Rule baseline (v0 heuristic)",
    "logreg": "LogReg + char n-grams",
    "lightgbm": "**LightGBM + n-grams + numeric**",
}


def _row(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def comparison_table(metrics: dict) -> str:
    header = ["Model", "macro-F1", "PR-AUC", "SQLi recall", "XSS recall",
              "recall @ FPR", "achieved FPR", "ms/req"]
    lines = [_row(header), _row(["---"] * len(header))]

    for name in MODEL_ORDER:
        m = metrics[name]
        at = m["at_fpr"]["0.001"]
        lines.append(_row([
            LABELS[name],
            f"{m['macro_f1']:.3f}",
            f"{m['binary_pr_auc']:.3f}",
            f"{m['per_class']['sqli']['recall']:.3f}",
            f"{m['per_class']['xss']['recall']:.3f}",
            f"{at['recall']:.3f}",
            f"{at['fpr']:.3f}",
            f"{m['predict_ms_per_request']:.2f}",
        ]))
    return "\n".join(lines)


def final_table(metrics: dict) -> str:
    final = metrics["FINAL_TEST"]
    header = ["Class", "Precision", "Recall", "F1", "Support"]
    lines = [_row(header), _row(["---"] * len(header))]
    for cls, m in final["per_class"].items():
        lines.append(_row([
            f"`{cls}`", f"{m['precision']:.3f}", f"{m['recall']:.3f}",
            f"{m['f1']:.3f}", str(m["support"]),
        ]))
    return "\n".join(lines)


def operating_points_table(metrics: dict) -> str:
    final = metrics["FINAL_TEST"]
    header = ["FPR budget", "Threshold", "Recall", "Precision", "Achieved FPR",
              "False blocks"]
    lines = [_row(header), _row(["---"] * len(header))]
    for budget, m in final["at_fpr"].items():
        lines.append(_row([
            f"{float(budget) * 100:.1f}%", f"{m['threshold']:.4f}",
            f"{m['recall']:.3f}", f"{m['precision']:.3f}",
            f"{m['fpr'] * 100:.2f}%", f"{m['fp']} / {m['fp'] + m['tn']}",
        ]))
    return "\n".join(lines)


def main() -> None:
    metrics = json.loads((REPORTS / "metrics.json").read_text())
    final = metrics["FINAL_TEST"]
    gen = final["generalisation"]

    unseen = gen["unseen_attack_types"]
    csic = gen["csic_cross_corpus"]
    leak = final["leakage_check"]["source_discrimination_accuracy"]

    out = [
        "## Model comparison (validation set)\n",
        comparison_table(metrics),
        "\n## Final model, held-out test set\n",
        final_table(metrics),
        "\n## Operating points\n",
        operating_points_table(metrics),
        "\n## Generalisation\n",
        (
            f"- Unseen attack types (never trained on): **{unseen['recall']:.3f}** "
            f"({unseen['caught']}/{unseen['n']})"
        ),
        (
            f"- CSIC 2010, separate corpus: recall **{csic['recall']:.3f}**, "
            f"FPR {csic['fpr']:.3f}"
        ),
        f"- Corpus discrimination accuracy: **{leak:.3f}**",
    ]
    text = "\n".join(out)
    (REPORTS / "tables.md").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
