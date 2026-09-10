"""Render the README results tables from reports/metrics.json.

Generated rather than hand-typed, so the numbers in the README cannot drift away
from the numbers the run actually produced.
"""

from __future__ import annotations

import json
from pathlib import Path

REPORTS = Path("reports")
MODEL_ORDER = ["rule_baseline", "logreg", "lightgbm"]
FAMILY = {
    "case_flip": "encoding", "url_encode": "encoding",
    "double_url_encode": "encoding", "html_entity_encode": "encoding",
    "js_unicode_escape": "encoding", "fullwidth": "encoding",
    "space_to_comment": "sql syntax", "mysql_version_comment": "sql syntax",
    "space_to_tab": "whitespace", "space_to_newline": "whitespace",
    "char_function": "literal", "hex_literal": "literal",
    "concat_quotes": "literal",
}
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


def robustness_table() -> str:
    """Bypass rate per transform, before and after the normaliser was hardened."""
    current = json.loads((REPORTS / "robustness.json").read_text())
    baseline_path = REPORTS / "robustness_baseline.json"
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}

    header = ["Transform", "Family", "Bypass before", "Bypass after", "Change"]
    lines = [_row(header), _row(["---"] * len(header))]

    for name, m in current.items():
        if name == "none":
            continue
        after = m["bypass_rate"]
        before = baseline.get(name, {}).get("bypass_rate")
        if before is None:
            before_s, change = ", ", "new"
        else:
            before_s = f"{before:.1%}"
            delta = before - after
            change = ", " if abs(delta) < 0.005 else f"{'-' if delta > 0 else '+'}{abs(delta):.1%}"
        lines.append(_row([
            f"`{name}`", FAMILY.get(name, ""), before_s, f"{after:.1%}", change,
        ]))
    return "\n".join(lines)


def adversarial_table() -> str:
    """Held-out obfuscations are the ones that matter: they were never trained on."""
    data = json.loads((REPORTS / "adversarial.json").read_text())
    before, after = data["robustness_before"], data["robustness_after"]

    header = ["Transform", "Seen in training", "Recall before", "Recall after", "Change"]
    lines = [_row(header), _row(["---"] * len(header))]
    for name, m in after.items():
        if name == "none":
            continue
        b, a = before[name]["recall"], m["recall"]
        lines.append(_row([
            f"`{name}`",
            "yes" if m["seen_in_training"] else "**no**",
            f"{b:.3f}", f"{a:.3f}", f"{a - b:+.3f}",
        ]))
    return "\n".join(lines)


def error_summary() -> str:
    e = json.loads((REPORTS / "errors.json").read_text())
    tp, fn = e["true_positives"], e["false_negatives"]
    header = ["", "Caught", "Missed"]
    keys = [("median_length", "Median length"),
            ("median_decode_depth", "Median decode depth"),
            ("has_body", "Share with a body"),
            ("median_sql_keywords", "Median SQL keywords"),
            ("median_xss_keywords", "Median XSS keywords")]
    lines = [_row(header), _row(["---"] * len(header))]
    for key, label in keys:
        lines.append(_row([label, str(tp.get(key)), str(fn.get(key))]))
    rates = ", ".join(f"{k} {v:.1%}" for k, v in e["miss_rate_by_class"].items())
    return "\n".join(lines) + f"\n\nMiss rate by class: {rates}."


def stability_table() -> str:
    """Mean +/- std across seeds. A difference smaller than the spread is not a result."""
    data = json.loads((REPORTS / "stability.json").read_text())
    summary, seeds = data["summary"], data["seeds"]

    metrics = ["macro_f1", "binary_pr_auc", "sqli_recall", "xss_recall",
               "recall_at_budget", "unseen_recall"]
    header = ["Model", *[m.replace("_", " ") for m in metrics]]
    lines = [_row(header), _row(["---"] * len(header))]
    for name, stats in summary.items():
        cells = [f"`{name}`"]
        cells += [f"{stats[m]['mean']:.3f} ± {stats[m]['std']:.3f}" for m in metrics]
        lines.append(_row(cells))
    return f"Across {len(seeds)} seeds.\n\n" + "\n".join(lines)


def external_summary() -> str:
    e = json.loads((REPORTS / "external.json").read_text())
    o = e["overall"]
    header = ["Attack family", "Recall", "Caught"]
    lines = [_row(header), _row(["---"] * len(header))]
    for fam, m in e["by_family"].items():
        label = f"`{fam}`" + ("" if fam in ("sqli", "xss") else " *(never trained)*")
        lines.append(_row([label, f"{m['recall']:.3f}", f"{m['caught']}/{m['n']}"]))
    return (
        f"Overall recall **{o['recall']:.3f}** ({o['caught']}/{o['n']}) on "
        f"third-party obfuscated payloads.\n\n" + "\n".join(lines)
    )


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
    if (REPORTS / "robustness.json").exists():
        out += ["\n## Robustness to obfuscation\n", robustness_table()]
    if (REPORTS / "adversarial.json").exists():
        out += ["\n## Adversarial training\n", adversarial_table()]
    if (REPORTS / "errors.json").exists():
        out += ["\n## What it misses\n", error_summary()]
    if (REPORTS / "stability.json").exists():
        out += ["\n## Stability across seeds\n", stability_table()]
    if (REPORTS / "external.json").exists():
        out += ["\n## Independent benchmark\n", external_summary()]
    text = "\n".join(out)
    (REPORTS / "tables.md").write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
