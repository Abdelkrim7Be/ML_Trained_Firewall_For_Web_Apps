"""Command line entry point: mlwaf <download|dataset|train|plots|predict>."""

from __future__ import annotations

import argparse
import sys


def _predict(args: argparse.Namespace) -> None:
    import joblib
    import pandas as pd

    from mlwaf.decode import request_parts
    from mlwaf.features import build_matrix
    from mlwaf.model import CLASSES, attack_score

    bundle = joblib.load(args.model)
    pipeline, threshold = bundle["pipeline"], bundle["threshold"]

    path, _, query = args.url.partition("?")

    if bundle.get("unit_mode"):
        # This model was fit on individual parameter values, not whole requests.
        # Scoring a full request through it the other way, as this CLI did before
        # the model was unit-decomposed, would run real inputs through a pipeline
        # fit on a different shape of text and report a number that means nothing.
        # Mirror mlwaf.waf.engine.Engine._score_units: score every value on its
        # own and report whichever one drove the verdict.
        from mlwaf.units import decompose

        rows, labels = [], []
        for unit in decompose(args.method, path, query, args.body):
            text = unit.text()
            if not text:
                continue
            rows.append({
                "text": text, "text_url": text, "text_body": "",
                "query": unit.value, "path": "", "decode_depth": unit.depth(),
            })
            labels.append(f"{unit.kind}:{unit.name}" if unit.name else unit.kind)

        if not rows:
            print("ALLOW  attack_score=0.0000  threshold="
                  f"{threshold:.4f}  (nothing to score)")
            return

        proba = pipeline.predict_proba(build_matrix(pd.DataFrame(rows)))
        scores = attack_score(proba)
        worst = int(scores.argmax())
        score, worst_proba, worst_label = float(scores[worst]), proba[worst], labels[worst]
        verdict = "BLOCK" if score >= threshold else "ALLOW"

        print(f"{verdict}  attack_score={score:.4f}  threshold={threshold:.4f}"
              f"   worst_unit={worst_label}")
        for name, p in zip(CLASSES, worst_proba):
            print(f"  {name:<7} {p:.4f}")
        return

    url_text, body_text, depth = request_parts(args.method, path, query, args.body)
    frame = pd.DataFrame([{
        "text": "\n".join(t for t in (url_text, body_text) if t),
        "text_url": url_text,
        "text_body": body_text,
        "query": query,
        "path": path,
        "decode_depth": depth,
    }])

    proba = pipeline.predict_proba(build_matrix(frame))[0]
    score = float(attack_score(proba.reshape(1, -1))[0])
    verdict = "BLOCK" if score >= threshold else "ALLOW"

    print(f"{verdict}  attack_score={score:.4f}  threshold={threshold:.4f}")
    for name, p in zip(CLASSES, proba):
        print(f"  {name:<7} {p:.4f}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mlwaf", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("download", help="fetch the raw corpora")
    sub.add_parser("dataset", help="parse and build processed frames")
    sub.add_parser("train", help="train and evaluate the models")
    sub.add_parser("plots", help="render report figures")

    p = sub.add_parser("predict", help="score a single request")
    p.add_argument("url", help="path with optional query string, e.g. '/item?id=1'")
    p.add_argument("--method", default="GET")
    p.add_argument("--body", default="")
    p.add_argument("--model", default="models/model.joblib")

    args = parser.parse_args(argv)

    if args.command == "download":
        from mlwaf.download import main as run
    elif args.command == "dataset":
        from mlwaf.dataset import build as run
    elif args.command == "train":
        from mlwaf.train import main as run
    elif args.command == "plots":
        from mlwaf.plots import main as run
    else:
        _predict(args)
        return 0

    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
