"""Command line entry point: mlwaf <download|dataset|train|plots|predict>."""

from __future__ import annotations

import argparse
import sys


def _predict(args: argparse.Namespace) -> None:
    import joblib
    import pandas as pd

    from mlwaf.decode import request_text
    from mlwaf.features import build_matrix
    from mlwaf.model import CLASSES, attack_score

    bundle = joblib.load(args.model)
    pipeline, threshold = bundle["pipeline"], bundle["threshold"]

    path, _, query = args.url.partition("?")
    text, depth = request_text(args.method, path, query, args.body)
    frame = pd.DataFrame([{"text": text, "query": query, "path": path, "decode_depth": depth}])

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
