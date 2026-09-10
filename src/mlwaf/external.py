"""An independent benchmark: payloads written by someone else.

Everything else here is measured on ECML/PKDD, which the model was trained on. A
corpus can flatter a model in ways that are invisible from inside it, so this
scores the shipped model against a third-party set of deliberately obfuscated
payloads collected from real WAF bypass attempts -- comment-split SQL, hex- and
URL-encoded XSS, base64 `data:` URIs, path traversal, command injection.

It contains attacks only, so the number it produces is recall. False-positive rate
still has to come from the corpora that carry benign traffic.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import pandas as pd
import requests

from mlwaf.decode import request_parts
from mlwaf.model import attack_score

RAW_DIR = Path("data/raw")
REPORTS = Path("reports")
URL = (
    "https://huggingface.co/datasets/darkknight25/WAF_DETECTION_DATASET"
    "/resolve/main/WAF_DETECTION_DATASET.jsonl"
)

# The model classifies SQLi and XSS. Everything else is scored separately, because
# flagging it at all is generalisation to a class that was never trained.
SQLI_MARKERS = ("union", "select", "sleep(", "' or", "'or", "--", "concat(", "0x7c")
XSS_MARKERS = ("script", "onerror", "alert(", "javascript:", "svg", "img src", "%3c")


def _download() -> Path:
    dest = RAW_DIR / "waf_detection.jsonl"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(URL, timeout=60)
    r.raise_for_status()
    dest.write_bytes(r.content)
    return dest


def _load(path: Path) -> list[dict]:
    """Tolerant reader: a handful of lines carry two concatenated JSON objects."""
    decoder = json.JSONDecoder()
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        idx = 0
        try:
            while idx < len(line):
                obj, end = decoder.raw_decode(line, idx)
                rows.append(obj)
                idx = end
                while idx < len(line) and line[idx] in " \t":
                    idx += 1
        except json.JSONDecodeError:
            continue  # malformed line, skip rather than fail the run
    return rows


def _family(payload: str) -> str:
    low = payload.lower()
    if any(m in low for m in XSS_MARKERS):
        return "xss"
    if any(m in low for m in SQLI_MARKERS):
        return "sqli"
    return "other"


def main(model_path: str = "models/model.joblib") -> None:
    REPORTS.mkdir(exist_ok=True)
    bundle = joblib.load(model_path)
    pipeline, threshold = bundle["pipeline"], bundle["threshold"]

    rows = _load(_download())
    payloads = [r["payload"] for r in rows if r.get("payload")]
    techniques = [r.get("technique", "unknown") for r in rows if r.get("payload")]
    families = [_family(p) for p in payloads]
    print(f"payloads: {len(payloads)}   families: {dict(Counter(families))}")

    # Each payload is presented as a query-string value on a neutral path.
    from mlwaf.features import build_matrix

    frames = []
    for p in payloads:
        url_text, body_text, depth = request_parts("GET", "/search", f"q={p}", "")
        frames.append({
            "text": "\n".join(t for t in (url_text, body_text) if t),
            "text_url": url_text, "text_body": body_text,
            "query": f"q={p}", "path": "/search", "decode_depth": depth,
        })
    scores = attack_score(pipeline.predict_proba(build_matrix(pd.DataFrame(frames))))
    caught = scores >= threshold

    by_family: dict[str, list[bool]] = defaultdict(list)
    by_technique: dict[str, list[bool]] = defaultdict(list)
    for fam, tech, hit in zip(families, techniques, caught):
        by_family[fam].append(bool(hit))
        by_technique[tech].append(bool(hit))

    def summarise(groups: dict[str, list[bool]]) -> dict:
        return {
            k: {"n": len(v), "caught": sum(v), "recall": round(sum(v) / len(v), 4)}
            for k, v in sorted(groups.items(), key=lambda kv: -len(kv[1]))
        }

    report = {
        "source": URL,
        "threshold": round(threshold, 6),
        "overall": {
            "n": len(payloads),
            "caught": int(caught.sum()),
            "recall": round(float(caught.mean()), 4),
        },
        "by_family": summarise(by_family),
        "by_technique": summarise(by_technique),
    }

    print(f"\noverall recall: {report['overall']['recall']:.3f} "
          f"({report['overall']['caught']}/{report['overall']['n']})\n")
    print("by attack family (sqli/xss were trained; 'other' never was):")
    for k, v in report["by_family"].items():
        print(f"  {k:<8} {v['recall']:.3f}  ({v['caught']}/{v['n']})")
    print("\nby bypass technique:")
    for k, v in report["by_technique"].items():
        print(f"  {k:<28} {v['recall']:.3f}  ({v['caught']}/{v['n']})")

    (REPORTS / "external.json").write_text(json.dumps(report, indent=2))
    print("\nwrote reports/external.json")


if __name__ == "__main__":
    main()
