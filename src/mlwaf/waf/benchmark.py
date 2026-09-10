"""Large scale measurement against traffic nobody in this project wrote.

Every other number here comes from a corpus the model was trained on, or from
payloads chosen by hand. Both flatter it. This module measures the two figures an
operator actually has to know, using data from outside the project entirely:

- **False positive rate**, against roughly a million real HTTP requests recorded
  from NASA's Kennedy Space Center web server in 1995. Real paths, real filenames,
  real English words, none of it sanitised. This is where a model that has learned
  spurious tokens gets found out, which is exactly what happened.
- **Recall**, against community maintained attack payload lists, including
  libinjection's bypass corpus, which is a collection of payloads specifically
  chosen to defeat a well known SQL injection detector.

Neither corpus was involved in training, and neither was assembled by anyone
trying to make this model look good.
"""

from __future__ import annotations

import gzip
import json
import random
import re
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import joblib
import requests

from mlwaf.waf.config import Settings
from mlwaf.waf.engine import Engine, RequestView

RAW = Path("data/raw/benchmark")
REPORTS = Path("reports")

# Two months of requests to a real, busy, public web server. Freely
# redistributable, which is why it is still the standard reference trace.
NASA_LOGS = {
    "nasa_jul95.gz": "https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz",
}

PAYLOAD_BASE = "https://raw.githubusercontent.com/foospidy/payloads/master"
PAYLOAD_FILES = {
    "sqli": [
        "other/sqli/libinjection-bypasses.txt",
        "other/sqli/sqlifuzzer.txt",
        "owasp/fuzzing_code_database/sqli/sqli.txt",
        "other/sqli/camoufl4g3.txt",
        "other/sqli/d0znpp.txt",
    ],
    "xss": [
        "other/xss/ismailtasdelen.txt",
        "other/xss/rafaybaloch.txt",
        "other/xss/xssdb.txt",
        "owasp/jbrofuzz/xss.txt",
    ],
}

# Common Log Format: host - - [date] "METHOD path HTTP/1.0" status bytes
LOG_LINE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"')


def _download(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  fetching {dest.name}")
    with requests.get(url, stream=True, timeout=300) as r:
        r.raise_for_status()
        with dest.open("wb") as fh:
            for chunk in r.iter_content(1 << 20):
                fh.write(chunk)
    return dest


def load_real_traffic(limit: int | None = None) -> list[tuple[str, str, str]]:
    """(method, path, query) from the NASA trace, deduplicated."""
    rows: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    for name, url in NASA_LOGS.items():
        path = _download(url, RAW / name)
        with gzip.open(path, "rt", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                m = LOG_LINE.search(line)
                if not m:
                    continue
                target = m.group("path")
                if target in seen:
                    continue
                seen.add(target)
                route, _, query = target.partition("?")
                rows.append((m.group("method"), route, query))
                if limit and len(rows) >= limit:
                    return rows
    return rows


def load_payloads() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for kind, files in PAYLOAD_FILES.items():
        seen: set[str] = set()
        for rel in files:
            dest = RAW / kind / Path(rel).name
            try:
                text = _download(f"{PAYLOAD_BASE}/{rel}", dest).read_text(
                    encoding="utf-8", errors="replace"
                )
            except requests.HTTPError:
                print(f"  skipped {rel}")
                continue
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and len(line) < 2000:
                    seen.add(line)
        out[kind] = sorted(seen)
    return out


def _engine(model_path: str, threshold: float | None) -> Engine:
    settings = Settings(mode="block", scoring_budget_ms=600_000.0, model_path=model_path)
    if threshold is not None:
        settings.threshold = threshold
    e = Engine(settings, bundle=dict(joblib.load(model_path)))
    e.load()
    return e


def false_positive_rate(engine: Engine, traffic, sample: int | None) -> dict:
    if sample and len(traffic) > sample:
        traffic = random.Random(42).sample(traffic, sample)

    flagged, worst = [], []
    started = time.perf_counter()
    for method, path, query in traffic:
        d = engine.decide(RequestView(method, path, query, ""))
        if d.would_block:
            flagged.append((d.score, method, path, query))
        elif d.score > 0.5:
            worst.append((d.score, path))
    elapsed = time.perf_counter() - started

    flagged.sort(reverse=True)
    # What do the refused requests have in common? On a model that has learned a
    # spurious token, this is where the token shows itself.
    tokens: Counter = Counter()
    for _, _, path, query in flagged:
        for word in re.findall(r"[a-z]{3,}", f"{path} {query}".lower()):
            tokens[word] += 1

    return {
        "requests": len(traffic),
        "flagged": len(flagged),
        "false_positive_rate": round(len(flagged) / max(len(traffic), 1), 6),
        "requests_per_second": round(len(traffic) / max(elapsed, 1e-9), 1),
        "top_tokens_in_flagged": tokens.most_common(15),
        "examples": [
            {"score": round(s, 4), "method": m, "path": p, "query": q[:120]}
            for s, m, p, q in flagged[:25]
        ],
        "near_misses": len(worst),
    }


def recall(engine: Engine, payloads: dict[str, list[str]]) -> dict:
    results = {}
    for kind, items in payloads.items():
        caught, missed = 0, []
        for payload in items:
            d = engine.decide(
                RequestView("GET", "/item", f"id={quote(payload, safe='')}", "")
            )
            if d.would_block:
                caught += 1
            elif len(missed) < 25:
                missed.append({"score": round(d.score, 4), "payload": payload[:140]})
        results[kind] = {
            "payloads": len(items),
            "caught": caught,
            "recall": round(caught / max(len(items), 1), 4),
            "missed_examples": missed,
        }
    return results


def main(sample: int | None = 60_000, model_path: str = "models/model.joblib") -> None:
    REPORTS.mkdir(exist_ok=True)
    engine = _engine(model_path, threshold=None)
    print(f"threshold {engine.threshold:.4f}\n")

    print("[real traffic: NASA KSC web server, 1995]")
    traffic = load_real_traffic()
    print(f"  {len(traffic)} distinct requests parsed")
    fp = false_positive_rate(engine, traffic, sample)
    print(f"  scored {fp['requests']} at {fp['requests_per_second']} req/s")
    print(f"  false positives: {fp['flagged']}  rate {fp['false_positive_rate']:.4%}")
    if fp["examples"]:
        print("  worst offenders:")
        for e in fp["examples"][:10]:
            print(f"    {e['score']:.4f}  {e['method']} {e['path'][:70]}")
        print(f"  common tokens in refused requests: "
              f"{', '.join(t for t, _ in fp['top_tokens_in_flagged'][:8])}")

    print("\n[attack payloads: community lists]")
    payloads = load_payloads()
    rec = recall(engine, payloads)
    for kind, r in rec.items():
        print(f"  {kind:<5} {r['recall']:.3f}  ({r['caught']}/{r['payloads']})")

    report = {"threshold": engine.threshold, "false_positives": fp, "recall": rec}
    (REPORTS / "benchmark.json").write_text(json.dumps(report, indent=2))
    print("\nwrote reports/benchmark.json")


if __name__ == "__main__":
    main()
