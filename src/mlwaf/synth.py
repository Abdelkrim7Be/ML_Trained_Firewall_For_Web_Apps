"""Build a corpus where benign traffic actually looks like benign traffic.

ECML/PKDD was sanitised before release: its benign URLs are randomised strings
while its attack payloads were left intact. A model trained on it therefore never
sees a real English word outside an attack, and duly learns that real words are
evidence of one. Measured against a real web server trace, that model refuses
1.6% of ordinary requests, including `/shuttle/missions/sts-78/news/`.

The fix is not a different algorithm. It is a corpus in which both classes share
the same paths, so the only thing separating a benign request from an attack is
the payload:

    benign   GET /shuttle/missions/sts-78/news/?qt=hubble
    attack   GET /shuttle/missions/sts-78/news/?qt=1' UNION SELECT password--

`shuttle` now appears on both sides in equal measure and carries no signal.

Two holdouts keep it honest. Paths are partitioned, so no path in the test split
appears in training; payloads are partitioned the same way. An attack row is only
ever assembled from a path and a payload belonging to the same split, which means
the test set measures generalisation to unseen URLs *and* unseen payloads rather
than memorisation of either.
"""

from __future__ import annotations

import gzip
import hashlib
import random
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import pandas as pd
import requests

from mlwaf.decode import request_parts

RAW = Path("data/raw/traffic")
PROCESSED = Path("data/processed")

# Real HTTP logs from public web servers. Freely redistributable, which is why
# they remain the standard reference traces.
TRACES = {
    "nasa_jul95.gz": "https://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz",
    "nasa_aug95.gz": "https://ita.ee.lbl.gov/traces/NASA_access_log_Aug95.gz",
    "clarknet_aug28.gz": "https://ita.ee.lbl.gov/traces/clarknet_access_log_Aug28.gz",
    "calgary.gz": "https://ita.ee.lbl.gov/traces/calgary_access_log.gz",
}

PAYLOAD_BASE = "https://raw.githubusercontent.com/foospidy/payloads/master"
PAYLOAD_FILES = {
    "sqli": [
        "other/sqli/libinjection-bypasses.txt",
        "other/sqli/sqlifuzzer.txt",
        "owasp/fuzzing_code_database/sqli/sqli.txt",
        "other/sqli/camoufl4g3.txt",
        "other/sqli/d0znpp.txt",
        "other/sqli/jstnkndy.txt",
    ],
    "xss": [
        "other/xss/ismailtasdelen.txt",
        "other/xss/rafaybaloch.txt",
        "other/xss/xssdb.txt",
        "owasp/jbrofuzz/xss.txt",
        "other/xss/smeegesec.com.txt",
        "other/xss/bhandarkar.txt",
    ],
}

LOG_LINE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[\d.]+"')

SPLITS = ("train", "val", "test")
SPLIT_WEIGHTS = (0.60, 0.20, 0.20)

# Parameter names that turn up in ordinary applications. The traces are mostly
# static file requests, so their own parameter vocabulary is thin; these keep the
# generated benign traffic from looking like one repeated shape.
PARAM_NAMES = [
    "q", "query", "search", "id", "page", "sort", "order", "limit", "offset",
    "category", "tag", "lang", "ref", "utm_source", "format", "view", "filter",
    "from", "to", "date", "user", "name", "email", "city", "country", "status",
]
BENIGN_VALUES = [
    "hubble", "apollo 13", "shuttle launch", "2", "42", "name", "asc", "desc",
    "10", "science", "en", "homepage", "json", "grid", "active", "2026-01-01",
    "O'Brien", "don't stop", "Marie-Claire", "café", "a book about SQL",
    "user@example.com", "Cork", "Ireland", "shipped", "pending", "true",
    "Smith & Sons", "50% off", "C++ guide", "x=1", "hello world",
]


@dataclass
class Corpus:
    paths: dict[str, list[str]]
    payloads: dict[str, dict[str, list[str]]]
    query_params: list[str]


def _download(url: str, dest: Path) -> Path | None:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with requests.get(url, stream=True, timeout=300) as r:
            r.raise_for_status()
            with dest.open("wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    fh.write(chunk)
    except requests.HTTPError:
        print(f"  unavailable: {url}")
        return None
    return dest


def _split_of(value: str, salt: str) -> str:
    """Deterministic split assignment, so a rerun produces the same partition."""
    digest = hashlib.sha1(f"{salt}:{value}".encode()).digest()
    point = int.from_bytes(digest[:4], "big") / 0xFFFFFFFF
    cumulative = 0.0
    for name, weight in zip(SPLITS, SPLIT_WEIGHTS):
        cumulative += weight
        if point < cumulative:
            return name
    return SPLITS[-1]


def load_traces() -> tuple[dict[str, list[str]], list[str]]:
    """Real paths partitioned by split, plus real query parameter pairs."""
    print("[traces]")
    paths: dict[str, set[str]] = {s: set() for s in SPLITS}
    params: Counter = Counter()

    for name, url in TRACES.items():
        dest = _download(url, RAW / name)
        if dest is None:
            continue
        seen = 0
        with gzip.open(dest, "rt", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                m = LOG_LINE.search(line)
                if not m:
                    continue
                route, _, query = m.group("target").partition("?")
                # Some traces log the target relative to the document root
                # ("GET index.html" rather than "GET /index.html"). Rejecting
                # those on the leading slash silently discarded an entire trace.
                if route and not route.startswith("/"):
                    route = "/" + route
                # Long junk routes are logging artefacts, not real pages.
                if not route.startswith("/") or len(route) > 160:
                    continue
                paths[_split_of(route, "path")].add(route)
                seen += 1
                for pair in query.split("&"):
                    if "=" in pair and len(pair) < 80:
                        params[pair] += 1
        print(f"  {name:<20} {seen:>9,} requests")

    ordered = {s: sorted(paths[s]) for s in SPLITS}
    for s in SPLITS:
        print(f"  paths[{s}] {len(ordered[s]):,}")
    return ordered, [p for p, _ in params.most_common(4000)]


def load_payloads() -> dict[str, dict[str, list[str]]]:
    """Attack payloads partitioned by split, so test payloads are unseen."""
    print("[payloads]")
    out: dict[str, dict[str, list[str]]] = {}
    for kind, files in PAYLOAD_FILES.items():
        buckets: dict[str, set[str]] = {s: set() for s in SPLITS}
        for rel in files:
            dest = _download(f"{PAYLOAD_BASE}/{rel}", RAW / "payloads" / Path(rel).name)
            if dest is None:
                continue
            text = dest.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and 2 < len(line) < 600:
                    buckets[_split_of(line, "payload")].add(line)
        out[kind] = {s: sorted(buckets[s]) for s in SPLITS}
        total = sum(len(v) for v in out[kind].values())
        print(f"  {kind:<5} {total:>6,}  " +
              "  ".join(f"{s}={len(out[kind][s]):,}" for s in SPLITS))
    return out


def _benign_query(rng: random.Random, real_params: list[str]) -> str:
    if rng.random() < 0.35:
        return ""
    pairs = []
    for _ in range(rng.randint(1, 4)):
        if real_params and rng.random() < 0.4:
            pairs.append(rng.choice(real_params))
        else:
            key = rng.choice(PARAM_NAMES)
            pairs.append(f"{key}={quote(rng.choice(BENIGN_VALUES), safe='')}")
    return "&".join(pairs)


def _attack_query(rng: random.Random, payload: str, real_params: list[str]) -> str:
    """One parameter carries the payload; the rest are ordinary.

    Real injections arrive alongside normal parameters, and surrounding a payload
    with plausible neighbours is also what stops the model from keying on the
    request being short and strange.
    """
    target = rng.choice(PARAM_NAMES)
    pairs = [f"{target}={quote(payload, safe='')}"]
    for _ in range(rng.randint(0, 3)):
        if real_params and rng.random() < 0.4:
            pairs.append(rng.choice(real_params))
        else:
            key = rng.choice(PARAM_NAMES)
            pairs.append(f"{key}={quote(rng.choice(BENIGN_VALUES), safe='')}")
    rng.shuffle(pairs)
    return "&".join(pairs)


def _row(method: str, path: str, query: str, body: str, label: str, split: str) -> dict:
    url_text, body_text, depth = request_parts(method, path, query, body)
    return {
        "source": "synth",
        "split": split,
        "raw_label": label,
        "label": label,
        "method": method,
        "path": path,
        "query": query,
        "body": body,
        "text_url": url_text,
        "text_body": body_text,
        "text": "\n".join(t for t in (url_text, body_text) if t),
        "decode_depth": depth,
    }


def build(per_split_benign: int = 24_000, attack_ratio: float = 0.5,
          seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    paths, real_params = load_traces()
    payloads = load_payloads()

    print("[generating]")
    rows: list[dict] = []

    for split, weight in zip(SPLITS, SPLIT_WEIGHTS):
        n_benign = int(per_split_benign * weight / SPLIT_WEIGHTS[0])
        pool = paths[split]
        if not pool:
            continue

        for _ in range(n_benign):
            path = rng.choice(pool)
            if rng.random() < 0.18:
                body = _benign_query(rng, real_params) or "field=value"
                rows.append(_row("POST", path, "", body, "benign", split))
            else:
                rows.append(_row("GET", path, _benign_query(rng, real_params), "",
                                 "benign", split))

        for kind in ("sqli", "xss"):
            available = payloads[kind][split]
            if not available:
                continue
            n_attack = int(n_benign * attack_ratio / 2)
            for _ in range(n_attack):
                path = rng.choice(pool)
                payload = rng.choice(available)
                if rng.random() < 0.3:
                    body = _attack_query(rng, payload, real_params)
                    rows.append(_row("POST", path, "", body, kind, split))
                else:
                    rows.append(_row("GET", path,
                                     _attack_query(rng, payload, real_params), "",
                                     kind, split))

    df = pd.DataFrame(rows)
    # Deduplicate on the normalised text, as the ECML pipeline does, so identical
    # generated rows cannot straddle a split.
    digest = df["text"].map(lambda t: hashlib.sha1(t.encode()).hexdigest())
    before = len(df)
    df = df.loc[~digest.duplicated()].reset_index(drop=True)
    print(f"  dedupe: {before:,} -> {len(df):,}")
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    df = build()
    df.to_parquet(PROCESSED / "synth.parquet")

    print("\n[summary]")
    print(df.groupby(["split", "label"]).size().unstack(fill_value=0))
    print(f"\nwrote data/processed/synth.parquet ({len(df):,} rows)")

    print("\nsample rows:")
    for label in ("benign", "sqli", "xss"):
        row = df[df["label"] == label].iloc[0]
        print(f"  [{label}] {row['method']} {row['path'][:50]}?{row['query'][:70]}")




# ---------------------------------------------------------------------------
# Unit level corpus
#
# The request level corpus above still lets context leak: the model sees the path
# and the neighbouring parameters, and learns what a particular site looks like.
# This builds the corpus the decomposition in `mlwaf.units` implies, where one row
# is one value and there is no context to learn.
# ---------------------------------------------------------------------------

def _trace_values(limit: int = 200_000) -> tuple[list[str], list[str]]:
    """Real parameter values and real paths, from every trace."""
    values: set[str] = set()
    paths: set[str] = set()

    for name, url in TRACES.items():
        dest = _download(url, RAW / name)
        if dest is None:
            continue
        with gzip.open(dest, "rt", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                m = LOG_LINE.search(line)
                if not m:
                    continue
                route, _, query = m.group("target").partition("?")
                if route and not route.startswith("/"):
                    route = "/" + route
                if route.startswith("/") and len(route) <= 160:
                    paths.add(route)
                if query and len(query) < 400:
                    for pair in query.split("&"):
                        _, _, value = pair.partition("=")
                        if value:
                            values.add(value[:400])
                        elif pair:
                            values.add(pair[:400])
                if len(values) > limit:
                    break
    return sorted(values), sorted(paths)


def build_units(seed: int = 42) -> pd.DataFrame:
    """One row per value. Benign values come from real traffic, from generated
    application data, and from deliberately confusing but harmless input."""
    from mlwaf.hardneg import generate as hard_negatives
    from mlwaf.units import Unit

    rng = random.Random(seed)
    print("[unit corpus]")
    values, paths = _trace_values()
    print(f"  real parameter values {len(values):,}")
    print(f"  real paths            {len(paths):,}")

    payloads = load_payloads()
    hard = hard_negatives(20_000)
    print(f"  hard negatives        {len(hard):,}")

    rows: list[dict] = []

    def add(value: str, label: str, kind: str, split: str, origin: str) -> None:
        unit = Unit(kind, "", value)
        text = unit.text()
        if not text:
            return
        rows.append({
            "source": origin, "split": split, "raw_label": label, "label": label,
            "method": "", "path": "", "query": value, "body": "",
            "text": text, "text_url": text, "text_body": "",
            "decode_depth": unit.depth(),
        })

    # Benign: real values, real paths, generated application data, hard negatives.
    for value in values:
        add(value, "benign", "query", _split_of(value, "value"), "trace_value")
    for path in paths:
        add(path, "benign", "path", _split_of(path, "path"), "trace_path")
    for value in hard:
        add(value, "benign", "query", _split_of(value, "hardneg"), "hard_negative")
    for _ in range(20_000):
        value = rng.choice(BENIGN_VALUES)
        add(value, "benign", "query", _split_of(value + str(rng.random()), "gen"), "generated")

    # Attacks: the payload alone, with no request built around it.
    for kind, buckets in payloads.items():
        for split, items in buckets.items():
            for payload in items:
                add(payload, kind, "query", split, "payload")
                # A payload that arrives encoded is the same attack, and the
                # normaliser is meant to make it look identical. Including both
                # forms keeps that assumption honest at training time.
                if rng.random() < 0.5:
                    add(quote(payload, safe=""), kind, "query", split, "payload_encoded")

    df = pd.DataFrame(rows)
    digest = df["text"].map(lambda t: hashlib.sha1(t.encode()).hexdigest())
    before = len(df)
    df = df.loc[~digest.duplicated()].reset_index(drop=True)
    print(f"  dedupe: {before:,} -> {len(df):,}")
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main_units() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    df = build_units()
    df.to_parquet(PROCESSED / "units.parquet")
    print("\n[summary]")
    print(df.groupby(["split", "label"]).size().unstack(fill_value=0))
    print("\nby origin:")
    print(df.groupby("source").size())
    print(f"\nwrote data/processed/units.parquet ({len(df):,} rows)")


if __name__ == "__main__":
    import sys

    if "--units" in sys.argv:
        main_units()
    else:
        main()
