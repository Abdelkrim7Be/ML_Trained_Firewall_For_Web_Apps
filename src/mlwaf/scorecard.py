"""Every model against every dataset, in one table.

Individual numbers have been misleading throughout this project. A model that
looked good on its own corpus blocked 1.6% of real traffic; a model that fixed
that still flagged a fifth of an unseen site; a feature change that fixed a
demonstrable defect made everything worse. The only way to see what is actually
happening is to score the same models on the same varied data and put the results
side by side.

Datasets are grouped by what they can tell you:

- **held out corpora** the model never trained on, which is where generalisation
  either exists or does not
- **community payloads**, assembled by other people with no interest in these
  numbers
- **probes**, written by hand to cover cases the corpora miss: multilingual form
  input, boolean search, API traffic, and the classic attacks everyone knows
- **evasions**, the same attacks obfuscated, which measures the normaliser
"""

from __future__ import annotations

import gzip
import json
import math
import random
import re
from pathlib import Path

import joblib
import pandas as pd

from mlwaf.evasion import TRANSFORMS
from mlwaf.waf.config import Settings
from mlwaf.waf.engine import Engine, RequestView

REPORTS = Path("reports")
LOG_LINE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[\d.]+"')

MODELS = {
    "ecml": "models/model.joblib",
    "traces_request": "models/model_synth.joblib",
    "traces_units": "models/model_units.joblib",
}

# --- hand written probes ----------------------------------------------------
BENIGN_PROBES = [
    # ordinary browsing
    ("GET", "/", "", ""),
    ("GET", "/index.html", "", ""),
    ("GET", "/assets/app.4f2c.css", "", ""),
    ("GET", "/users/42/profile", "", ""),
    ("GET", "/shuttle/missions/sts-78/news/", "", ""),
    ("GET", "/api/v1/orders", "status=shipped&from=2026-01-01", ""),
    ("GET", "/blog/2024/01/a-post-about-sql-injection", "", ""),
    ("GET", "/docs/select-statement-tutorial", "", ""),
    # search, including boolean operators
    ("GET", "/search", "q=running+shoes", ""),
    ("GET", "/search", "q=fuel+AND+vacuum+OR+space", ""),
    ("GET", "/search", "q=challenger+or+51L", ""),
    ("GET", "/search", "q=how+to+prevent+sql+injection", ""),
    ("GET", "/search", "q=%3Cscript%3E+tag+explained", ""),
    # names, addresses, free text
    ("POST", "/account", "", "name=O'Brien&city=Cork"),
    ("POST", "/account", "", "name=Masdevall+Villaz%E1n&ciudad=Madrid"),
    ("POST", "/account", "", "nombre=libel&login=lilian&password=lipis"),
    ("POST", "/account", "", "name=%E5%B1%B1%E7%94%B0&city=%E6%9D%B1%E4%BA%AC"),
    ("POST", "/comment", "", "text=don't+stop+believing+--+chorus"),
    ("POST", "/comment", "", "text=5+%3C+10+and+10+%3E+5"),
    ("POST", "/order", "", "ntc=4111111111111111&exp=12%2F2028&total=1299.00"),
    ("POST", "/order", "", "modo=insertar&precio=8456&B1=Pasar+por+caja"),
    # api shaped
    ("POST", "/api/search", "", '{"q":"laptop","filters":{"price":{"lt":1000}}}'),
    ("PUT", "/api/v1/items/9", "", '{"title":"C++ Primer","tags":["c++","book"]}'),
    ("GET", "/api/report", "select=name,email&order=asc&limit=50", ""),
]

ATTACK_PROBES = [
    ("GET", "/item", "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--", ""),
    ("GET", "/item", "id=1%27+OR+1%3D1--", ""),
    ("GET", "/item", "id=1%27+OR+%271%27%3D%271", ""),
    ("GET", "/item", "id=1%27%3B+DROP+TABLE+users--", ""),
    ("GET", "/item", "id=1%27+AND+SLEEP%285%29--", ""),
    ("GET", "/item", "id=1+UNION+ALL+SELECT+NULL%2Cversion%28%29--", ""),
    ("GET", "/item", "id=admin%27%23", ""),
    ("POST", "/login", "", "user=admin%27+OR+1%3D1--&pw=x"),
    ("POST", "/api/search", "", '{"q":"1\' OR 1=1--"}'),
    ("GET", "/search", "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", ""),
    ("GET", "/search", "q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E", ""),
    ("GET", "/search", "q=%3Csvg%2Fonload%3Dalert%281%29%3E", ""),
    ("GET", "/search", "q=%3Ciframe+src%3Djavascript%3Aalert%281%29%3E", ""),
    ("GET", "/search", "q=%3Cbody+onload%3Dalert%28document.cookie%29%3E", ""),
    ("POST", "/comment", "", "text=%3Cscript%3Efetch%28%27%2F%2Fevil%27%29%3C%2Fscript%3E"),
]


def _nasa(limit: int) -> list[tuple[str, str, str, str]]:
    path = Path("data/raw/benchmark/nasa_jul95.gz")
    if not path.exists():
        path = Path("data/raw/traffic/nasa_jul95.gz")
    if not path.exists():
        return []
    seen, rows = set(), []
    with gzip.open(path, "rt", encoding="latin-1", errors="replace") as fh:
        for line in fh:
            m = LOG_LINE.search(line)
            if not m:
                continue
            target = m.group("target")
            if target in seen:
                continue
            seen.add(target)
            route, _, query = target.partition("?")
            rows.append((m.group("method"), route, query, ""))
            if len(rows) >= limit:
                break
    return rows


def _csic(label: str, limit: int) -> list[tuple[str, str, str, str]]:
    path = Path("data/processed/csic.parquet")
    if not path.exists():
        return []
    df = pd.read_parquet(path)
    df = df[df["label"] == label].head(limit)
    return [(r.method, r.path, r.query, r.body) for r in df.itertuples(index=False)]


def _payloads(kind: str, limit: int) -> list[tuple[str, str, str, str]]:
    base = Path("data/raw/benchmark") / kind
    if not base.exists():
        base = Path("data/raw/traffic/payloads")
    if not base.exists():
        return []
    from urllib.parse import quote
    seen = set()
    for f in sorted(base.glob("*.txt")):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and 2 < len(line) < 600:
                seen.add(line)
    payloads = sorted(seen)[:limit]
    return [("GET", "/item", f"id={quote(p, safe='')}", "") for p in payloads]


def _evasions(limit: int) -> list[tuple[str, str, str, str]]:
    """One attack, obfuscated every way the suite knows."""
    from urllib.parse import quote
    base = "1' UNION SELECT username,password FROM users--"
    rows = []
    for name, fn in TRANSFORMS.items():
        if name == "none":
            continue
        rows.append(("GET", "/item", f"id={quote(fn(base), safe='%')}", ""))
    return rows[:limit]


def datasets(sample: int) -> dict[str, tuple[str, list]]:
    """name -> (expected verdict, requests)."""
    rng = random.Random(11)
    nasa = _nasa(sample)
    csic_b = _csic("benign", sample)
    rng.shuffle(csic_b)
    return {
        "NASA real traffic":      ("allow", nasa),
        "CSIC benign":            ("allow", csic_b),
        "benign probes":          ("allow", BENIGN_PROBES),
        "CSIC attacks":           ("block", _csic("attack", sample)),
        "payloads sqli":          ("block", _payloads("sqli", 800)),
        "payloads xss":           ("block", _payloads("xss", 800)),
        "attack probes":          ("block", ATTACK_PROBES),
        "evasions":               ("block", _evasions(20)),
    }


def score(engine: Engine, requests: list) -> float:
    if not requests:
        return float("nan")
    blocked = sum(
        1 for m, p, q, b in requests
        if engine.decide(RequestView(m, p, q, b)).would_block
    )
    return blocked / len(requests)


def main(sample: int = 2500) -> None:
    REPORTS.mkdir(exist_ok=True)
    data = datasets(sample)

    engines = {}
    for name, path in MODELS.items():
        if not Path(path).exists():
            print(f"  missing {path}, skipping {name}")
            continue
        e = Engine(Settings(mode="block", scoring_budget_ms=600_000.0, model_path=path),
                   bundle=dict(joblib.load(path)))
        e.load()
        engines[name] = e

    results: dict[str, dict[str, float]] = {}
    for model_name, engine in engines.items():
        results[model_name] = {}
        for ds_name, (_expect, requests) in data.items():
            results[model_name][ds_name] = score(engine, requests)
            print(f"  {model_name:<16} {ds_name:<20} done")

    width = max(len(n) for n in data) + 2
    header = f"{'dataset':<{width}}" + "".join(f"{m:>18}" for m in engines)
    print("\n" + header)
    print("-" * len(header))
    for ds_name, (expect, requests) in data.items():
        want = "block %" if expect == "block" else "FP %"
        row = f"{ds_name:<{width}}"
        for model_name in engines:
            v = results[model_name][ds_name]
            row += f"{'n/a':>17}" if math.isnan(v) else f"{v * 100:>15.2f} %"
        print(row + f"   <- {want}, n={len(requests)}")

    (REPORTS / "scorecard.json").write_text(json.dumps(
        {"sample": sample,
         "expectations": {k: v[0] for k, v in data.items()},
         "sizes": {k: len(v[1]) for k, v in data.items()},
         "results": results}, indent=2))
    print("\nwrote reports/scorecard.json")


if __name__ == "__main__":
    main()
