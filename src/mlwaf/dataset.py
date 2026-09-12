"""Build model-ready frames from the parsed corpora.

Design decisions worth stating, because they are what make the numbers honest:

1. ECML/PKDD is the training corpus. It is the only public set that labels the
   attack *type*, so benign / sqli / xss are all ground truth rather than derived
   from a rule.
2. Both classes come from the same corpus. If benign came from one dataset and
   attacks from another, the model would learn to recognise the dataset -- host
   names, header order, formatting -- and score near-perfectly while knowing
   nothing about attacks.
3. The five other ECML attack types (Ldap, XPath, PathTransversal, OsCommanding,
   SSI) are never trained on. They are kept aside to measure whether the model
   generalises to attack classes it has never seen.
4. CSIC 2010 is a second, independent corpus used only at evaluation time.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pandas as pd

from mlwaf.decode import request_parts
from mlwaf.parse import parse_file

RAW_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")

BENIGN, SQLI, XSS = "benign", "sqli", "xss"
CLASSES = [BENIGN, SQLI, XSS]

ECML_LABELS = {"Valid": BENIGN, "SqlInjection": SQLI, "XSS": XSS}
UNSEEN_ATTACKS = {"LdapInjection", "XPathInjection", "PathTransversal", "OsCommanding", "SSI"}


def _records(path: Path, source: str) -> list[dict]:
    rows = []
    for req in parse_file(path):
        url_text, body_text, depth = request_parts(
            req.method, req.path, req.query, req.body
        )
        rows.append(
            {
                "source": source,
                "request_id": req.request_id,
                "raw_label": req.label,
                "method": req.method,
                "path": req.path,
                "query": req.query,
                "body": req.body,
                "text_url": url_text,
                "text_body": body_text,
                "text": "\n".join(t for t in (url_text, body_text) if t),
                "decode_depth": depth,
            }
        )
    return rows


def _dedupe(df: pd.DataFrame) -> pd.DataFrame:
    """Drop exact duplicates of the normalised text.

    Near-identical rows that straddle a train/test split leak the answer and
    inflate every metric, so they go before splitting, not after.
    """
    digest = df["text"].map(lambda t: hashlib.sha1(t.encode()).hexdigest())
    before = len(df)
    df = df.loc[~digest.duplicated()].reset_index(drop=True)
    print(f"  dedupe: {before} -> {len(df)} ({before - len(df)} duplicates dropped)")
    return df


def load_ecml() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (labelled 3-class frame, held-out unseen-attack-type frame)."""
    rows = _records(RAW_DIR / "ecml_pkdd" / "xml_test.txt", "ecml")
    df = _dedupe(pd.DataFrame(rows))

    labelled = df[df["raw_label"].isin(ECML_LABELS)].copy()
    labelled["label"] = labelled["raw_label"].map(ECML_LABELS)

    unseen = df[df["raw_label"].isin(UNSEEN_ATTACKS)].copy()
    unseen["label"] = "unseen_attack"

    return labelled.reset_index(drop=True), unseen.reset_index(drop=True)


def load_csic() -> pd.DataFrame:
    """Independent corpus, binary labels only (benign vs attack)."""
    rows = _records(RAW_DIR / "csic_2010" / "cisc_normalTraffic_test.txt", "csic")
    rows += _records(RAW_DIR / "csic_2010" / "cisc_anomalousTraffic_test.txt", "csic")
    df = _dedupe(pd.DataFrame(rows))
    df["label"] = df["raw_label"].map({"Valid": BENIGN, "Attack": "attack"})
    return df.dropna(subset=["label"]).reset_index(drop=True)


def build() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print("[ecml_pkdd]")
    labelled, unseen = load_ecml()
    labelled.to_parquet(PROCESSED_DIR / "ecml_labelled.parquet")
    unseen.to_parquet(PROCESSED_DIR / "ecml_unseen.parquet")
    print(f"  labelled  {len(labelled):>6}  {labelled['label'].value_counts().to_dict()}")
    print(f"  unseen    {len(unseen):>6}  {unseen['raw_label'].value_counts().to_dict()}")

    print("[csic_2010]")
    csic = load_csic()
    csic.to_parquet(PROCESSED_DIR / "csic.parquet")
    print(f"  rows      {len(csic):>6}  {csic['label'].value_counts().to_dict()}")


if __name__ == "__main__":
    build()
