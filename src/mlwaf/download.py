"""Fetch the raw HTTP attack corpora.

Two public datasets contain full HTTP requests (headers + body), which is what a
WAF actually sees:

- ECML/PKDD 2007: labelled with the attack *type* (XSS, SqlInjection, ...). This
  is the training corpus, because we need per-class ground truth.
- CSIC 2010: labelled Valid/Attack only. Held back as an independent corpus so we
  can measure how the model travels to traffic it was not trained on.

Both are mirrored in the same formatted layout by msudol/Web-Application-Attack-Datasets.
"""

from __future__ import annotations

import tarfile
from pathlib import Path

import requests

RAW_DIR = Path("data/raw")
BASE = "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master"

ARCHIVES = {
    "ecml_pkdd": f"{BASE}/OriginalDataSets/ecml_pkdd/dataset_ecml_pkdd_train_test.tar.gz",
    "csic_2010": f"{BASE}/OriginalDataSets/csic_2010/dataset_cisc_train_test.tar.gz",
}


def _download(url: str, dest: Path) -> Path:
    if dest.exists():
        print(f"  cached  {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  fetch   {dest.name}")
    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with dest.open("wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
    print(f"  saved   {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
    return dest


def _extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        print(f"  already extracted -> {dest}")
        return
    with tarfile.open(archive) as tf:
        # filter="data" refuses absolute paths and symlinks escaping the target dir
        tf.extractall(dest, filter="data")
    print(f"  extracted -> {dest}")


def main() -> None:
    for name, url in ARCHIVES.items():
        print(f"[{name}]")
        archive = _download(url, RAW_DIR / f"{name}.tar.gz")
        _extract(archive, RAW_DIR / name)

    print("\nfiles:")
    for p in sorted(RAW_DIR.rglob("*")):
        if p.is_file() and p.suffix != ".gz":
            print(f"  {p}  ({p.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
