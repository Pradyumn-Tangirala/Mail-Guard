"""
scripts/download_data.py
=========================
Downloads the training / evaluation datasets into data/raw/ and verifies them
against the MD5 checksums published by Zenodo.

Source:  "Phishing Email Curated Datasets" — A. I. Champa et al.
         Zenodo, DOI 10.5281/zenodo.8339691, licensed CC BY 4.0
         https://zenodo.org/records/8339691

Files:
  Nazario_5.csv   Nazario phishing corpus + legitimate mail from 5 corpora
                  (train / test split for the NLP model)
  Nigerian_5.csv  Nigerian advance-fee fraud + legitimate mail
                  (held-out cross-dataset generalisation test)

The data is not committed to git (data/raw/ is ignored); run this script
before train_model.py.

Usage:
  python scripts/download_data.py
"""

import hashlib
import pathlib
import sys
import urllib.request

RAW_DIR = pathlib.Path(__file__).resolve().parent.parent / "data" / "raw"

_RECORD = "https://zenodo.org/api/records/8339691/files"
DATASETS = {
    "Nazario_5.csv":  "45db8330ea4aabbf72f5199949ae03e5",
    "Nigerian_5.csv": "edfbbb89c40e7447f47867bcc82e72f9",
}


def _md5(path: pathlib.Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(name: str, expected_md5: str) -> None:
    dest = RAW_DIR / name
    if dest.exists() and _md5(dest) == expected_md5:
        print(f"[ok]   {name} already present")
        return

    url = f"{_RECORD}/{name}/content"
    print(f"[get]  {name}  <-  {url}")
    tmp = dest.with_suffix(".part")
    urllib.request.urlretrieve(url, tmp)

    actual = _md5(tmp)
    if actual != expected_md5:
        tmp.unlink()
        sys.exit(f"[fail] {name}: MD5 mismatch (expected {expected_md5}, got {actual})")
    tmp.replace(dest)
    print(f"[ok]   {name}  ({dest.stat().st_size / 1e6:.1f} MB, MD5 verified)")


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for name, md5 in DATASETS.items():
        download(name, md5)


if __name__ == "__main__":
    main()
