"""
Download the official MITRE ATT&CK Enterprise STIX bundle from MITRE's official GitHub repository
(mitre-attack/attack-stix-data). This is the PRIMARY source, not a third-party copy.

Source: https://github.com/mitre-attack/attack-stix-data
Domain: enterprise-attack (not mobile-attack / ics-attack)
"""

import pathlib
import sys

import requests

# Pinned to ATT&CK v19.2 (the version used in the paper; SHA-256
# dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4). The original version downloaded
# "enterprise-attack.json" (master, always the latest) -- identical content when downloaded in August 2026.
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-19.2.json"
)

OUT_PATH = pathlib.Path(__file__).parent / "data" / "enterprise-attack.json"


def main() -> None:
    print(f"Downloading {URL} ...")
    resp = requests.get(URL, timeout=60)
    resp.raise_for_status()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_bytes(resp.content)
    size_mb = OUT_PATH.stat().st_size / (1024 * 1024)
    print(f"Saved to {OUT_PATH} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)
