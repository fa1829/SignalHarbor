"""Add CISA KEV and FIRST EPSS values to a scanner export, as an explicit offline-first step.

    .venv/bin/python scripts/enrich_vulns.py examples/scanner-export.csv -o data/enriched.csv

Why a separate script: the web app never makes outbound calls for this, so its network
behaviour stays predictable; you choose when to refresh threat intelligence.

Sources (public, no API key):
  CISA KEV catalog : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  FIRST EPSS API   : https://api.first.org/data/v1/epss?cve=CVE-...,CVE-...
Existing kev/epss values in the file are kept unless --overwrite is given.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
UA = {"User-Agent": "SignalHarbor-enrich/1.1"}


def fetch_json(url: str, timeout=30) -> dict:
    req = urllib.request.Request(url, headers=UA)
    # B310 reviewed: only the fixed https:// feed URLs above are fetched
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
        return json.loads(r.read(50_000_000))


def kev_set() -> set[str]:
    return {v["cveID"].upper() for v in fetch_json(KEV_URL).get("vulnerabilities", [])}


def epss_scores(cves: list[str]) -> dict[str, float]:
    out = {}
    for i in range(0, len(cves), 100):  # keep URLs short
        data = fetch_json(EPSS_URL + ",".join(cves[i:i + 100]))
        out.update({d["cve"].upper(): float(d["epss"]) for d in data.get("data", [])})
    return out


def enrich(rows: list[dict], kev: set[str], epss: dict[str, float], overwrite=False) -> int:
    changed = 0
    for r in rows:
        cve = r.get("cve", "").strip().upper()
        if overwrite or not r.get("kev"):
            r["kev"] = "true" if cve in kev else "false"
            changed += 1
        if cve in epss and (overwrite or not r.get("epss")):
            r["epss"] = f"{epss[cve]:.5f}"
    return changed


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--overwrite", action="store_true")
    a = p.parse_args(argv)
    with a.input.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows, fields = list(reader), list(reader.fieldnames or [])
    for col in ("kev", "epss"):
        if col not in fields:
            fields.append(col)
    cves = sorted({r["cve"].strip().upper() for r in rows if r.get("cve")})
    try:
        kev = kev_set()
        epss = epss_scores([c for c in cves if not c.startswith("CVE-2099-")])  # skip synthetic ids
    except OSError as e:
        print(f"Could not reach threat-intel feeds ({e}). Check internet access from WSL and retry.", file=sys.stderr)
        return 1
    enrich(rows, kev, epss, a.overwrite)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"KEV entries loaded: {len(kev)} · EPSS scores found: {len(epss)} · wrote {a.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
