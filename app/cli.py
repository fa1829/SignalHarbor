"""Command-line gate for CI/CD (shift-left).

Examples:
  python -m app.cli config deploy/k8s/signalharbor.yaml --fail-on high
  python -m app.cli vulns examples/scanner-export.csv --sarif vulns.sarif
  python -m app.cli coverage examples/purple-team-results.json --json

Exit codes: 0 = no finding at/above threshold, 1 = threshold breached, 2 = input error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import attack, checks, coverage, sarif, vulns

SEV = ["info", "low", "medium", "high", "critical"]
RUNNERS = {
    "config": lambda b, n: checks.check_config(b, n),
    "events": lambda b, n: checks.check_events(b),
    "device": lambda b, n: checks.check_device(b),
    "vulns": lambda b, n: vulns.check_vulns(b, n),
    "coverage": lambda b, n: coverage.check_coverage(b),
}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="signalharbor", description="Run SignalHarbor checks offline.")
    p.add_argument("module", choices=sorted(RUNNERS))
    p.add_argument("file", type=Path)
    p.add_argument("--fail-on", choices=SEV + ["never"], default="high")
    p.add_argument("--sarif", type=Path, help="write SARIF 2.1.0 to this path")
    p.add_argument("--json", action="store_true", help="print findings as JSON")
    a = p.parse_args(argv)
    try:
        findings, details = RUNNERS[a.module](a.file.read_bytes(), a.file.name)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    findings = [attack.tag(f) for f in findings]
    if a.sarif:
        a.sarif.write_text(json.dumps(sarif.to_sarif(findings, str(a.file)), indent=2))
    if a.json:
        print(json.dumps({"findings": findings, "details": {k: v for k, v in details.items() if k != "ranked"}}, indent=2, default=str))
    else:
        for f in sorted(findings, key=lambda f: -SEV.index(f["severity"])):
            tag = f"  [{f['attack']}]" if f.get("attack") else ""
            print(f"{f['severity'].upper():9} {f['title']}{tag}\n          {f['description']}")
        print(f"\n{len(findings)} finding(s) in {a.file}")
    if a.fail_on == "never":
        return 0
    worst = max((SEV.index(f["severity"]) for f in findings), default=-1)
    if worst >= SEV.index(a.fail_on):
        print(f"gate: FAILED (finding at or above '{a.fail_on}')", file=sys.stderr)
        return 1
    print(f"gate: passed (nothing at or above '{a.fail_on}')", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
