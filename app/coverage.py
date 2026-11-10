"""Purple-team detection coverage analysis.

Ingests the *results* of an emulation exercise (e.g. exported from a BAS platform,
Atomic Red Team runs or a manual purple-team tracker) and measures how well the blue
team prevented, detected and alerted on each ATT&CK technique. Nothing is executed.

Outcome ladder per test (best first): prevented > alerted > logged (telemetry only) > missed.
"""
from __future__ import annotations

import json
from statistics import median

from .attack import TACTIC_ORDER, TECHNIQUE_RE, normalize_tactic
from .checks import MAX_INPUT_BYTES, finding

TTD_TARGET_S = 900  # 15 minutes from execution to alert


def _outcome(r: dict) -> str:
    if r.get("prevented") is True:
        return "prevented"
    if r.get("alerted") is True:
        return "alerted"
    if r.get("detected") is True or r.get("logged") is True:
        return "logged"
    return "missed"


def check_coverage(content: bytes) -> tuple[list[dict], dict]:
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("Exercise results exceed 2 MB")
    try:
        data = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("Exercise results must be UTF-8 JSON") from e
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError('Expected {"exercise": "...", "results": [...]}')
    results = data["results"]
    if not results or len(results) > 2000:
        raise ValueError("Provide between 1 and 2000 test results")
    tests = []
    for i, r in enumerate(results, 1):
        if not isinstance(r, dict):
            raise ValueError(f"Result {i} must be an object")
        tid = str(r.get("technique_id", "")).strip().upper()
        if not TECHNIQUE_RE.match(tid):
            raise ValueError(f"Result {i}: technique_id must look like T1059 or T1059.001")
        ttd = r.get("time_to_detect_s")
        if ttd is not None and (not isinstance(ttd, (int, float)) or ttd < 0):
            raise ValueError(f"Result {i}: time_to_detect_s must be a non-negative number")
        tests.append({"technique_id": tid, "technique": str(r.get("technique", tid))[:80],
                      "tactic": normalize_tactic(r.get("tactic")), "test": str(r.get("test", ""))[:120],
                      "outcome": _outcome(r), "ttd": ttd})

    by_tactic = {}
    for t in tests:
        row = by_tactic.setdefault(t["tactic"], {"tactic": t["tactic"], "tests": 0, "prevented": 0,
                                                 "alerted": 0, "logged": 0, "missed": 0})
        row["tests"] += 1
        row[t["outcome"]] += 1
    order = {k: i for i, k in enumerate(TACTIC_ORDER + ["unmapped"])}
    matrix = sorted(by_tactic.values(), key=lambda r: order[r["tactic"]])
    for row in matrix:
        row["coverage_pct"] = round(100 * (row["prevented"] + row["alerted"]) / row["tests"])

    n = len(tests)
    counts = {k: sum(t["outcome"] == k for t in tests) for k in ("prevented", "alerted", "logged", "missed")}
    ttds = [t["ttd"] for t in tests if t["outcome"] == "alerted" and t["ttd"] is not None]
    items = []
    seen = set()
    for t in tests:
        key = (t["technique_id"], t["outcome"])
        if key in seen:
            continue
        seen.add(key)
        label = f"{t['technique_id']} {t['technique']}"
        if t["outcome"] == "missed":
            items.append(finding("high", "Technique executed without detection", "Detection Gap",
                                 f"{label} ({t['tactic']}) produced no prevention, alert or usable telemetry.",
                                 "Confirm log source coverage, then write and test a detection; re-run the same test to validate.",
                                 t["test"] or label) | {"attack": label})
        elif t["outcome"] == "logged":
            items.append(finding("medium", "Telemetry present but no alert", "Detection Engineering",
                                 f"{label} was visible in logs but no alert fired.",
                                 "Build an analytic on the existing telemetry and tune it against benign baseline activity.",
                                 t["test"] or label) | {"attack": label})
    if ttds and median(ttds) > TTD_TARGET_S:
        items.append(finding("low", "Median time-to-detect above target", "Response Readiness",
                             f"Median alert latency {round(median(ttds) / 60, 1)} min vs {TTD_TARGET_S // 60} min target.",
                             "Review pipeline ingestion delay, correlation windows and alert routing."))
    return items[:150], {
        "exercise": str(data.get("exercise", "Untitled exercise"))[:100],
        "tool": str(data.get("tool", "unspecified"))[:60],
        "tests": n, "techniques": len({t["technique_id"] for t in tests}),
        "outcomes": counts,
        "detection_rate_pct": round(100 * (counts["prevented"] + counts["alerted"]) / n),
        "visibility_pct": round(100 * (n - counts["missed"]) / n),
        "median_ttd_min": round(median(ttds) / 60, 1) if ttds else None,
        "matrix": matrix,
        "scope": "Analysis of supplied exercise results; no attack simulation is executed by SignalHarbor",
    }
