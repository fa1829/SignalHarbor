"""Risk-based vulnerability prioritization (explainable, offline).

Input is a scanner export you already have (CSV or JSON). Nothing is scanned here.
Priority combines severity (CVSS), likelihood (EPSS, CISA KEV), exposure and asset
criticality, then assigns a remediation SLA. Every decision carries a plain-language reason.

Optional enrichment (KEV/EPSS) is a separate, explicit step: scripts/enrich_vulns.py.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import date, datetime, timedelta, timezone

from .checks import MAX_INPUT_BYTES, finding

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
CRITICALITY = {"low": 0.6, "medium": 0.8, "high": 1.0, "crown_jewel": 1.2}
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
SEVERITY_FOR = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
MAX_ROWS = 5000


def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "y")


def _float(v, lo, hi, field, row_no):
    if v in (None, ""):
        return None
    try:
        x = float(v)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Row {row_no}: {field} must be a number") from e
    if not lo <= x <= hi:
        raise ValueError(f"Row {row_no}: {field} must be between {lo} and {hi}")
    return x


def _date(v):
    if not v:
        return None
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def parse(content: bytes, filename: str) -> list[dict]:
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("Vulnerability export exceeds 2 MB")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise ValueError("Export must be UTF-8") from e
    if filename.lower().endswith(".json") or text.lstrip().startswith(("[", "{")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON export") from e
        rows = data.get("vulnerabilities", []) if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise ValueError("JSON must be a list or {\"vulnerabilities\": [...]} ")
    else:
        rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise ValueError("No vulnerability rows found")
    if len(rows) > MAX_ROWS:
        raise ValueError(f"Limit uploads to {MAX_ROWS} rows")
    out = []
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict):
            raise ValueError(f"Row {i} must be an object")
        r = {str(k).strip().lower(): v for k, v in r.items() if k is not None}
        cve = str(r.get("cve", "")).strip().upper()
        if not CVE_RE.match(cve):
            raise ValueError(f"Row {i}: invalid or missing CVE id")
        cvss = _float(r.get("cvss"), 0, 10, "cvss", i)
        if cvss is None:
            raise ValueError(f"Row {i}: cvss is required")
        crit = str(r.get("asset_criticality", "medium")).strip().lower() or "medium"
        if crit not in CRITICALITY:
            raise ValueError(f"Row {i}: asset_criticality must be one of {', '.join(CRITICALITY)}")
        out.append({
            "cve": cve, "asset": str(r.get("asset", "unknown"))[:80] or "unknown",
            "cvss": cvss, "epss": _float(r.get("epss"), 0, 1, "epss", i),
            "kev": _bool(r.get("kev", False)), "internet_exposed": _bool(r.get("internet_exposed", False)),
            "asset_criticality": crit, "first_seen": _date(r.get("first_seen")),
            "fix_available": _bool(r.get("fix_available", True)),
            "title": str(r.get("title", ""))[:120],
        })
    return out


def prioritize(row: dict) -> dict:
    """Return priority, numeric risk, SLA and the reasons that decided it."""
    cvss, epss, kev = row["cvss"], row["epss"], row["kev"]
    exposed, crit = row["internet_exposed"], row["asset_criticality"]
    likely = kev or (epss is not None and epss >= 0.1)
    reasons = []
    if kev:
        reasons.append("listed in CISA KEV (exploited in the wild)")
    if epss is not None:
        reasons.append(f"EPSS {epss:.2f}")
    reasons.append(f"CVSS {cvss:.1f}")
    if exposed:
        reasons.append("internet-exposed")
    if crit in ("high", "crown_jewel"):
        reasons.append(f"{crit.replace('_', ' ')} asset")

    if kev and (exposed or crit in ("high", "crown_jewel")):
        p = "P1"
    elif epss is not None and epss >= 0.5 and cvss >= 7 and exposed:
        p = "P1"
    elif kev or (likely and cvss >= 7) or (cvss >= 9 and (exposed or crit == "crown_jewel")):
        p = "P2"
    elif cvss >= 7:
        p = "P3"
    else:
        p = "P4"
    likelihood = max(epss or 0.0, 0.97 if kev else 0.0)
    risk = round(100 * (cvss / 10) * (0.4 + 0.6 * likelihood) * (1.25 if exposed else 1.0) * CRITICALITY[crit], 1)
    sla = SLA_DAYS[p]
    due = (row["first_seen"] + timedelta(days=sla)) if row["first_seen"] else None
    today = datetime.now(timezone.utc).date()
    return {**row, "priority": p, "risk": min(risk, 150.0), "sla_days": sla,
            "due": due.isoformat() if due else None,
            "overdue": bool(due and due < today),
            "first_seen": row["first_seen"].isoformat() if row["first_seen"] else None,
            "reason": "; ".join(reasons)}


def check_vulns(content: bytes, filename: str) -> tuple[list[dict], dict]:
    ranked = sorted((prioritize(r) for r in parse(content, filename)), key=lambda x: (x["priority"], -x["risk"]))
    items = []
    for v in ranked:
        if v["priority"] in ("P1", "P2") and len(items) < 40:
            title = ("Known-exploited vulnerability on exposed asset" if v["kev"] and v["internet_exposed"]
                     else f"{v['priority']} vulnerability requires remediation")
            items.append(finding(SEVERITY_FOR[v["priority"]], title, "Vulnerability Management",
                                 f"{v['cve']} on {v['asset']}: {v['reason']}. SLA {v['sla_days']} days"
                                 + (" — OVERDUE." if v["overdue"] else "."),
                                 "Patch or apply vendor mitigation; if no fix exists, add compensating controls and document risk acceptance."
                                 if v["fix_available"] else "No fix available: isolate, add compensating controls and monitor; record a time-boxed exception.",
                                 f"{v['cve']} · risk {v['risk']}"))
    for p in ("P3", "P4"):
        group = [v for v in ranked if v["priority"] == p]
        if group:
            items.append(finding(SEVERITY_FOR[p], f"{len(group)} {p} {'vulnerability' if len(group) == 1 else 'vulnerabilities'} queued", "Vulnerability Management",
                                 f"Lower-likelihood items batched for routine patch cycles ({SLA_DAYS[p]}-day SLA).",
                                 "Handle through the standard patch window; re-prioritize when KEV/EPSS changes.",
                                 ", ".join(v["cve"] for v in group[:5])))
    counts = {p: sum(1 for v in ranked if v["priority"] == p) for p in SLA_DAYS}
    return items, {"rows": len(ranked), "priority_counts": counts,
                   "overdue": sum(v["overdue"] for v in ranked),
                   "enriched": any(v["epss"] is not None for v in ranked),
                   "ranked": ranked[:200],
                   "method": "Tiered rules (KEV, EPSS, CVSS, exposure, criticality); see docs/ARCHITECTURE.md"}
