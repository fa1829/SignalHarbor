"""SARIF 2.1.0 export so findings can flow into GitHub code scanning / Azure DevOps."""
from __future__ import annotations

import re

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def rule_id(title: str) -> str:
    return "SH-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60]


def to_sarif(findings: list[dict], artifact_uri: str | None = None) -> dict:
    rules, results = {}, []
    for f in findings:
        rid = rule_id(f["title"])
        rules.setdefault(rid, {
            "id": rid, "name": f["title"],
            "shortDescription": {"text": f["title"]},
            "help": {"text": f["recommendation"]},
            "properties": {"tags": [t for t in (f.get("category"), f.get("attack")) if t],
                           "security-severity": SCORE.get(f["severity"], "0.0")},
        })
        res = {"ruleId": rid, "level": LEVEL.get(f["severity"], "note"),
               "message": {"text": f"{f['description']} Evidence: {f.get('evidence', '')}".strip()}}
        uri = artifact_uri or f.get("asset_name")
        if uri:
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(uri)}}}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "SignalHarbor", "version": "1.1.0",
                                          "informationUri": "https://github.com/",
                                          "rules": list(rules.values())}},
                      "results": results}]}
