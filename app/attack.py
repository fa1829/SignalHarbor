"""MITRE ATT&CK context for SignalHarbor findings.

These are *related* techniques: a finding either shows an exposure that the technique
abuses, or an observation consistent with it. A mapping is analyst context, not proof
that the technique occurred.
"""
from __future__ import annotations

import re

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# title -> (technique id, technique name, tactic)
BY_TITLE: dict[str, tuple[str, str, str]] = {
    # Event Triage
    "Repeated authentication failures": ("T1110", "Brute Force", "credential-access"),
    "Successful login after repeated failures": ("T1110", "Brute Force", "credential-access"),
    "Possible password spraying": ("T1110.003", "Password Spraying", "credential-access"),
    "Privilege change event observed": ("T1098", "Account Manipulation", "persistence"),
    "Security control disabled": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "Login from a source not seen in baseline": ("T1078", "Valid Accounts", "initial-access"),
    "Unusual activity volume for identity": ("T1078", "Valid Accounts", "defense-evasion"),
    # Config Inspector
    "Privileged container enabled": ("T1611", "Escape to Host", "privilege-escalation"),
    "Privilege escalation explicitly allowed": ("T1611", "Escape to Host", "privilege-escalation"),
    "Host namespace sharing": ("T1611", "Escape to Host", "privilege-escalation"),
    "Docker socket mounted": ("T1610", "Deploy Container", "execution"),
    "Container runs as root": ("T1611", "Escape to Host", "privilege-escalation"),
    "Container image not pinned": ("T1525", "Implant Internal Image", "persistence"),
    "Host network enabled": ("T1611", "Escape to Host", "privilege-escalation"),
    # Domain Trust
    "DMARC record not detected": ("T1566", "Phishing", "initial-access"),
    "SPF record not detected": ("T1566", "Phishing", "initial-access"),
    # Device Health
    "Endpoint protection not running": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "Security patch age over 60 days": ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation"),
    # Vulnerability prioritization
    "Known-exploited vulnerability on exposed asset": ("T1190", "Exploit Public-Facing Application", "initial-access"),
}

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


def tag(item: dict) -> dict:
    """Attach an ATT&CK reference if the finding does not already carry one."""
    if item.get("attack"):
        return item
    ref = BY_TITLE.get(item.get("title", ""))
    item["attack"] = f"{ref[0]} {ref[1]}" if ref else ""
    return item


def normalize_tactic(value: str) -> str:
    v = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    return v if v in TACTIC_ORDER else "unmapped"
