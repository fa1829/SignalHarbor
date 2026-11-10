"""SQLite persistence with transaction boundaries and hashed audit trail."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import attack


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path() -> Path:
    return Path(os.getenv("SIGNALHARBOR_DB", "data/signalharbor.db")).resolve()


@contextmanager
def connect():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, kind TEXT NOT NULL,
            created_at TEXT NOT NULL, UNIQUE(name, kind)
        );
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id),
            module TEXT NOT NULL, score INTEGER NOT NULL,
            summary TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id),
            asset_id INTEGER NOT NULL REFERENCES assets(id),
            severity TEXT NOT NULL, title TEXT NOT NULL,
            category TEXT NOT NULL, description TEXT NOT NULL,
            recommendation TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL, module TEXT NOT NULL,
            message TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL, label TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
            note TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL, details TEXT NOT NULL,
            prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
        CREATE INDEX IF NOT EXISTS idx_assessments_asset ON assessments(asset_id);
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(created_at);
        """)
        _migrate(con)
        exists = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        if not exists:
            seed_demo(con)


def _migrate(con):
    """Additive, idempotent schema upgrades for databases created by v1.0."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
    if "attack" not in cols:
        con.execute("ALTER TABLE findings ADD COLUMN attack TEXT NOT NULL DEFAULT ''")
    cols = {r[1] for r in con.execute("PRAGMA table_info(assessments)")}
    if "details" not in cols:
        con.execute("ALTER TABLE assessments ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")


def _json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def audit_event(con, action: str, details: str) -> None:
    previous = con.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = previous[0] if previous else "0" * 64
    created = now()
    payload = _json({"action": action, "details": details, "prev": prev_hash, "timestamp": created})
    digest = hashlib.sha256(payload.encode()).hexdigest()
    con.execute("INSERT INTO audit(action,details,prev_hash,entry_hash,created_at) VALUES (?,?,?,?,?)",
                (action, details, prev_hash, digest, created))


def verify_audit(con) -> dict:
    previous = "0" * 64
    rows = con.execute("SELECT * FROM audit ORDER BY id ASC").fetchall()
    for row in rows:
        payload = _json({"action": row["action"], "details": row["details"],
                         "prev": previous, "timestamp": row["created_at"]})
        digest = hashlib.sha256(payload.encode()).hexdigest()
        if row["prev_hash"] != previous or row["entry_hash"] != digest:
            return {"valid": False, "checked": len(rows), "broken_at": row["id"]}
        previous = digest
    return {"valid": True, "checked": len(rows), "head": previous}


def add_asset(con, name: str, kind: str) -> int:
    con.execute("INSERT OR IGNORE INTO assets(name,kind,created_at) VALUES (?,?,?)", (name, kind, now()))
    return con.execute("SELECT id FROM assets WHERE name=? AND kind=?", (name, kind)).fetchone()[0]


def add_assessment(con, asset_id: int, module: str, items: list[dict], summary: str,
                   details: dict | None = None) -> tuple[int, int]:
    weight = {"critical": 29, "high": 17, "medium": 8, "low": 3, "info": 0}
    score = max(0, 100 - sum(weight.get(f["severity"], 0) for f in items))
    stamp = now()
    cur = con.execute("INSERT INTO assessments(asset_id,module,score,summary,created_at,details) VALUES (?,?,?,?,?,?)",
                      (asset_id, module, score, summary, stamp, json.dumps(details or {}, default=str)[:200_000]))
    assessment_id = cur.lastrowid
    for f in items:
        attack.tag(f)
        con.execute("""INSERT INTO findings(assessment_id,asset_id,severity,title,category,description,
                       recommendation,evidence,status,created_at,attack) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (assessment_id, asset_id, f["severity"], f["title"], f["category"],
                     f["description"], f["recommendation"], str(f.get("evidence", ""))[:200], "open", stamp,
                     f.get("attack", "")[:100]))
    con.execute("INSERT INTO events(level,module,message,created_at) VALUES (?,?,?,?)",
                ("success" if score >= 70 else "warning", module,
                 f"Assessment complete · score {score}/100 · {len(items)} observations", stamp))
    audit_event(con, "assessment.created", f"module={module};asset={asset_id};assessment={assessment_id}")
    return assessment_id, score


LATEST_FINDINGS_SQL = """SELECT f.*, a.name AS asset_name, s.module FROM findings f
      JOIN assessments s ON s.id=f.assessment_id
      JOIN assets a ON a.id=f.asset_id
      WHERE s.id=(SELECT MAX(s2.id) FROM assessments s2 WHERE s2.asset_id=s.asset_id) """


def latest_findings_query(where="") -> str:
    # Callers append fixed SQL fragments only; every user-supplied value is a bound parameter.
    return LATEST_FINDINGS_SQL + where  # nosec B608


def seed_demo(con):
    samples = [
        ("shop.example.org", "domain", "Domain Trust", 82, [
            ("medium", "Content Security Policy missing", "Web Headers", "No CSP response header found", "Define an application-specific Content-Security-Policy"),
            ("low", "Referrer policy not defined", "Web Headers", "Referrer-Policy was absent", "Set a Referrer-Policy suitable for this application"),
        ]),
        ("payments-cluster.yaml", "configuration", "Config Inspector", 54, [
            ("high", "Privileged container enabled", "Container Hardening", "A container is marked privileged", "Remove privileged mode unless essential"),
            ("medium", "Resource limits not configured", "Kubernetes", "Container has no resource limits", "Specify CPU and memory limits"),
            ("low", "Container image not pinned", "Supply Chain", "Image uses the latest tag", "Pin image by immutable digest"),
        ]),
        ("workstation-023", "device", "Device Health", 91, [
            ("low", "Patch age exceeds policy", "Endpoint Hygiene", "Device patch age exceeds 30 days", "Apply approved security updates"),
        ]),
        ("auth-events-demo.jsonl", "telemetry", "Event Triage", 63, [
            ("high", "Repeated authentication failures", "Identity Monitoring", "Several unsuccessful logins detected in a short time", "Review affected account and enforce MFA or lockout"),
            ("medium", "Privilege change event observed", "Identity Monitoring", "Administrative role change observed", "Verify authorization and change ticket"),
        ]),
        ("q4-identity-purple-team", "exercise", "Purple Team", 0, [
            ("high", "Technique executed without detection", "Detection Gap", "T1003.001 LSASS Memory produced no alert or telemetry", "Write and validate a detection, then re-run the test"),
            ("medium", "Telemetry present but no alert", "Detection Engineering", "T1078.004 Cloud Accounts visible in logs but no alert fired", "Build an analytic on existing telemetry"),
        ]),
    ]
    for name, kind, module, _display_score, entries in samples:
        asset_id = add_asset(con, name, kind)
        items = [{"severity": sev, "title": title, "category": cat, "description": desc,
                  "recommendation": rec, "evidence": "Sample dataset · not an actual scan"} for sev, title, cat, desc, rec in entries]
        add_assessment(con, asset_id, module, items, "Illustrative assessment seeded for demo")
    con.execute("INSERT INTO events(level,module,message,created_at) VALUES (?,?,?,?)",
                ("info", "System", "Demo workspace initialized · replace sample data with your own", now()))
    audit_event(con, "workspace.seeded", "Demo data is synthetic")
