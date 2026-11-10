"""FastAPI server: dashboards, assessors, evidence manifest, reporting."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import ai, checks, coverage, db, reports, sarif, vulns

ROOT = Path(__file__).parent
security = HTTPBasic(auto_error=False)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="SignalHarbor API", description="Local-first security observability for authorized assets",
              version="1.1.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")


APP_CSP = ("default-src 'self'; img-src 'self' data:; font-src 'self'; script-src 'self'; style-src 'self'; "
           "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
# Swagger UI is served from jsDelivr; allow that origin on /docs only.
DOCS_CSP = ("default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; script-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _same_origin(request: Request) -> bool:
    """CSRF defence: browsers attach Basic-auth credentials to cross-site requests automatically,
    so reject state-changing requests that a browser marks as cross-site or whose Origin differs."""
    if request.headers.get("sec-fetch-site") in ("cross-site", "same-site"):
        return False
    origin = request.headers.get("origin")
    if origin and origin != "null":
        host = request.headers.get("host", "")
        return origin.split("://", 1)[-1] == host
    return origin != "null"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.method in UNSAFE_METHODS and not _same_origin(request):
        response = JSONResponse({"detail": "Cross-origin state-changing request blocked"}, status_code=403)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = DOCS_CSP if request.url.path == "/docs" else APP_CSP
    response.headers["Cache-Control"] = "no-store"
    return response


class RateLimiter:
    """Small in-memory sliding window; adequate for a single-process local tool."""

    def __init__(self, limit: int, window_s: int):
        self.limit, self.window, self.hits = limit, window_s, defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            raise HTTPException(429, "Too many domain checks; wait a minute and retry")
        q.append(now)


domain_limiter = RateLimiter(int(os.getenv("SIGNALHARBOR_DOMAIN_RATE", "10")), 60)


def auth(credentials: HTTPBasicCredentials | None = Depends(security)):
    password = os.getenv("SIGNALHARBOR_PASSWORD")
    if not password:
        return
    username = os.getenv("SIGNALHARBOR_USER", "admin")
    if not credentials or not (secrets.compare_digest(credentials.username.encode(), username.encode()) and
                               secrets.compare_digest(credentials.password.encode(), password.encode())):
        raise HTTPException(status_code=401, detail="Authentication required",
                            headers={"WWW-Authenticate": 'Basic realm="SignalHarbor"'})


@app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(auth)])
def openapi_schema():
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False, dependencies=[Depends(auth)])
def swagger_docs():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="SignalHarbor API")


class DomainRequest(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    authorized: bool


class FindingUpdate(BaseModel):
    status: Literal["open", "resolved", "accepted"]


async def upload_bytes(file: UploadFile, limit=checks.MAX_INPUT_BYTES) -> bytes:
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"Upload exceeds {limit // (1024 * 1024)} MB limit")
    if not data:
        raise HTTPException(400, "Empty file")
    return data


def rows(seq) -> list[dict]:
    return [dict(r) for r in seq]


def overview_data(con) -> dict:
    assets = rows(con.execute("""SELECT a.*, s.id AS assessment_id, s.score, s.module,
        s.created_at AS last_assessed, s.summary FROM assets a
        LEFT JOIN assessments s ON s.id=(SELECT MAX(id) FROM assessments WHERE asset_id=a.id)
        ORDER BY COALESCE(s.created_at,'') DESC, a.id DESC"""))
    assessments_count = con.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
    findings = rows(con.execute(db.latest_findings_query() + " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id DESC"))
    active = [f for f in findings if f["status"] == "open"]
    counts = {sev: sum(1 for f in active if f["severity"] == sev) for sev in ("critical", "high", "medium", "low", "info")}
    average_score = round(sum(x["score"] for x in assets if x["score"] is not None) / max(1, sum(x["score"] is not None for x in assets)))
    assessment_trend = rows(con.execute("""SELECT s.id, s.score, s.module, s.created_at, a.name FROM assessments s
      JOIN assets a ON a.id=s.asset_id ORDER BY s.id DESC LIMIT 15"""))[::-1]
    events = rows(con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10"))
    return {"assets_count": len(assets), "assessments_count": assessments_count,
            "open_findings": len(active), "average_score": average_score,
            "severity_counts": counts, "assets": assets, "findings": findings,
            "events": events, "trend": assessment_trend}


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(auth)])
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SignalHarbor", "version": app.version, "mode": "local-first"}


@app.get("/api/overview", dependencies=[Depends(auth)])
def overview():
    with db.connect() as con:
        return overview_data(con)


@app.get("/api/findings", dependencies=[Depends(auth)])
def get_findings(status: Literal["all", "open", "resolved", "accepted"] = "all"):
    with db.connect() as con:
        q = db.latest_findings_query()
        params = []
        if status != "all":
            q += " AND f.status=?"
            params.append(status)
        q += " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id DESC LIMIT 250"
        return rows(con.execute(q, params))


@app.patch("/api/findings/{finding_id}", dependencies=[Depends(auth)])
def update_finding(finding_id: int, payload: FindingUpdate):
    with db.connect() as con:
        row = con.execute("SELECT id, title FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Finding does not exist")
        con.execute("UPDATE findings SET status=? WHERE id=?", (payload.status, finding_id))
        db.audit_event(con, "finding.status_changed", f"finding={finding_id};status={payload.status}")
    return {"id": finding_id, "status": payload.status}


@app.get("/api/assessments", dependencies=[Depends(auth)])
def assessments():
    with db.connect() as con:
        return rows(con.execute("""SELECT s.*, a.name AS asset_name, a.kind AS asset_kind,
          (SELECT COUNT(*) FROM findings f WHERE f.assessment_id=s.id) AS finding_count
          FROM assessments s JOIN assets a ON a.id=s.asset_id ORDER BY s.id DESC LIMIT 100"""))


@app.post("/api/domain", dependencies=[Depends(auth)])
def scan_domain(payload: DomainRequest, request: Request):
    domain_limiter.check(request.client.host if request.client else "local")
    if payload.authorized is not True:
        raise HTTPException(400, "Confirm authorization to assess this domain")
    try:
        findings, details = checks.check_domain(payload.domain)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with db.connect() as con:
        asset_id = db.add_asset(con, details["name"], "domain")
        assessment_id, score = db.add_assessment(con, asset_id, "Domain Trust", findings,
                                                 f"DNS records, HTTPS response headers, TLS for {details['name']}")
    return {"assessment_id": assessment_id, "score": score, "findings": findings, "details": details}


@app.post("/api/config", dependencies=[Depends(auth)])
async def scan_config(file: UploadFile = File(...)):
    content = await upload_bytes(file)
    try:
        findings, details = checks.check_config(content, file.filename or "configuration")
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    name = Path((file.filename or "config.yaml").replace("\\", "/")).name[:100]
    with db.connect() as con:
        asset_id = db.add_asset(con, name, "configuration")
        assessment_id, score = db.add_assessment(con, asset_id, "Config Inspector", findings,
                                                 f"Static IaC and container checks ({details['resources_evaluated']} documents)")
    return {"assessment_id": assessment_id, "score": score, "findings": findings, "details": details}


@app.post("/api/device", dependencies=[Depends(auth)])
async def scan_device(file: UploadFile = File(...)):
    content = await upload_bytes(file)
    try:
        findings, details = checks.check_device(content)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with db.connect() as con:
        asset_id = db.add_asset(con, details["device_id"], "device")
        assessment_id, score = db.add_assessment(con, asset_id, "Device Health", findings,
                                                 "Offline evaluation of user-provided device posture")
    return {"assessment_id": assessment_id, "score": score, "findings": findings, "details": details}


@app.post("/api/events", dependencies=[Depends(auth)])
async def scan_events(file: UploadFile = File(...)):
    content = await upload_bytes(file)
    try:
        findings, details = checks.check_events(content)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    name = Path((file.filename or "events.jsonl").replace("\\", "/")).name[:100]
    with db.connect() as con:
        asset_id = db.add_asset(con, name, "telemetry")
        assessment_id, score = db.add_assessment(con, asset_id, "Event Triage", findings,
                                                 f"Aggregated analysis of {details['events_analyzed']} JSONL events")
    return {"assessment_id": assessment_id, "score": score, "findings": findings, "details": details}


@app.post("/api/evidence", dependencies=[Depends(auth)])
async def evidence(file: UploadFile = File(...), label: str = Form(...), note: str = Form("")):
    if not label.strip() or len(label) > 120 or len(note) > 500:
        raise HTTPException(400, "Label required (max 120 chars); note max 500 chars")
    # Only a hash and metadata are persisted; source bytes are discarded.
    content = await upload_bytes(file, 5 * 1024 * 1024)
    digest = hashlib.sha256(content).hexdigest()
    filename = Path((file.filename or "artifact").replace("\\", "/")).name[:150]
    with db.connect() as con:
        cur = con.execute("INSERT INTO artifacts(filename,label,size_bytes,sha256,note,created_at) VALUES (?,?,?,?,?,?)",
                          (filename, label.strip(), len(content), digest, note.strip(), db.now()))
        db.audit_event(con, "evidence.hashed", f"artifact={cur.lastrowid};sha256={digest}")
        return {"id": cur.lastrowid, "sha256": digest, "size_bytes": len(content),
                "retention": "Hash and metadata only; uploaded bytes discarded"}


@app.get("/api/evidence", dependencies=[Depends(auth)])
def artifacts():
    with db.connect() as con:
        return rows(con.execute("SELECT * FROM artifacts ORDER BY id DESC LIMIT 200"))


@app.get("/api/audit/verify", dependencies=[Depends(auth)])
def audit_verify():
    with db.connect() as con:
        return db.verify_audit(con)


@app.get("/api/audit", dependencies=[Depends(auth)])
def audit_records():
    with db.connect() as con:
        return rows(con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100"))


@app.get("/api/report.json", dependencies=[Depends(auth)])
def report_json():
    with db.connect() as con:
        data = overview_data(con)
        payload = {"notice": "May include illustrative demo data. Not a certified security audit.",
                   "generated_at": db.now(), "overview": {k: data[k] for k in ("assets_count", "assessments_count", "open_findings", "average_score", "severity_counts")},
                   "assets": data["assets"], "findings": data["findings"],
                   "audit_integrity": db.verify_audit(con)}
    return Response(json.dumps(payload, indent=2), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=signalharbor-report.json"})


@app.get("/api/report.pdf", dependencies=[Depends(auth)])
def report_pdf():
    with db.connect() as con:
        data = overview_data(con)
        pdf = reports.pdf_report({"overview": data, "assets": data["assets"],
                                  "findings": [x for x in data["findings"] if x["status"] == "open"]})
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=signalharbor-report.pdf"})


@app.post("/api/vulns", dependencies=[Depends(auth)])
async def scan_vulns(file: UploadFile = File(...)):
    content = await upload_bytes(file)
    name = Path((file.filename or "scanner-export.csv").replace("\\", "/")).name[:100]
    try:
        findings, details = vulns.check_vulns(content, name)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with db.connect() as con:
        asset_id = db.add_asset(con, name, "vulnerabilities")
        assessment_id, score = db.add_assessment(con, asset_id, "Vuln Priority", findings,
                                                 f"Risk-ranked {details['rows']} vulnerabilities", details)
    return {"assessment_id": assessment_id, "score": score, "findings": findings, "details": details}


@app.post("/api/coverage", dependencies=[Depends(auth)])
async def scan_coverage(file: UploadFile = File(...)):
    content = await upload_bytes(file)
    try:
        findings, details = coverage.check_coverage(content)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with db.connect() as con:
        asset_id = db.add_asset(con, details["exercise"], "exercise")
        assessment_id, score = db.add_assessment(con, asset_id, "Purple Team", findings,
                                                 f"{details['tests']} emulation results · {details['detection_rate_pct']}% detected", details)
    return {"assessment_id": assessment_id, "score": score, "findings": findings, "details": details}


@app.post("/api/ai/brief", dependencies=[Depends(auth)])
def ai_brief():
    with db.connect() as con:
        findings = rows(con.execute(db.latest_findings_query() + " AND f.status='open'"))
        result = ai.generate(findings)
        db.audit_event(con, "brief.generated", f"engine={result['engine']}")
    return result


@app.get("/api/report.sarif", dependencies=[Depends(auth)])
def report_sarif():
    with db.connect() as con:
        findings = rows(con.execute(db.latest_findings_query() + " AND f.status='open'"))
    return Response(json.dumps(sarif.to_sarif(findings), indent=2), media_type="application/sarif+json",
                    headers={"Content-Disposition": "attachment; filename=signalharbor.sarif"})


@app.get("/api/audit/anchor", dependencies=[Depends(auth)])
def audit_anchor():
    """Chain head to store OUTSIDE this machine (ticket, e-mail, git). With SIGNALHARBOR_AUDIT_KEY set,
    the head is HMAC-signed, so rewriting the whole chain no longer reproduces a previously anchored value."""
    with db.connect() as con:
        state = db.verify_audit(con)
    out = {"generated_at": db.now(), **state}
    key = os.getenv("SIGNALHARBOR_AUDIT_KEY")
    if key and state.get("valid"):
        msg = f"{state['head']}|{state['checked']}|{out['generated_at']}".encode()
        out["hmac_sha256"] = hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()
    return out
