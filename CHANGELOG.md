# Changelog

## 1.1.0 (2026-11-09)

### Fixed
- **Browser uploads for Config Inspector, Event Triage and Device Health were broken in 1.0.** The `<input type=file>` elements had no `name`, so the browser sent no `file` field and the API answered 422. A regression test now covers this.
- **`pytest -q` failed in 1.0** with `ModuleNotFoundError: app`. `pytest.ini` now sets `pythonpath = .`.
- **Severity legend colours were blocked by the app's own CSP** (inline `style=` attributes vs `style-src 'self'`). Colours now go through `data-*` attributes and the CSSOM, and the browser console shows zero CSP violations.
- `/docs` (Swagger UI) was blocked by the same CSP and was reachable without auth. It now sits behind auth, with a docs-only CSP.
- Demo seed titles now match the real rule names, so they get ATT&CK tags and de-duplicate correctly.

### Added
- **Vuln Priority** module (`app/vulns.py`): tiered KEV/EPSS/CVSS/exposure/criticality rules, P1–P4 SLAs, overdue tracking and a written reason per item. `scripts/enrich_vulns.py` adds live KEV and EPSS values as an explicit offline-first step.
- **Purple Team** module (`app/coverage.py`): coverage per ATT&CK tactic from emulation results, detection rate, visibility and median TTD. Gaps become prioritized findings.
- **Event analytics**: password spraying, success-after-failures, baseline new-source logins, robust z-score (median/MAD) volume anomalies.
- **MITRE ATT&CK context** on findings (`app/attack.py`), shown in the UI, PDF, SARIF and CLI.
- **Analyst brief** (`app/ai.py`): deterministic, or drafted by a local Ollama model, with prompt-injection, SSRF and XSS controls.
- **SARIF 2.1.0 export** plus a **CLI gate** (`python -m app.cli … --fail-on high`) for CI/CD.
- **HMAC-signed audit anchor** (`/api/audit/anchor`).
- **WSL2 deployment**: `scripts/wsl-setup.sh` (idempotent, auto-relocates from `/mnt/c`, random secrets, `chmod 600`), a systemd user service, `Makefile` and `docs/WSL_DEPLOYMENT.md` with screenshots.
- **CI**: ruff, bandit, pip-audit, pytest, self-gating of the repo's own K8s and Compose files, SARIF upload.
- Hardened `deploy/k8s/signalharbor.yaml` that passes its own gate at `--fail-on low`.

### Security hardening
- CSRF protection for state-changing requests (`Sec-Fetch-Site` / `Origin`).
- Domain-check rate limiting (10/min per client by default).
- `run.py` refuses an unauthenticated non-loopback bind, warns on short passwords and reads `.env`.
- Extra headers: Permissions-Policy, COOP, `form-action 'self'`. Uvicorn's server header is disabled.
- Additive, idempotent DB migration from 1.0 databases.
