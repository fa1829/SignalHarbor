# Presenting SignalHarbor in an interview

## The 30-second pitch

> "SignalHarbor is a local-first workbench I built to practise the defender side of what red teams test. It takes data a security team already has (configs, identity logs, scanner exports, purple-team results) and turns it into prioritized, ATT&CK-mapped findings. It also has a CLI gate for CI/CD and SARIF output. Two things I care about in it: every decision explains itself, and the AI feature is built assuming its inputs are hostile."

Say up front that you began with an AI-generated v1.0 prototype, then **found and fixed its bugs, re-designed the modules and hardened it**. Interviewers trust a candidate who can audit generated code more than one who claims to have written everything.

## A 5-minute demo

1. **Command Center** (20 s): assets, scores, severity mix. Mention that the data is synthetic and labelled.
2. **Event Triage → `security-events.jsonl`** (60 s): password spraying (one source, ≥ 5 identities in 30 min) and success-after-failures. These two together are the classic sign of a spray that got in. Then point to the **robust z-score**: "I use median/MAD rather than mean/std-dev because a single burst inflates the std-dev and hides itself."
3. **Vuln Priority → `scanner-export.csv`** (60 s): "CVE-2099-0006 is CVSS 9.1 but lands below a CVSS 8.1 that's on the KEV list, because exploitation evidence beats theoretical severity. Each row says *why*." Mention the SLA and overdue tracking, and that KEV/EPSS enrichment is an explicit offline step.
4. **Purple Team → `purple-team-results.json`** (60 s): the outcome ladder prevented → alerted → logged → missed. "Logged but no alert is the cheapest win, because the telemetry already exists. Missed means first checking that the log source exists." Then median TTD against target.
5. **Terminal → CLI gate** (40 s): the insecure manifest fails with exit 1 and produces SARIF; the repo's own hardened manifest passes. "That's shift-left: the same rule set runs in the pipeline."
6. **Reports → Analyst brief** (40 s): explain the injection controls (below). If Ollama is connected, generate one live; otherwise show the rule-based version.

## How it maps to the two BNP Paribas Montreal roles

| JD bullet | Where to point |
|---|---|
| *AI Automation:* shift-left / DevSecOps controls in the SDLC | `app/cli.py` gate, SARIF, `.github/workflows/ci.yml` (ruff, bandit, pip-audit, self-gating) |
| *AI Automation:* automate vulnerability analysis, prioritization, remediation | `app/vulns.py` tiers, SLA, overdue, `scripts/enrich_vulns.py` |
| *AI Automation:* statistical models for log analysis | `_volume_anomalies` (robust z), `_new_source_logins` (baseline), spraying windows |
| *AI Automation:* dashboards for vulnerability trends | Command Center, Vuln Priority stat tiles. Be honest: no Power BI here; you'd feed `report.json` into Power BI |
| *AI Automation:* LLM/NLP for security text | `app/ai.py` local-LLM brief. Be honest that this is summarization, not NLP model training |
| *Red Team:* purple-team engagements, validate detection coverage with BAS | Purple Team module: it consumes BAS / Atomic Red Team results |
| *Red Team:* prompt injection, tool tampering in AI agents | The threat model in `app/ai.py`: untrusted-data fencing, operator-only endpoint (no SSRF), text-only rendering, length caps |
| *Red Team:* reporting with attack chains and business impact | ATT&CK chips, PDF executive report, priority reasons |
| *Red Team:* assess identity and privilege abuse | Identity analytics + T1098/T1078 mappings. Connect this to your SC-300 study |

## Questions to expect, with honest answers

- **"Is the AI brief safe against prompt injection?"** "Safer, not safe. The model only sees structured fields, the user-influenced strings are sanitized and fenced, and the output can't execute in the page. A determined injection could still bend the summary's wording, so it's labelled a draft that needs verifying. Next I'd add an output check that every finding the model mentions exists in the input."
- **"Why not just sort by CVSS?"** CVSS measures severity, not likelihood. Only a small share of published CVEs are ever exploited, and KEV/EPSS target exactly that likelihood.
- **"What would you red-team in your own tool?"** The Basic-auth + CSRF interplay (that's why the Origin/Sec-Fetch checks exist), YAML parsing of hostile files (resource exhaustion through anchors and aliases is an open item), the audit chain (anyone with DB write access can rebuild it, hence the HMAC anchor stored elsewhere), and prompt injection through asset names.
- **"What bugs did you find in the generated version?"** File inputs without `name` meant three of the modules never worked from the browser. The test suite couldn't import the app. The app's own CSP blocked its Swagger docs and legend colours. All of it was found by actually running the app and the tests, not by reading the code.
- **"Limits?"** Single-user SQLite, Basic auth, heuristic rules, no sandboxed parser, synthetic data. It's a lab tool, and the README says so.

## Don't
- Don't call it a SIEM, EDR, scanner or BAS tool.
- Don't claim offensive capability: it analyses *results* and never runs attacks. For the Red Team role, that's your purple-team bridge, not a substitute for offensive experience.
