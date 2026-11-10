# Convenience targets for WSL/Linux. Run `make help`.
PY := .venv/bin/python
.PHONY: help setup run test lint scan service docker clean-data
help:      ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-11s %s\n", $$1, $$2}'
setup:     ## install everything (WSL/Ubuntu)
	bash scripts/wsl-setup.sh
run:       ## start the web app on http://localhost:8088
	$(PY) run.py
test:      ## unit tests
	$(PY) -m pytest -q
lint:      ## ruff + bandit + pip-audit
	$(PY) -m ruff check app scripts tests && $(PY) -m bandit -q -r app scripts -ll && $(PY) -m pip_audit -r requirements.txt
scan:      ## run every CLI module on the bundled samples
	-$(PY) -m app.cli config examples/insecure-deployment.yaml
	-$(PY) -m app.cli events examples/security-events.jsonl
	-$(PY) -m app.cli vulns examples/scanner-export.csv
	-$(PY) -m app.cli coverage examples/purple-team-results.json
service:   ## run in background via systemd user service
	bash scripts/wsl-service.sh install
docker:    ## run in Docker (Docker Desktop with WSL integration, or docker-ce in WSL)
	docker compose up --build
clean-data: ## delete the local database (asks first)
	@read -p "Delete data/signalharbor.db? [y/N] " a; [ "$$a" = y ] && rm -f data/signalharbor.db* || echo kept
