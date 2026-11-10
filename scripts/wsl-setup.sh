#!/usr/bin/env bash
# SignalHarbor one-shot setup for WSL2 Ubuntu (also works on native Ubuntu/Debian).
#
#   bash scripts/wsl-setup.sh            # install, configure, test
#   bash scripts/wsl-setup.sh --service  # ...and run it in the background as a systemd user service
#   bash scripts/wsl-setup.sh --no-apt   # skip apt (packages already installed / no sudo)
#   bash scripts/wsl-setup.sh --dev      # also install lint/security tooling (ruff, bandit, pip-audit)
#
# Safe to re-run: every step checks before it changes anything.
set -euo pipefail

APT=1; SERVICE=0; DEV=0; TESTS=1
for arg in "$@"; do
  case "$arg" in
    --no-apt) APT=0 ;;
    --service) SERVICE=1 ;;
    --dev) DEV=1 ;;
    --skip-tests) TESTS=0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_dim=$'\e[2m'; c_end=$'\e[0m'
step() { printf '\n%s[%s]%s %s\n' "$c_dim" "$1" "$c_end" "$2"; }
ok()   { printf '  %s✔%s %s\n' "$c_ok" "$c_end" "$1"; }
warn() { printf '  %s!%s %s\n' "$c_warn" "$c_end" "$1"; }
die()  { printf '  %s✘ %s%s\n' "$c_err" "$1" "$c_end" >&2; exit 1; }

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step 1/7 "Checking environment"
if grep -qi microsoft /proc/version 2>/dev/null; then
  ok "Running inside WSL ($(. /etc/os-release && echo "$PRETTY_NAME"))"
else
  warn "Not WSL — continuing as a regular Linux install"
fi
case "$PROJECT" in
  /mnt/*)
    TARGET="$HOME/SignalHarbor"
    warn "Project is on the Windows drive ($PROJECT)."
    warn "Windows-mounted files are slow under WSL and cannot hold Linux permissions (needed to protect .env)."
    if [ -e "$TARGET" ]; then die "$TARGET already exists — remove it or run the script from there."; fi
    cp -r "$PROJECT" "$TARGET"
    ok "Copied to $TARGET — continuing from there"
    exec bash "$TARGET/scripts/wsl-setup.sh" "$@"
    ;;
esac
ok "Project directory: $PROJECT"
cd "$PROJECT"

step 2/7 "System packages"
if [ "$APT" = 1 ]; then
  command -v sudo >/dev/null || die "sudo not found; re-run with --no-apt after installing python3-venv"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip curl ca-certificates >/dev/null
  ok "python3, python3-venv, pip, curl installed"
else
  warn "Skipping apt (--no-apt)"
fi

pick_python() {
  for py in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$py" >/dev/null && "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
      echo "$py"; return 0
    fi
  done
  return 1
}
PY="$(pick_python || true)"
if [ -z "$PY" ] && [ "$APT" = 1 ]; then
  warn "Python >= 3.10 not found; installing python3.11 (Ubuntu 22.04 path)"
  sudo apt-get install -y -qq python3.11 python3.11-venv >/dev/null
  PY="$(pick_python || true)"
fi
[ -n "$PY" ] || die "Python 3.10+ is required (Ubuntu 24.04 ships 3.12)."
ok "Using $($PY --version) at $(command -v "$PY")"

step 3/7 "Virtual environment and dependencies"
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv || die "venv failed — install the matching pythonX.Y-venv package"
  ok "Created .venv"
else
  ok ".venv already present"
fi
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
if [ "$DEV" = 1 ] || [ "$TESTS" = 1 ]; then .venv/bin/python -m pip install -q -r requirements-dev.txt; fi
ok "Dependencies installed ($(.venv/bin/python -m pip list 2>/dev/null | wc -l) packages)"

step 4/7 "Configuration (.env)"
if [ ! -f .env ]; then
  PASS="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(18))')"
  KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
  sed -e "s|^SIGNALHARBOR_PASSWORD=.*|SIGNALHARBOR_PASSWORD=$PASS|" \
      -e "s|^SIGNALHARBOR_AUDIT_KEY=.*|SIGNALHARBOR_AUDIT_KEY=$KEY|" .env.example > .env
  chmod 600 .env
  ok "Created .env with a random password and audit key (permissions 600)"
else
  ok ".env exists — leaving it unchanged"
fi
mkdir -p data && chmod 700 data

step 5/7 "Self-test"
if [ "$TESTS" = 1 ]; then
  .venv/bin/python -m pytest -q 2>&1 | tail -n 1
  .venv/bin/python -m app.cli config deploy/k8s/signalharbor.yaml --fail-on low >/dev/null 2>&1 \
    && ok "Own Kubernetes manifest passes the SignalHarbor gate" || warn "Own manifest gate reported findings"
else
  warn "Skipped (--skip-tests)"
fi

step 6/7 "Background service"
if [ "$SERVICE" = 1 ]; then
  bash scripts/wsl-service.sh install
else
  ok "Not requested (add --service, or run later: bash scripts/wsl-service.sh install)"
fi

step 7/7 "Done"
PORT="$(grep -E '^SIGNALHARBOR_PORT=' .env | cut -d= -f2)"; PORT="${PORT:-8088}"
USERNAME="$(grep -E '^SIGNALHARBOR_USER=' .env | cut -d= -f2)"
cat <<EOF

  Start:     cd $PROJECT && .venv/bin/python run.py      (or: make run)
  Open:      http://localhost:${PORT}   ← in your Windows browser
  Sign in:   user '${USERNAME:-admin}', password = SIGNALHARBOR_PASSWORD in $PROJECT/.env
             (show it with:  grep PASSWORD $PROJECT/.env)
  Stop:      Ctrl+C   (or: bash scripts/wsl-service.sh stop)
  Guide:     docs/WSL_DEPLOYMENT.md

EOF
