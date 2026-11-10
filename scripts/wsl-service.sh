#!/usr/bin/env bash
# Manage SignalHarbor as a systemd *user* service (no root daemon).
#   bash scripts/wsl-service.sh install|start|stop|restart|status|logs|uninstall
# Requires systemd in WSL: /etc/wsl.conf must contain
#   [boot]
#   systemd=true
# then run `wsl --shutdown` from Windows PowerShell and reopen Ubuntu.
set -euo pipefail
PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT="signalharbor.service"
UNIT_DIR="$HOME/.config/systemd/user"

need_systemd() {
  if [ "$(ps -p 1 -o comm= 2>/dev/null)" != "systemd" ]; then
    cat >&2 <<'EOF'
systemd is not running in this WSL distribution.
Enable it once:
  sudo tee /etc/wsl.conf >/dev/null <<'CONF'
[boot]
systemd=true
CONF
Then in Windows PowerShell:  wsl --shutdown   and reopen Ubuntu.
(Without systemd you can still run:  cd ~/SignalHarbor && .venv/bin/python run.py)
EOF
    exit 1
  fi
}

case "${1:-status}" in
  install)
    need_systemd
    [ -x "$PROJECT/.venv/bin/python" ] || { echo "Run scripts/wsl-setup.sh first" >&2; exit 1; }
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/$UNIT" <<EOF
[Unit]
Description=SignalHarbor local security workspace
After=network-online.target

[Service]
WorkingDirectory=$PROJECT
ExecStart=$PROJECT/.venv/bin/python $PROJECT/run.py
Restart=on-failure
RestartSec=3
# Hardening for a user service
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "$UNIT"
    loginctl enable-linger "$USER" 2>/dev/null || true
    sleep 2
    systemctl --user --no-pager --lines=0 status "$UNIT" | head -n 3
    echo "Installed. Logs: bash scripts/wsl-service.sh logs"
    ;;
  start|stop|restart) need_systemd; systemctl --user "$1" "$UNIT"; echo "$1: ok" ;;
  status) need_systemd; systemctl --user --no-pager status "$UNIT" || true ;;
  logs) need_systemd; journalctl --user -u "$UNIT" -n 50 --no-pager ;;
  uninstall)
    need_systemd
    systemctl --user disable --now "$UNIT" 2>/dev/null || true
    rm -f "$UNIT_DIR/$UNIT"; systemctl --user daemon-reload
    echo "Removed $UNIT (data and .env untouched)"
    ;;
  *) echo "usage: $0 install|start|stop|restart|status|logs|uninstall" >&2; exit 2 ;;
esac
