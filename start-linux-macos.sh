#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
. .venv/bin/activate
python -m pip install -r requirements.txt
printf "\nTip: on Ubuntu/WSL prefer: bash scripts/wsl-setup.sh\nSignalHarbor is available at http://127.0.0.1:8088\n"
python run.py
