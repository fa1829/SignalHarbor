"""Start SignalHarbor:  python run.py

Reads optional settings from a .env file next to this script (KEY=VALUE lines; real
environment variables win). Binds to 127.0.0.1 unless told otherwise, and refuses to
listen on a non-loopback address without a password unless the operator explicitly
acknowledges that the network path is otherwise restricted (SIGNALHARBOR_INSECURE_BIND_OK=1,
used inside the container where only 127.0.0.1 on the host is published).
"""
import ipaddress
import os
import sys
from pathlib import Path

import uvicorn

HERE = Path(__file__).resolve().parent


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    load_env(HERE / ".env")
    os.chdir(HERE)
    host = os.environ.get("SIGNALHARBOR_HOST", "127.0.0.1")
    port = int(os.environ.get("SIGNALHARBOR_PORT", "8088"))
    password = os.environ.get("SIGNALHARBOR_PASSWORD", "")
    if not is_loopback(host) and not password and os.environ.get("SIGNALHARBOR_INSECURE_BIND_OK") != "1":
        sys.exit(f"Refusing to listen on {host} without SIGNALHARBOR_PASSWORD. "
                 "Set a password (and use TLS in front) or bind to 127.0.0.1.")
    if password and len(password) < 12:
        print("WARNING: SIGNALHARBOR_PASSWORD is shorter than 12 characters.", file=sys.stderr)
    print(f"SignalHarbor listening on http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}"
          f"  (auth: {'on' if password else 'off'}, db: {os.environ.get('SIGNALHARBOR_DB', 'data/signalharbor.db')})")
    uvicorn.run("app.main:app", host=host, port=port, log_level=os.environ.get("SIGNALHARBOR_LOG_LEVEL", "info"),
                proxy_headers=False, server_header=False)
