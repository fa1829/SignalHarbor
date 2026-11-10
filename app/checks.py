"""Safe, explainable security posture checks (not a penetration-testing engine)."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.resolver
import yaml

MAX_INPUT_BYTES = 2 * 1024 * 1024


def finding(severity: str, title: str, category: str, description: str, recommendation: str, evidence="") -> dict:
    return dict(severity=severity, title=title, category=category, description=description,
                recommendation=recommendation, evidence=str(evidence)[:200])


def public_domain(value: str) -> tuple[str, list[str]]:
    """Only permit DNS names that resolve exclusively to globally routable addresses."""
    name = value.strip().lower().rstrip(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError("Invalid internationalized domain") from e
    if len(name) > 253 or "." not in name:
        raise ValueError("Provide a public fully qualified domain name")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in name.split(".")):
        raise ValueError("Domain name contains invalid characters")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)})
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve domain: {e}") from e
    if not addresses:
        raise ValueError("Domain has no usable address")
    if any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("Local, private, reserved, or mixed-address targets are blocked")
    return name, addresses


def dns_values(name: str, rrtype: str) -> list[str]:
    try:
        res = dns.resolver.Resolver(configure=True)
        res.timeout = 2
        res.lifetime = 3
        return [r.to_text() for r in res.resolve(name, rrtype, raise_on_no_answer=False)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        return []


def https_headers_pinned(name: str, addresses: list[str]) -> dict:
    """Connect to validated IP instead of re-resolving; SNI+hostname verification retained."""
    last = None
    for ip in addresses[:4]:
        try:
            with socket.create_connection((ip, 443), timeout=5) as connection:
                connection.settimeout(5)
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(connection, server_hostname=name) as tls:
                    cert = tls.getpeercert()
                    tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {name}\r\nUser-Agent: SignalHarbor/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode("ascii"))
                    raw = bytearray()
                    while len(raw) < 32768 and b"\r\n\r\n" not in raw:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        raw.extend(chunk)
                    header_blob = bytes(raw).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
                    lines = header_blob.split("\r\n")
                    headers = {}
                    for line in lines[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.lower().strip()] = v.strip()[:1000]
                    return {"status": lines[0][:120], "headers": headers,
                            "tls_version": tls.version(), "cert_not_after": cert.get("notAfter")}
        except (OSError, ssl.SSLError, TimeoutError) as e:
            last = str(e)
            continue
    raise ValueError(f"TLS/HTTPS could not be validated: {str(last)[:180]}")


def check_domain(domain: str) -> tuple[list[dict], dict]:
    name, addresses = public_domain(domain)
    items = []
    dmarc = dns_values("_dmarc." + name, "TXT")
    spf = dns_values(name, "TXT")
    caa = dns_values(name, "CAA")
    ds = dns_values(name, "DS")
    if not any("V=DMARC1" in x.upper() for x in dmarc):
        items.append(finding("high", "DMARC record not detected", "Email Authentication",
                             "No DMARC TXT policy was found at _dmarc for this name.",
                             "Configure and validate DMARC after confirming SPF/DKIM alignment."))
    if not any("v=spf1" in x.lower() for x in spf):
        items.append(finding("medium", "SPF record not detected", "Email Authentication",
                             "No SPF TXT record was found at the requested hostname.",
                             "Publish an SPF policy at the organizational sending domain, if applicable."))
    if not caa:
        items.append(finding("low", "No CAA record found", "DNS Trust",
                             "DNS CAA was not detected; inherited CAA policies were not checked.",
                             "Consider CAA rules to constrain authorized certificate issuers."))
    if not ds:
        items.append(finding("info", "No DS record observed", "DNS Trust",
                             "The requested name has no directly observed DS record; DNSSEC validation was not performed.",
                             "Review DNSSEC at the relevant zone delegation before making changes."))
    tls = {}
    try:
        tls = https_headers_pinned(name, addresses)
        headers = tls["headers"]
        rules = [
            ("strict-transport-security", "medium", "HSTS header missing", "Enable HTTPS Strict Transport Security after confirming all subdomains support TLS."),
            ("content-security-policy", "medium", "Content Security Policy missing", "Deploy a restrictive CSP adapted to your application."),
            ("x-content-type-options", "low", "MIME sniffing protection missing", "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "low", "Referrer policy missing", "Set a suitable Referrer-Policy."),
            ("permissions-policy", "low", "Permissions policy not defined", "Disable unneeded browser features with Permissions-Policy."),
        ]
        for header, sev, title, remediation in rules:
            if header not in headers:
                items.append(finding(sev, title, "HTTP Security Headers",
                                     f"{header} was absent from the root HEAD response.", remediation))
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            items.append(finding("medium", "Framing restrictions absent", "HTTP Security Headers",
                                 "Neither X-Frame-Options nor CSP frame-ancestors was seen.",
                                 "Add CSP frame-ancestors or X-Frame-Options as appropriate."))
        if tls.get("cert_not_after"):
            days = int((datetime.fromtimestamp(ssl.cert_time_to_seconds(tls["cert_not_after"]), timezone.utc) - datetime.now(timezone.utc)).total_seconds() // 86400)
            if days < 45:
                sev = "high" if days < 15 else "medium"
                items.append(finding(sev, "TLS certificate close to expiration", "TLS Hygiene",
                                     f"Certificate has approximately {days} days remaining.",
                                     "Renew and validate the deployed TLS certificate."))
    except ValueError as e:
        items.append(finding("high", "HTTPS validation unsuccessful", "TLS Hygiene", str(e),
                             "Investigate certificate chain, hostname, listener availability and TLS settings."))
    return items, {"name": name, "addresses": addresses, "tls": tls, "dns": {
        "spf_found": any("v=spf1" in x.lower() for x in spf),
        "dmarc_found": any("V=DMARC1" in x.upper() for x in dmarc),
        "caa_found": bool(caa), "ds_observed": bool(ds)
    }}


def _container_rules(container: dict, path: str, result: list[dict], include_k8s=True):
    if not isinstance(container, dict):
        return
    security = container.get("securityContext") or {}
    if not isinstance(security, dict):
        security = {}
    if container.get("privileged") is True or security.get("privileged") is True:
        result.append(finding("high", "Privileged container enabled", "Container Hardening",
                              f"Privileged execution at {path}.", "Remove privileged mode unless formally required.", path))
    if security.get("allowPrivilegeEscalation") is True:
        result.append(finding("high", "Privilege escalation explicitly allowed", "Container Hardening",
                              f"Privilege escalation enabled at {path}.", "Set allowPrivilegeEscalation to false.", path))
    if security.get("runAsUser") == 0 or container.get("user") in ("0", "root", 0):
        result.append(finding("medium", "Container runs as root", "Container Hardening",
                              f"Root execution configured at {path}.", "Use a non-root user and a non-root image.", path))
    image = str(container.get("image", ""))
    if image and (":" not in image.split("/")[-1] or image.endswith(":latest")) and "@sha256:" not in image:
        result.append(finding("low", "Container image not pinned", "Supply Chain",
                              f"Image is not immutable: {image[:100]}.", "Pin release versions and preferably image digests.", path))
    if include_k8s:
        resources = container.get("resources") or {}
        if not isinstance(resources, dict) or not resources.get("limits"):
            result.append(finding("medium", "Container resource limits missing", "Availability",
                                  f"No CPU/memory limits observed at {path}.", "Define CPU and memory limits.", path))
        if security.get("readOnlyRootFilesystem") is not True:
            result.append(finding("low", "Writable container root filesystem", "Container Hardening",
                                  f"Read-only root filesystem not enabled at {path}.",
                                  "Use readOnlyRootFilesystem where the workload supports it.", path))


def check_config(content: bytes, filename: str) -> tuple[list[dict], dict]:
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("Configuration exceeds 2 MB limit")
    try:
        text = content.decode("utf-8-sig")
        documents = list(yaml.safe_load_all(text))
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as e:
        raise ValueError("Provide valid UTF-8 YAML or JSON") from e
    if len(documents) > 100:
        raise ValueError("Limit upload to 100 configuration documents")
    items = []
    resources = 0
    for idx, doc in enumerate(documents):
        if not isinstance(doc, dict):
            continue
        resources += 1
        kind = doc.get("kind", "")
        services = doc.get("services")
        if isinstance(services, dict):
            for name, svc in list(services.items())[:100]:
                path = f"services.{name}"
                if not isinstance(svc, dict):
                    continue
                _container_rules(svc, path, items, include_k8s=False)
                if any("docker.sock" in str(vol) for vol in (svc.get("volumes") or []) if isinstance(vol, str)):
                    items.append(finding("high", "Docker socket mounted", "Container Hardening",
                                         "The host Docker socket is mounted in a service.",
                                         "Remove docker.sock mounts and avoid host daemon control.", path))
                if svc.get("network_mode") == "host":
                    items.append(finding("medium", "Host network enabled", "Network Isolation",
                                         f"Host networking configured in {path}.", "Use isolated container networking.", path))
        spec = doc.get("spec", {})
        if not isinstance(spec, dict):
            continue
        if kind == "CronJob":
            spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet"):
            spec = (spec.get("template") or {}).get("spec") or {}
        if kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet", "CronJob"):
            if spec.get("hostNetwork") is True or spec.get("hostPID") is True:
                items.append(finding("high", "Host namespace sharing", "Kubernetes Isolation",
                                     f"Host network/PID sharing enabled in document {idx+1}.",
                                     "Disable host-level namespaces where possible.", f"doc[{idx}]"))
            for j, c in enumerate(((spec.get("containers") or []) if isinstance(spec.get("containers"), list) else [])[:100]):
                _container_rules(c, f"doc[{idx}].containers[{j}]", items)
    return items[:150], {"resources_evaluated": resources, "findings": min(150, len(items)),
                         "scope": "Static checks only; this is not a full policy engine"}


def check_device(content: bytes) -> tuple[list[dict], dict]:
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("Device report exceeds 2 MB")
    try:
        profile = json.loads(content)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("Device posture must be valid JSON") from e
    if not isinstance(profile, dict):
        raise ValueError("Device JSON must contain one object")
    required = {"device_id", "disk_encrypted", "screen_lock", "patch_age_days", "edr_running", "backup_encrypted"}
    if not required.issubset(profile):
        raise ValueError("Missing required fields: " + ", ".join(sorted(required - set(profile))))
    if not isinstance(profile["patch_age_days"], int) or not 0 <= profile["patch_age_days"] <= 3650:
        raise ValueError("patch_age_days must be a non-negative integer")
    for key in ["disk_encrypted", "screen_lock", "edr_running", "backup_encrypted"]:
        if not isinstance(profile[key], bool):
            raise ValueError(f"{key} must be true or false")
    items = []
    if not profile["disk_encrypted"]:
        items.append(finding("high", "Full-disk encryption disabled", "Device Hygiene",
                             "Self-reported full-disk encryption is disabled.", "Enable approved full-disk encryption."))
    if not profile["screen_lock"]:
        items.append(finding("medium", "Screen lock disabled", "Device Hygiene",
                             "Device self-report indicates no screen lock.", "Configure a strong screen lock."))
    age = profile["patch_age_days"]
    if age > 60:
        items.append(finding("high", "Security patch age over 60 days", "Device Hygiene",
                             f"Reported OS patch age: {age} days.", "Apply approved OS security updates."))
    elif age > 30:
        items.append(finding("low", "Security patch age over 30 days", "Device Hygiene",
                             f"Reported OS patch age: {age} days.", "Schedule approved security updates."))
    if not profile["edr_running"]:
        items.append(finding("medium", "Endpoint protection not running", "Device Hygiene",
                             "Device reports that endpoint protection is inactive.", "Verify approved endpoint protection is operational."))
    if not profile["backup_encrypted"]:
        items.append(finding("medium", "Backup encryption disabled", "Data Protection",
                             "Backup encryption is disabled in the supplied posture report.", "Encrypt backups and protect keys."))
    return items, {"device_id": str(profile["device_id"])[:90], "mode": "User-supplied snapshot; no remote device extraction"}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


FAILURE_TYPES = ("login_failed", "auth_failure")
SUCCESS_TYPES = ("login_success", "auth_success")


def _max_in_window(dates: list[datetime], window: timedelta) -> int:
    dates = sorted(dates)
    left = largest = 0
    for right, moment in enumerate(dates):
        while moment - dates[left] > window:
            left += 1
        largest = max(largest, right - left + 1)
    return largest


def _spray_and_success(parsed: list[dict]) -> list[dict]:
    """Password spraying (one source, many identities) and success shortly after many failures."""
    out = []
    by_ip = defaultdict(list)
    for e in parsed:
        if e["event_type"] in FAILURE_TYPES:
            by_ip[e["ip"]].append(e)
    for ip, evs in by_ip.items():
        left = 0
        for right in range(len(evs)):
            while evs[right]["timestamp"] - evs[left]["timestamp"] > timedelta(minutes=30):
                left += 1
            users = {x["user"] for x in evs[left:right + 1]}
            if len(users) >= 5:
                out.append(finding("high", "Possible password spraying", "Identity Monitoring",
                                   f"One source failed authentication for {len(users)} distinct identities within 30 minutes.",
                                   "Block or rate-limit the source, check for any successful logins from it, enforce MFA.",
                                   f"Source: {ip[:45]}"))
                break
    recent_fail = defaultdict(list)
    flagged = set()
    for e in parsed:
        key = e["user"]
        if e["event_type"] in FAILURE_TYPES:
            recent_fail[key].append(e["timestamp"])
        elif e["event_type"] in SUCCESS_TYPES and key not in flagged:
            window = [t for t in recent_fail[key] if e["timestamp"] - t <= timedelta(minutes=30)]
            if len(window) >= 5:
                flagged.add(key)
                out.append(finding("high", "Successful login after repeated failures", "Identity Monitoring",
                                   f"{len(window)} failures were followed by a success within 30 minutes.",
                                   "Treat as possible credential compromise: verify with the user, reset credentials, review session activity.",
                                   f"Account: {key[:32]}"))
    return out


def _new_source_logins(parsed: list[dict]) -> list[dict]:
    """Baseline = first 70% of each identity's successful logins; flag later sources never seen before."""
    out = []
    by_user = defaultdict(list)
    for e in parsed:
        if e["event_type"] in SUCCESS_TYPES:
            by_user[e["user"]].append(e)
    for user, evs in by_user.items():
        if len(evs) < 5:
            continue
        cut = max(1, int(len(evs) * 0.7))
        baseline = {x["ip"] for x in evs[:cut]}
        new = sorted({x["ip"] for x in evs[cut:]} - baseline)
        if new:
            out.append(finding("low", "Login from a source not seen in baseline", "Identity Analytics",
                               f"{len(new)} source(s) appeared after a baseline of {cut} successful logins.",
                               "Confirm travel/VPN/device change with the user; correlate with MFA and device signals.",
                               f"Account: {user[:32]}"))
    return out[:20]


def _volume_anomalies(parsed: list[dict]) -> list[dict]:
    """Robust z-score on hourly event counts per identity (Iglewicz-Hoaglin, threshold 3.5)."""
    if not parsed:
        return []
    start = parsed[0]["timestamp"].replace(minute=0, second=0, microsecond=0)
    hours = int((parsed[-1]["timestamp"] - start).total_seconds() // 3600) + 1
    if hours < 6:
        return []
    per_user = defaultdict(lambda: [0] * hours)
    for e in parsed:
        per_user[e["user"]][int((e["timestamp"] - start).total_seconds() // 3600)] += 1
    out = []
    for user, counts in per_user.items():
        ordered = sorted(counts)
        median = ordered[len(ordered) // 2]
        mad = sorted(abs(c - median) for c in counts)[len(counts) // 2]
        scale = mad if mad > 0 else (sum(abs(c - median) for c in counts) / len(counts)) or 1
        peak = max(counts)
        z = 0.6745 * (peak - median) / scale
        if z > 3.5 and peak >= 10:
            out.append(finding("medium", "Unusual activity volume for identity", "Identity Analytics",
                               f"Peak of {peak} events in one hour vs. median {median} (robust z = {z:.1f}).",
                               "Check for automation, token misuse or data staging by this identity.",
                               f"Account: {user[:32]}"))
    return out[:20]


def check_events(content: bytes) -> tuple[list[dict], dict]:
    if len(content) > MAX_INPUT_BYTES:
        raise ValueError("Event data exceeds 2 MB")
    try:
        lines = content.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as e:
        raise ValueError("Event data must be UTF-8") from e
    if len(lines) > 10000:
        raise ValueError("Maximum 10,000 event lines")
    parsed = []
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON at line {line_no}") from e
        if not isinstance(event, dict) or not isinstance(event.get("event_type"), str):
            raise ValueError(f"Event at line {line_no} requires event_type")
        ts = _parse_timestamp(event.get("timestamp"))
        if ts is None:
            raise ValueError(f"Event at line {line_no} requires ISO 8601 timestamp")
        parsed.append({"timestamp": ts, "event_type": event["event_type"].lower()[:60],
                       "user": str(event.get("user", "unknown"))[:90],
                       "ip": str(event.get("ip", "unknown"))[:90]})
    items = []
    parsed.sort(key=lambda e: e["timestamp"])
    failures = defaultdict(list)
    for e in parsed:
        if e["event_type"] in FAILURE_TYPES:
            failures[(e["user"], e["ip"])].append(e["timestamp"])
    for (username, _ip), dates in failures.items():
        largest = _max_in_window(dates, timedelta(minutes=10))
        if largest >= 5:
            items.append(finding("high", "Repeated authentication failures", "Identity Monitoring",
                                 f"At least {largest} failed logins within 10 minutes for a single identity/source pair.",
                                 "Review login history and apply MFA, rate controls, or account protection.",
                                 f"Account: {username[:32]}"))
    items.extend(_spray_and_success(parsed))
    items.extend(_new_source_logins(parsed))
    items.extend(_volume_anomalies(parsed))
    escalations = [e for e in parsed if e["event_type"] in ("role_granted_admin", "privilege_changed", "admin_role_change")]
    if escalations:
        items.append(finding("medium", "Privilege change event observed", "Identity Monitoring",
                             f"{len(escalations)} administrative role change event(s) in this dataset.",
                             "Confirm each change was approved and documented."))
    disabled = [e for e in parsed if e["event_type"] in ("edr_disabled", "audit_logging_disabled")]
    if disabled:
        items.append(finding("high", "Security control disabled", "Detection Coverage",
                             f"{len(disabled)} event(s) indicate a security control was switched off.",
                             "Validate approved maintenance and restore monitoring coverage."))
    types = Counter(e["event_type"] for e in parsed)
    return items, {"events_analyzed": len(parsed), "event_types": dict(types.most_common(10)),
                         "failure_events": sum(types[k] for k in FAILURE_TYPES),
                         "analytics": ["sliding-window brute force", "spray detection", "success-after-failure",
                                       "baseline new-source", "robust z-score (median/MAD) volume"],
                         "privacy": "Raw log records are not stored"}
