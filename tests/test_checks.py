import socket
from pathlib import Path

import pytest

from app import checks

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples'


def test_config_findings():
    data = (EXAMPLES / 'insecure-deployment.yaml').read_bytes()
    findings, details = checks.check_config(data, 'manifest.yaml')
    assert details['resources_evaluated'] == 1
    titles = {f['title'] for f in findings}
    assert 'Privileged container enabled' in titles
    assert 'Host namespace sharing' in titles
    assert 'Container image not pinned' in titles
    assert 'Container resource limits missing' in titles


def test_events_detection():
    findings, details = checks.check_events((EXAMPLES / 'security-events.jsonl').read_bytes())
    assert details['events_analyzed'] == 164
    assert details['failure_events'] == 12
    assert {f['title'] for f in findings} == {
        'Repeated authentication failures', 'Privilege change event observed', 'Security control disabled',
        'Possible password spraying', 'Successful login after repeated failures',
        'Login from a source not seen in baseline', 'Unusual activity volume for identity',
    }


def test_device_hygiene():
    findings, details = checks.check_device((EXAMPLES / 'device-posture.json').read_bytes())
    assert details['device_id'] == 'lab-workstation-007'
    assert len(findings) == 2
    assert {f['severity'] for f in findings} == {'high','medium'}


def test_insecure_yaml_does_not_execute_code():
    payload = b'!!python/object/apply:os.system ["echo unsafe"]'
    with pytest.raises(ValueError):
        checks.check_config(payload, 'evil.yaml')


def test_private_address_is_rejected(monkeypatch):
    monkeypatch.setattr(checks.socket, 'getaddrinfo', lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1',443))])
    with pytest.raises(ValueError, match='blocked'):
        checks.public_domain('example.org')


def test_mixed_dns_address_is_rejected(monkeypatch):
    monkeypatch.setattr(checks.socket, 'getaddrinfo', lambda *_args, **_kwargs: [
        (socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),
        (socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.1',443))])
    with pytest.raises(ValueError, match='blocked'):
        checks.public_domain('example.org')


def test_domain_check_with_stubbed_network(monkeypatch):
    monkeypatch.setattr(checks, 'public_domain', lambda d: (d,['8.8.8.8']))
    monkeypatch.setattr(checks, 'dns_values', lambda name, typ: ['"v=DMARC1; p=reject"'] if name.startswith('_dmarc.') else ['"v=spf1 -all"'] if typ=='TXT' else ['0 issue "letsencrypt.org"'] if typ=='CAA' else ['12345 8 2 AB12'])
    monkeypatch.setattr(checks, 'https_headers_pinned', lambda *_a: {'headers':{'strict-transport-security':'max-age=3600','content-security-policy':"default-src 'self'; frame-ancestors 'none'",'referrer-policy':'same-origin','x-content-type-options':'nosniff','permissions-policy':'camera=()'},'tls_version':'TLSv1.3'})
    findings, details = checks.check_domain('example.org')
    assert findings == []
    assert details['dns']['dmarc_found'] is True


def test_bad_event_format():
    with pytest.raises(ValueError,match='line 1'):
        checks.check_events(b'not-json')


def test_device_missing_required_fields():
    with pytest.raises(ValueError, match='Missing required fields'):
        checks.check_device(b'{"device_id":"x"}')
