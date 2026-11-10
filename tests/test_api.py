from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples'


def test_api_full_workflow(tmp_path, monkeypatch):
    monkeypatch.setenv('SIGNALHARBOR_DB', str(tmp_path/'test.db'))
    monkeypatch.delenv('SIGNALHARBOR_PASSWORD', raising=False)
    with TestClient(app) as client:
        overview = client.get('/api/overview')
        assert overview.status_code == 200
        assert overview.json()['assets_count'] == 5
        for name, endpoint in [('insecure-deployment.yaml','/api/config'),
                               ('device-posture.json','/api/device'),
                               ('security-events.jsonl','/api/events')]:
            result = client.post(endpoint, files={'file': (name,(EXAMPLES/name).read_bytes())})
            assert result.status_code == 200, result.text
            assert result.json()['assessment_id'] > 0
            assert result.json()['findings']
        artifact = client.post('/api/evidence',data={'label':'Demo hash','note':'Safe sample'},
                               files={'file':('sample.txt',b'hello')})
        assert artifact.status_code == 200, artifact.text
        assert artifact.json()['sha256'] == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
        assert client.get('/api/evidence').json()[0]['label'] == 'Demo hash'
        finding = client.get('/api/findings').json()[0]
        update = client.patch(f"/api/findings/{finding['id']}", json={'status':'resolved'})
        assert update.status_code == 200
        assert client.get('/api/audit/verify').json()['valid'] is True
        pdf = client.get('/api/report.pdf')
        assert pdf.status_code == 200
        assert pdf.content.startswith(b'%PDF-')
        data = client.get('/api/report.json')
        assert data.status_code == 200
        assert data.json()['audit_integrity']['valid'] is True
        assert client.get('/').status_code == 200
        assert b'SIGNAL' in client.get('/').content


def test_api_rejects_oversize_and_missing_consent(tmp_path, monkeypatch):
    monkeypatch.setenv('SIGNALHARBOR_DB', str(tmp_path/'test2.db'))
    with TestClient(app) as client:
        assert client.post('/api/domain', json={'domain':'example.org','authorized':False}).status_code == 400
        assert client.post('/api/config', files={'file':('bad.yaml',b'A'*(2*1024*1024+1))}).status_code == 413
        assert client.post('/api/device',files={'file':('x.json',b'not json')}).status_code == 400


def test_password_protects_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv('SIGNALHARBOR_DB', str(tmp_path/'auth.db'))
    monkeypatch.setenv('SIGNALHARBOR_USER','admin')
    monkeypatch.setenv('SIGNALHARBOR_PASSWORD','example-test-only-password')
    with TestClient(app) as client:
        assert client.get('/api/overview').status_code == 401
        assert client.get('/api/overview', auth=('admin','example-test-only-password')).status_code == 200
