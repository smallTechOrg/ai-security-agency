from fastapi.testclient import TestClient
from app.main import app, startup
client=TestClient(app)
startup()
def test_health():
    r=client.get('/health'); assert r.status_code==200; assert r.json()['status']=='ok'
def test_approval_required_flow():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'T','workspace_name':'W','budget_usd':1.0}); assert r.status_code==200
    run=r.json(); assert run['needs_approval'] is True
    blocked=client.post(f"/api/runs/{run['run_id']}/execute"); assert blocked.status_code==409
    ok=client.post(f"/api/runs/{run['run_id']}/approve", json={'decided_by':'tester','reason':'safe'}); assert ok.status_code==200; assert ok.json()['status']=='queued'

def test_private_targets_blocked():
    r=client.post('/api/bootstrap', json={'target_url':'http://127.0.0.1:9999','client_name':'T','workspace_name':'W','budget_usd':1.0})
    assert r.status_code==400
def test_policy_endpoint():
    r=client.get('/api/policy'); assert r.status_code==200; assert 'destructive exploits' in r.json()['blocked']
