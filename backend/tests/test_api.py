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
def test_free_and_paid_scan_gates():
    # This test verifies the payment gate itself, so disable the demo unlock for its duration.
    from app.config import settings as _s; _prev=_s.demo_unlock_detailed; _s.demo_unlock_detailed=False
    try:
        _run_scan_gate_assertions()
    finally:
        _s.demo_unlock_detailed=_prev

def _run_scan_gate_assertions():
    free=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'T','workspace_name':'W','scan_tier':'free'}); assert free.status_code==200; assert free.json()['status']=='awaiting_approval'
    unpaid=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'T','workspace_name':'W','scan_tier':'detailed'}); assert unpaid.status_code==200; assert unpaid.json()['status']=='payment_required'; assert unpaid.json()['needs_approval'] is False
    blocked=client.post(f"/api/runs/{unpaid.json()['run_id']}/execute"); assert blocked.status_code==402
    approve_blocked=client.post(f"/api/runs/{unpaid.json()['run_id']}/approve", json={'decided_by':'admin','reason':'no payment'}); assert approve_blocked.status_code==402
    intent=client.post('/api/payments/intent', json={'target_url':'https://example.com','scan_tier':'detailed'}); assert intent.status_code==200; assert intent.json()['payment_required'] is True
    paid=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'T','workspace_name':'W','scan_tier':'detailed','payment_reference':intent.json()['payment_reference']}); assert paid.status_code==200; assert paid.json()['status']=='awaiting_approval'
    ok=client.post(f"/api/runs/{paid.json()['run_id']}/approve", json={'decided_by':'admin','reason':'domain verified'}); assert ok.status_code==200; assert ok.json()['status']=='queued'

def test_policy_endpoint():
    r=client.get('/api/policy'); assert r.status_code==200; assert 'destructive exploits' in r.json()['blocked']; assert 'paid detailed scans' in r.json()['requires_approval']

def test_browser_recon_and_intelligence():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'B','workspace_name':'B','budget_usd':1.0}); run=r.json(); rid=run['run_id']; wid=run['workspace_id']
    client.post(f'/api/runs/{rid}/approve', json={'decided_by':'tester','reason':'safe'})
    br=client.post(f'/api/runs/{rid}/browser-recon'); assert br.status_code==200; assert br.json()['stage']=='browser_recon_complete'
    intel=client.get(f'/api/runs/{rid}/intelligence'); assert intel.status_code==200; assert intel.json()['redacted'] is True
    ent=client.post(f'/api/workspaces/{wid}/enterprise-program'); assert ent.status_code==200; assert ent.json()['enterprise_ready'] is True
    compat=client.post(f'/api/workspaces/{wid}/demo-enterprise'); assert compat.status_code==200; assert compat.json()['enterprise_ready'] is True
    queue=client.get('/api/admin/domain-queue'); assert queue.status_code==200; assert 'items' in queue.json()

def test_admin_domain_queue_approval_endpoint():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'Q','workspace_name':'Q','scan_tier':'free'}); rid=r.json()['run_id']
    ok=client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'}); assert ok.status_code==200; assert ok.json()['status']=='queued'
    intent=client.post('/api/payments/intent', json={'target_url':'https://example.com','scan_tier':'detailed'}).json()
    paid=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'Q','workspace_name':'Q','scan_tier':'detailed','payment_reference':intent['payment_reference']}); prid=paid.json()['run_id']
    pok=client.post(f'/api/admin/domain-queue/{prid}/approve', json={'decided_by':'admin','reason':'paid owner verified'}); assert pok.status_code==200; assert pok.json()['status']=='queued'

def test_admin_execute_approved_queued_run():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'X','workspace_name':'X','scan_tier':'free'}); rid=r.json()['run_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    out=client.post(f'/api/admin/domain-queue/{rid}/execute'); assert out.status_code==200; assert out.json()['status']=='completed'
    report=client.get(f'/api/runs/{rid}/report'); assert report.status_code==200; assert report.json()['status']=='completed'

def test_report_export_endpoints():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'R','workspace_name':'R','scan_tier':'free'}); rid=r.json()['run_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    client.post(f'/api/admin/domain-queue/{rid}/execute')
    html=client.get(f'/api/runs/{rid}/report.html'); assert html.status_code==200; assert 'Zer0' in html.text; assert 'text/html' in html.headers['content-type']
    head=client.head(f'/api/runs/{rid}/report.html'); assert head.status_code==200; assert 'text/html' in head.headers['content-type']
    bundle=client.get(f'/api/runs/{rid}/evidence-bundle'); assert bundle.status_code==200; body=bundle.json(); assert body['run_id']==rid; assert body['report']['status']=='completed'; assert len(body['timeline']['evidence'])>0

def test_paid_detailed_scan_has_enterprise_depth():
    intent=client.post('/api/payments/intent', json={'target_url':'https://example.com','scan_tier':'detailed'}).json()
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'E','workspace_name':'E','scan_tier':'detailed','payment_reference':intent['payment_reference']}); run=r.json(); rid=run['run_id']
    client.post(f'/api/runs/{rid}/approve', json={'decided_by':'admin','reason':'domain verified'})
    out=client.post(f'/api/runs/{rid}/execute'); assert out.status_code==200
    report=client.get(f'/api/runs/{rid}/report').json(); assert report['app_model']['scan_tier']=='detailed'; assert report['cost_estimate_usd']>=49
    tasks=client.get(f'/api/runs/{rid}/tasks').json(); assert any(t['module']=='paid_detailed_vanguard_review' for t in tasks['tasks'])

def test_admin_domain_registry_and_revoke():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'D','workspace_name':'D','scan_tier':'free'}); rid=r.json()['run_id']; aid=r.json()['asset_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    registry=client.get('/api/admin/domains'); assert registry.status_code==200; assert any(x['asset_id']==aid and x['authorized'] for x in registry.json()['domains'])
    revoke=client.post(f'/api/admin/domains/{aid}/revoke'); assert revoke.status_code==200; assert revoke.json()['authorized'] is False
    blocked=client.post(f'/api/admin/domain-queue/{rid}/execute'); assert blocked.status_code==403

def test_admin_audit_log_stream():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'A','workspace_name':'A','scan_tier':'free'}); rid=r.json()['run_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    client.post(f'/api/admin/domain-queue/{rid}/execute')
    logs=client.get('/api/admin/audit-log'); assert logs.status_code==200; body=logs.json(); assert body['immutable'] is True; assert any(x['action']=='approval.granted' for x in body['events'])

def test_billing_subscription_endpoints():
    billing=client.get('/api/billing/plans'); assert billing.status_code==200; assert billing.json()['plans']['free']['price_usd']==0; assert billing.json()['plans']['vanguard']['price_usd']==49
    sub=client.post('/api/billing/subscribe', json={'workspace_id':123,'plan':'vanguard','payment_reference':'zer0_stub_test'}); assert sub.status_code==200; assert sub.json()['subscription']['status']=='active'
    status=client.get('/api/billing/status/123'); assert status.status_code==200; assert status.json()['subscription']['plan']=='vanguard'
    sub2=client.post('/api/billing/subscribe', json={'workspace_id':123,'plan':'free'}); assert sub2.status_code==200
    status2=client.get('/api/billing/status/123'); assert status2.json()['subscription']['plan']=='free'

def test_rbac_permissions_and_client_safe_report():
    matrix=client.get('/api/rbac/matrix'); assert matrix.status_code==200; assert matrix.json()['roles']['client_viewer']==['read_approved_reports']
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'C','workspace_name':'C','scan_tier':'free'}); rid=r.json()['run_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    client.post(f'/api/admin/domain-queue/{rid}/execute')
    client_report=client.get(f'/api/client/reports/{rid}'); assert client_report.status_code==200; body=client_report.json(); assert 'evidence_count' not in body; assert 'findings' in body; assert body['client_visible'] is True
    denied=client.get(f'/api/client/reports/{rid}?role=viewer'); assert denied.status_code==403

def test_recurring_schedule_requires_subscription_and_approval():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'S','workspace_name':'S','scan_tier':'free'}); run=r.json(); wid=run['workspace_id']; aid=run['asset_id']
    client.post(f'/api/workspaces/{wid}/enterprise-program')
    schedules=client.get('/api/admin/schedules'); assert schedules.status_code==200; assert 'schedules' in schedules.json()
    blocked=client.post(f'/api/admin/schedules/{wid}/enable'); assert blocked.status_code==402
    client.post('/api/billing/subscribe', json={'workspace_id':wid,'plan':'vanguard','payment_reference':'zer0_stub_schedule'})
    still_blocked=client.post(f'/api/admin/schedules/{wid}/enable'); assert still_blocked.status_code==403
    client.post(f'/api/admin/domain-queue/{run["run_id"]}/approve', json={'decided_by':'admin','reason':'owner verified'})
    enabled=client.post(f'/api/admin/schedules/{wid}/enable'); assert enabled.status_code==200; assert enabled.json()['schedule']['status']=='active'; assert enabled.json()['schedule']['asset_id']==aid

def test_remediation_ticket_generation_and_status():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'M','workspace_name':'M','scan_tier':'free'}); rid=r.json()['run_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    client.post(f'/api/admin/domain-queue/{rid}/execute')
    gen=client.post(f'/api/runs/{rid}/remediation-tickets'); assert gen.status_code==200; assert gen.json()['created'] > 0
    tickets=client.get('/api/remediation-tickets'); assert tickets.status_code==200; tid=tickets.json()['tickets'][0]['id']; assert tickets.json()['tickets'][0]['status']=='open'
    closed=client.post(f'/api/remediation-tickets/{tid}/status', json={'status':'closed'}); assert closed.status_code==200; assert closed.json()['ticket']['status']=='closed'

def test_program_summary_endpoint():
    summary=client.get('/api/program/summary'); assert summary.status_code==200; body=summary.json(); assert body['product']=='Zer0 - The Vanguard'; assert 'risk' in body and 'operations' in body and 'commerce' in body; assert body['operations']['domains_total'] >= body['operations']['domains_approved']

def test_launch_readiness_checklist():
    r=client.get('/api/program/readiness'); assert r.status_code==200; body=r.json(); assert body['product']=='Zer0 - The Vanguard'; assert body['ready_score'] >= 0; names=[x['name'] for x in body['checks']]; assert 'domain_approval' in names and 'payment_gating' in names and 'report_exports' in names and 'audit_log' in names

def test_admin_user_rbac_management():
    up=client.post('/api/admin/users', json={'workspace_id':42,'email':'analyst@zer0.local','role':'analyst'}); assert up.status_code==200; assert up.json()['user']['role']=='analyst'
    up2=client.post('/api/admin/users', json={'workspace_id':42,'email':'analyst@zer0.local','role':'admin'}); assert up2.status_code==200; assert up2.json()['user']['role']=='admin'
    users=client.get('/api/admin/users'); assert users.status_code==200; assert any(u['email']=='analyst@zer0.local' and u['role']=='admin' for u in users.json()['users'])

def test_run_attestation_endpoint():
    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'AT','workspace_name':'AT','scan_tier':'free'}); run=r.json(); rid=run['run_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    client.post(f'/api/admin/domain-queue/{rid}/execute')
    att=client.get(f'/api/runs/{rid}/attestation'); assert att.status_code==200; body=att.json(); assert body['product']=='Zer0 - The Vanguard'; assert body['domain_authorized'] is True; assert 'non_destructive' in body['methodology']; assert body['target']=='https://example.com/'

def test_billing_webhook_activates_subscription():
    hook=client.post('/api/billing/webhook', json={'workspace_id':777,'event':'checkout.session.completed','plan':'vanguard','payment_reference':'stripe_stub_777'}); assert hook.status_code==200; assert hook.json()['subscription']['status']=='active'
    status=client.get('/api/billing/status/777'); assert status.json()['subscription']['plan']=='vanguard'
    logs=client.get('/api/admin/audit-log'); assert any(e['action']=='billing.webhook.received' for e in logs.json()['events'])

def test_intelligence_model_selector_endpoints():
    lst=client.get('/api/intelligence/models'); assert lst.status_code==200; assert any(m['id']=='gemini' for m in lst.json()['models'])
    setm=client.post('/api/intelligence/models', json={'mode':'gemini'}); assert setm.status_code==200; assert setm.json()['current']=='gemini'
    bad=client.post('/api/intelligence/models', json={'mode':'nope'}); assert bad.status_code==400
    client.post('/api/intelligence/models', json={'mode':'deterministic'})

    r=client.post('/api/bootstrap', json={'target_url':'https://example.com','client_name':'CG','workspace_name':'CG','scan_tier':'free','budget_usd':0.01}); run=r.json(); rid=run['run_id']; wid=run['workspace_id']
    client.post(f'/api/admin/domain-queue/{rid}/approve', json={'decided_by':'admin','reason':'owner verified'})
    from app.config import settings as _s; _prev=_s.demo_unlock_detailed; _s.demo_unlock_detailed=False
    try:
        gov=client.get(f'/api/workspaces/{wid}/cost-governor?run_id={rid}'); assert gov.status_code==200; body=gov.json(); assert body['allowed'] is False; assert body['projected_run_cost_usd'] >= 0.04
    finally:
        _s.demo_unlock_detailed=_prev
def test_upi_access_key_flow():
    qr=client.post('/api/payments/upi-qr', json={'plan':'vanguard'}); assert qr.status_code==200
    key=qr.json()['access_key']; assert qr.json()['status']=='pending'
    # Deep audit with non-activated key must be blocked (402).
    blocked=client.post('/api/bootstrap', json={'target_url':'https://example.com','scan_tier':'detailed','access_key':key}); assert blocked.status_code==402
    act=client.post(f'/api/admin/access-key/{key}/activate', json={'decided_by':'admin','reason':'UPI received'}); assert act.status_code==200; assert act.json()['status']=='active'
    # Now deep audit with active key is allowed.
    ok=client.post('/api/bootstrap', json={'target_url':'https://example.com','scan_tier':'detailed','access_key':key}); assert ok.status_code==200; assert ok.json()['status']=='awaiting_approval'
    rev=client.post(f'/api/admin/access-key/{key}/revoke'); assert rev.status_code==200; assert rev.json()['status']=='revoked'


def test_fingerprint_flags_vulnerable_and_ignores_modern():
    from app import fingerprint as fp
    r=fp.fingerprint({'Server':'Apache/2.2.15','X-Powered-By':'PHP/5.6.40'},'<html></html>',
                     ['https://cdn/jquery-1.7.2.min.js','https://cdn/lodash-4.17.10.js'])
    titles=' '.join(f[1] for f in r['findings'])
    assert 'jquery' in titles.lower(); assert 'CVE-2019-10744' in titles  # lodash proto pollution
    assert 'PHP' in titles; assert 'version disclosure' in titles.lower()
    clean=fp.fingerprint({'Server':'nginx'},'',['https://cdn/jquery-3.6.0.min.js','https://cdn/bootstrap-5.2.0.js'])
    assert clean['findings']==[]  # no false positives on a current stack
    assert clean['libraries']['jquery']=='3.6.0'

def test_repo_analyzer_deterministic_and_cost_free():
    import tempfile, os
    tmp=tempfile.mkdtemp(prefix='zer0_repotest_')
    with open(os.path.join(tmp,'config.py'),'w') as fh:
        fh.write("AWS_KEY='AKIAIOSFODNN7EXAMPLE'\np=subprocess.run('ls', shell=True)\n")
    with open(os.path.join(tmp,'.gitignore'),'w') as fh:
        fh.write('node_modules\n')
    r=client.post('/api/repo/analyze', json={'repo_path':tmp,'deep':True,'workspace_id':0}); assert r.status_code==200
    body=r.json()
    assert body['cost_usd']==0.0
    assert body['intelligence']['cost_usd']==0.0
    assert body['files_scanned']>=1
    rules=[f['rule'] for f in body['findings']]
    assert any('AWS' in ru for ru in rules)
    assert any('shell=True' in ru or 'shell' in ru for ru in rules)
    import shutil; shutil.rmtree(tmp, ignore_errors=True)

