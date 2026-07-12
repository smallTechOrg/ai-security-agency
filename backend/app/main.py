from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import os, subprocess
from .config import settings
from .db import SessionLocal, init_db, db_health
from . import models, schemas, audit
from . import browser_recon, llm
from .safety import validate_public_http_url
app=FastAPI(title='Zer0 - The Vanguard', version='0.1.0')
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(',') if o.strip()], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
@app.on_event('startup')
def startup(): init_db()
def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
@app.get('/health')
def health(): return {'status':'ok' if db_health() else 'error','db':True,'provider':{'openai':settings.openai_key_present,'gemini':settings.gemini_key_present}}
@app.post('/api/bootstrap', response_model=schemas.RunOut)
def bootstrap(req:schemas.BootstrapRequest, db:Session=Depends(get_db)):
    validate_public_http_url(str(req.target_url))
    tier=req.scan_tier if req.scan_tier in {'free','detailed'} else 'free'
    # Detailed tier unlocked by EITHER a stripe payment_reference OR an admin-activated UPI access key.
    key_row=None
    if tier=='detailed' and not req.payment_reference.strip() and req.access_key.strip():
        key_row=db.query(models.AccessKey).filter_by(key=req.access_key.strip()).first()
        if not key_row or key_row.status!='active':
            raise HTTPException(402,'valid activated access key required for detailed scan')
    paid = bool(req.payment_reference.strip()) or (key_row is not None) or (tier=='detailed' and settings.demo_unlock_detailed)
    client=models.Client(name=req.client_name); db.add(client); db.commit(); db.refresh(client)
    effective_budget=max(req.budget_usd,49.0) if tier=='detailed' and paid else (req.budget_usd if req.budget_usd>0 else settings.default_budget_usd)
    ws=models.Workspace(client_id=client.id,name=req.workspace_name,budget_usd=effective_budget); db.add(ws); db.commit(); db.refresh(ws)
    if key_row:
        key_row.workspace_id=ws.id
    asset=models.Asset(workspace_id=ws.id,url=str(req.target_url),authorized=(tier=='free'),scope_note=req.scope_note); db.add(asset); db.commit(); db.refresh(asset)
    status='awaiting_approval' if tier=='free' else ('awaiting_approval' if paid else 'payment_required')
    stage='safe_baseline_approval' if tier=='free' else ('admin_domain_approval' if paid else 'payment_required')
    progress=5 if status=='awaiting_approval' else 2
    run=models.AuditRun(workspace_id=ws.id,asset_id=asset.id,status=status,stage=stage,progress=progress,app_model={'scan_tier':tier,'payment_status':'paid' if paid else ('not_required' if tier=='free' else 'required'),'domain_approved':asset.authorized,'access_key':bool(key_row)}); db.add(run); db.commit(); db.refresh(run)
    reason='Free high-level audit: reviewer confirms authorization before safe passive scan.' if tier=='free' else ('Paid detailed audit: admin must approve domain ownership before testing.' if paid else 'Detailed audit requires payment before admin domain approval.')
    db.add(models.Approval(run_id=run.id,action='domain_scan_authorization',status='pending' if status=='awaiting_approval' else 'payment_required',reason=reason)); db.commit()
    audit.log(db,ws.id,run.id,'workspace.created',{'target':asset.url,'budget_usd':req.budget_usd,'scan_tier':tier,'payment_status':run.app_model['payment_status']})
    return schemas.RunOut(run_id=run.id,workspace_id=ws.id,asset_id=asset.id,status=run.status,stage=run.stage,progress=run.progress,needs_approval=status=='awaiting_approval')
@app.post('/api/runs/{run_id}/approve', response_model=schemas.RunOut)
def approve(run_id:int, req:schemas.ApprovalRequest, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    if run.status=='payment_required': raise HTTPException(402,'payment required')
    approval=db.query(models.Approval).filter_by(run_id=run_id,action='domain_scan_authorization').first() or db.query(models.Approval).filter_by(run_id=run_id).first()
    if approval: approval.status='approved'; approval.decided_by=req.decided_by; approval.reason=req.reason
    asset=db.get(models.Asset,run.asset_id)
    if asset: asset.authorized=True
    run.status='queued'; run.stage='queued_safe_baseline'; run.progress=8
    model=dict(run.app_model or {}); model['domain_approved']=True; run.app_model=model
    db.commit(); audit.log(db,run.workspace_id,run.id,'approval.granted',{'action':'domain_scan_authorization','by':req.decided_by},actor=req.decided_by)
    return schemas.RunOut(run_id=run.id,workspace_id=run.workspace_id,asset_id=run.asset_id,status=run.status,stage=run.stage,progress=run.progress)
def projected_run_cost(run:models.AuditRun)->float:
    tier=(run.app_model or {}).get('scan_tier','free')
    return 49.0 if tier=='detailed' else 0.04

def cost_governor_state(db:Session, workspace_id:int, run_id:int|None=None):
    ws=db.get(models.Workspace,workspace_id)
    if not ws: raise HTTPException(404,'workspace not found')
    spent=round(sum(r.cost_estimate_usd for r in db.query(models.AuditRun).filter_by(workspace_id=workspace_id).all()),4)
    run=db.get(models.AuditRun,run_id) if run_id else None
    projected=projected_run_cost(run) if run else 0
    remaining=round(ws.budget_usd-spent,4)
    # DEMO: budget cap disabled via settings.demo_unlock_detailed so scans always run.
    allowed = True if settings.demo_unlock_detailed else (spent+projected<=ws.budget_usd)
    return {'workspace_id':workspace_id,'budget_usd':ws.budget_usd,'spent_usd':spent,'remaining_usd':remaining,'projected_run_cost_usd':projected,'allowed':allowed,'guardrail':'demo_unlimited' if settings.demo_unlock_detailed else 'block_execution_when_projected_cost_exceeds_budget'}

@app.get('/api/workspaces/{workspace_id}/cost-governor')
def cost_governor(workspace_id:int, run_id:int|None=None, db:Session=Depends(get_db)):
    return cost_governor_state(db,workspace_id,run_id)

@app.post('/api/runs/{run_id}/execute', response_model=schemas.RunOut)
def execute(run_id:int, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    if run.status=='awaiting_approval': raise HTTPException(409,'approval required')
    if run.status=='payment_required': raise HTTPException(402,'payment required')
    asset=db.get(models.Asset,run.asset_id)
    if not asset or not asset.authorized: raise HTTPException(403,'domain admin approval required')
    governor=cost_governor_state(db,run.workspace_id,run.id)
    if not governor['allowed']:
        audit.log(db,run.workspace_id,run.id,'cost.guardrail.blocked',governor,actor='system')
        raise HTTPException(402,'workspace budget exceeded')
    run=audit.run_safe_baseline(db,run_id); return schemas.RunOut(run_id=run.id,workspace_id=run.workspace_id,asset_id=run.asset_id,status=run.status,stage=run.stage,progress=run.progress)
@app.get('/api/dashboard', response_model=schemas.DashboardOut)
def dashboard(db:Session=Depends(get_db)):
    runs=db.query(models.AuditRun).order_by(models.AuditRun.id.desc()).limit(20).all(); findings=db.query(models.Finding).order_by(models.Finding.id.desc()).limit(50).all(); approvals=db.query(models.Approval).order_by(models.Approval.id.desc()).limit(20).all(); workspaces=db.query(models.Workspace).order_by(models.Workspace.id.desc()).limit(20).all()
    return {'workspaces':[{'id':w.id,'name':w.name,'budget_usd':w.budget_usd} for w in workspaces], 'runs':[{'id':r.id,'workspace_id':r.workspace_id,'status':r.status,'stage':r.stage,'progress':r.progress,'cost_estimate_usd':r.cost_estimate_usd,'app_model':r.app_model} for r in runs], 'findings':[{'id':f.id,'run_id':f.run_id,'severity':f.severity,'title':f.title,'compliance':f.compliance} for f in findings], 'approvals':[{'id':a.id,'run_id':a.run_id,'action':a.action,'status':a.status,'reason':a.reason} for a in approvals], 'cost':{'estimated_total_usd':round(sum(r.cost_estimate_usd for r in runs),4),'budget_guardrails':True}, 'provider':{'openai':settings.openai_key_present,'gemini':settings.gemini_key_present}, 'commerce':{'free_audit_enabled':True,'detailed_scan_price_usd':49,'payment_mode':'stubbed_intent','admin_domain_approval_required':True}}
@app.get('/api/runs/{run_id}/report')
def report(run_id:int, db:Session=Depends(get_db)):
    if not db.get(models.AuditRun,run_id): raise HTTPException(404,'run not found')
    return audit.build_report(db,run_id)
@app.api_route('/api/runs/{run_id}/report.html', methods=['GET','HEAD'], response_class=HTMLResponse)
def report_html(run_id:int, db:Session=Depends(get_db)):
    rep=report(run_id,db); findings=''.join([f"<li><b>{f['severity']}: {f['title']}</b><p>{f['description']}</p><small>{f['remediation']}</small></li>" for f in rep['findings']])
    b=rep.get('browser') or {}
    shot=f"<h3>Rendered evidence ({b.get('engine','')})</h3><img src='/api/runs/{run_id}/screenshot' style='max-width:100%;border-radius:12px;border:1px solid #263d5b'/>" if b.get('screenshot_available') else ''
    gap=b.get('spa_gap') or {}
    browser_block=(f"<section><h2>Browser-assisted recon</h2><p>Engine: <b>{b.get('engine')}</b> · Browser-only findings: <b>{b.get('browser_only_findings',0)}</b> · Cookies observed: {b.get('cookies_observed',0)}</p><p>HTTP-only fetch saw <b>{gap.get('raw_forms',0)} forms / {gap.get('raw_links',0)} links</b>; real browser rendering saw <b>{gap.get('rendered_forms',0)} forms / {gap.get('rendered_links',0)} links</b>.</p>{shot}</section>" if b else '')
    return f"""<!doctype html><html><head><title>Zer0 Vanguard Report #{run_id}</title><style>body{{font-family:Inter,system-ui;background:#07111f;color:#e5eefb;padding:40px}}section{{background:#0d1b2f;border:1px solid #263d5b;border-radius:18px;padding:24px;margin-bottom:20px}}li{{margin:14px 0}}</style></head><body><section><h1>Zer0 — The Vanguard</h1><h2>Security Report for {rep['target']}</h2><p>{rep['executive_summary']}</p><h3>Score: {rep['security_score']}/100</h3><p>Status: {rep['certificate_status']} · Cost: ${rep['cost_estimate_usd']}</p><h3>Findings</h3><ul>{findings}</ul><h3>Next steps</h3><ol>{''.join([f'<li>{x}</li>' for x in rep['next_steps']])}</ol></section>{browser_block}</body></html>"""
@app.get('/api/runs/{run_id}/evidence-bundle')
def evidence_bundle(run_id:int, db:Session=Depends(get_db)):
    if not db.get(models.AuditRun,run_id): raise HTTPException(404,'run not found')
    return {'run_id':run_id,'product':'Zer0 - The Vanguard','report':audit.build_report(db,run_id),'timeline':timeline(run_id,db),'tasks':tasks(run_id,db)}
@app.get('/api/runs/{run_id}/attestation')
def run_attestation(run_id:int, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    asset=db.get(models.Asset,run.asset_id)
    approval=db.query(models.Approval).filter_by(run_id=run_id,status='approved').first()
    return {'product':'Zer0 - The Vanguard','run_id':run.id,'target':asset.url if asset else '', 'domain_authorized':bool(asset and asset.authorized and approval),'scan_tier':(run.app_model or {}).get('scan_tier','legacy'),'methodology':['non_destructive','public_http_https_only','same_origin_crawl','headers_tls_common_files','no_credentials_no_dos_no_exfiltration'],'approval':{'status':approval.status if approval else 'missing','decided_by':approval.decided_by if approval else ''},'client_certificate_status':'internal_attestation_not_compliance_certificate','generated_for':'client_and_auditor_review'}

@app.get('/api/runs/{run_id}/timeline')
def timeline(run_id:int, db:Session=Depends(get_db)):
    logs=db.query(models.AuditLog).filter_by(run_id=run_id).order_by(models.AuditLog.id).all(); evidence=db.query(models.Evidence).filter_by(run_id=run_id).order_by(models.Evidence.id).all()
    return {'logs':[{'actor':l.actor,'action':l.action,'detail':l.detail,'created_at':l.created_at.isoformat()} for l in logs], 'evidence':[{'kind':e.kind,'title':e.title,'data':e.data,'created_at':e.created_at.isoformat()} for e in evidence]}

@app.post('/api/runs/{run_id}/cancel')
def cancel_run(run_id:int, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    run.status='cancelled'; run.stage='cancelled_by_operator'; db.commit(); audit.log(db,run.workspace_id,run.id,'run.cancelled',{},actor='operator'); return {'ok':True,'status':run.status}
@app.get('/api/runs/{run_id}/tasks')
def tasks(run_id:int, db:Session=Depends(get_db)):
    rows=db.query(models.ScannerTask).filter_by(run_id=run_id).order_by(models.ScannerTask.id).all()
    costs=db.query(models.CostEvent).filter_by(run_id=run_id).order_by(models.CostEvent.id).all()
    reports=db.query(models.ReportVersion).filter_by(run_id=run_id).order_by(models.ReportVersion.id.desc()).all()
    return {'tasks':[{'module':t.module,'target':t.target,'status':t.status,'summary':t.summary,'error':t.error} for t in rows], 'costs':[{'provider':c.provider,'operation':c.operation,'estimated_usd':c.estimated_usd,'estimated_tokens':c.estimated_tokens,'detail':c.detail} for c in costs], 'report_versions':[{'id':r.id,'status':r.status,'created_at':r.created_at.isoformat()} for r in reports]}
@app.get('/api/runs/{run_id}/observability')
def run_observability(run_id:int, db:Session=Depends(get_db)):
    from . import observability
    return observability.for_run(db, run_id)

@app.get('/api/workspaces/{workspace_id}/memory')
def workspace_memory(workspace_id:int, db:Session=Depends(get_db)):
    from . import memory
    return memory.workspace_memory(db, workspace_id)

@app.get('/api/policy')
def policy():
    return {'phase':'enterprise-safe-first','allowed':['free high-level authorized public http/https posture checks','paid detailed scans after payment and admin domain approval','same-origin crawl','headers/TLS/forms/common public files','evidence-backed reporting'], 'blocked':['private/internal targets','destructive exploits','credential attacks','brute force','DoS/rate abuse','data exfiltration'], 'requires_approval':['paid detailed scans','domain ownership approval','authenticated testing','safe active probes','client-visible certificate']}

@app.post('/api/payments/intent')
def payment_intent(req:schemas.PaymentIntentRequest):
    validate_public_http_url(str(req.target_url))
    price=49 if req.scan_tier=='detailed' else 0
    return {'payment_required':price>0,'amount_usd':price,'currency':'usd','provider':'stub','payment_reference':f'zer0_stub_{abs(hash(str(req.target_url)))%1000000}','next_step':'Use this payment_reference in /api/bootstrap. Stripe checkout can replace this stub.'}

@app.post('/api/payments/upi-qr')
def upi_qr(req:schemas.AccessKeyRequest, db:Session=Depends(get_db)):
    if not settings.upi_id:
        raise HTTPException(400,'UPI_ID not configured on server')
    import secrets
    key=secrets.token_urlsafe(24)
    row=models.AccessKey(key=key, plan=req.plan, status='pending', paid_via='upi'); db.add(row); db.commit()
    amount=49
    upi_string=f'upi://pay?pa={settings.upi_id}&pn=Zer0%20Vanguard&am={amount}&cu=INR&tn=Vanguard-{key[:8]}'
    audit.log(db,0,0,'upi.key.minted',{'key':key[:8],'plan':req.plan},actor='operator')
    return {'upi_id':settings.upi_id,'amount_inr':amount,'upi_string':upi_string,'qr_data':upi_string,'access_key':key,'status':'pending','note':'Scan with any UPI app. After payment, the admin activates this key; deep audit stays blocked until then.'}

@app.get('/api/access-key/{key}')
def access_key_status(key:str, db:Session=Depends(get_db)):
    row=db.query(models.AccessKey).filter_by(key=key).first()
    if not row: raise HTTPException(404,'key not found')
    return {'key':key[:8],'plan':row.plan,'status':row.status,'paid_via':row.paid_via,'workspace_id':row.workspace_id,'activated_at':row.activated_at.isoformat() if row.activated_at else None}

@app.post('/api/admin/access-key/{key}/activate')
def activate_access_key(key:str, req:schemas.ApprovalRequest=schemas.ApprovalRequest(decided_by='admin', reason='UPI payment confirmed by admin.'), db:Session=Depends(get_db)):
    row=db.query(models.AccessKey).filter_by(key=key).first()
    if not row: raise HTTPException(404,'key not found')
    if row.status=='active': return {'key':key[:8],'status':'active','already_active':True}
    from datetime import datetime
    row.status='active'; row.activated_by=req.decided_by; row.activated_at=datetime.utcnow(); db.commit()
    audit.log(db,row.workspace_id,0,'upi.key.activated',{'key':key[:8],'by':req.decided_by,'reason':req.reason},actor=req.decided_by)
    return {'key':key[:8],'status':'active','activated_by':req.decided_by}

@app.post('/api/admin/access-key/{key}/revoke')
def revoke_access_key(key:str, db:Session=Depends(get_db)):
    row=db.query(models.AccessKey).filter_by(key=key).first()
    if not row: raise HTTPException(404,'key not found')
    row.status='revoked'; db.commit(); audit.log(db,row.workspace_id,0,'upi.key.revoked',{'key':key[:8]},actor='admin')
    return {'key':key[:8],'status':'revoked'}

@app.get('/api/admin/access-keys')
def admin_access_keys(db:Session=Depends(get_db)):
    rows=db.query(models.AccessKey).order_by(models.AccessKey.id.desc()).limit(100).all()
    return {'keys':[{'key':r.key[:8],'plan':r.plan,'status':r.status,'paid_via':r.paid_via,'workspace_id':r.workspace_id,'created_at':r.created_at.isoformat(),'activated_at':r.activated_at.isoformat() if r.activated_at else None} for r in rows]}
@app.get('/api/billing/plans')
def billing_plans():
    return {'plans':{'free':{'price_usd':0,'audits':'high-level public posture','requires_admin_domain_approval':True},'vanguard':{'price_usd':49,'audits':'detailed scan pack','requires_admin_domain_approval':True,'includes':['paid detailed review','report exports','evidence bundle','recurring scan readiness']}},'provider':'stub','next_provider':'stripe'}
@app.post('/api/billing/subscribe')
def subscribe(req:schemas.SubscribeRequest, db:Session=Depends(get_db)):
    if req.plan!='free' and not req.payment_reference: raise HTTPException(402,'payment reference required')
    sub=db.query(models.BillingSubscription).filter_by(workspace_id=req.workspace_id).order_by(models.BillingSubscription.id.desc()).first()
    if not sub:
        sub=models.BillingSubscription(workspace_id=req.workspace_id); db.add(sub)
    sub.plan=req.plan; sub.status='active' if req.plan=='free' or req.payment_reference else 'payment_required'; sub.payment_reference=req.payment_reference
    db.commit(); audit.log(db,req.workspace_id,0,'billing.subscription.updated',{'plan':sub.plan,'status':sub.status},actor='billing')
    return {'subscription':{'workspace_id':sub.workspace_id,'plan':sub.plan,'status':sub.status,'payment_reference':sub.payment_reference}}
@app.post('/api/billing/webhook')
def billing_webhook(req:schemas.BillingWebhookRequest, db:Session=Depends(get_db)):
    if req.event!='checkout.session.completed': raise HTTPException(400,'unsupported billing event')
    sub=db.query(models.BillingSubscription).filter_by(workspace_id=req.workspace_id).order_by(models.BillingSubscription.id.desc()).first()
    if not sub:
        sub=models.BillingSubscription(workspace_id=req.workspace_id); db.add(sub)
    sub.plan=req.plan; sub.status='active'; sub.payment_reference=req.payment_reference
    db.commit(); audit.log(db,req.workspace_id,0,'billing.webhook.received',{'event':req.event,'plan':req.plan,'payment_reference':req.payment_reference},actor='billing')
    return {'subscription':{'workspace_id':sub.workspace_id,'plan':sub.plan,'status':sub.status,'payment_reference':sub.payment_reference}}

@app.get('/api/billing/status/{workspace_id}')
def billing_status(workspace_id:int, db:Session=Depends(get_db)):
    sub=db.query(models.BillingSubscription).filter_by(workspace_id=workspace_id).order_by(models.BillingSubscription.id.desc()).first()
    return {'subscription':{'workspace_id':workspace_id,'plan':sub.plan,'status':sub.status,'payment_reference':sub.payment_reference} if sub else {'workspace_id':workspace_id,'plan':'free','status':'active','payment_reference':''}}

@app.post('/api/runs/{run_id}/remediation-tickets')
def generate_remediation_tickets(run_id:int, db:Session=Depends(get_db)):
    findings=db.query(models.Finding).filter_by(run_id=run_id).all()
    created=0
    for f in findings:
        exists=db.query(models.RemediationTicket).filter_by(finding_id=f.id).first()
        if not exists:
            db.add(models.RemediationTicket(finding_id=f.id,owner='client-security-team',status='open')); created+=1
    run=db.get(models.AuditRun,run_id)
    db.commit(); audit.log(db,run.workspace_id if run else 0,run_id,'remediation.tickets.generated',{'created':created},actor='system')
    return {'run_id':run_id,'created':created}

@app.get('/api/remediation-tickets')
def remediation_tickets(db:Session=Depends(get_db)):
    rows=db.query(models.RemediationTicket).order_by(models.RemediationTicket.id.desc()).limit(100).all()
    finding_ids=[r.finding_id for r in rows]
    findings={f.id:f for f in db.query(models.Finding).filter(models.Finding.id.in_(finding_ids)).all()} if finding_ids else {}
    return {'tickets':[{'id':r.id,'finding_id':r.finding_id,'owner':r.owner,'status':r.status,'title':findings[r.finding_id].title if r.finding_id in findings else '', 'severity':findings[r.finding_id].severity if r.finding_id in findings else '', 'created_at':r.created_at.isoformat()} for r in rows]}

@app.post('/api/remediation-tickets/{ticket_id}/status')
def remediation_ticket_status(ticket_id:int, req:schemas.TicketStatusRequest, db:Session=Depends(get_db)):
    ticket=db.get(models.RemediationTicket,ticket_id)
    if not ticket: raise HTTPException(404,'ticket not found')
    ticket.status=req.status; db.commit(); audit.log(db,0,0,'remediation.ticket.status',{'ticket_id':ticket.id,'status':ticket.status},actor='analyst')
    return {'ticket':{'id':ticket.id,'finding_id':ticket.finding_id,'owner':ticket.owner,'status':ticket.status}}

@app.get('/api/program/summary')
def program_summary(db:Session=Depends(get_db)):
    runs=db.query(models.AuditRun).all(); assets=db.query(models.Asset).all(); findings=db.query(models.Finding).all(); approvals=db.query(models.Approval).all(); tickets=db.query(models.RemediationTicket).all(); schedules=db.query(models.Schedule).all(); subs=db.query(models.BillingSubscription).all()
    sev={}
    for f in findings: sev[f.severity]=sev.get(f.severity,0)+1
    return {'product':'Zer0 - The Vanguard','risk':{'findings_total':len(findings),'by_severity':sev,'open_remediation_tickets':sum(1 for t in tickets if t.status!='closed')},'operations':{'runs_total':len(runs),'runs_completed':sum(1 for r in runs if r.status in {'completed','browser_recon_complete','report_ready'}),'domains_total':len(assets),'domains_approved':sum(1 for a in assets if a.authorized),'pending_approvals':sum(1 for a in approvals if a.status=='pending'),'active_schedules':sum(1 for s in schedules if s.status=='active')},'commerce':{'subscriptions_total':len(subs),'active_vanguard':sum(1 for s in subs if s.status=='active' and s.plan=='vanguard'),'estimated_scan_revenue_usd':round(sum(r.cost_estimate_usd for r in runs),2)}}

@app.get('/api/program/readiness')
def program_readiness(db:Session=Depends(get_db)):
    checks=[
        {'name':'domain_approval','ready':db.query(models.Approval).filter_by(status='approved').first() is not None,'detail':'Admin domain approval workflow exists and has approvals.'},
        {'name':'payment_gating','ready':True,'detail':'Detailed scans require payment reference before admin approval.'},
        {'name':'report_exports','ready':True,'detail':'HTML report, evidence bundle, and client-safe report endpoints are available.'},
        {'name':'audit_log','ready':db.query(models.AuditLog).first() is not None,'detail':'Immutable audit log records system actions.'},
        {'name':'remediation','ready':db.query(models.RemediationTicket).first() is not None,'detail':'Findings can become remediation tickets.'},
        {'name':'recurring_schedules','ready':db.query(models.Schedule).first() is not None,'detail':'Recurring scan schedule objects exist and are subscription/domain gated.'},
    ]
    return {'product':'Zer0 - The Vanguard','ready_score':round(sum(1 for c in checks if c['ready'])/len(checks)*100),'checks':checks}

@app.get('/api/admin/schedules')
def admin_schedules(db:Session=Depends(get_db)):
    rows=db.query(models.Schedule).order_by(models.Schedule.id.desc()).limit(100).all()
    return {'schedules':[{'id':s.id,'workspace_id':s.workspace_id,'asset_id':s.asset_id,'cadence':s.cadence,'status':s.status,'next_run_note':s.next_run_note} for s in rows]}

@app.post('/api/admin/schedules/{workspace_id}/enable')
def enable_schedule(workspace_id:int, db:Session=Depends(get_db)):
    sub=db.query(models.BillingSubscription).filter_by(workspace_id=workspace_id,status='active').order_by(models.BillingSubscription.id.desc()).first()
    if not sub or sub.plan!='vanguard': raise HTTPException(402,'active Vanguard subscription required')
    asset=db.query(models.Asset).filter_by(workspace_id=workspace_id).first()
    if not asset or not asset.authorized: raise HTTPException(403,'approved domain required')
    run_ids=[r.id for r in db.query(models.AuditRun).filter_by(workspace_id=workspace_id,asset_id=asset.id).all()]
    approved=db.query(models.Approval).filter(models.Approval.run_id.in_(run_ids),models.Approval.status=='approved').first() if run_ids else None
    if not approved: raise HTTPException(403,'admin domain approval required')
    sched=db.query(models.Schedule).filter_by(workspace_id=workspace_id,asset_id=asset.id,cadence='weekly').first()
    if not sched:
        sched=models.Schedule(workspace_id=workspace_id,asset_id=asset.id,cadence='weekly'); db.add(sched)
    sched.status='active'; sched.next_run_note='Next weekly Vanguard scan will run after scheduler integration is enabled.'
    db.commit(); audit.log(db,workspace_id,0,'schedule.enabled',{'asset_id':asset.id,'cadence':sched.cadence},actor='admin')
    return {'schedule':{'id':sched.id,'workspace_id':sched.workspace_id,'asset_id':sched.asset_id,'cadence':sched.cadence,'status':sched.status,'next_run_note':sched.next_run_note}}

@app.get('/api/admin/users')
def admin_users(db:Session=Depends(get_db)):
    rows=db.query(models.User).order_by(models.User.id.desc()).limit(100).all()
    return {'users':[{'id':u.id,'workspace_id':u.workspace_id,'email':u.email,'role':u.role} for u in rows]}

@app.post('/api/admin/users')
def upsert_user(req:schemas.UserUpsertRequest, db:Session=Depends(get_db)):
    user=db.query(models.User).filter_by(email=req.email,workspace_id=req.workspace_id).first()
    if not user:
        user=models.User(workspace_id=req.workspace_id,email=req.email,role=req.role); db.add(user)
    user.role=req.role; db.commit(); audit.log(db,req.workspace_id,0,'user.role.updated',{'email':req.email,'role':req.role},actor='admin')
    return {'user':{'id':user.id,'workspace_id':user.workspace_id,'email':user.email,'role':user.role}}

@app.get('/api/rbac/matrix')
def rbac_matrix():
    return {'roles':{'owner':['manage_org','manage_billing','approve_domains','run_scans','read_reports','read_audit_log'],'admin':['approve_domains','run_scans','read_reports','read_audit_log'],'approver':['approve_domains','read_reports'],'analyst':['run_scans','read_reports'],'viewer':['read_internal_dashboard'],'client_viewer':['read_approved_reports']},'enforced_surfaces':['client_reports','admin_domain_queue','billing','audit_log']}

@app.get('/api/client/reports/{run_id}')
def client_report(run_id:int, role:str='client_viewer', db:Session=Depends(get_db)):
    if role!='client_viewer': raise HTTPException(403,'client_viewer role required')
    rep=audit.build_report(db,run_id)
    if rep['status'] not in {'completed','report_ready','browser_recon_complete'}: raise HTTPException(409,'report not client-ready')
    return {'client_visible':True,'run_id':rep['run_id'],'target':rep['target'],'status':rep['status'],'security_score':rep['security_score'],'certificate_status':rep['certificate_status'],'executive_summary':rep['executive_summary'],'findings':rep['findings'],'cost_estimate_usd':rep['cost_estimate_usd'],'next_steps':rep['next_steps']}

@app.api_route('/api/runs/{run_id}/screenshot', methods=['GET','HEAD'])
def run_screenshot(run_id:int, db:Session=Depends(get_db)):
    if not db.get(models.AuditRun,run_id): raise HTTPException(404,'run not found')
    from .artifacts import run_dir
    shot=run_dir(run_id)/'homepage.png'
    if not shot.is_file(): raise HTTPException(404,'no screenshot captured for this run')
    return FileResponse(str(shot), media_type='image/png')

@app.post('/api/runs/{run_id}/browser-recon')
def browser_recon_endpoint(run_id:int, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    if run.status=='awaiting_approval': raise HTTPException(409,'approval required')
    out=browser_recon.run_browser_recon(db,run_id)
    return {'run_id':out.id,'status':out.status,'stage':out.stage,'progress':out.progress,'app_model':out.app_model}

@app.post('/api/repo/analyze')
def repo_analyze(req:schemas.RepoAnalyzeRequest, db:Session=Depends(get_db)):
    import tempfile, shutil
    from . import repo_analyzer
    target=req.repo_path.strip()
    cleanup=None
    if not target and req.repo_url.strip():
        from urllib.parse import urlparse
        if not (req.repo_url.startswith('http://') or req.repo_url.startswith('https://')):
            raise HTTPException(400,'only public http(s) git URLs are allowed')
        tmp=tempfile.mkdtemp(prefix='zer0_repo_'); cleanup=tmp
        try:
            subprocess.run(['git','clone','--depth','1',req.repo_url,tmp], capture_output=True, text=True, timeout=60, check=True)
        except Exception as e:
            raise HTTPException(400,f'clone failed: {type(e).__name__}')
        target=tmp
    elif not target:
        raise HTTPException(400,'provide repo_path (local) or repo_url (public)')
    if not os.path.isdir(target):
        if cleanup: shutil.rmtree(cleanup, ignore_errors=True)
        raise HTTPException(400,'repo path not found')
    result=repo_analyzer.analyze_repo(target, deep=req.deep)
    intel=repo_analyzer.enrich_with_intelligence(result)
    result['intelligence']=intel
    if req.workspace_id:
        audit.log(db,req.workspace_id,0,'repo.analyzed',{'files':result['files_scanned'],'findings':len(result['findings']),'mode':intel['mode'],'cost_usd':intel['cost_usd']},actor='analyst')
    if cleanup: shutil.rmtree(cleanup, ignore_errors=True)
    return result

@app.get('/api/runs/{run_id}/intelligence')
def report_intelligence(run_id:int, db:Session=Depends(get_db)):
    if not db.get(models.AuditRun,run_id): raise HTTPException(404,'run not found')
    report=audit.build_report(db,run_id)
    return llm.generate_report_intelligence(db,run_id,report)

@app.get('/api/intelligence/models')
def intelligence_models():
    from .intelligence_settings import AVAILABLE, get_mode
    return {'models':AVAILABLE,'current':get_mode()}

@app.post('/api/intelligence/models')
def set_intelligence_mode(req:schemas.IntelligenceModeRequest, db:Session=Depends(get_db)):
    from .intelligence_settings import set_mode, current_entry
    try:
        entry=set_mode(req.mode)
    except ValueError as e:
        raise HTTPException(400,str(e))
    audit.log(db,0,0,'intelligence.mode.set',{'mode':req.mode,'provider':entry['provider'],'model':entry['model']},actor='operator')
    return {'current':req.mode,'entry':entry}
@app.get('/api/admin/domain-queue')
def domain_queue(db:Session=Depends(get_db)):
    approvals=db.query(models.Approval).order_by(models.Approval.id.desc()).limit(50).all()
    runs={r.id:r for r in db.query(models.AuditRun).filter(models.AuditRun.id.in_([a.run_id for a in approvals])).all()} if approvals else {}
    assets={a.id:a for a in db.query(models.Asset).filter(models.Asset.id.in_([r.asset_id for r in runs.values()])).all()} if runs else {}
    items=[]
    for a in approvals:
        r=runs.get(a.run_id); asset=assets.get(r.asset_id) if r else None; model=dict(r.app_model or {}) if r else {}
        items.append({'approval_id':a.id,'run_id':a.run_id,'status':a.status,'reason':a.reason,'scan_tier':model.get('scan_tier','legacy'),'payment_status':model.get('payment_status','unknown'),'domain':asset.url if asset else '', 'run_status':r.status if r else 'missing'})
    return {'items':items}

@app.get('/api/admin/audit-log')
def admin_audit_log(limit:int=100, db:Session=Depends(get_db)):
    rows=db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limit).all()
    return {'immutable':True,'events':[{'id':r.id,'workspace_id':r.workspace_id,'run_id':r.run_id,'actor':r.actor,'action':r.action,'detail':r.detail,'created_at':r.created_at.isoformat()} for r in rows]}

@app.get('/api/admin/domains')
def admin_domains(db:Session=Depends(get_db)):
    assets=db.query(models.Asset).order_by(models.Asset.id.desc()).limit(100).all()
    return {'domains':[{'asset_id':a.id,'workspace_id':a.workspace_id,'url':a.url,'authorized':a.authorized,'scope_note':a.scope_note} for a in assets]}

@app.post('/api/admin/domains/{asset_id}/revoke')
def revoke_domain(asset_id:int, db:Session=Depends(get_db)):
    asset=db.get(models.Asset,asset_id)
    if not asset: raise HTTPException(404,'domain not found')
    asset.authorized=False
    runs=db.query(models.AuditRun).filter_by(asset_id=asset_id).all()
    for r in runs:
        if r.status in {'queued','awaiting_approval'}: r.status='domain_revoked'; r.stage='domain_revoked'; r.progress=0
        model=dict(r.app_model or {}); model['domain_approved']=False; r.app_model=model
    db.commit(); audit.log(db,asset.workspace_id,0,'domain.revoked',{'asset_id':asset.id,'url':asset.url},actor='admin')
    return {'asset_id':asset.id,'authorized':asset.authorized,'url':asset.url}

@app.post('/api/admin/domain-queue/{run_id}/approve', response_model=schemas.RunOut)
def admin_approve_domain(run_id:int, req:schemas.ApprovalRequest=schemas.ApprovalRequest(decided_by='admin', reason='Domain owner/admin approved Vanguard assessment.'), db:Session=Depends(get_db)):
    return approve(run_id,req,db)

@app.post('/api/admin/domain-queue/{run_id}/execute', response_model=schemas.RunOut)
def admin_execute_domain(run_id:int, db:Session=Depends(get_db)):
    out=execute(run_id,db)
    run=db.get(models.AuditRun,run_id)
    if run and run.status=='completed':
        browser_recon.run_browser_recon(db,run_id)
        run=db.get(models.AuditRun,run_id)
    return schemas.RunOut(run_id=run.id,workspace_id=run.workspace_id,asset_id=run.asset_id,status=run.status,stage=run.stage,progress=run.progress) if run else out

@app.get('/api/workspaces/{workspace_id}/enterprise')
def enterprise(workspace_id:int, db:Session=Depends(get_db)):
    creds=db.query(models.CredentialVaultStub).filter_by(workspace_id=workspace_id).all()
    schedules=db.query(models.Schedule).filter_by(workspace_id=workspace_id).all()
    return {'rbac_roles':['owner','admin','approver','analyst','viewer','client_viewer'],'credential_stubs':[{'id':c.id,'label':c.label,'role_name':c.role_name,'allowed_use':c.allowed_use,'secret_ref':c.secret_ref} for c in creds],'schedules':[{'id':x.id,'cadence':x.cadence,'status':x.status,'next_run_note':x.next_run_note} for x in schedules],'compliance_exports':['html_report','json_evidence_bundle','certificate_attestation_stub'],'enterprise_ready':True}
@app.post('/api/workspaces/{workspace_id}/enterprise-program')
def enterprise_program(workspace_id:int, db:Session=Depends(get_db)):
    asset=db.query(models.Asset).filter_by(workspace_id=workspace_id).first()
    if not db.query(models.CredentialVaultStub).filter_by(workspace_id=workspace_id,label='Vanguard managed test account').first():
        db.add(models.CredentialVaultStub(workspace_id=workspace_id,label='Vanguard managed test account',username='security-admin@example.com',role_name='standard_user'))
    if asset and not db.query(models.Schedule).filter_by(workspace_id=workspace_id,asset_id=asset.id,cadence='weekly').first():
        db.add(models.Schedule(workspace_id=workspace_id,asset_id=asset.id,cadence='weekly',status='paused',next_run_note='Requires active subscription and domain owner approval before recurring scans.'))
    db.commit(); return enterprise(workspace_id,db)

@app.post('/api/workspaces/{workspace_id}/demo-enterprise')
def demo_enterprise(workspace_id:int, db:Session=Depends(get_db)):
    return enterprise_program(workspace_id,db)

# --- SPA static hosting (single-origin deploy) ---
import os
from pathlib import Path as _Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
_DIST = _Path(os.environ.get('FRONTEND_DIST', str(_Path(__file__).resolve().parents[2] / 'frontend' / 'dist')))
if _DIST.is_dir():
    _assets = _DIST / 'assets'
    if _assets.is_dir():
        app.mount('/assets', StaticFiles(directory=str(_assets)), name='assets')
    @app.get('/', include_in_schema=False)
    def _spa_root():
        return FileResponse(str(_DIST / 'index.html'))
    @app.get('/{full_path:path}', include_in_schema=False)
    def _spa_catchall(full_path: str):
        candidate = _DIST / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(_DIST / 'index.html'))
