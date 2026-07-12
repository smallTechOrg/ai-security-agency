from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .config import settings
from .db import SessionLocal, init_db, db_health
from . import models, schemas, audit
from . import browser_recon, llm
from .safety import validate_public_http_url
app=FastAPI(title='AI Security Agency', version='0.1.0')
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
    client=models.Client(name=req.client_name); db.add(client); db.commit(); db.refresh(client)
    ws=models.Workspace(client_id=client.id,name=req.workspace_name,budget_usd=req.budget_usd); db.add(ws); db.commit(); db.refresh(ws)
    asset=models.Asset(workspace_id=ws.id,url=str(req.target_url),authorized=True,scope_note=req.scope_note); db.add(asset); db.commit(); db.refresh(asset)
    run=models.AuditRun(workspace_id=ws.id,asset_id=asset.id,status='awaiting_approval',stage='safe_baseline_approval',progress=5); db.add(run); db.commit(); db.refresh(run)
    db.add(models.Approval(run_id=run.id,action='safe_passive_baseline',status='pending',reason='Reviewer must confirm authorization and budget before scan.')); db.commit()
    audit.log(db,ws.id,run.id,'workspace.created',{'target':asset.url,'budget_usd':req.budget_usd})
    return schemas.RunOut(run_id=run.id,workspace_id=ws.id,asset_id=asset.id,status=run.status,stage=run.stage,progress=run.progress,needs_approval=True)
@app.post('/api/runs/{run_id}/approve', response_model=schemas.RunOut)
def approve(run_id:int, req:schemas.ApprovalRequest, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    approval=db.query(models.Approval).filter_by(run_id=run_id,action='safe_passive_baseline').first()
    if approval: approval.status='approved'; approval.decided_by=req.decided_by; approval.reason=req.reason
    run.status='queued'; run.stage='queued_safe_baseline'; run.progress=8; db.commit(); audit.log(db,run.workspace_id,run.id,'approval.granted',{'action':'safe_passive_baseline','by':req.decided_by},actor=req.decided_by)
    return schemas.RunOut(run_id=run.id,workspace_id=run.workspace_id,asset_id=run.asset_id,status=run.status,stage=run.stage,progress=run.progress)
@app.post('/api/runs/{run_id}/execute', response_model=schemas.RunOut)
def execute(run_id:int, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    if run.status=='awaiting_approval': raise HTTPException(409,'approval required')
    run=audit.run_safe_baseline(db,run_id); return schemas.RunOut(run_id=run.id,workspace_id=run.workspace_id,asset_id=run.asset_id,status=run.status,stage=run.stage,progress=run.progress)
@app.get('/api/dashboard', response_model=schemas.DashboardOut)
def dashboard(db:Session=Depends(get_db)):
    runs=db.query(models.AuditRun).order_by(models.AuditRun.id.desc()).limit(20).all(); findings=db.query(models.Finding).order_by(models.Finding.id.desc()).limit(50).all(); approvals=db.query(models.Approval).order_by(models.Approval.id.desc()).limit(20).all(); workspaces=db.query(models.Workspace).order_by(models.Workspace.id.desc()).limit(20).all()
    return {'workspaces':[{'id':w.id,'name':w.name,'budget_usd':w.budget_usd} for w in workspaces], 'runs':[{'id':r.id,'workspace_id':r.workspace_id,'status':r.status,'stage':r.stage,'progress':r.progress,'cost_estimate_usd':r.cost_estimate_usd,'app_model':r.app_model} for r in runs], 'findings':[{'id':f.id,'run_id':f.run_id,'severity':f.severity,'title':f.title,'compliance':f.compliance} for f in findings], 'approvals':[{'id':a.id,'run_id':a.run_id,'action':a.action,'status':a.status,'reason':a.reason} for a in approvals], 'cost':{'estimated_total_usd':round(sum(r.cost_estimate_usd for r in runs),4),'budget_guardrails':True}, 'provider':{'openai':settings.openai_key_present,'gemini':settings.gemini_key_present}}
@app.get('/api/runs/{run_id}/report')
def report(run_id:int, db:Session=Depends(get_db)):
    if not db.get(models.AuditRun,run_id): raise HTTPException(404,'run not found')
    return audit.build_report(db,run_id)
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
@app.get('/api/policy')
def policy():
    return {'phase':'safe-first','allowed':['authorized public http/https targets','same-origin crawl','headers/TLS/forms/common public files','evidence-backed reporting'], 'blocked':['private/internal targets','destructive exploits','credential attacks','brute force','DoS/rate abuse','data exfiltration'], 'requires_approval':['authenticated testing','safe active probes','deep active tests','client-visible certificate']}

@app.post('/api/runs/{run_id}/browser-recon')
def browser_recon_endpoint(run_id:int, db:Session=Depends(get_db)):
    run=db.get(models.AuditRun,run_id)
    if not run: raise HTTPException(404,'run not found')
    if run.status=='awaiting_approval': raise HTTPException(409,'approval required')
    out=browser_recon.run_browser_recon(db,run_id)
    return {'run_id':out.id,'status':out.status,'stage':out.stage,'progress':out.progress,'app_model':out.app_model}
@app.get('/api/runs/{run_id}/intelligence')
def report_intelligence(run_id:int, db:Session=Depends(get_db)):
    if not db.get(models.AuditRun,run_id): raise HTTPException(404,'run not found')
    report=audit.build_report(db,run_id)
    return llm.generate_report_intelligence(db,run_id,report)
@app.get('/api/workspaces/{workspace_id}/enterprise')
def enterprise(workspace_id:int, db:Session=Depends(get_db)):
    creds=db.query(models.CredentialVaultStub).filter_by(workspace_id=workspace_id).all()
    schedules=db.query(models.Schedule).filter_by(workspace_id=workspace_id).all()
    return {'rbac_roles':['owner','admin','approver','analyst','viewer','client_viewer'],'credential_stubs':[{'id':c.id,'label':c.label,'role_name':c.role_name,'allowed_use':c.allowed_use,'secret_ref':c.secret_ref} for c in creds],'schedules':[{'id':x.id,'cadence':x.cadence,'status':x.status,'next_run_note':x.next_run_note} for x in schedules],'compliance_exports':['html_report','json_evidence_bundle','certificate_attestation_stub'],'enterprise_ready':True}
@app.post('/api/workspaces/{workspace_id}/demo-enterprise')
def demo_enterprise(workspace_id:int, db:Session=Depends(get_db)):
    asset=db.query(models.Asset).filter_by(workspace_id=workspace_id).first()
    db.add(models.CredentialVaultStub(workspace_id=workspace_id,label='Demo test account',username='analyst@example.com',role_name='standard_user'))
    if asset: db.add(models.Schedule(workspace_id=workspace_id,asset_id=asset.id,cadence='weekly',status='paused',next_run_note='Requires client approval before enabling recurring scans.'))
    db.commit(); return enterprise(workspace_id,db)
