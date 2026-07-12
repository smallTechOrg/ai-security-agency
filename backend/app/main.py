from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .config import settings
from .db import SessionLocal, init_db, db_health
from . import models, schemas, audit
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
