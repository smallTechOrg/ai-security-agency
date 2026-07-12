from __future__ import annotations
import json, re, httpx
from sqlalchemy.orm import Session
from .config import settings
from . import models, audit
SECRET_RE=re.compile(r'(sk-[A-Za-z0-9_-]{12,}|api[_-]?key\s*[:=]\s*[^\s]+|password\s*[:=]\s*[^\s]+|token\s*[:=]\s*[^\s]+)', re.I)

def redact(obj):
    text=json.dumps(obj, default=str)[:12000]
    return SECRET_RE.sub('[REDACTED]', text)

def estimate_cost(prompt:str)->dict:
    toks=max(1,len(prompt)//4); return {'estimated_tokens':toks,'estimated_usd':round(toks/1000*0.003,4)}

def deterministic_intelligence(report:dict, playbooks:list[models.Playbook])->dict:
    return {'mode':'deterministic-fallback','summary':report['executive_summary'],'business_risk':'Baseline public-site posture has reviewable security-hardening gaps. No destructive testing was performed.','recommended_playbooks':[{'id':p.id,'name':p.name,'trigger':p.trigger} for p in playbooks[:5]],'reviewer_notes':['Validate evidence before client delivery.','Approve browser/authenticated testing only when scope and budget are explicit.'],'certificate_language':'Internal baseline attestation only; not a legal compliance certificate until reviewer sign-off and scoped controls are complete.'}

def generate_report_intelligence(db:Session, run_id:int, report:dict)->dict:
    playbooks=db.query(models.Playbook).limit(8).all()
    if not playbooks:
        seeds=[('Security header hardening','missing_security_header'),('Public exposure review','sensitive_file_200'),('Human takeover for auth walls','captcha_or_login_wall')]
        for name,trig in seeds: db.add(models.Playbook(name=name,trigger=trig,steps={'safe':True,'requires_approval_for_active':True},confidence=0.7))
        db.commit(); playbooks=db.query(models.Playbook).limit(8).all()
    prompt='Generate concise security report intelligence from redacted evidence: '+redact(report)+' playbooks='+redact([{'id':p.id,'name':p.name,'trigger':p.trigger} for p in playbooks])
    est=estimate_cost(prompt); audit.cost(db,run_id,'openai' if settings.openai_key_present else 'deterministic','report_intelligence',est['estimated_usd'],est['estimated_tokens'],{'one_call_budgeted':True})
    # Live LLM disabled by default in Phase 3 path to protect hackathon budget; adapter + cost ledger are ready.
    return deterministic_intelligence(report, playbooks) | {'cost_estimate':est, 'redacted':True, 'one_call_per_deliverable':True}
