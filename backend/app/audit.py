from __future__ import annotations
from urllib.parse import urljoin, urlparse
import ssl, socket, time
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from . import models
SECURITY_HEADERS={
 'strict-transport-security':('High','Missing HSTS header','Add Strict-Transport-Security with max-age.'),
 'content-security-policy':('Medium','Missing Content Security Policy','Add a restrictive CSP to reduce XSS impact.'),
 'x-frame-options':('Medium','Missing clickjacking protection','Add X-Frame-Options or frame-ancestors CSP.'),
 'x-content-type-options':('Low','Missing MIME sniffing protection','Add X-Content-Type-Options: nosniff.'),
 'referrer-policy':('Low','Missing Referrer-Policy','Set a privacy-preserving Referrer-Policy.'),
 'permissions-policy':('Low','Missing Permissions-Policy','Restrict unused browser capabilities.'),
}
COMMON_FILES=['/robots.txt','/sitemap.xml','/.well-known/security.txt','/.env','/.git/config','/backup.zip']
def log(db:Session, workspace_id:int, run_id:int, action:str, detail:dict, actor='system'):
    db.add(models.AuditLog(workspace_id=workspace_id, run_id=run_id, actor=actor, action=action, detail=detail)); db.commit()
def create_finding(db, run_id, severity, title, description, evidence, remediation, compliance):
    f=models.Finding(run_id=run_id,severity=severity,title=title,description=description,evidence=evidence,remediation=remediation,compliance=compliance); db.add(f); db.commit(); return f
def tls_info(hostname:str)->dict:
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((hostname,443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert=ssock.getpeercert(); return {'issuer':str(cert.get('issuer'))[:300], 'notAfter':cert.get('notAfter'), 'version':cert.get('version')}
    except Exception as e: return {'error':type(e).__name__}
def classify_business(title:str, text:str, forms:list[dict])->dict:
    lower=(title+' '+text).lower(); sectors=[]
    for word,sector in [('payment','commerce'),('shop','commerce'),('cart','commerce'),('login','saas'),('dashboard','saas'),('patient','healthcare'),('bank','finance'),('course','education')]:
        if word in lower and sector not in sectors: sectors.append(sector)
    features=[]
    if forms: features.append('forms')
    if 'login' in lower or any('password' in str(f).lower() for f in forms): features.append('authentication')
    if any(x in lower for x in ['pricing','checkout','cart']): features.append('commerce')
    if any(x in lower for x in ['api','developer','docs']): features.append('developer/API surface')
    return {'title':title[:120], 'likely_sectors':sectors or ['general website'], 'features':features or ['content/marketing'], 'risk_notes':['Public baseline only; authenticated and active tests require approval.']}

def task(db:Session, run_id:int, module:str, target:str, status:str='running', summary:str='', error:str=''):
    t=models.ScannerTask(run_id=run_id,module=module,target=target,status=status,summary=summary,error=error)
    db.add(t); db.commit(); return t
def finish_task(db:Session, t, summary:str):
    from datetime import datetime
    t.status='completed'; t.summary=summary; t.completed_at=datetime.utcnow(); db.commit()
def cost(db:Session, run_id:int, provider:str, operation:str, usd:float, tokens:int=0, detail:dict|None=None):
    db.add(models.CostEvent(run_id=run_id,provider=provider,operation=operation,estimated_usd=usd,estimated_tokens=tokens,detail=detail or {})); db.commit()

def run_safe_baseline(db:Session, run_id:int):
    run=db.get(models.AuditRun, run_id); asset=db.get(models.Asset, run.asset_id)
    run.status='running'; run.stage='crawl'; run.progress=10; db.commit(); log(db, run.workspace_id, run.id, 'run.started', {'url':asset.url}); t_crawl=task(db,run.id,'public_crawl',asset.url)
    started=time.time(); parsed=urlparse(asset.url); origin=f'{parsed.scheme}://{parsed.netloc}'
    pages=[]; forms=[]; headers={}; title=''; text=''
    with httpx.Client(timeout=8, follow_redirects=True, headers={'User-Agent':'AI-Security-Agency-SafeBaseline/0.1'}) as client:
        resp=client.get(asset.url); headers=dict(resp.headers); soup=BeautifulSoup(resp.text,'html.parser')
        title=(soup.title.string.strip() if soup.title and soup.title.string else parsed.netloc); text=soup.get_text(' ', strip=True)[:4000]
        links=[]
        for a in soup.select('a[href]')[:80]:
            href=urljoin(asset.url, a.get('href'))
            if urlparse(href).netloc==parsed.netloc and href not in links: links.append(href)
        pages=[asset.url]+links[:12]
        for form in soup.select('form')[:20]:
            inputs=[i.get('name') or i.get('type') or 'unnamed' for i in form.select('input,textarea,select')]
            forms.append({'action':urljoin(asset.url, form.get('action') or ''), 'method':(form.get('method') or 'GET').upper(), 'inputs':inputs})
        exposed=[]
        for path in COMMON_FILES:
            try:
                r=client.get(origin+path); exposed.append({'path':path,'status':r.status_code,'content_type':r.headers.get('content-type','')[:80],'bytes':len(r.content)})
            except Exception as e: exposed.append({'path':path,'error':type(e).__name__})
    finish_task(db,t_crawl,f'Discovered {len(pages)} same-origin pages and {len(forms)} forms'); db.add(models.Evidence(run_id=run.id, kind='crawl', title='Public crawl inventory', data={'pages':pages,'forms':forms,'elapsed_sec':round(time.time()-started,2)}))
    db.add(models.Evidence(run_id=run.id, kind='headers', title='HTTP response headers', data={'headers':headers}))
    db.add(models.Evidence(run_id=run.id, kind='tls', title='TLS certificate metadata', data=tls_info(parsed.hostname or '')))
    db.add(models.Evidence(run_id=run.id, kind='common-files', title='Common exposed file checks', data={'files':exposed}))
    task(db,run.id,'header_tls_common_file_checks',origin,status='completed',summary='Headers, TLS metadata, robots/sitemap/security.txt and sensitive-file checks completed'); run.stage='analysis'; run.progress=65; db.commit()
    lower_headers={k.lower():v for k,v in headers.items()}
    for h,(sev,title_f,rem) in SECURITY_HEADERS.items():
        if h not in lower_headers: create_finding(db, run.id, sev, title_f, f'{h} was not present on the target response.', f'Checked {asset.url} headers.', rem, {'OWASP':'A05 Security Misconfiguration'})
    for item in exposed:
        if item.get('path') in ['/.env','/.git/config','/backup.zip'] and item.get('status')==200:
            create_finding(db, run.id, 'Critical', f'Potentially exposed sensitive file {item["path"]}', 'A sensitive path returned HTTP 200 during a safe GET check. Contents were not exfiltrated.', str(item), 'Remove the file from web root and add server deny rules.', {'OWASP':'A01 Broken Access Control'})
    existing=dict(run.app_model or {})
    tier=existing.get('scan_tier','free')
    app_model=classify_business(title,text,forms); app_model.update(existing); app_model.update({'pages_seen':len(pages),'forms_seen':len(forms),'tech_hints':{'server':headers.get('server','unknown'),'powered_by':headers.get('x-powered-by','')}})
    scan_cost=49.0 if tier=='detailed' else 0.04
    if tier=='detailed':
        task(db,run.id,'paid_detailed_vanguard_review',origin,status='completed',summary='Detailed paid review pack staged: extended evidence, executive risk narrative, remediation program, and retest plan')
        db.add(models.Evidence(run_id=run.id, kind='vanguard-paid-depth', title='Paid detailed scan entitlement', data={'tier':'detailed','payment_status':app_model.get('payment_status'),'included':['extended evidence review','executive risk narrative','remediation roadmap','retest planning']}))
        app_model['paid_entitlements']=['extended evidence review','executive risk narrative','remediation roadmap','retest planning']
    cost(db,run.id,'deterministic','safe_baseline' if tier!='detailed' else 'paid_detailed_vanguard_scan',scan_cost,detail={'pages':len(pages),'forms':len(forms),'tier':tier}); run.app_model=app_model; run.status='completed'; run.stage='report_ready'; run.progress=100; run.cost_estimate_usd=scan_cost; db.add(models.ReportVersion(run_id=run.id,status='draft',content={'score_pending':True,'app_model':app_model})); db.commit(); log(db, run.workspace_id, run.id, 'run.completed', {'findings':db.query(models.Finding).filter_by(run_id=run.id).count(),'cost_estimate_usd':run.cost_estimate_usd,'scan_tier':tier})
    return run
def build_report(db:Session, run_id:int)->dict:
    run=db.get(models.AuditRun, run_id); asset=db.get(models.Asset, run.asset_id); findings=db.query(models.Finding).filter_by(run_id=run_id).all(); evidence=db.query(models.Evidence).filter_by(run_id=run_id).all()
    sev_score={'Critical':35,'High':20,'Medium':10,'Low':4}; score=max(0,100-sum(sev_score.get(f.severity,2) for f in findings))
    return {'run_id':run_id,'target':asset.url,'status':run.status,'security_score':score,'certificate_status':'review-required' if findings else 'baseline-pass-review-required','executive_summary':f'Safe baseline audit completed for {asset.url}. {len(findings)} findings require reviewer validation before client delivery.','app_model':run.app_model,'findings':[{'severity':f.severity,'title':f.title,'description':f.description,'evidence':f.evidence,'remediation':f.remediation,'compliance':f.compliance} for f in findings],'evidence_count':len(evidence),'cost_estimate_usd':run.cost_estimate_usd,'next_steps':['Reviewer validates findings','Approve authenticated/deeper testing if in scope','Retest after remediation']}
