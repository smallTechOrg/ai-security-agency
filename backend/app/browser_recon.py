from __future__ import annotations
from urllib.parse import urljoin, urlparse
import json, time
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from . import models, audit
from .artifacts import write_text_artifact

async def _try_playwright(url:str, run_id:int) -> dict:
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        return {'available': False, 'reason': type(e).__name__}
    events=[]; console=[]
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={'width':1365,'height':900})
            page.on('console', lambda msg: console.append({'type':msg.type,'text':msg.text[:300]}))
            page.on('requestfinished', lambda req: events.append({'url':req.url[:500], 'method':req.method, 'resource_type':req.resource_type}))
            await page.goto(url, wait_until='domcontentloaded', timeout=15000)
            title = await page.title()
            body = (await page.locator('body').inner_text(timeout=3000))[:2000]
            # screenshot path is absolute; return relative artifact reference where possible
            from .artifacts import run_dir
            shot = run_dir(run_id) / 'homepage.png'
            await page.screenshot(path=str(shot), full_page=True)
            await browser.close()
            return {'available': True, 'title': title, 'body_excerpt': body, 'console': console[:50], 'network': events[:100], 'screenshot': str(shot)}
    except Exception as e:
        return {'available': False, 'reason': type(e).__name__, 'detail': str(e)[:300]}

def run_browser_recon(db:Session, run_id:int) -> models.AuditRun:
    run=db.get(models.AuditRun, run_id); asset=db.get(models.Asset, run.asset_id)
    run.status='running'; run.stage='browser_recon'; run.progress=max(run.progress,35); db.commit()
    t=audit.task(db,run.id,'browser_assisted_recon',asset.url)
    parsed=urlparse(asset.url); page_model={'url':asset.url,'links':[],'forms':[],'scripts':[],'human_takeover':False,'takeover_reason':''}
    try:
        with httpx.Client(timeout=10, follow_redirects=True, headers={'User-Agent':'AI-Security-Agency-BrowserRecon/0.1'}) as client:
            r=client.get(asset.url); soup=BeautifulSoup(r.text,'html.parser')
            page_model['title']=(soup.title.string.strip() if soup.title and soup.title.string else parsed.netloc)
            page_model['links']=[urljoin(asset.url,a.get('href')) for a in soup.select('a[href]')[:40]]
            page_model['forms']=[{'action':urljoin(asset.url,f.get('action') or ''),'method':(f.get('method') or 'GET').upper(),'inputs':[i.get('name') or i.get('type') or 'unnamed' for i in f.select('input,textarea,select')]} for f in soup.select('form')[:15]]
            page_model['scripts']=[urljoin(asset.url,s.get('src')) for s in soup.select('script[src]')[:30]]
            txt=soup.get_text(' ', strip=True).lower()[:5000]
            if any(x in txt for x in ['captcha','verify you are human','multi-factor','one-time code']):
                page_model['human_takeover']=True; page_model['takeover_reason']='CAPTCHA/MFA/login-wall indicator found; pause for browser human assistance.'
            html_path=write_text_artifact(run.id,'homepage.html',r.text[:200000])
            json_path=write_text_artifact(run.id,'browser_recon.json',json.dumps(page_model,indent=2))
    except Exception as e:
        t.status='failed'; t.error=type(e).__name__+': '+str(e)[:300]; run.status='failed'; run.stage='browser_recon_failed'; db.commit(); return run
    db.add(models.Evidence(run_id=run.id, kind='browser-recon', title='Browser-assisted recon model', data={'model':page_model,'artifacts':[html_path,json_path]}))
    audit.finish_task(db,t,f"Browser recon captured {len(page_model['links'])} links, {len(page_model['forms'])} forms, {len(page_model['scripts'])} scripts")
    audit.cost(db,run.id,'browser-recon','browser_recon',0.02,detail={'links':len(page_model['links']),'forms':len(page_model['forms'])})
    run.stage='browser_recon_complete'; run.progress=max(run.progress,80); run.status='completed' if run.stage else run.status; db.commit()
    audit.log(db,run.workspace_id,run.id,'browser_recon.completed',{'human_takeover':page_model['human_takeover'],'artifacts':[html_path,json_path]})
    return run
