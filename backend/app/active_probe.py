"""Safe, non-destructive active probes for AUTHORIZED domains only.

Every check is a single benign request with a harmless canary — no exploitation, no payloads
that alter state, no brute force, no DoS. Gated on asset.authorized. Detects real, exploitable
misconfigurations (reflected input, CORS, open redirect, clickjacking) without causing harm.
"""
from __future__ import annotations
from urllib.parse import urlparse, urljoin
import secrets
import httpx
from sqlalchemy.orm import Session
from . import models, audit

CANARY = 'zq' + secrets.token_hex(4) + 'qz'


def _client():
    return httpx.Client(timeout=8, follow_redirects=False,
                        headers={'User-Agent': 'Zer0-Vanguard-ActiveProbe/0.1 (authorized, non-destructive)'})


def probe_reflected_input(client, url):
    try:
        sep = '&' if '?' in url else '?'
        r = client.get(f'{url}{sep}q={CANARY}')
        if CANARY in r.text:
            ctype = r.headers.get('content-type', '')
            if 'html' in ctype:
                return ('Medium', 'Unencoded reflected input (possible XSS vector)',
                        'A unique benign canary sent in a query parameter was reflected unencoded in the HTML response. '
                        'This is a cross-site-scripting indicator; no exploit payload was sent.',
                        f'Canary q={CANARY} reflected in response body.',
                        'Context-encode all user input on output and add a strict Content-Security-Policy.',
                        {'OWASP': 'A03 Injection'})
    except Exception:
        pass
    return None


def probe_cors(client, url):
    try:
        r = client.get(url, headers={'Origin': 'https://evil.example'})
        acao = r.headers.get('access-control-allow-origin', '')
        acac = r.headers.get('access-control-allow-credentials', '')
        if acao == 'https://evil.example' or (acao == '*' and acac.lower() == 'true'):
            return ('High', 'Permissive CORS misconfiguration',
                    'The server reflected an arbitrary Origin (or allows * with credentials), letting malicious '
                    'sites read authenticated responses.',
                    f'Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}',
                    'Allow-list only trusted origins; never reflect arbitrary Origin with credentials.',
                    {'OWASP': 'A05 Security Misconfiguration'})
    except Exception:
        pass
    return None


def probe_open_redirect(client, url):
    parsed = urlparse(url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    for param in ('next', 'url', 'redirect', 'return', 'dest'):
        try:
            r = client.get(f'{origin}/?{param}=https://example.com/{CANARY}')
            loc = r.headers.get('location', '')
            if loc.startswith('https://example.com/') and CANARY in loc:
                return ('Medium', f'Open redirect via ?{param}',
                        'A redirect parameter forwarded to an external URL unchecked — usable for phishing.',
                        f'?{param}= redirected to {loc}',
                        'Validate redirect targets against an allow-list of internal paths.',
                        {'OWASP': 'A01 Broken Access Control'})
        except Exception:
            pass
    return None


def probe_clickjacking(client, url):
    try:
        r = client.get(url)
        h = {k.lower(): v for k, v in r.headers.items()}
        xfo = h.get('x-frame-options', '')
        csp = h.get('content-security-policy', '')
        if not xfo and 'frame-ancestors' not in csp:
            return ('Low', 'Page is framable (clickjacking exposure)',
                    'No X-Frame-Options or CSP frame-ancestors present, so the page can be embedded in an '
                    'attacker iframe for clickjacking.',
                    'Neither X-Frame-Options nor frame-ancestors set.',
                    'Add X-Frame-Options: DENY or CSP frame-ancestors \'none\'.',
                    {'OWASP': 'A05 Security Misconfiguration'})
    except Exception:
        pass
    return None


def run(db: Session, run_id: int) -> dict:
    run = db.get(models.AuditRun, run_id)
    asset = db.get(models.Asset, run.asset_id)
    if not asset or not asset.authorized:
        return {'ok': False, 'reason': 'domain not authorized for active testing'}
    t = audit.task(db, run.id, 'safe_active_probe', asset.url)
    results = []
    with _client() as client:
        for fn in (probe_reflected_input, probe_cors, probe_open_redirect, probe_clickjacking):
            f = fn(client, asset.url)
            if f:
                results.append(f)
                audit.create_finding(db, run.id, *f)
    db.add(models.Evidence(run_id=run.id, kind='active-probe',
                           title='Safe active probe results',
                           data={'authorized': True, 'non_destructive': True,
                                 'findings': len(results), 'checks_run': 4, 'canary': CANARY}))
    audit.finish_task(db, t, f'Ran 4 non-destructive active probes; {len(results)} issues confirmed')
    audit.cost(db, run.id, 'deterministic', 'safe_active_probe', 0.0, detail={'findings': len(results)})
    model = dict(run.app_model or {}); model['active_probe'] = True; run.app_model = model
    db.commit()
    audit.log(db, run.workspace_id, run.id, 'active_probe.completed',
              {'findings': len(results), 'non_destructive': True}, actor='active-probe-agent')
    return {'ok': True, 'findings': len(results), 'checks_run': 4}
