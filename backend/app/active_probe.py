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


SQL_ERROR_SIGNS = ('you have an error in your sql syntax', 'warning: mysql', 'unclosed quotation mark',
                   'pg_query', 'sqlite3.operationalerror', 'psql:', 'odbc sql', 'ora-01756', 'sqlstate')


def probe_sql_error_indicator(client, url):
    """Detection only: append one benign quote and look for a DB error signature. No data extraction."""
    try:
        sep = '&' if '?' in url else '?'
        r = client.get(f"{url}{sep}id={CANARY}'")
        low = r.text.lower()
        if any(s in low for s in SQL_ERROR_SIGNS):
            return ('High', 'SQL error signature exposed on malformed input',
                    'A single quote in a parameter triggered a database error message in the response — a strong '
                    'SQL-injection indicator. No data was extracted; this is detection only.',
                    'Database error string reflected after appending a quote to a parameter.',
                    'Use parameterized queries/prepared statements and suppress verbose DB errors.',
                    {'OWASP': 'A03 Injection'})
    except Exception:
        pass
    return None


def probe_http_methods(client, url):
    try:
        r = client.request('OPTIONS', url)
        allow = r.headers.get('allow', '') or r.headers.get('access-control-allow-methods', '')
        risky = [m for m in ('PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH') if m in allow.upper()]
        if risky:
            return ('Medium', f'Risky HTTP methods enabled: {", ".join(risky)}',
                    'The server advertises state-changing or debug HTTP methods that are rarely needed publicly.',
                    f'Allow: {allow}',
                    'Disable unused methods (esp. TRACE/PUT/DELETE) at the web server or WAF.',
                    {'OWASP': 'A05 Security Misconfiguration'})
    except Exception:
        pass
    return None


def probe_host_header(client, url):
    """Detection: send a spoofed Host and see if it is reflected into links/redirects."""
    parsed = urlparse(url)
    try:
        r = client.get(url, headers={'Host': f'{CANARY}.evil.example'})
        loc = r.headers.get('location', '')
        if f'{CANARY}.evil.example' in loc or f'{CANARY}.evil.example' in r.text[:5000]:
            return ('Medium', 'Host header reflected (possible host-header injection)',
                    'A spoofed Host header was reflected into a redirect or the page, which can enable cache '
                    'poisoning or password-reset poisoning.',
                    f'Spoofed Host reflected: {CANARY}.evil.example',
                    'Validate the Host header against an allow-list; do not build URLs from it.',
                    {'OWASP': 'A05 Security Misconfiguration'})
    except Exception:
        pass
    return None


def probe_error_disclosure(client, url):
    parsed = urlparse(url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    try:
        r = client.get(f'{origin}/{CANARY}/%00../.%2e/')
        low = r.text.lower()
        if any(s in low for s in ('traceback (most recent call last)', 'stack trace', 'exception in thread',
                                  'at java.', 'system.web.', '<b>warning</b>', 'fatal error')):
            return ('Low', 'Verbose error / stack trace disclosure',
                    'An unusual request elicited a stack trace or framework error, leaking internal implementation detail.',
                    'Stack-trace/error signature returned for a malformed path.',
                    'Return generic error pages; log details server-side only.',
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
    checks = [('Reflected input (XSS indicator)', probe_reflected_input),
              ('CORS misconfiguration', probe_cors),
              ('Open redirect', probe_open_redirect),
              ('Clickjacking (framable)', probe_clickjacking),
              ('SQL error signature', probe_sql_error_indicator),
              ('Risky HTTP methods', probe_http_methods),
              ('Host-header injection', probe_host_header),
              ('Verbose error disclosure', probe_error_disclosure)]
    check_results = []
    with _client() as client:
        for name, fn in checks:
            f = fn(client, asset.url)
            check_results.append({'check': name, 'issue_found': bool(f),
                                  'severity': f[0] if f else None, 'title': f[1] if f else None})
            if f:
                results.append(f)
                audit.create_finding(db, run.id, *f)
    db.add(models.Evidence(run_id=run.id, kind='active-probe',
                           title='Safe active probe (authorized penetration test)',
                           data={'authorized': True, 'non_destructive': True,
                                 'findings': len(results), 'checks_run': len(checks),
                                 'checks': check_results, 'canary': CANARY}))
    audit.finish_task(db, t, f'Ran {len(checks)} non-destructive active probes; {len(results)} issues confirmed')
    audit.cost(db, run.id, 'deterministic', 'safe_active_probe', 0.0, detail={'findings': len(results)})
    model = dict(run.app_model or {}); model['active_probe'] = True; run.app_model = model
    db.commit()
    audit.log(db, run.workspace_id, run.id, 'active_probe.completed',
              {'findings': len(results), 'non_destructive': True}, actor='active-probe-agent')
    return {'ok': True, 'findings': len(results), 'checks_run': len(checks)}
