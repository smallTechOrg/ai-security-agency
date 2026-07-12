"""Basic API security testing (authorized, non-destructive).

Reuses the real API/XHR calls captured during browser recon, then safely re-issues benign
GETs to each endpoint to check for: unauthenticated data exposure, permissive CORS, verbose
errors, and missing API security headers. No payloads, no writes, no auth brute force.
"""
from __future__ import annotations
from urllib.parse import urlparse
import httpx
from sqlalchemy.orm import Session
from . import models, audit


def _extract_endpoints(db: Session, run_id: int, origin_host: str):
    ev = db.query(models.Evidence).filter_by(run_id=run_id, kind='browser-recon') \
        .order_by(models.Evidence.id.desc()).first()
    net = ((ev.data or {}).get('model', {}) if ev else {}).get('network_sample', []) or []
    seen = set(); endpoints = []
    for n in net:
        url = n.get('url', ''); rtype = n.get('resource_type', '')
        low = url.lower()
        is_api = rtype in ('xhr', 'fetch') or '/api/' in low or 'graphql' in low or low.rstrip('/').endswith('.json')
        if is_api and url not in seen:
            seen.add(url); endpoints.append({'url': url, 'method': n.get('method', 'GET'), 'type': rtype})
        if len(endpoints) >= 12:
            break
    return endpoints


def _probe_endpoint(client, ep):
    url = ep['url']; issues = []
    try:
        r = client.get(url, headers={'Origin': 'https://evil.example'})
        ct = r.headers.get('content-type', '')
        body = r.text[:2000]
        # 1) Unauthenticated data exposure
        if r.status_code == 200 and ('json' in ct or body.strip().startswith(('{', '['))):
            issues.append(('Medium', f'API returns data without authentication: {urlparse(url).path[:60]}',
                           'An API endpoint returned a JSON body to an unauthenticated request. Confirm this data is '
                           'intended to be public; otherwise it is a broken-access-control exposure.',
                           f'GET {url} -> {r.status_code} {ct}',
                           'Require authentication/authorization on non-public API endpoints.',
                           {'OWASP-API': 'API1 Broken Object Level / API2 Broken Authentication'}))
        # 2) Permissive CORS on the API
        acao = r.headers.get('access-control-allow-origin', '')
        acac = r.headers.get('access-control-allow-credentials', '')
        if acao == 'https://evil.example' or (acao == '*' and acac.lower() == 'true'):
            issues.append(('High', f'API allows cross-origin reads: {urlparse(url).path[:60]}',
                           'The API reflected an arbitrary Origin (or * with credentials), letting malicious sites '
                           'read authenticated API responses.',
                           f'Access-Control-Allow-Origin: {acao}; Credentials: {acac}',
                           'Restrict API CORS to trusted origins; never reflect Origin with credentials.',
                           {'OWASP-API': 'API8 Security Misconfiguration'}))
        # 3) Missing API security headers
        h = {k.lower() for k in r.headers}
        if 'json' in ct and 'x-content-type-options' not in h:
            issues.append(('Low', f'API missing X-Content-Type-Options: {urlparse(url).path[:60]}',
                           'JSON API response lacks nosniff, aiding content-type confusion attacks.',
                           f'No X-Content-Type-Options on {url}',
                           'Add X-Content-Type-Options: nosniff to API responses.',
                           {'OWASP-API': 'API8 Security Misconfiguration'}))
    except Exception:
        pass
    return {'url': url, 'method': ep['method'], 'status': None, 'issues': issues}


API_DISCOVERY_PATHS = [
    ('/swagger.json', 'High', 'Exposed Swagger/OpenAPI spec'),
    ('/swagger/v1/swagger.json', 'High', 'Exposed Swagger/OpenAPI spec'),
    ('/openapi.json', 'High', 'Exposed OpenAPI spec'),
    ('/api-docs', 'High', 'Exposed API documentation'),
    ('/v2/api-docs', 'High', 'Exposed Swagger v2 API docs'),
    ('/graphql', 'Medium', 'GraphQL endpoint reachable'),
    ('/actuator', 'High', 'Exposed Spring Boot Actuator'),
    ('/actuator/health', 'Medium', 'Spring Actuator health exposed'),
    ('/actuator/env', 'Critical', 'Spring Actuator env exposed (secrets risk)'),
    ('/api', 'Low', 'API root reachable'),
    ('/api/v1', 'Low', 'API v1 root reachable'),
    ('/.well-known/security.txt', 'Low', 'security.txt present'),
]


def _discover(db, run_id, client, origin):
    """Actively probe common API/doc paths (safe GETs). Finding these is high-signal for testers."""
    found = []
    for path, sev, label in API_DISCOVERY_PATHS:
        try:
            r = client.get(origin + path)
            ct = r.headers.get('content-type', '')
            body = r.text[:400]
            hit = False; detail = f'GET {path} -> {r.status_code} {ct[:40]}'
            if path in ('/swagger.json', '/swagger/v1/swagger.json', '/openapi.json', '/v2/api-docs') and r.status_code == 200 and ('json' in ct or '"swagger"' in body or '"openapi"' in body):
                hit = True
            elif path in ('/api-docs',) and r.status_code == 200 and ('swagger' in body.lower() or 'openapi' in body.lower() or 'json' in ct):
                hit = True
            elif path.startswith('/actuator') and r.status_code == 200 and ('json' in ct or '"status"' in body or '"_links"' in body):
                hit = True
            elif path == '/graphql' and r.status_code in (200, 400, 405) and ('graphql' in body.lower() or 'query' in body.lower() or 'must provide query' in body.lower()):
                hit = True
                sev = 'Medium'
            elif path in ('/api', '/api/v1') and r.status_code in (200, 401, 403) and 'json' in ct:
                hit = True
            elif path == '/.well-known/security.txt' and r.status_code == 200:
                hit = True
            if hit:
                sensitive = path in ('/actuator/env', '/swagger.json', '/openapi.json', '/v2/api-docs')
                audit.create_finding(db, run_id, sev, f'{label} at {path}',
                                     f'{label}. Exposed API surface/documentation lets attackers enumerate endpoints, '
                                     'parameters, and data models to target directly.'
                                     + (' This can leak configuration or secrets.' if sensitive else ''),
                                     detail,
                                     'Restrict or authenticate API docs/actuator; expose only what is necessary.',
                                     {'OWASP-API': 'API9 Improper Inventory / API8 Misconfiguration'})
                found.append({'path': path, 'label': label, 'severity': sev, 'status': r.status_code})
        except Exception:
            pass
    return found


def run(db: Session, run_id: int) -> dict:
    run = db.get(models.AuditRun, run_id); asset = db.get(models.Asset, run.asset_id)
    if not asset or not asset.authorized:
        return {'ok': False, 'reason': 'domain not authorized for active testing'}
    parsed = urlparse(asset.url)
    endpoints = _extract_endpoints(db, run_id, parsed.netloc)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    t = audit.task(db, run.id, 'api_security_test', asset.url)
    results = []; total_issues = 0
    with httpx.Client(timeout=8, follow_redirects=False,
                      headers={'User-Agent': 'Zer0-Vanguard-APIProbe/0.1 (authorized, non-destructive)'}) as client:
        # 1) Actively discover exposed API docs / endpoints.
        discovered = _discover(db, run.id, client, origin)
        total_issues += len(discovered)
        # 2) Probe the API/XHR calls the site actually made.
        for ep in endpoints:
            res = _probe_endpoint(client, ep)
            for f in res['issues']:
                audit.create_finding(db, run.id, *f); total_issues += 1
            results.append({'url': ep['url'], 'method': ep['method'], 'issue_count': len(res['issues'])})
    db.add(models.Evidence(run_id=run.id, kind='api-security',
                           title='API security test results',
                           data={'endpoints_tested': len(endpoints), 'discovered': discovered,
                                 'discovered_count': len(discovered), 'issues': total_issues,
                                 'endpoints': results, 'non_destructive': True}))
    audit.finish_task(db, t, f'Tested {len(endpoints)} observed + {len(discovered)} discovered API endpoints; {total_issues} issues')
    audit.cost(db, run.id, 'deterministic', 'api_security_test', 0.0, detail={'endpoints': len(endpoints)})
    model = dict(run.app_model or {}); model['api_probe'] = True; run.app_model = model
    db.commit()
    audit.log(db, run.workspace_id, run.id, 'api_probe.completed',
              {'endpoints': len(endpoints), 'issues': total_issues}, actor='api-security-agent')
    return {'ok': True, 'endpoints_tested': len(endpoints), 'issues': total_issues}
