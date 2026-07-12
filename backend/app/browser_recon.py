from __future__ import annotations
from urllib.parse import urljoin, urlparse
import json, re, time
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from . import models, audit
from .config import settings
from .artifacts import write_text_artifact, run_dir

# Secrets that must never ship to the browser. Matches live keys, not placeholders.
JS_SECRET_RE = re.compile(
    r'(AKIA[0-9A-Z]{16}'                              # AWS access key id
    r'|AIza[0-9A-Za-z_\-]{35}'                        # Google API key
    r'|sk-[A-Za-z0-9]{20,}'                           # OpenAI-style secret key
    r'|sk_live_[0-9a-zA-Z]{20,}'                      # Stripe live secret
    r'|ghp_[0-9a-zA-Z]{36}'                           # GitHub PAT
    r'|xox[baprs]-[0-9A-Za-z\-]{10,}'                 # Slack token
    r'|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'     # private key material
)
# Known third-party data/tracking origins (privacy / GDPR relevance).
TRACKER_HINTS = ('google-analytics.com', 'googletagmanager.com', 'doubleclick.net', 'facebook.net',
                 'connect.facebook', 'hotjar.com', 'segment.io', 'segment.com', 'mixpanel.com',
                 'fullstory.com', 'clarity.ms', 'analytics.tiktok', 'ads-twitter.com')


def _render_with_browser(url: str, run_id: int) -> dict:
    """Render the target in headless Chromium and capture the real, post-JavaScript surface.

    Returns {'available': True, ...} on success or {'available': False, 'reason': ...} so the
    caller can fall back to an HTTP-only pass and keep the run alive.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {'available': False, 'reason': 'playwright_import:' + type(e).__name__}
    network: list[dict] = []
    console: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=settings.browser_headless)
            context = browser.new_context(viewport={'width': 1365, 'height': 900},
                                          user_agent='Zer0-Vanguard-BrowserRecon/0.2')
            page = context.new_page()
            page.on('console', lambda m: console.append({'type': m.type, 'text': (m.text or '')[:300]}))
            page.on('request', lambda r: network.append(
                {'url': r.url[:500], 'method': r.method, 'resource_type': r.resource_type}))
            page.goto(url, wait_until='networkidle', timeout=settings.browser_timeout_ms)
            title = page.title()
            rendered_html = page.content()
            body_excerpt = (page.locator('body').inner_text(timeout=3000))[:3000]
            cookies = context.cookies()
            shot = run_dir(run_id) / 'homepage.png'
            page.screenshot(path=str(shot), full_page=True)
            context.close()
            browser.close()
            return {
                'available': True, 'engine': 'chromium', 'title': title,
                'rendered_html': rendered_html, 'body_excerpt': body_excerpt,
                'cookies': cookies, 'network': network[:settings.browser_max_network_events],
                'console': console[:60], 'screenshot': str(shot),
            }
    except Exception as e:
        return {'available': False, 'reason': type(e).__name__ + ':' + str(e)[:200],
                'network': network[:settings.browser_max_network_events], 'console': console[:60]}


def _dom_surface(html: str, base_url: str) -> dict:
    """Extract the interactive surface (links, forms, scripts) from a rendered/raw DOM."""
    soup = BeautifulSoup(html or '', 'html.parser')
    links = [urljoin(base_url, a.get('href')) for a in soup.select('a[href]')[:60]]
    forms = [{'action': urljoin(base_url, f.get('action') or ''),
              'method': (f.get('method') or 'GET').upper(),
              'inputs': [i.get('name') or i.get('type') or 'unnamed' for i in f.select('input,textarea,select')],
              'has_password': bool(f.select('input[type=password]'))}
             for f in soup.select('form')[:20]]
    scripts = [urljoin(base_url, s.get('src')) for s in soup.select('script[src]')[:40]]
    inline_js = ' '.join((s.string or '')[:4000] for s in soup.select('script:not([src])')[:20])
    return {'links': links, 'forms': forms, 'scripts': scripts,
            'inline_js': inline_js, 'text': soup.get_text(' ', strip=True)[:6000]}


# ---- Browser-only security analyzers (things a plain HTTP scanner cannot see) ----

def _finding(db, run_id, sev, title, desc, evidence, remediation, compliance):
    audit.create_finding(db, run_id, sev, title, desc, evidence, remediation, compliance)


def analyze_cookies(db, run_id, url, cookies) -> int:
    is_https = urlparse(url).scheme == 'https'
    weak = []
    for c in cookies or []:
        issues = []
        if is_https and not c.get('secure'):
            issues.append('missing Secure')
        if not c.get('httpOnly'):
            issues.append('missing HttpOnly')
        if not c.get('sameSite') or str(c.get('sameSite')).lower() == 'none':
            issues.append('weak SameSite')
        if issues:
            weak.append({'name': c.get('name', '?'), 'issues': issues})
    if weak:
        _finding(db, run_id, 'Medium', 'Insecure cookie flags on rendered session cookies',
                 f'{len(weak)} cookie(s) set during real browser rendering lack hardening flags. '
                 'These are only observable after JavaScript executes and are invisible to an HTTP-only header scan.',
                 json.dumps(weak)[:1500],
                 'Set Secure, HttpOnly, and SameSite=Lax/Strict on session and auth cookies.',
                 {'OWASP': 'A05 Security Misconfiguration', 'privacy': 'session integrity'})
        return 1
    return 0


def analyze_mixed_content(db, run_id, url, network) -> int:
    if urlparse(url).scheme != 'https':
        return 0
    insecure = [n for n in (network or []) if str(n.get('url', '')).startswith('http://')]
    if insecure:
        sample = list({n['url'] for n in insecure})[:6]
        _finding(db, run_id, 'Medium', 'Mixed content: HTTPS page loads insecure HTTP subresources',
                 f'The page loaded {len(insecure)} resource(s) over plaintext HTTP from an HTTPS origin, '
                 'observed via real browser network capture. Attackers on the path can tamper with these.',
                 json.dumps(sample)[:1200],
                 'Serve all subresources over HTTPS and add a Content-Security-Policy upgrade-insecure-requests directive.',
                 {'OWASP': 'A02 Cryptographic Failures'})
        return 1
    return 0


def analyze_js_secrets(db, run_id, rendered_html, inline_js, network) -> int:
    haystack = (rendered_html or '')[:400000] + ' ' + (inline_js or '')
    haystack += ' ' + ' '.join(n.get('url', '') for n in (network or []))
    hits = list({m.group(0)[:12] + '…' for m in JS_SECRET_RE.finditer(haystack)})
    if hits:
        _finding(db, run_id, 'High', 'Potential secret/API key exposed in client-side JavaScript',
                 f'{len(hits)} high-entropy credential pattern(s) were found in rendered client-side code or '
                 'request URLs. Client-shipped secrets can be extracted by any visitor. Values are shown truncated only.',
                 json.dumps(hits)[:800],
                 'Move secrets server-side, rotate any exposed key immediately, and use scoped public tokens for the browser.',
                 {'OWASP': 'A07 Identification & Auth Failures', 'severity_note': 'rotate keys'})
        return 1
    return 0


def analyze_third_parties(db, run_id, url, network) -> int:
    origin = urlparse(url).netloc
    third = {}
    for n in (network or []):
        host = urlparse(n.get('url', '')).netloc
        if host and host != origin and not host.endswith(origin):
            third.setdefault(host, 0)
            third[host] += 1
    trackers = [h for h in third if any(t in h for t in TRACKER_HINTS)]
    if trackers:
        _finding(db, run_id, 'Low', 'Third-party trackers receive visitor data (privacy/GDPR)',
                 f'The page shares visitor requests with {len(trackers)} known tracking/analytics origin(s), '
                 'captured from real browser network traffic. This carries consent and data-transfer obligations.',
                 json.dumps(sorted(trackers))[:1000],
                 'Confirm a lawful basis and cookie consent for each third-party processor; gate non-essential tags behind consent.',
                 {'privacy': 'GDPR data sharing', 'OWASP': 'A05 Security Misconfiguration'})
        return 1
    return 0


def analyze_spa_gap(db, run_id, raw, rendered) -> dict:
    """Quantify how much attack surface JavaScript reveals that the HTTP-only baseline missed."""
    raw_forms, rendered_forms = len(raw['forms']), len(rendered['forms'])
    raw_links, rendered_links = len(raw['links']), len(rendered['links'])
    gap_forms = max(0, rendered_forms - raw_forms)
    gap_links = max(0, rendered_links - raw_links)
    js_heavy = len((raw.get('text') or '')) < 500 and len((rendered.get('text') or '')) > 1500
    revealed = js_heavy or gap_forms > 0 or gap_links >= 5
    if revealed:
        _finding(db, run_id, 'Low', 'JavaScript-rendered surface not visible to HTTP-only scanning',
                 f'Real browser rendering exposed {rendered_forms} forms / {rendered_links} links versus '
                 f'{raw_forms} forms / {raw_links} links seen by a plain HTTP fetch'
                 + (' (single-page-app shell detected)' if js_heavy else '') + '. '
                 'HTTP-only baselines under-report the true attack surface of modern apps.',
                 json.dumps({'raw': {'forms': raw_forms, 'links': raw_links},
                             'rendered': {'forms': rendered_forms, 'links': rendered_links}})[:800],
                 'Assess authenticated and client-rendered flows with browser-driven testing, not header checks alone.',
                 {'coverage': 'client-rendered app surface'})
    return {'raw_forms': raw_forms, 'rendered_forms': rendered_forms, 'raw_links': raw_links,
            'rendered_links': rendered_links, 'gap_forms': gap_forms, 'gap_links': gap_links,
            'spa_shell': js_heavy, 'surface_revealed': revealed}


def _detect_takeover(text: str) -> tuple[bool, str]:
    for marker in ('captcha', 'verify you are human', 'multi-factor', 'one-time code', 'enter the code'):
        if marker in (text or '').lower():
            return True, f'Auth/anti-bot wall indicator ("{marker}") found; pause for human-assisted browser takeover.'
    return False, ''


def run_browser_recon(db: Session, run_id: int) -> models.AuditRun:
    run = db.get(models.AuditRun, run_id)
    asset = db.get(models.Asset, run.asset_id)
    run.status = 'running'; run.stage = 'browser_recon'; run.progress = max(run.progress, 35); db.commit()
    t = audit.task(db, run.id, 'browser_assisted_recon', asset.url)
    started = time.time()

    # Always take a raw HTTP snapshot (fallback source + SPA-gap comparison baseline).
    raw_html = ''
    try:
        with httpx.Client(timeout=10, follow_redirects=True,
                          headers={'User-Agent': 'Zer0-Vanguard-BrowserRecon/0.2'}) as client:
            raw_html = client.get(asset.url).text
    except Exception as e:
        raw_html = ''
        audit.log(db, run.workspace_id, run.id, 'browser_recon.raw_fetch_failed', {'error': type(e).__name__})

    browser = _render_with_browser(asset.url, run.id)
    engine = 'chromium' if browser.get('available') else 'http-fallback'
    rendered_html = browser.get('rendered_html') if browser.get('available') else raw_html

    if not rendered_html and not raw_html:
        t.status = 'failed'; t.error = 'no_content:' + str(browser.get('reason', ''))[:200]
        run.status = 'failed'; run.stage = 'browser_recon_failed'; db.commit()
        audit.log(db, run.workspace_id, run.id, 'browser_recon.failed', {'reason': browser.get('reason')})
        return run

    raw_surface = _dom_surface(raw_html, asset.url)
    rendered_surface = _dom_surface(rendered_html, asset.url)
    network = browser.get('network', [])
    cookies = browser.get('cookies', [])
    console = browser.get('console', [])

    # Run browser-only analyzers → real findings that feed the score, report, and tickets.
    findings_added = 0
    findings_added += analyze_cookies(db, run.id, asset.url, cookies)
    findings_added += analyze_mixed_content(db, run.id, asset.url, network)
    findings_added += analyze_js_secrets(db, run.id, rendered_html, rendered_surface['inline_js'], network)
    findings_added += analyze_third_parties(db, run.id, asset.url, network)
    spa = analyze_spa_gap(db, run.id, raw_surface, rendered_surface)
    findings_added += 1 if spa['surface_revealed'] else 0

    takeover, takeover_reason = _detect_takeover(rendered_surface['text'])

    page_model = {
        'url': asset.url, 'engine': engine, 'title': browser.get('title') or rendered_surface['text'][:80],
        'links': rendered_surface['links'], 'forms': rendered_surface['forms'],
        'scripts': rendered_surface['scripts'],
        'cookies': [{'name': c.get('name'), 'secure': c.get('secure'), 'httpOnly': c.get('httpOnly'),
                     'sameSite': c.get('sameSite')} for c in cookies][:30],
        'network_sample': network[:40], 'console_sample': console[:20],
        'spa_gap': spa, 'human_takeover': takeover, 'takeover_reason': takeover_reason,
        'screenshot': browser.get('screenshot'),
    }
    if not browser.get('available'):
        page_model['browser_unavailable_reason'] = browser.get('reason')

    html_path = write_text_artifact(run.id, 'rendered_dom.html', (rendered_html or '')[:400000])
    json_path = write_text_artifact(run.id, 'browser_recon.json', json.dumps(page_model, indent=2, default=str))
    screenshot_available = bool(browser.get('screenshot'))

    db.add(models.Evidence(run_id=run.id, kind='browser-recon',
                           title=f'Browser-assisted recon ({engine})',
                           data={'model': page_model, 'artifacts': [html_path, json_path],
                                 'screenshot_available': screenshot_available,
                                 'browser_findings': findings_added}))
    audit.finish_task(db, t, f"{engine}: {len(page_model['links'])} links, {len(page_model['forms'])} forms, "
                             f"{len(cookies)} cookies, {findings_added} browser-only findings")
    audit.cost(db, run.id, 'browser-recon', 'browser_recon', 0.03,
               detail={'engine': engine, 'findings': findings_added, 'network_events': len(network)})
    run.stage = 'browser_recon_complete'; run.progress = max(run.progress, 80)
    run.status = 'completed'
    model = dict(run.app_model or {})
    model['browser_recon'] = {'engine': engine, 'findings': findings_added,
                              'screenshot_available': screenshot_available,
                              'spa_surface_revealed': spa['surface_revealed'],
                              'elapsed_sec': round(time.time() - started, 2)}
    run.app_model = model
    db.commit()
    audit.log(db, run.workspace_id, run.id, 'browser_recon.completed',
              {'engine': engine, 'human_takeover': takeover, 'browser_findings': findings_added,
               'screenshot': screenshot_available, 'artifacts': [html_path, json_path]})
    return run
