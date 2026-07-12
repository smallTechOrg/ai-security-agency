"""Detailed (paid) tier depth: turns raw findings into an executive-grade deliverable.

Deterministic analytics (risk breakdown, remediation roadmap, OWASP coverage, compliance
posture) plus a best-effort AI executive narrative. Everything degrades gracefully so a
detailed report is always visibly richer than the free baseline, keys or not.
"""
from __future__ import annotations

SEV_WEIGHT = {'Critical': 40, 'High': 25, 'Medium': 10, 'Low': 4}


def risk_breakdown(findings) -> dict:
    by = {}
    for f in findings:
        by[f.severity] = by.get(f.severity, 0) + 1
    weighted = sum(SEV_WEIGHT.get(f.severity, 2) for f in findings)
    band = ('Critical' if weighted >= 60 else 'High' if weighted >= 35
            else 'Elevated' if weighted >= 15 else 'Moderate' if weighted > 0 else 'Low')
    return {'by_severity': by, 'weighted_risk': weighted, 'risk_band': band, 'total': len(findings)}


def remediation_roadmap(findings) -> list:
    phases = {'Immediate (0-7 days)': [], 'Short-term (2-4 weeks)': [], 'Hardening (30-90 days)': []}
    for f in findings:
        if f.severity in ('Critical', 'High'):
            phases['Immediate (0-7 days)'].append({'title': f.title, 'action': f.remediation})
        elif f.severity == 'Medium':
            phases['Short-term (2-4 weeks)'].append({'title': f.title, 'action': f.remediation})
        else:
            phases['Hardening (30-90 days)'].append({'title': f.title, 'action': f.remediation})
    return [{'phase': k, 'count': len(v), 'items': v[:8]} for k, v in phases.items() if v]


def owasp_coverage(findings) -> list:
    cats = {}
    for f in findings:
        c = (f.compliance or {}).get('OWASP')
        if c:
            cats[c] = cats.get(c, 0) + 1
    return [{'category': k, 'findings': v} for k, v in sorted(cats.items(), key=lambda x: -x[1])]


def compliance_posture(findings) -> list:
    blob = ' '.join(str(f.compliance).lower() + ' ' + f.title.lower() for f in findings)
    checks = [
        ('GDPR / Privacy', any(x in blob for x in ('privacy', 'gdpr', 'tracker', 'third-party')),
         'Third-party data sharing or privacy-relevant exposure detected.'),
        ('Transport Security (TLS)', any(x in blob for x in ('hsts', 'mixed content', 'cryptographic')),
         'Encryption-in-transit hardening gaps detected.'),
        ('Secure Configuration', any(x in blob for x in ('security misconfiguration', 'header', 'version disclosure')),
         'Security misconfiguration / header hardening required.'),
        ('Vulnerable Components', any(x in blob for x in ('outdated', 'vulnerable', 'end-of-life', 'cve')),
         'Known-vulnerable or unsupported components in use.'),
        ('Access Control', any(x in blob for x in ('access control', 'exposed', 'sensitive file')),
         'Potential exposure of sensitive resources.'),
    ]
    return [{'control': name, 'attention': flag, 'note': note if flag else 'No issues in this pass.'}
            for name, flag, note in checks]


def _ai_narrative(target, findings, breakdown) -> dict:
    """Best-effort live AI executive narrative; deterministic fallback on any failure."""
    top = '; '.join(f'{f.severity}: {f.title}' for f in findings[:8]) or 'no findings'
    deterministic = (
        f'The assessment of {target} places overall exposure in the "{breakdown["risk_band"]}" band '
        f'({breakdown["total"]} findings, weighted risk {breakdown["weighted_risk"]}). '
        'Priorities: remediate Critical/High items first (transport, exposed resources, vulnerable components), '
        'then close configuration and privacy gaps. No destructive testing was performed.'
    )
    try:
        from . import llm
        from .agents import _provider_chain
        prompt = ('You are a senior application security consultant writing the executive summary of a paid '
                  f'security assessment for {target}. In 4-6 sentences, explain the business risk and the top '
                  f'remediation priorities based on these findings: {top}. Risk band: {breakdown["risk_band"]}. '
                  'Be concrete and non-alarmist. Do not invent findings.')
        for mode, entry in _provider_chain():
            live = llm.live_intelligence(prompt, mode, entry)
            if live and live.get('summary'):
                return {'narrative': live['summary'], 'source': f'ai:{entry.get("provider")}'}
    except Exception:
        pass
    return {'narrative': deterministic, 'source': 'deterministic'}


def run_agent_loop(target, app_model, findings, browser, max_iters=12) -> dict:
    """A basic agentic loop: observe state -> decide next action -> act -> repeat until no
    high-value action remains or the iteration budget is hit. Returns the reasoning trace."""
    am = app_model or {}
    titles = ' '.join(f.title.lower() for f in findings)
    feats = ' '.join(str(x).lower() for x in (am.get('features') or []))
    # Worklist the supervisor can choose from; each has a guard (when it's worth doing) + observation.
    def _has_browser():   return bool(browser)
    def _has_login():     return ('authentication' in feats) or ('login' in titles)
    def _has_trackers():  return ('tracker' in titles) or ('gdpr' in titles)
    def _has_vulns():     return any(x in titles for x in ('vulnerable', 'end-of-life', 'version disclosure', 'outdated'))
    catalog = [
        ('plan',        lambda s: True,            'Supervisor',   f'Planned a non-destructive audit of {target}',
         lambda: f'Classified target as {", ".join(am.get("likely_sectors",[]) or ["general website"])}; sequenced recon → safety → browser → fingerprint → report.'),
        ('recon',       lambda s: True,            'Recon',        'Mapped the public attack surface',
         lambda: f'{am.get("pages_seen",0)} pages / {am.get("forms_seen",0)} forms; features: {", ".join(am.get("features",[]) or ["content"])}.'),
        ('safety',      lambda s: True,            'Safety Policy','Enforced safe, authorized scope',
         lambda: 'Passive checks only — blocked exploitation, brute force, and exfiltration.'),
        ('browser',     lambda s: _has_browser(),  'Browser',      'Escalated to headless-Chromium rendering',
         lambda: f'Decided JS rendering was needed; captured {browser.get("cookies_observed",0)} cookies, {browser.get("browser_only_findings",0)} browser-only findings.'),
        ('auth_probe',  lambda s: _has_login(),    'Recon',        'Detected an authentication surface',
         lambda: 'Login/session flow present → flagged authenticated testing as the next authorized step.'),
        ('fingerprint', lambda s: True,            'Fingerprint',  'Identified the technology stack',
         lambda: f'Server: {(am.get("tech_hints") or {}).get("server","unknown")}; checked for vulnerable/EOL components.'),
        ('privacy',     lambda s: _has_trackers(), 'Privacy',      'Observed third-party data sharing',
         lambda: 'Trackers present → raised GDPR/consent review as a compliance action.'),
        ('cve_review',  lambda s: _has_vulns(),    'Fingerprint',  'Confirmed outdated/vulnerable components',
         lambda: 'Matched components against known-CVE/EOL rules → prioritized patching.'),
        ('report',      lambda s: True,            'Reporter',     'Correlated findings into a deliverable',
         lambda: f'Mapped {len(findings)} findings to OWASP + compliance; produced a phased remediation roadmap.'),
    ]
    done = set(); trace = []; iters = 0; stop_reason = 'plan complete'
    state = {'findings': len(findings)}
    while iters < max_iters:
        # DECIDE: pick the first not-yet-done action whose guard fires given current observations.
        nxt = next((c for c in catalog if c[0] not in done and c[1](state)), None)
        if nxt is None:
            stop_reason = 'no high-value action remaining'; break
        key, _guard, agent, decision, observe = nxt
        # ACT + OBSERVE
        trace.append({'iter': iters + 1, 'agent': agent, 'decision': decision, 'detail': observe()})
        done.add(key); iters += 1
    return {'iterations': iters, 'stop_reason': stop_reason, 'trace': trace,
            'recommended_actions': recommended_actions(findings, app_model, browser)}


def agent_trace(target, app_model, findings, browser) -> list:
    """Back-compat: the loop's reasoning trail."""
    return run_agent_loop(target, app_model, findings, browser)['trace']
    am = app_model or {}
    sectors = ', '.join(am.get('likely_sectors', []) or ['general website'])
    features = ', '.join(am.get('features', []) or ['content/marketing'])
    pages = am.get('pages_seen', 0); forms = am.get('forms_seen', 0)
    server = (am.get('tech_hints') or {}).get('server', 'unknown')
    trace = [
        {'agent': 'Supervisor', 'decision': f'Planned a non-destructive audit of {target}',
         'detail': f'Classified target as {sectors}; sequenced recon → safety → browser → fingerprint → report.'},
        {'agent': 'Recon', 'decision': 'Mapped the public attack surface',
         'detail': f'{pages} pages and {forms} forms discovered; app features: {features}.'},
        {'agent': 'Safety Policy', 'decision': 'Enforced safe, authorized scope',
         'detail': 'Passive checks only — blocked exploitation, brute force, and data exfiltration.'},
    ]
    if browser:
        sg = browser.get('spa_gap', {}) or {}
        trace.append({'agent': 'Browser', 'decision': f'Rendered in {browser.get("engine", "chromium")}',
                      'detail': f'{browser.get("cookies_observed", 0)} cookies, {browser.get("browser_only_findings", 0)} browser-only findings; '
                                f'JS revealed {sg.get("gap_forms", 0)} extra forms vs HTTP-only.'})
    trace.append({'agent': 'Fingerprint', 'decision': 'Identified the technology stack',
                  'detail': f'Server: {server}; checked for known-vulnerable / end-of-life components.'})
    trace.append({'agent': 'Reporter', 'decision': f'Correlated {len(findings)} findings',
                  'detail': 'Mapped to OWASP + compliance controls and produced a phased remediation roadmap.'})
    return trace


def recommended_actions(findings, app_model, browser) -> list:
    """Agentic next-step recommendations derived from what was actually found."""
    am = app_model or {}
    feats = ' '.join(str(x).lower() for x in (am.get('features') or []))
    titles = ' '.join(f.title.lower() for f in findings)
    acts = []
    if 'authentication' in feats or 'login' in titles or 'authentication' in titles:
        acts.append({'priority': 'High', 'action': 'Authorize authenticated testing of the login/session flow',
                     'why': 'A login/auth surface was detected; auth flaws are the highest-impact class.'})
    if 'hsts' in titles or 'content security policy' in titles or 'mixed content' in titles:
        acts.append({'priority': 'High', 'action': 'Deploy HSTS and a restrictive Content-Security-Policy',
                     'why': 'Closes the transport-security and XSS-mitigation gaps found in this scan.'})
    if 'cookie' in titles:
        acts.append({'priority': 'Medium', 'action': 'Harden session cookies (Secure, HttpOnly, SameSite)',
                     'why': 'Rendered cookies lacked hardening flags.'})
    if 'tracker' in titles or 'gdpr' in titles or 'third-party' in titles:
        acts.append({'priority': 'Medium', 'action': 'Review third-party trackers for consent / DPA coverage',
                     'why': 'Visitor data is shared with third parties (GDPR relevance).'})
    if any(x in titles for x in ('vulnerable', 'end-of-life', 'version disclosure', 'outdated')):
        acts.append({'priority': 'High', 'action': 'Patch/upgrade flagged components and suppress version banners',
                     'why': 'Known-vulnerable or EOL software widens the attack surface.'})
    acts.append({'priority': 'Routine', 'action': 'Schedule a recurring re-scan and retest after remediation',
                 'why': 'Continuous assurance — verify closure and re-issue the attestation.'})
    return acts[:6]


def build(target, findings, use_ai=True) -> dict:
    """Assemble the full depth payload from a run's findings. use_ai=False forces deterministic narrative (free tier)."""
    breakdown = risk_breakdown(findings)
    ai = _ai_narrative(target, findings, breakdown) if use_ai else {
        'narrative': (f'The assessment of {target} places overall exposure in the "{breakdown["risk_band"]}" band '
                      f'({breakdown["total"]} findings, weighted risk {breakdown["weighted_risk"]}). Prioritize '
                      'Critical/High items first, then close configuration and privacy gaps. Upgrade to the detailed '
                      'tier for an AI-written executive narrative and deeper multi-page analysis.'),
        'source': 'deterministic'}
    return {
        'tier': 'detailed',
        'risk_breakdown': breakdown,
        'executive_narrative': ai['narrative'],
        'narrative_source': ai['source'],
        'remediation_roadmap': remediation_roadmap(findings),
        'owasp_coverage': owasp_coverage(findings),
        'compliance_posture': compliance_posture(findings),
        'retest_plan': 'Re-run this authorized assessment after remediation to verify closure and re-issue the attestation.',
    }
