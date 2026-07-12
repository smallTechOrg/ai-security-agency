"""Real LLM-backed sub-agents. Each has its own role/system prompt and makes its own
LLM call. Starts with the Reporter agent; more roles can follow the same pattern.
"""
from __future__ import annotations


def _provider_chain():
    """Ordered list of live providers to try (selector choice first, then any other configured key)."""
    from .intelligence_settings import get_mode, current_entry
    from .config import settings
    chain = []
    entry = current_entry()
    if entry.get('provider') in ('gemini', 'openai'):
        chain.append((get_mode(), entry))
    if settings.gemini_key_present and not any(e[1]['provider'] == 'gemini' for e in chain):
        chain.append(('gemini', {'provider': 'gemini', 'model': settings.gemini_model}))
    if settings.openai_key_present and not any(e[1]['provider'] == 'openai' for e in chain):
        chain.append(('openai', {'provider': 'openai', 'model': settings.openai_model}))
    return chain


REPORTER_SYSTEM = (
    "You are the Reporter agent in an authorized web security assessment. Your job is to translate "
    "raw technical findings into a concise business-impact assessment a non-technical owner can act on. "
    "Be specific and non-alarmist. Do NOT invent findings beyond those provided. "
    "Write 4-6 sentences covering: what a customer/business stands to lose, which 2-3 issues to fix first, "
    "and why. No markdown, no headings — plain prose."
)


ANALYST_SYSTEM = (
    "You are the Threat Analyst agent in an authorized web security assessment. Given the findings, "
    "identify the single most important attack path or risk to address first and explain the likely "
    "exploitation scenario and impact in 3-4 sentences. Be concrete about the chain of events. "
    "Do NOT invent findings beyond those provided. No markdown, plain prose."
)


def analyst_agent(target, findings, app_model, db=None, run_id=None) -> dict:
    """Second LLM-backed sub-agent: threat prioritization / attack-path reasoning."""
    sectors = ', '.join((app_model or {}).get('likely_sectors', []) or ['general website'])
    finding_lines = '; '.join(f'{f.severity}: {f.title}' for f in findings[:12]) or 'no findings'
    deterministic = (
        f'The highest-priority path on {target} is chaining missing transport/security headers with weak '
        'cookie flags: without HSTS/CSP and with non-hardened session cookies, an on-path or XSS foothold can '
        'lead to session theft and account takeover. Address header hardening and cookie flags first to break '
        'that chain; third-party exposure is a secondary privacy concern.'
    )
    try:
        prompt = (f'{ANALYST_SYSTEM}\n\nTarget: {target}\nBusiness type: {sectors}\n'
                  f'Findings: {finding_lines}\n\nGive your threat-prioritization analysis now.')
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Analyst', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Analyst', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'reasoning': out['summary'].strip()}
    except Exception:
        pass
    return {'agent': 'Analyst', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'reasoning': deterministic}


REMEDIATION_SYSTEM = (
    "You are the Remediation Engineer agent. For the given findings, provide concrete, copy-paste "
    "remediation for the top 3-4 issues: exact HTTP response headers, cookie attributes, or config "
    "directives (nginx/Apache/express as appropriate). Keep it tight and actionable. "
    "Do NOT invent findings. Use short labelled snippets, one per issue."
)


def remediation_agent(target, findings, app_model, db=None, run_id=None) -> dict:
    """Third LLM-backed sub-agent: concrete remediation snippets for the findings."""
    finding_lines = '; '.join(f'{f.severity}: {f.title}' for f in findings[:12]) or 'no findings'
    deterministic = (
        'Add security headers (nginx): '
        'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always; '
        'add_header Content-Security-Policy "default-src \'self\'" always; '
        'add_header X-Frame-Options DENY always; add_header X-Content-Type-Options nosniff always. '
        'Harden cookies: Set-Cookie: <name>=<v>; Secure; HttpOnly; SameSite=Lax.'
    )
    try:
        prompt = (f'{REMEDIATION_SYSTEM}\n\nTarget: {target}\nFindings: {finding_lines}\n\n'
                  'Write the remediation snippets now.')
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Remediation', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Remediation', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'fixes': out['summary'].strip()}
    except Exception:
        pass
    return {'agent': 'Remediation', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'fixes': deterministic}


REDTEAM_SYSTEM = (
    "You are the Red Team agent. Think like an attacker: from the given findings, describe the most "
    "plausible ATTACK CHAIN — how an adversary would combine these weaknesses step by step to reach a "
    "concrete objective (account takeover, data access, defacement). 3-5 numbered steps. This is analysis "
    "for the defender's report; do NOT provide working exploit code and do NOT invent findings."
)


def redteam_agent(target, findings, app_model, db=None, run_id=None) -> dict:
    """Offensive-analysis LLM sub-agent: attacker's-eye attack chain (analysis only, no exploit code)."""
    finding_lines = '; '.join(f'{f.severity}: {f.title}' for f in findings[:12]) or 'no findings'
    deterministic = (
        '1) Recon: enumerate the exposed surface and missing headers. '
        '2) Foothold: leverage a reflected-input or CORS gap to run script in a victim session. '
        '3) Escalate: pair weak cookie flags with clickjacking/host-header issues to hijack an authenticated '
        'session. 4) Impact: act as the victim (account takeover / data access). Breaking any single link '
        '(CSP, cookie flags, header validation) collapses the chain.'
    )
    try:
        prompt = (f'{REDTEAM_SYSTEM}\n\nTarget: {target}\nFindings: {finding_lines}\n\n'
                  'Give the attack-chain analysis now.')
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Red Team', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Red Team', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'attack_chain': out['summary'].strip()}
    except Exception:
        pass
    return {'agent': 'Red Team', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'attack_chain': deterministic}


def reporter_agent(target, findings, app_model, db=None, run_id=None) -> dict:
    """LLM-backed Reporter sub-agent → business-impact assessment. Deterministic fallback on any failure."""
    am = app_model or {}
    sectors = ', '.join(am.get('likely_sectors', []) or ['general website'])
    finding_lines = '; '.join(f'{f.severity}: {f.title}' for f in findings[:12]) or 'no findings'
    deterministic = (
        f'Across {len(findings)} findings on {target} ({sectors}), the main business exposure is weakened '
        'defense-in-depth: missing security headers and cookie hardening make session hijacking and clickjacking '
        'easier, and any third-party tracking raises privacy/GDPR obligations. Fix transport and header hardening '
        '(HSTS, CSP) and session-cookie flags first, then review third-party data sharing. None of these require '
        'downtime to remediate.'
    )
    try:
        prompt = (f'{REPORTER_SYSTEM}\n\nTarget: {target}\nBusiness type: {sectors}\n'
                  f'Findings: {finding_lines}\n\nWrite the business-impact assessment now.')
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Reporter', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Reporter', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'assessment': out['summary'].strip()}
    except Exception:
        pass
    return {'agent': 'Reporter', 'llm_backed': False, 'source': 'deterministic',
            'model': None, 'assessment': deterministic}
