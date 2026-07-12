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


DEEP_SYSTEM = (
    "You are a senior penetration tester doing a deep manual review. You are given the REAL captured "
    "data from an authorized assessment (response headers, cookies, the API/XHR endpoints the site calls, "
    "detected tech, forms, and exposed paths). Identify SPECIFIC, non-generic security issues and concrete "
    "attack ideas grounded in THIS data — call out exact endpoints, headers, or params. Prioritize the "
    "highest-impact items (auth, API access control, injection, secrets, IDOR). 4-7 short bullet points. "
    "Do not restate generic best practices; be specific to what you see. No exploit code."
)


def deep_analysis_agent(target, context, db=None, run_id=None) -> dict:
    """LLM deep-dive over the real captured evidence — finds site-specific issues a checklist misses."""
    import json as _json
    ctx = _json.dumps(context, default=str)[:9000]
    deterministic = ('Deep analysis requires a live model; review the captured endpoints and headers manually. '
                     'Focus on any API returning data without auth, permissive CORS, and exposed docs.')
    try:
        prompt = f'{DEEP_SYSTEM}\n\nTarget: {target}\nCAPTURED DATA:\n{ctx}\n\nGive your deep findings now.'
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Deep Analysis', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Deep Analysis', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'findings_text': out['summary'].strip()}
    except Exception:
        pass
    return {'agent': 'Deep Analysis', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'findings_text': deterministic}


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


COMPLIANCE_SYSTEM = (
    "You are the Compliance Mapper agent for an authorized web security assessment. Map only the given "
    "findings to common control themes (OWASP Top 10, SOC 2 Security/Availability, ISO 27001 Annex A, "
    "PCI DSS if payment context is present, GDPR if privacy/cookies are present). Do not claim formal "
    "certification. Return 4-7 short bullets: control, evidence, remediation owner."
)


def compliance_agent(target, findings, app_model, db=None, run_id=None) -> dict:
    """Compliance-mapping sub-agent with deterministic fallback."""
    finding_lines = '; '.join(f'{f.severity}: {f.title} ({(f.compliance or {}).get("OWASP", "unmapped")})' for f in findings[:12]) or 'no findings'
    deterministic = (
        'OWASP A05 Security Misconfiguration: missing browser security headers require platform-team remediation. '
        'SOC 2 CC7/CC8: findings should be tracked through a change/retest workflow. '
        'ISO 27001 Annex A 8.8/8.9: technical vulnerability management and configuration management evidence is needed. '
        'GDPR privacy review is recommended if cookies or third-party trackers are present. This is a control map, not a compliance attestation.'
    )
    try:
        prompt = (f'{COMPLIANCE_SYSTEM}\n\nTarget: {target}\nApp context: {app_model or {}}\n'
                  f'Findings: {finding_lines}\n\nProduce the control map now.')
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Compliance Mapper', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Compliance Mapper', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'control_map': out['summary'].strip(),
                    'disclaimer': 'control mapping only; not a compliance certificate'}
    except Exception:
        pass
    return {'agent': 'Compliance Mapper', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'control_map': deterministic, 'disclaimer': 'control mapping only; not a compliance certificate'}


def evidence_qa_agent(target, findings, evidence) -> dict:
    """Deterministic quality gate: every finding should have evidence and a remediation."""
    evidence_kinds = sorted({e.kind for e in evidence})
    gaps = []
    for f in findings:
        if not (f.evidence or '').strip():
            gaps.append({'severity': f.severity, 'title': f.title, 'gap': 'missing evidence text'})
        if not (f.remediation or '').strip():
            gaps.append({'severity': f.severity, 'title': f.title, 'gap': 'missing remediation'})
    required = {'crawl', 'headers', 'tls', 'common-files'}
    missing = sorted(required - set(evidence_kinds))
    if missing:
        gaps.append({'severity': 'Medium', 'title': target, 'gap': 'missing evidence kinds: ' + ', '.join(missing)})
    return {'agent': 'Evidence QA', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'evidence_kinds': evidence_kinds, 'claims_checked': len(findings), 'gaps': gaps,
            'ready_for_client': len(gaps) == 0}


SUPERVISOR_SYSTEM = (
    "You are the Supervisor agent for a multi-agent security assessment. Summarize the specialists' outputs "
    "into a decision record: current risk, top two work items, whether evidence is strong enough for client "
    "delivery, and which agent should run next. Keep it executive, concrete, and evidence-bound."
)


def supervisor_agent(target, findings, app_model, specialist_outputs, db=None, run_id=None) -> dict:
    """Supervisor/routing agent over the specialist results."""
    high = [f for f in findings if f.severity in {'Critical', 'High'}]
    deterministic = (
        f'{target} has {len(findings)} validated findings ({len(high)} Critical/High). '
        'Priority is to break the highest-risk chain, ship header/cookie hardening, then retest and close tickets. '
        'Evidence QA gates client delivery; unresolved evidence gaps should be fixed before certificate-style language is used.'
    )
    try:
        import json as _json
        payload = _json.dumps(specialist_outputs, default=str)[:8000]
        prompt = (f'{SUPERVISOR_SYSTEM}\n\nTarget: {target}\nApp context: {app_model or {}}\n'
                  f'Findings count: {len(findings)}\nSpecialists:\n{payload}\n\nWrite the decision record now.')
        chain = _provider_chain()
        out = entry = None
        if db is not None:
            from . import observability
            out, entry = observability.call_with_trace(db, run_id, 'Supervisor', prompt, chain)
        else:
            from . import llm
            for m, e in chain:
                r = llm.live_intelligence(prompt, m, e)
                if r and r.get('summary'):
                    out, entry = r, e; break
        if out and out.get('summary'):
            return {'agent': 'Supervisor', 'llm_backed': True, 'source': f'ai:{entry.get("provider")}',
                    'model': entry.get('model'), 'decision_record': out['summary'].strip(),
                    'next_agent': 'Remediation Engineer' if high else 'Evidence QA'}
    except Exception:
        pass
    return {'agent': 'Supervisor', 'llm_backed': False, 'source': 'deterministic', 'model': None,
            'decision_record': deterministic, 'next_agent': 'Remediation Engineer' if high else 'Evidence QA'}
