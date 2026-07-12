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
