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
        from .intelligence_settings import get_mode, current_entry
        from .config import settings
        from . import llm
        mode = get_mode(); entry = current_entry()
        # Detailed tier: if the selector is on deterministic but a key exists, still use AI for the narrative.
        if entry.get('provider') not in ('gemini', 'openai'):
            if settings.gemini_key_present:
                entry = {'provider': 'gemini', 'model': settings.gemini_model}; mode = 'gemini'
            elif settings.openai_key_present:
                entry = {'provider': 'openai', 'model': settings.openai_model}; mode = 'openai'
        if entry.get('provider') in ('gemini', 'openai'):
            prompt = ('You are a senior application security consultant writing the executive summary of a paid '
                      f'security assessment for {target}. In 4-6 sentences, explain the business risk and the top '
                      f'remediation priorities based on these findings: {top}. Risk band: {breakdown["risk_band"]}. '
                      'Be concrete and non-alarmist. Do not invent findings.')
            live = llm.live_intelligence(prompt, mode, entry)
            if live and live.get('summary'):
                return {'narrative': live['summary'], 'source': f'ai:{entry.get("provider")}'}
    except Exception:
        pass
    return {'narrative': deterministic, 'source': 'deterministic'}


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
