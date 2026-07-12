from __future__ import annotations
import json, re, httpx
from sqlalchemy.orm import Session
from .config import settings
from . import models, audit
from .intelligence_settings import get_mode, current_entry

SECRET_RE = re.compile(r'(sk-[A-Za-z0-9_-]{12,}|api[_-]?key\s*[:=]\s*[^\s]+|password\s*[:=]\s*[^\s]+|token\s*[:=]\s*[^\s]+)', re.I)


def redact(obj):
    text = json.dumps(obj, default=str)[:12000]
    return SECRET_RE.sub('[REDACTED]', text)


def estimate_cost(prompt: str) -> dict:
    toks = max(1, len(prompt) // 4)
    return {'estimated_tokens': toks, 'estimated_usd': round(toks / 1000 * 0.003, 4)}


def deterministic_intelligence(report: dict, playbooks: list[models.Playbook]) -> dict:
    return {
        'mode': 'deterministic-fallback',
        'summary': report['executive_summary'],
        'business_risk': 'Baseline public-site posture has reviewable security-hardening gaps. No destructive testing was performed.',
        'recommended_playbooks': [{'id': p.id, 'name': p.name, 'trigger': p.trigger} for p in playbooks[:5]],
        'reviewer_notes': [
            'Validate evidence before client delivery.',
            'Approve browser/authenticated testing only when scope and budget are explicit.',
        ],
        'certificate_language': 'Internal baseline attestation only; not a legal compliance certificate until reviewer sign-off and scoped controls are complete.',
    }


def live_intelligence(prompt: str, mode: str, entry: dict) -> dict | None:
    """Call the selected live provider once (one call per deliverable). Returns None on any failure."""
    try:
        if entry['provider'] == 'gemini':
            if not settings.gemini_key_present:
                return None
            url = f'https://generativelanguage.googleapis.com/v1beta/models/{entry["model"]}:generateContent?key={settings.gemini_api_key or settings.agent_gemini_api_key}'
            resp = httpx.post(url, json={'contents': [{'parts': [{'text': prompt}]}]}, timeout=30)
            data = resp.json()
            text = data['candidates'][0]['content']['parts'][0]['text']
        elif entry['provider'] == 'openai':
            if not settings.openai_key_present:
                return None
            url = f'{settings.openai_base_url}/chat/completions' if getattr(settings, 'openai_base_url', None) else 'https://api.openai.com/v1/chat/completions'
            resp = httpx.post(
                url,
                headers={'Authorization': f'Bearer {settings.agent_openai_api_key or settings.openai_api_key}', 'Content-Type': 'application/json'},
                json={'model': entry['model'], 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': 800},
                timeout=30,
            )
            data = resp.json()
            text = data['choices'][0]['message']['content']
        else:
            return None
        return {'mode': mode, 'summary': text.strip(), 'live': True}
    except Exception:
        return None


def generate_report_intelligence(db: Session, run_id: int, report: dict) -> dict:
    playbooks = db.query(models.Playbook).limit(8).all()
    if not playbooks:
        seeds = [('Security header hardening', 'missing_security_header'), ('Public exposure review', 'sensitive_file_200'), ('Human takeover for auth walls', 'captcha_or_login_wall')]
        for name, trig in seeds:
            db.add(models.Playbook(name=name, trigger=trig, steps={'safe': True, 'requires_approval_for_active': True}, confidence=0.7))
        db.commit()
        playbooks = db.query(models.Playbook).limit(8).all()

    prompt = 'Generate concise security report intelligence from redacted evidence: ' + redact(report) + ' playbooks=' + redact([{'id': p.id, 'name': p.name, 'trigger': p.trigger} for p in playbooks])
    est = estimate_cost(prompt)

    mode = get_mode()
    entry = current_entry()
    if entry['provider'] == 'none':
        audit.cost(db, run_id, 'deterministic', 'report_intelligence', 0.0, est['estimated_tokens'], {'mode': mode})
        return deterministic_intelligence(report, playbooks) | {'cost_estimate': est, 'redacted': True, 'one_call_per_deliverable': True}

    live = live_intelligence(prompt, mode, entry)
    if live:
        audit.cost(db, run_id, entry['provider'], 'report_intelligence', est['estimated_usd'], est['estimated_tokens'], {'mode': mode, 'model': entry['model'], 'one_call_budgeted': True})
        return live | {'cost_estimate': est, 'redacted': True, 'one_call_per_deliverable': True}
    # Fallback to deterministic if live call fails (keeps deliverables robust)
    audit.cost(db, run_id, 'deterministic-fallback', 'report_intelligence', 0.0, est['estimated_tokens'], {'mode': mode, 'fallback': True})
    return deterministic_intelligence(report, playbooks) | {'cost_estimate': est, 'redacted': True, 'one_call_per_deliverable': True, 'fell_back': True}
