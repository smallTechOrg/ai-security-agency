"""Agent observability: trace every LLM call (provider, model, latency, success, fallback)
so we can see exactly how the agents behaved — including provider failover.
"""
from __future__ import annotations
import time
from sqlalchemy.orm import Session
from . import models


def call_with_trace(db: Session, run_id: int, agent: str, prompt: str, chain, operation='completion'):
    """Try each (mode, entry) in the provider chain, recording a trace row per attempt.
    Returns (output, entry) for the first success, or (None, None)."""
    from . import llm
    for mode, entry in chain:
        t0 = time.time()
        ok = False; out = None; err = ''
        try:
            out = llm.live_intelligence(prompt, mode, entry)
            ok = bool(out and out.get('summary'))
        except Exception as e:
            err = type(e).__name__
        latency = int((time.time() - t0) * 1000)
        try:
            db.add(models.LLMTrace(run_id=run_id or 0, agent=agent, provider=entry.get('provider', ''),
                                   model=entry.get('model', '') or '', latency_ms=latency, ok=ok,
                                   fallback=not ok, operation=operation,
                                   detail={'mode': mode, 'error': err, 'prompt_chars': len(prompt)}))
            db.commit()
        except Exception:
            db.rollback()
        if ok:
            return out, entry
    return None, None


def for_run(db: Session, run_id: int) -> dict:
    rows = db.query(models.LLMTrace).filter_by(run_id=run_id).order_by(models.LLMTrace.id).all()
    calls = [{'agent': r.agent, 'provider': r.provider, 'model': r.model, 'latency_ms': r.latency_ms,
              'ok': r.ok, 'fallback': r.fallback, 'operation': r.operation,
              'error': (r.detail or {}).get('error', ''), 'at': r.created_at.isoformat()} for r in rows]
    ok_calls = [c for c in calls if c['ok']]
    return {'llm_calls': len(calls), 'successful': len(ok_calls),
            'failovers': sum(1 for c in calls if c['fallback']),
            'total_latency_ms': sum(c['latency_ms'] for c in calls),
            'avg_latency_ms': round(sum(c['latency_ms'] for c in calls) / len(calls)) if calls else 0,
            'providers_used': sorted({c['provider'] for c in ok_calls}),
            'calls': calls}
