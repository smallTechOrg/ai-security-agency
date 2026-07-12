"""Agent memory that accumulates across scans.

- short-term: one snapshot per run (recent working memory).
- long-term: a single per-domain record that accumulates over every scan — scan count,
  score history/trend, and recurring findings tally. This is what lets the agent 'learn'
  a domain's posture over time.
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy.orm import Session
from . import models


def _score(findings):
    w = {'Critical': 35, 'High': 20, 'Medium': 10, 'Low': 4}
    return max(0, 100 - sum(w.get(f.severity, 2) for f in findings))


def _norm(url):
    return (url or '').strip().lower().rstrip('/')


def _find_long_for_url(db: Session, url: str):
    """Long-term memory accumulates per DOMAIN (across workspaces/assets), keyed by normalized URL."""
    key = _norm(url)
    for m in db.query(models.AgentMemory).filter_by(scope='long').all():
        if _norm((m.content or {}).get('target')) == key:
            return m
    return None


def record_for_run(db: Session, run, asset, findings) -> None:
    """Idempotent: record short-term snapshot + fold into the long-term per-domain memory once per run."""
    if db.query(models.AgentMemory).filter_by(run_id=run.id, scope='short').first():
        return  # already recorded for this run
    tier = (run.app_model or {}).get('scan_tier', 'free')
    score = _score(findings)
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    snapshot = {'run_id': run.id, 'target': asset.url if asset else '', 'tier': tier, 'score': score,
                'findings_total': len(findings), 'by_severity': by_sev,
                'top_findings': [f.title for f in findings[:6]], 'at': datetime.utcnow().isoformat()}
    db.add(models.AgentMemory(workspace_id=run.workspace_id, asset_id=run.asset_id, scope='short',
                              run_id=run.id, title=f'Scan snapshot #{run.id}', content=snapshot))

    # Long-term: one accumulating record per DOMAIN (keyed by normalized URL, across workspaces).
    lt = _find_long_for_url(db, asset.url if asset else '')
    if not lt:
        lt = models.AgentMemory(workspace_id=run.workspace_id, asset_id=run.asset_id, scope='long',
                                title=f'Domain memory: {asset.url if asset else ""}',
                                content={'scans': 0, 'first_seen': snapshot['at'], 'target': asset.url if asset else '',
                                         'score_history': [], 'recurring_findings': {}, 'best_score': 0, 'worst_score': 100})
        db.add(lt); db.flush()
    c = dict(lt.content or {})
    c['scans'] = c.get('scans', 0) + 1
    c['last_seen'] = snapshot['at']
    c['score_history'] = (c.get('score_history', []) + [score])[-20:]
    rf = dict(c.get('recurring_findings', {}))
    for t in snapshot['top_findings']:
        rf[t] = rf.get(t, 0) + 1
    c['recurring_findings'] = rf
    c['best_score'] = max(c.get('best_score', 0), score)
    c['worst_score'] = min(c.get('worst_score', 100), score)
    hist = c['score_history']
    c['trend'] = ('improving' if len(hist) >= 2 and hist[-1] > hist[0]
                  else 'declining' if len(hist) >= 2 and hist[-1] < hist[0] else 'stable')
    lt.content = c; lt.updated_at = datetime.utcnow()
    db.commit()


def summary_for_run(db: Session, run, asset) -> dict:
    """Compact memory view for a run's report."""
    lt = _find_long_for_url(db, asset.url if asset else '')
    recent = db.query(models.AgentMemory).filter_by(scope='short') \
        .order_by(models.AgentMemory.id.desc()).limit(5).all()
    long_term = lt.content if lt else None
    if long_term:
        rf = long_term.get('recurring_findings', {})
        long_term = {**long_term,
                     'top_recurring': sorted(rf.items(), key=lambda x: -x[1])[:5]}
    return {'long_term': long_term,
            'short_term': [r.content for r in recent]}


def workspace_memory(db: Session, workspace_id: int) -> dict:
    longs = db.query(models.AgentMemory).filter_by(workspace_id=workspace_id, scope='long').all()
    shorts = db.query(models.AgentMemory).filter_by(workspace_id=workspace_id, scope='short') \
        .order_by(models.AgentMemory.id.desc()).limit(20).all()
    return {'long_term': [l.content for l in longs],
            'short_term': [s.content for s in shorts]}
