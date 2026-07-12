"""Multi-agent control plane orchestration.

This module builds a cached, evidence-backed agent mesh for a completed run. It is
safe by construction: agents reason over captured evidence/findings only, do not
perform destructive actions, and fall back to deterministic output when no live LLM
provider is configured.
"""
from __future__ import annotations

from sqlalchemy.orm import Session
from . import models

AGENT_CATALOG = [
    {
        'id': 'supervisor',
        'label': 'Supervisor',
        'role': 'Routes evidence to specialist agents, rejects unsafe work, and produces the executive decision record.',
        'model_policy': 'Live provider when selected; deterministic fallback.',
        'safety_boundary': 'Planning and prioritization only; no exploitation.',
    },
    {
        'id': 'threat_analyst',
        'label': 'Threat Analyst',
        'role': 'Prioritizes likely attack paths from real findings and application context.',
        'model_policy': 'LLM-backed when a configured provider succeeds.',
        'safety_boundary': 'Explains likely chains without exploit code.',
    },
    {
        'id': 'red_team',
        'label': 'Red Team',
        'role': 'Models attacker objectives and kill-chain pressure for defender reports.',
        'model_policy': 'LLM-backed when a configured provider succeeds.',
        'safety_boundary': 'No working exploit payloads or destructive steps.',
    },
    {
        'id': 'remediation_engineer',
        'label': 'Remediation Engineer',
        'role': 'Turns findings into concrete fixes, headers, controls, and retest guidance.',
        'model_policy': 'LLM-backed when a configured provider succeeds.',
        'safety_boundary': 'Defensive configuration guidance only.',
    },
    {
        'id': 'compliance_mapper',
        'label': 'Compliance Mapper',
        'role': 'Maps findings to OWASP, SOC 2, ISO 27001, PCI, and GDPR control themes.',
        'model_policy': 'LLM-backed when a configured provider succeeds.',
        'safety_boundary': 'Control mapping only; not a legal attestation.',
    },
    {
        'id': 'evidence_qa',
        'label': 'Evidence QA',
        'role': 'Checks whether report claims are backed by stored evidence and marks gaps.',
        'model_policy': 'Deterministic evidence accounting.',
        'safety_boundary': 'Quality gate; cannot create new findings.',
    },
    {
        'id': 'reporter',
        'label': 'Reporter',
        'role': 'Writes client-safe business impact from validated findings.',
        'model_policy': 'LLM-backed when a configured provider succeeds.',
        'safety_boundary': 'No unverified claims beyond captured findings.',
    },
]


def _cached_evidence(db: Session, run_id: int, kind: str):
    row = db.query(models.Evidence).filter_by(run_id=run_id, kind=kind).order_by(models.Evidence.id.desc()).first()
    return row.data if row else None


def _store(db: Session, run_id: int, kind: str, title: str, data: dict) -> dict:
    db.add(models.Evidence(run_id=run_id, kind=kind, title=title, data=data))
    db.commit()
    return data


def _serialize_findings(findings) -> list[dict]:
    return [
        {
            'severity': f.severity,
            'title': f.title,
            'description': f.description,
            'evidence': f.evidence,
            'remediation': f.remediation,
            'compliance': f.compliance or {},
        }
        for f in findings
    ]


def _risk_register(findings) -> list[dict]:
    severity_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    ordered = sorted(findings, key=lambda f: severity_rank.get(f.severity, 0), reverse=True)
    return [
        {
            'risk_id': f'R-{idx:03d}',
            'severity': f.severity,
            'title': f.title,
            'owner': 'client-security-team' if f.severity in {'Critical', 'High'} else 'web-platform-team',
            'sla': '24h' if f.severity == 'Critical' else ('7d' if f.severity == 'High' else '30d'),
            'status': 'open',
            'evidence': f.evidence[:240],
        }
        for idx, f in enumerate(ordered, start=1)
    ]


def _agent_status(name: str, payload: dict | None) -> dict:
    return {
        'agent': name,
        'status': 'completed' if payload else 'skipped',
        'llm_backed': bool(payload and payload.get('llm_backed')),
        'source': (payload or {}).get('source', 'deterministic'),
    }


def run_mesh(db: Session, run_id: int) -> dict:
    cached = _cached_evidence(db, run_id, 'agent-mesh')
    if cached:
        return cached

    run = db.get(models.AuditRun, run_id)
    if not run:
        raise ValueError('run not found')
    asset = db.get(models.Asset, run.asset_id)
    findings = db.query(models.Finding).filter_by(run_id=run_id).all()
    evidence = db.query(models.Evidence).filter_by(run_id=run_id).all()
    target = asset.url if asset else ''

    from . import agents, observability

    analyst = _cached_evidence(db, run_id, 'analyst-agent') or agents.analyst_agent(target, findings, run.app_model, db=db, run_id=run_id)
    redteam = _cached_evidence(db, run_id, 'redteam-agent') or agents.redteam_agent(target, findings, run.app_model, db=db, run_id=run_id)
    remediation = _cached_evidence(db, run_id, 'remediation-agent') or agents.remediation_agent(target, findings, run.app_model, db=db, run_id=run_id)
    reporter = _cached_evidence(db, run_id, 'reporter-agent') or agents.reporter_agent(target, findings, run.app_model, db=db, run_id=run_id)
    compliance = _cached_evidence(db, run_id, 'compliance-agent') or agents.compliance_agent(target, findings, run.app_model, db=db, run_id=run_id)
    evidence_qa = agents.evidence_qa_agent(target, findings, evidence)
    supervisor = agents.supervisor_agent(target, findings, run.app_model, [analyst, redteam, remediation, reporter, compliance, evidence_qa], db=db, run_id=run_id)

    if not _cached_evidence(db, run_id, 'compliance-agent'):
        db.add(models.Evidence(run_id=run_id, kind='compliance-agent', title='Compliance Mapper sub-agent', data=compliance))
    db.commit()

    status = [
        _agent_status('Supervisor', supervisor),
        _agent_status('Threat Analyst', analyst),
        _agent_status('Red Team', redteam),
        _agent_status('Remediation Engineer', remediation),
        _agent_status('Compliance Mapper', compliance),
        _agent_status('Evidence QA', evidence_qa),
        _agent_status('Reporter', reporter),
    ]
    mesh = {
        'run_id': run_id,
        'target': target,
        'status': 'ready',
        'catalog': AGENT_CATALOG,
        'agent_status': status,
        'handoffs': [
            {'from': 'Supervisor', 'to': 'Threat Analyst', 'artifact': 'prioritized_findings'},
            {'from': 'Threat Analyst', 'to': 'Red Team', 'artifact': 'likely_attack_path'},
            {'from': 'Red Team', 'to': 'Remediation Engineer', 'artifact': 'chain_break_points'},
            {'from': 'Remediation Engineer', 'to': 'Compliance Mapper', 'artifact': 'control_fix_map'},
            {'from': 'Evidence QA', 'to': 'Reporter', 'artifact': 'claim_evidence_gate'},
        ],
        'risk_register': _risk_register(findings),
        'outputs': {
            'supervisor': supervisor,
            'analyst': analyst,
            'redteam': redteam,
            'remediation': remediation,
            'compliance': compliance,
            'evidence_qa': evidence_qa,
            'reporter': reporter,
        },
        'cost_guardrail': {
            'llm_calls': observability.for_run(db, run_id)['llm_calls'],
            'policy': 'one provider chain per specialist; deterministic fallback; no loop-until-credits exhaustion',
        },
        'input_summary': {
            'findings': _serialize_findings(findings),
            'evidence_items': [{'kind': e.kind, 'title': e.title} for e in evidence],
            'scan_tier': (run.app_model or {}).get('scan_tier', 'free'),
        },
    }
    return _store(db, run_id, 'agent-mesh', 'Multi-agent control-plane result', mesh)


def catalog() -> dict:
    return {'agents': AGENT_CATALOG, 'safety': 'authorized public web assessments only; no destructive exploitation'}
