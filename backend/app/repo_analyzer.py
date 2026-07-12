from __future__ import annotations
import re, os, json, subprocess, httpx
from sqlalchemy.orm import Session
from . import models, audit
from .llm import live_intelligence, estimate_cost, redact
from .intelligence_settings import get_mode, current_entry

SECRET_PATTERNS = [
    ('AWS Access Key', re.compile(r'AKIA[0-9A-Z]{16}', re.I), 'Critical'),
    ('Private Key Block', re.compile(r'-----BEGIN (RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----', re.I), 'Critical'),
    ('Slack Token', re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,}', re.I), 'High'),
    ('Google API Key', re.compile(r'AIza[0-9A-Za-z_-]{35}', re.I), 'High'),
    ('GitHub PAT', re.compile(r'ghp_[0-9A-Za-z]{36}', re.I), 'Critical'),
    ('Generic API Key Assignment', re.compile(r'(api[_-]?key|secret|token|password)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', re.I), 'Medium'),
    ('Stripe Key', re.compile(r'sk_live_[0-9A-Za-z]{24,}', re.I), 'Critical'),
    ('Twilio Key', re.compile(r'SK[0-9a-fA-F]{32}', re.I), 'High'),
]
DANGEROUS_PATTERNS = [
    ('eval() usage', re.compile(r'(?<![\w.])eval\s*\('), 'Low'),
    ('exec() usage', re.compile(r'(?<![\w.])exec\s*\('), 'Low'),
    ('subprocess shell=True', re.compile(r'shell\s*=\s*True'), 'Medium'),
    ('os.system', re.compile(r'os\.system\s*\('), 'Medium'),
    ('pickle.loads', re.compile(r'pickle\.loads?\s*\('), 'Medium'),
    ('yaml.load (unsafe)', re.compile(r'yaml\.load\s*\('), 'Medium'),
    ('SQL string concat', re.compile(r'(execute|cursor\.execute)\s*\(\s*[\'"].*?%s.*?[\'"]\s*%'), 'Medium'),
    ('md5 (weak hash)', re.compile(r'hashlib\.md5\s*\('), 'Low'),
    ('verify=False (TLS off)', re.compile(r'verify\s*=\s*False'), 'Medium'),
]

SCAN_EXTS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php', '.cs', '.rs', '.sh', '.yml', '.yaml', '.json', '.env', '.toml', '.sql', '.html', '.xml'}
SKIP_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', 'target', '.idea', '.vscode', 'vendor'}

def _iter_files(root: str, max_files: int = 2000):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SCAN_EXTS:
                yield os.path.join(dirpath, fn)
                count += 1
                if count >= max_files:
                    return

def _git_meta(root: str) -> dict:
    meta = {'default_branch': None, 'commit_count': 0, 'remotes': [], 'last_commit': None}
    try:
        out = subprocess.run(['git', '-C', root, 'remote', '-v'], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1] == '(push)':
                meta['remotes'].append(parts[1])
        bc = subprocess.run(['git', '-C', root, 'rev-parse', '--abbrev-ref', 'HEAD'], capture_output=True, text=True, timeout=10)
        meta['default_branch'] = bc.stdout.strip() or None
        cc = subprocess.run(['git', '-C', root, 'rev-list', '--count', 'HEAD'], capture_output=True, text=True, timeout=10)
        meta['commit_count'] = int(cc.stdout.strip() or 0)
        lc = subprocess.run(['git', '-C', root, 'log', '-1', '--format=%H|%an|%ar'], capture_output=True, text=True, timeout=10)
        if lc.stdout.strip():
            h, an, ar = (lc.stdout.strip().split('|') + ['', '', ''])[:3]
            meta['last_commit'] = {'hash': h[:12], 'author': an, 'relative': ar}
    except Exception:
        pass
    return meta

def analyze_repo(repo_path: str, deep: bool = False) -> dict:
    """Deterministic, cost-free static analysis of a local repo checkout.
    Scans source for secrets, dangerous patterns, dependency/SAST signals.
    Returns a structured result; no LLM calls (cost = $0)."""
    findings = []
    stats = {'files_scanned': 0, 'lines_scanned': 0, 'by_severity': {}, 'languages': {}}
    scanned = []
    for path in _iter_files(repo_path):
        rel = os.path.relpath(path, repo_path)
        scanned.append(rel)
        stats['files_scanned'] += 1
        ext = os.path.splitext(path)[1].lower()
        stats['languages'][ext] = stats['languages'].get(ext, 0) + 1
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                lines = fh.readlines()
        except Exception:
            continue
        stats['lines_scanned'] += len(lines)
        for idx, line in enumerate(lines, 1):
            for name, rx, sev in SECRET_PATTERNS:
                if rx.search(line):
                    findings.append({'severity': sev, 'category': 'secret', 'rule': name, 'file': rel, 'line': idx, 'match': line.strip()[:120], 'remediation': 'Rotate and remove the secret; load from environment/secret manager. Add to .gitignore and purge history.'})
                    break
            if deep:
                for name, rx, sev in DANGEROUS_PATTERNS:
                    if rx.search(line):
                        findings.append({'severity': sev, 'category': 'insecure_code', 'rule': name, 'file': rel, 'line': idx, 'match': line.strip()[:120], 'remediation': 'Review and replace with a safe equivalent (parameterized queries, subprocess without shell, pinned hashing).'})
                        break
    for f in findings:
        stats['by_severity'][f['severity']] = stats['by_severity'].get(f['severity'], 0) + 1
    meta = _git_meta(repo_path)
    score = max(0, 100 - sum({'Critical': 30, 'High': 15, 'Medium': 7, 'Low': 2}.get(f['severity'], 1) for f in findings))
    return {'files_scanned': stats['files_scanned'], 'lines_scanned': stats['lines_scanned'], 'languages': stats['languages'], 'findings': findings, 'by_severity': stats['by_severity'], 'git': meta, 'security_score': score, 'cost_usd': 0.0, 'mode': 'deterministic', 'deep': deep}

def enrich_with_intelligence(result: dict, mode: str | None = None) -> dict:
    """Optional: ONE live-LLM call to summarize the deterministic repo findings.
    Costs only when a live model is selected (else returns deterministic summary)."""
    m = mode or get_mode()
    entry = current_entry()
    summary = {
        'mode': m,
        'summary': f"Static analysis of {result['files_scanned']} files ({result['lines_scanned']} lines) found {len(result['findings'])} issues. "
                   f"Security score {result['security_score']}/100. Fix secrets and insecure code patterns before shipping.",
        'top_risks': [f"{f['severity']}: {f['rule']} in {f['file']}:{f['line']}" for f in result['findings'][:8]],
        'cost_usd': 0.0,
    }
    if entry['provider'] == 'none':
        return summary
    prompt = 'Summarize this source-code security review for an engineering lead (concise, no secrets echoed): ' + redact(result)
    est = estimate_cost(prompt)
    live = live_intelligence(prompt, m, entry)
    if live:
        summary['summary'] = live.get('summary', summary['summary'])
        summary['cost_usd'] = est['estimated_usd']
        summary['live'] = True
    return summary

