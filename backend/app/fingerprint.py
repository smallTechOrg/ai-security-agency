"""Technology & vulnerable-dependency fingerprinting.

Deterministic, offline, non-destructive: infers the tech stack from response headers,
HTML, and script URLs, then flags known end-of-life / known-vulnerable component
versions from a small curated ruleset. No network calls, no exploitation.
"""
from __future__ import annotations
import re

# --- version helpers ---------------------------------------------------------

def _parse_version(v: str):
    parts = re.findall(r'\d+', v or '')
    return tuple(int(p) for p in parts[:4]) or (0,)


def _lt(a: str, b: str) -> bool:
    """True if version a < version b (component-wise, zero-padded)."""
    va, vb = _parse_version(a), _parse_version(b)
    n = max(len(va), len(vb))
    va += (0,) * (n - len(va)); vb += (0,) * (n - len(vb))
    return va < vb


# --- library detection from script URLs --------------------------------------
# name -> regex that captures a version group from a URL/path
_LIB_PATTERNS = {
    'jquery': re.compile(r'jquery[-/@.]?(\d+\.\d+(?:\.\d+)?)', re.I),
    'bootstrap': re.compile(r'bootstrap[-/@.]?(\d+\.\d+(?:\.\d+)?)', re.I),
    'angularjs': re.compile(r'angular(?:\.min)?[-/@.]?(1\.\d+(?:\.\d+)?)', re.I),
    'lodash': re.compile(r'lodash[-/@.]?(\d+\.\d+(?:\.\d+)?)', re.I),
    'handlebars': re.compile(r'handlebars[-/@.]?(\d+\.\d+(?:\.\d+)?)', re.I),
    'moment': re.compile(r'moment[-/@.]?(\d+\.\d+(?:\.\d+)?)', re.I),
    'vue': re.compile(r'vue[-/@.]?(\d+\.\d+(?:\.\d+)?)', re.I),
}

# library -> (fixed_version, severity, cve/advisory, issue)
_LIB_RULES = {
    'jquery': ('3.5.0', 'Medium', 'CVE-2020-11022/11023', 'jQuery < 3.5.0 is vulnerable to cross-site scripting via htmlPrefilter.'),
    'bootstrap': ('4.3.1', 'Medium', 'CVE-2019-8331', 'Bootstrap < 4.3.1 has XSS in data-template/tooltip/popover.'),
    'lodash': ('4.17.12', 'High', 'CVE-2019-10744', 'Lodash < 4.17.12 is vulnerable to prototype pollution.'),
    'handlebars': ('4.3.0', 'High', 'CVE-2019-19919', 'Handlebars < 4.3.0 is vulnerable to prototype pollution / RCE in templates.'),
}


def _detect_libraries(script_urls, inline_html):
    hay = ' '.join(script_urls or []) + ' ' + (inline_html or '')[:20000]
    found = {}
    for lib, pat in _LIB_PATTERNS.items():
        m = pat.search(hay)
        if m:
            found[lib] = m.group(1)
    return found


# --- server / framework signals from headers ---------------------------------

def _header_findings(headers):
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out = []
    server = lower.get('server', '')
    powered = lower.get('x-powered-by', '')

    # Version disclosure (info leak) — helps attackers target known CVEs.
    if re.search(r'\d', server) or powered or 'x-aspnet-version' in lower or 'x-aspnetmvc-version' in lower:
        detail = '; '.join(x for x in [f'Server: {server}' if server else '', f'X-Powered-By: {powered}' if powered else '',
                                        f"X-AspNet-Version: {lower.get('x-aspnet-version','')}" if 'x-aspnet-version' in lower else ''] if x)
        out.append(('Low', 'Software version disclosure in response headers',
                    'The server advertises specific software and versions, letting attackers map known CVEs directly to your stack.',
                    detail, 'Suppress or genericize Server/X-Powered-By/X-AspNet-Version headers.',
                    {'OWASP': 'A05 Security Misconfiguration', 'info': 'version disclosure'}))

    # End-of-life runtimes.
    m = re.search(r'php/(\d+\.\d+)', (server + ' ' + powered).lower())
    if m and _lt(m.group(1), '8.0'):
        out.append(('High', f'End-of-life PHP runtime detected ({m.group(1)})',
                    f'PHP {m.group(1)} is past end-of-life and no longer receives security patches.',
                    f'Detected via headers: {m.group(0)}', 'Upgrade to a supported PHP release (8.1+).',
                    {'OWASP': 'A06 Vulnerable & Outdated Components'}))
    m = re.search(r'apache/(\d+\.\d+)', server.lower())
    if m and _lt(m.group(1), '2.4'):
        out.append(('Medium', f'Outdated Apache httpd ({m.group(1)})',
                    f'Apache {m.group(1)} predates the supported 2.4 branch and carries multiple known CVEs.',
                    f'Server: {server}', 'Upgrade Apache httpd to a supported 2.4.x release.',
                    {'OWASP': 'A06 Vulnerable & Outdated Components'}))
    return out


def fingerprint(headers, html, script_urls):
    """Return {'tech': {...}, 'libraries': {...}, 'findings': [(sev,title,desc,evidence,remediation,compliance), ...]}."""
    libs = _detect_libraries(script_urls, html)
    findings = []

    for lib, ver in libs.items():
        rule = _LIB_RULES.get(lib)
        if rule:
            fixed, sev, cve, issue = rule
            if _lt(ver, fixed):
                findings.append((sev, f'Vulnerable {lib} {ver} ({cve})',
                                 f'{issue} Detected version {ver}; fixed in {fixed}.',
                                 f'Referenced client-side script advertises {lib} {ver}.',
                                 f'Upgrade {lib} to {fixed} or later.',
                                 {'OWASP': 'A06 Vulnerable & Outdated Components', 'cve': cve}))
        if lib == 'angularjs':
            findings.append(('Medium', f'End-of-life AngularJS {ver} in use',
                             f'AngularJS {ver} (1.x) reached end-of-life in Jan 2022 and receives no security fixes.',
                             f'Referenced client-side script advertises AngularJS {ver}.',
                             'Migrate off AngularJS 1.x to a supported framework.',
                             {'OWASP': 'A06 Vulnerable & Outdated Components'}))
        if lib == 'moment':
            findings.append(('Low', f'Deprecated Moment.js {ver} bundled',
                             'Moment.js is in maintenance mode; it ships a large attack/maintenance surface and is no longer recommended.',
                             f'Referenced client-side script advertises Moment.js {ver}.',
                             'Migrate to a maintained date library (e.g. date-fns, Luxon, or Temporal).',
                             {'OWASP': 'A06 Vulnerable & Outdated Components'}))

    findings.extend(_header_findings(headers))
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tech = {'server': lower.get('server', 'unknown'), 'powered_by': lower.get('x-powered-by', ''),
            'detected_libraries': libs}
    return {'tech': tech, 'libraries': libs, 'findings': findings}
