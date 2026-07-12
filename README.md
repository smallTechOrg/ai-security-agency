# AI Security Agency

AI-first security agency platform for authorized website/application audits. Vanguard by Zer0 now includes resilient audit workspaces, safe public-website baseline scans, approval gates, evidence, findings, cost tracking, immutable audit logs, professional reports, and a multi-agent control plane.

## Run

```bash
cp .env.example .env
# add AGENT_OPENAI_API_KEY; GEMINI_API_KEY or AGENT_GEMINI_API_KEY is accepted as fallback
make setup
make backend
make frontend
```

Open UI: http://127.0.0.1:5173
API health: http://127.0.0.1:8011/health

## Multi-agent control plane

Completed scans can be reviewed by a specialist agent mesh:

- Supervisor — routes evidence and produces the decision record.
- Threat Analyst — prioritizes the attack path from captured findings.
- Red Team — models a defender-safe attack chain without exploit code.
- Remediation Engineer — turns findings into concrete fixes.
- Compliance Mapper — maps issues to OWASP/SOC 2/ISO/PCI/GDPR control themes.
- Evidence QA — checks whether claims are backed by stored evidence.
- Reporter — writes client-safe business impact.

API surfaces:

```bash
curl http://127.0.0.1:8011/api/agents/catalog
curl -X POST http://127.0.0.1:8011/api/runs/<run_id>/agent-mesh
```

The mesh uses configured OpenAI/Gemini providers when available and deterministic fallback otherwise; it does **not** loop indefinitely or intentionally burn credits.

## Authenticated testing workflow

Phase 4 adds safe authenticated-app preparation without storing secrets:

- Credential stubs store username/role/allowed-use plus an external secret reference only.
- Scope rules define included paths and destructive exclusions such as logout/delete/billing.
- Auth-session profiles record a human-verified login state target.
- Authenticated form testing is dry-run-only: forms are reviewed and classified, but Vanguard does not submit credentials or mutate state.

API surfaces:

```bash
curl http://127.0.0.1:8011/api/workspaces/<workspace_id>/credentials
curl http://127.0.0.1:8011/api/workspaces/<workspace_id>/auth-sessions
curl -X POST http://127.0.0.1:8011/api/runs/<run_id>/authenticated-form-test
```

## Remediation retests

Remediation tickets can spawn non-destructive retest validation runs. A retest packages the original finding, remediation guidance, reviewer note, and outcome into a new run with its own evidence, task log, cost event, and audit trail.

```bash
curl -X POST http://127.0.0.1:8011/api/remediation-tickets/<ticket_id>/retest \
  -H 'content-type: application/json' \
  -d '{"outcome":"ready_for_retest","reviewer":"analyst"}'
```

## Safety boundary

Only test targets you own or are authorized to test. Phase 1 performs passive/safe checks only: same-origin crawl, headers, TLS metadata, forms inventory, common public files, evidence capture, report generation. Destructive exploitation, data exfiltration, brute force, bypass, spam, and availability-impacting tests are policy-blocked.
