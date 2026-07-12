# Roadmap

## Phases of Development
1. Serious agency base: authorized public website audit workspace with safe baseline scan, evidence, findings, cost tracking, approvals, audit log, and report preview.
2. Browser-assisted recon: Playwright screenshots, console/network capture, human takeover for CAPTCHA/login.
3. LLM report intelligence + RAG playbooks: OpenAI/Gemini adapter, evidence summaries, reusable anonymized playbooks, cost/context budget controls.
4. Authenticated app testing workflow: credentials vault stubs, role boundaries, safe form testing, reviewer approval gates.
5. Enterprise program layer: RBAC, client portal, recurring schedules, remediation retests.
6. Deployment + compliance polish: Docker/GCP deploy, PDF exports, certificate attestations, OWASP/SOC2/GDPR mappings.


## Hackathon acceleration status
- Phase 2 browser-assisted recon scaffold: implemented via `/api/runs/{id}/browser-recon`, artifacts, task tracking, human-takeover detection indicators.
- Phase 3 LLM/RAG/cost scaffold: implemented via `/api/runs/{id}/intelligence`, redaction, one-call cost ledger, deterministic fallback, seeded playbooks.
- Phase 4-6 enterprise polish scaffold: implemented via credential vault stubs, schedules, enterprise readiness endpoint, compliance export placeholders.
- Phase 4 authenticated testing workflow: implemented credential-stub APIs, scope-rule APIs, auth-session profiles, and a dry-run-only authenticated form test gate that blocks live submissions and stores evidence/audit logs.
- Multi-agent control plane: implemented Supervisor, Threat Analyst, Red Team, Remediation Engineer, Compliance Mapper, Evidence QA, and Reporter mesh over completed scan evidence.
- Phase 5 remediation retests: implemented ticket-to-retest validation runs with non-destructive evidence packages, task/cost/audit trail, and UI actions from the remediation queue.
- Attack surface graph: implemented run-level graph that maps assets, pages, forms, APIs, findings, hotspots, and attack paths into the report cockpit and evidence bundle.
- Executive pack: implemented board/CISO-ready JSON + print-friendly HTML export with posture, KPIs, top risks, control mappings, assurance flags, and 90-day remediation roadmap.
