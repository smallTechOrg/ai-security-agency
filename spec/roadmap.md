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
