# Architecture

## Stack
- FastAPI + SQLAlchemy + SQLite dev, Postgres-ready via `DATABASE_URL`.
- React/Vite operator console.
- OpenAI primary LLM adapter, Gemini fallback aliases; Phase 1 has deterministic fallback so demos work without live keys.
- Resilient job state machine persisted in DB: queued → awaiting_approval → running → paused/failed/retrying/completed.

## Agent topology
Supervisor plans audit stages and coordinates specialist agents. Recon models business/app surface; Threat Analyst and Red Team reason over evidence; Remediation Engineer converts findings into fixes; Compliance Mapper maps controls; Evidence QA blocks unsupported claims; Reporter writes client-safe output. Safety Policy blocks risky actions, Evidence Collector stores artifacts, and Cost Governor tracks budget and approval gates.

## Authenticated testing boundary
Authenticated testing stores credential stubs only: username, role, allowed use, and an external secret reference. Secrets are not stored in the app database or returned to the browser. The Phase 4 workflow creates scope rules and auth-session profiles, then runs dry-run form review only; live authenticated submissions remain blocked until a later explicit approval mechanism is implemented.
