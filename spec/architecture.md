# Architecture

## Stack
- FastAPI + SQLAlchemy + SQLite dev, Postgres-ready via `DATABASE_URL`.
- React/Vite operator console.
- OpenAI primary LLM adapter, Gemini fallback aliases; Phase 1 has deterministic fallback so demos work without live keys.
- Resilient job state machine persisted in DB: queued → awaiting_approval → running → paused/failed/retrying/completed.

## Agent topology
Supervisor plans audit stages, Recon models business/app surface, Safety Policy blocks risky actions, Evidence Collector stores artifacts, Reporter maps findings to OWASP/compliance language, Cost Governor tracks budget and approval gates.
