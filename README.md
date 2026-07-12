# AI Security Agency

AI-first security agency platform for authorized website/application audits. Phase 1 is a serious hackathon base: resilient audit workspaces, safe public-website baseline scans, approval gates, evidence, findings, cost tracking, immutable audit logs, and professional reports.

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

## Safety boundary

Only test targets you own or are authorized to test. Phase 1 performs passive/safe checks only: same-origin crawl, headers, TLS metadata, forms inventory, common public files, evidence capture, report generation. Destructive exploitation, data exfiltration, brute force, bypass, spam, and availability-impacting tests are policy-blocked.
