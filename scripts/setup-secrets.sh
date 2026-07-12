#!/usr/bin/env bash
# One-time: push API keys / UPI from a local .env into Secret Manager so the
# Cloud Run service (zero-vanguard) reads them via --set-secrets and they
# survive every deploy. Re-run to rotate (adds a new secret version).
#
# Usage:  scripts/setup-secrets.sh [path-to-.env]   (default: ./.env)
set -euo pipefail

PROJECT="${GCP_PROJECT:-ai-agent-boilerplate0}"
ENV_FILE="${1:-.env}"
RUNTIME_SA="${RUNTIME_SA:-870371939888-compute@developer.gserviceaccount.com}"

[[ -f "$ENV_FILE" ]] || { echo "env file not found: $ENV_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

OKEY="${AGENT_OPENAI_API_KEY:-${OPENAI_API_KEY:-}}"
GKEY="${AGENT_GEMINI_API_KEY:-${GEMINI_API_KEY:-}}"
UPI="${UPI_ID:-}"

put() {  # name value
  local name="$1" val="$2"
  [[ -n "$val" ]] || { echo "skip $name (empty)"; return; }
  gcloud secrets create "$name" --replication-policy=automatic --project="$PROJECT" 2>/dev/null || true
  printf '%s' "$val" | gcloud secrets versions add "$name" --data-file=- --project="$PROJECT" >/dev/null
  gcloud secrets add-iam-policy-binding "$name" --member="serviceAccount:$RUNTIME_SA" \
    --role=roles/secretmanager.secretAccessor --project="$PROJECT" >/dev/null 2>&1 || true
  echo "set $name"
}

put vanguard-openai-key "$OKEY"
put vanguard-gemini-key "$GKEY"
put vanguard-upi-id     "$UPI"
echo "Done. Secrets are referenced by scripts/deploy.sh via --set-secrets."
