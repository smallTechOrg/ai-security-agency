#!/usr/bin/env bash
# Deploy Zer0 Vanguard (single combined container) to Cloud Run.
# Branch-aware: main -> prod service, any other branch -> dev service.
#
# Usage:
#   scripts/deploy.sh            # deploy current git branch
#   ENV=prod scripts/deploy.sh   # force prod service
#   ENV=dev  scripts/deploy.sh   # force dev service
set -euo pipefail

PROJECT="${GCP_PROJECT:-ai-agent-boilerplate0}"
REGION="${GCP_REGION:-us-central1}"

BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
# Single-service deploy: everything goes to `zero-vanguard`, which the global
# HTTPS load balancer fronts. Override with SERVICE=... for a throwaway service.
SERVICE="${SERVICE:-zero-vanguard}"
ENV_TARGET="${ENV:-prod}"

echo "==> Project : $PROJECT"
echo "==> Region  : $REGION"
echo "==> Branch  : $BRANCH"
echo "==> Service : $SERVICE ($ENV_TARGET)"

# Non-secret runtime env. API keys/UPI live in Secret Manager (see --set-secrets
# below) so they survive every deploy — set once with scripts/setup-secrets.sh.
RUNTIME_ENV="ENVIRONMENT=$ENV_TARGET,CORS_ORIGINS=*,OPENAI_MODEL=gpt-5-chat-latest,GEMINI_MODEL=gemini-2.5-flash"
SECRETS="AGENT_OPENAI_API_KEY=vanguard-openai-key:latest,OPENAI_API_KEY=vanguard-openai-key:latest,AGENT_GEMINI_API_KEY=vanguard-gemini-key:latest,GEMINI_API_KEY=vanguard-gemini-key:latest,UPI_ID=vanguard-upi-id:latest"

gcloud run deploy "$SERVICE" \
  --project "$PROJECT" \
  --region "$REGION" \
  --source . \
  --allow-unauthenticated \
  --port 8080 \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300 \
  --concurrency 40 \
  --set-env-vars "$RUNTIME_ENV" \
  --set-secrets "$SECRETS" \
  --labels "app=zero-vanguard,env=$ENV_TARGET,branch=$(echo "$BRANCH" | tr '/_' '--' | tr -cd 'a-z0-9-')"

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format='value(status.url)')"
echo ""
echo "==> Deployed: $URL"
echo "==> Health : $URL/health"
