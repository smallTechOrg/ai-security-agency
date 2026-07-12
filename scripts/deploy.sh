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
ENV_TARGET="${ENV:-}"
if [[ -z "$ENV_TARGET" ]]; then
  if [[ "$BRANCH" == "main" ]]; then ENV_TARGET="prod"; else ENV_TARGET="dev"; fi
fi

if [[ "$ENV_TARGET" == "prod" ]]; then
  SERVICE="zero-vanguard"
else
  SERVICE="zero-vanguard-dev"
fi

echo "==> Project : $PROJECT"
echo "==> Region  : $REGION"
echo "==> Branch  : $BRANCH"
echo "==> Target  : $ENV_TARGET ($SERVICE)"

# Runtime env vars. Secrets (API keys) are set separately, once, via:
#   gcloud run services update $SERVICE --update-secrets=... OR --set-env-vars in console.
RUNTIME_ENV="ENVIRONMENT=$ENV_TARGET,CORS_ORIGINS=*"

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
  --labels "app=zero-vanguard,env=$ENV_TARGET,branch=$(echo "$BRANCH" | tr '/_' '--' | tr -cd 'a-z0-9-')"

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format='value(status.url)')"
echo ""
echo "==> Deployed: $URL"
echo "==> Health : $URL/health"
