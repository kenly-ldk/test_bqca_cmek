#!/usr/bin/env bash
# Deploy Part 1 — Layer 3 on the DataAgent surface.
# Idempotent; safe to re-run.
#
# Prerequisites: scripts/00_bootstrap.sh, scripts/setup_agents.sh and
# scripts/deploy_controls.sh. This checks each rather than failing halfway.
#
# What it does: creates a BigQuery datasource and then the agent itself, with
# the Layer 1 policy evaluated in-process first, so the API is called only if
# the manifest passes — exactly what a deployment pipeline would do. The kms_key
# is set at creation and is immutable afterwards.
#
#   bash scripts/deploy_agents.sh             deploy, leave Layer 4 in dry run
#   bash scripts/deploy_agents.sh --enforce   deploy, then switch Layer 4 on
#
# --enforce is a separate flag because the honest order is: deploy, read the
# enforcer's logs, confirm it classified your known-good agent COMPLIANT, and
# only then arm it. Use the flag on re-deploys, once you have done that once.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"
cd "${REPO_ROOT}"

ENFORCE=0
for ARG in "$@"; do
  case "${ARG}" in
    --enforce) ENFORCE=1 ;;
    *) echo "unknown argument: ${ARG}" >&2; exit 2 ;;
  esac
done

log "Checking prerequisites"
if ! gcloud kms keys describe "${KMS_KEY}" --keyring="${KMS_KEYRING}" \
     --location="${AGENT_LOCATION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "No CMEK key at ${APPROVED_KMS_KEY_PATH}." >&2
  echo "Run:  bash scripts/setup_agents.sh" >&2
  exit 1
fi
echo "  agent key present: ${APPROVED_KMS_KEY_PATH}"

# Not fatal. Layer 3 stands up perfectly well without the control plane; you
# just do not get to watch Layer 4 rule on the agent, which is the point of
# deploying in this order.
if gcloud run services describe "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
     --region="${INFRA_REGION}" >/dev/null 2>&1; then
  echo "  Layer 4 enforcer deployed — it will classify the new agent"
else
  echo "  [WARN] Layer 4 is not deployed. The agent will be created, but no"
  echo "         enforcer will rule on it. Run scripts/deploy_controls.sh first"
  echo "         to see the detection path work."
fi

bash "${REPO_ROOT}/layer3/deploy.sh"

if [[ "${ENFORCE}" -eq 0 ]]; then
  cat <<EOF

Layer 4 is still in DRY RUN. Confirm from its logs that the new agent was
classified COMPLIANT, then arm it:

  bash scripts/deploy_agents.sh --enforce

To read the verdict first:

  gcloud logging read \\
    'resource.labels.service_name="${FUNCTION_NAME}" AND textPayload:COMPLIANT' \\
    --project="${PROJECT_ID}" --limit=5 --freshness=10m
EOF
  exit 0
fi

log "Switching Layer 4 out of dry run"
gcloud run services update "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
  --region="${INFRA_REGION}" --update-env-vars=DRY_RUN=false >/dev/null
echo "  ${FUNCTION_NAME} is now ENFORCING — it will redact and soft-delete"
echo "  any agent it classifies non-compliant"
