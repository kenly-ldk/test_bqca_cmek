#!/usr/bin/env bash
# Setup for Part 1 — the DataAgent surface. Run after scripts/00_bootstrap.sh.
# Idempotent; safe to re-run.
#
# A DataAgent takes a key in ITS OWN location, so this creates one key ring and
# key in ${LOCATION} and grants both service agents encrypter/decrypter on it.
# That is the whole of the agent-specific preflight. Conversations do not use
# this key — theirs must live in the multi-region's paired primary region, which
# is a different KMS location entirely (see scripts/setup_conversations.sh and
# validation-report F8).
#
#   bash scripts/setup_agents.sh                   production preflight
#   bash scripts/setup_agents.sh --with-fixtures   + the negatives the tests need
#
# Without --with-fixtures nothing here is test-specific, so this is safe to run
# against a project you care about.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

WITH_FIXTURES=0
for ARG in "$@"; do
  case "${ARG}" in
    --with-fixtures) WITH_FIXTURES=1 ;;
    *) echo "unknown argument: ${ARG}" >&2; exit 2 ;;
  esac
done

log "Cloud KMS key for the agent surface, in ${LOCATION}"
grant_cmek_key "${LOCATION}"
echo "  ${APPROVED_KMS_KEY_PATH}"
echo "  both service agents hold roles/cloudkms.cryptoKeyEncrypterDecrypter"

if [[ "${WITH_FIXTURES}" -eq 0 ]]; then
  log "Agent setup complete for ${PROJECT_ID}"
  cat <<EOF

Next, if you have not already:

  bash scripts/deploy_controls.sh   # Layers 2, 4, 5 — the shared control plane
  bash scripts/deploy_agents.sh     # Layer 3 — a datasource and a CMEK agent

To run the agent test suite later, add its negative fixtures first:

  bash scripts/setup_agents.sh --with-fixtures
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Validation-only from here down.
#
# NOTHING below belongs in a project you care about. It exists so the agent test
# suite can exercise paths a healthy estate never reaches:
#
#   * A deliberately UNAPPROVED KMS key, in a second project, that both service
#     agents can actually use. Layer 4's unapproved-key path only gets exercised
#     if agent creation SUCCEEDS and remediation is what removes the agent;
#     without the grant, creation fails with PERMISSION_DENIED and the path is
#     never tested.
#   * Cloud Asset Inventory export-to-BigQuery grants. The production scanner
#     uses SearchAllResources and needs none of this; only the ExportAssets
#     coverage check in tests/run_layer5.sh does.
#
# Both are agent-side. The conversation suite needs no provisioned negatives —
# see scripts/setup_conversations.sh --with-fixtures for why.
# ---------------------------------------------------------------------------

if [[ -z "${ROGUE_PROJECT_ID}" || "${ROGUE_PROJECT_ID}" == your-* ]]; then
  echo "ROGUE_PROJECT_ID is not set in config/shared.env.local." >&2
  echo "The agent test suite needs a SECOND, disposable project to hold the" >&2
  echo "unapproved key. See docs/design.md §10.2." >&2
  exit 1
fi

log "Enabling Cloud KMS on ${ROGUE_PROJECT_ID}"
gcloud services enable cloudkms.googleapis.com --project="${ROGUE_PROJECT_ID}"

log "Unapproved KMS key in ${ROGUE_PROJECT_ID}"
gcloud kms keyrings create "${ROGUE_KMS_KEYRING}" --location="${LOCATION}" \
  --project="${ROGUE_PROJECT_ID}" 2>/dev/null || echo "  rogue keyring exists"
gcloud kms keys create "${ROGUE_KMS_KEY}" --keyring="${ROGUE_KMS_KEYRING}" --location="${LOCATION}" \
  --purpose=encryption --project="${ROGUE_PROJECT_ID}" 2>/dev/null || echo "  rogue key exists"

log "Granting cryptoKeyEncrypterDecrypter on the UNAPPROVED key"
for MEMBER in "${GDA_SERVICE_AGENT}" "${AIC_SERVICE_AGENT}"; do
  gcloud kms keys add-iam-policy-binding "${ROGUE_KMS_KEY}" \
    --keyring="${ROGUE_KMS_KEYRING}" --location="${LOCATION}" --project="${ROGUE_PROJECT_ID}" \
    --member="${MEMBER}" --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --quiet >/dev/null
  echo "  ${MEMBER}"
done

log "Cloud Asset Inventory -> BigQuery permissions (ExportAssets check only)"
gcloud beta services identity create --service=cloudasset.googleapis.com \
  --project="${PROJECT_ID}"
CAI_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-cloudasset.iam.gserviceaccount.com"
for ROLE in roles/bigquery.dataEditor roles/bigquery.user; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="${CAI_SA}" --role="${ROLE}" --condition=None --quiet >/dev/null
  echo "  granted ${ROLE}"
done

log "Agent setup complete, with test fixtures, in ${PROJECT_ID} and ${ROGUE_PROJECT_ID}"
cat <<EOF

Run the agent suite once Layer 3 is deployed:

  bash scripts/deploy_agents.sh
  bash tests/run_agents.sh
EOF
