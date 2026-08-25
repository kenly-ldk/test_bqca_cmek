#!/usr/bin/env bash
# Validation-only fixtures. Run scripts/00_bootstrap.sh and layer3/deploy.sh
# first — the tests validate what those deploy; this script only adds the
# NEGATIVE inputs the suite needs on top of it.
#
# NOTHING here belongs in a project you care about. It exists so the test suite
# can exercise paths a healthy estate never reaches:
#
#   * A deliberately UNAPPROVED KMS key, in a second project, that both GDA
#     service agents can actually use. Layer 4's unapproved-key path only gets
#     exercised if agent creation SUCCEEDS and remediation is what removes the
#     agent; without the grant, creation fails with PERMISSION_DENIED and the
#     path is never tested.
#   * Cloud Asset Inventory export-to-BigQuery grants. The production scanner
#     uses SearchAllResources and needs none of this; only the ExportAssets
#     coverage check in tests/run_layer5.sh does.
#
# Idempotent; safe to re-run.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

if [[ -z "${ROGUE_PROJECT_ID}" || "${ROGUE_PROJECT_ID}" == your-* ]]; then
  echo "ROGUE_PROJECT_ID is not set in config/shared.env.local." >&2
  echo "The validation suite needs a SECOND, disposable project to hold the" >&2
  echo "unapproved key. See docs/design.md §10.2." >&2
  exit 1
fi

# The suite validates the existing deployment; it does not build one. Fail early
# with a clear message rather than letting agent creation fail on a missing
# table halfway through tests/run_layer4.sh.
if ! bq --project_id="${PROJECT_ID}" show \
     "${PROJECT_ID}:${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE}" >/dev/null 2>&1; then
  echo "${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} not found in ${PROJECT_ID}." >&2
  echo "Deploy the agent first:  bash layer3/deploy.sh" >&2
  exit 1
fi

GDA_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com"
AIC_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com"

log "Enabling Cloud KMS on ${ROGUE_PROJECT_ID}"
gcloud services enable cloudkms.googleapis.com --project="${ROGUE_PROJECT_ID}"

log "Unapproved KMS key in ${ROGUE_PROJECT_ID}"
gcloud kms keyrings create "${ROGUE_KMS_KEYRING}" --location="${LOCATION}" \
  --project="${ROGUE_PROJECT_ID}" 2>/dev/null || echo "  rogue keyring exists"
gcloud kms keys create "${ROGUE_KMS_KEY}" --keyring="${ROGUE_KMS_KEYRING}" --location="${LOCATION}" \
  --purpose=encryption --project="${ROGUE_PROJECT_ID}" 2>/dev/null || echo "  rogue key exists"

log "Granting cryptoKeyEncrypterDecrypter on the UNAPPROVED key"
for MEMBER in "${GDA_SA}" "${AIC_SA}"; do
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

log "Test fixtures ready in ${PROJECT_ID} and ${ROGUE_PROJECT_ID}"
