#!/usr/bin/env bash
# Production preflight for the GDA CMEK framework (design.md §11 Step 1).
# Idempotent; safe to re-run. Assumes ${PROJECT_ID} already exists and is
# billing-linked — project creation is deliberately left manual.
#
# Everything here is something a real deployment needs, so this script is safe
# to run against a project you care about. The sample datasource and agent live in
# layer3/deploy.sh; the validation-only negatives (the deliberately unapproved
# "rogue" key, the Cloud Asset Inventory export grants) live in
# scripts/01_test_fixtures.sh.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

log "Enabling APIs on ${PROJECT_ID}"
# cloudaicompanion is REQUIRED. The CMEK docs require its service agent to hold
# encrypter/decrypter on the key, and that agent does not exist until the API is
# enabled.
gcloud services enable \
  geminidataanalytics.googleapis.com cloudaicompanion.googleapis.com \
  cloudkms.googleapis.com bigquery.googleapis.com logging.googleapis.com \
  pubsub.googleapis.com cloudfunctions.googleapis.com run.googleapis.com \
  cloudbuild.googleapis.com artifactregistry.googleapis.com \
  eventarc.googleapis.com cloudscheduler.googleapis.com \
  cloudasset.googleapis.com iam.googleapis.com \
  --project="${PROJECT_ID}"

# These are Google-managed service agents (P4SAs), not service accounts you
# create or supply. Their addresses are derived from your PROJECT_NUMBER, so
# nothing here is specific to any one project. CMEK requires the grant on these
# exact identities — you cannot substitute your own service account.
log "Creating service identities (P4SAs)"
for SVC in geminidataanalytics.googleapis.com cloudaicompanion.googleapis.com; do
  gcloud beta services identity create --service="${SVC}" --project="${PROJECT_ID}"
done
GDA_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com"
AIC_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com"

log "Cloud KMS key in ${LOCATION}"
gcloud kms keyrings create "${KMS_KEYRING}" --location="${LOCATION}" \
  --project="${PROJECT_ID}" 2>/dev/null || echo "  keyring exists"
gcloud kms keys create "${KMS_KEY}" --keyring="${KMS_KEYRING}" --location="${LOCATION}" \
  --purpose=encryption --project="${PROJECT_ID}" 2>/dev/null || echo "  key exists"

log "Granting cryptoKeyEncrypterDecrypter on the approved key"
for MEMBER in "${GDA_SA}" "${AIC_SA}"; do
  gcloud kms keys add-iam-policy-binding "${KMS_KEY}" \
    --keyring="${KMS_KEYRING}" --location="${LOCATION}" --project="${PROJECT_ID}" \
    --member="${MEMBER}" --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --quiet >/dev/null
  echo "  ${MEMBER}"
done

# constraints/iam.automaticIamGrantsForDefaultServiceAccounts is enforced in
# many organizations, so the default compute SA (which Cloud Build uses for
# gen2 function and Cloud Run job builds) can start with no roles, and every
# Layer 4 / Layer 5 build then fails with "missing permission on the build
# service account".
log "Granting build roles to the default compute SA"
BUILD_SA="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for ROLE in roles/cloudbuild.builds.builder roles/logging.logWriter \
            roles/artifactregistry.writer roles/storage.objectAdmin; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="${BUILD_SA}" --role="${ROLE}" --condition=None --quiet >/dev/null
  echo "  granted ${ROLE}"
done

log "Preflight complete for ${PROJECT_ID}"
cat <<EOF

Next: deploy the controls, then a CMEK-protected agent on top of them.

  DRY_RUN=true bash layer4/deploy.sh
  bash layer5/deploy.sh
  bash layer3/deploy.sh

To then run the validation suite, add the negative fixtures:

  bash scripts/01_test_fixtures.sh
EOF
