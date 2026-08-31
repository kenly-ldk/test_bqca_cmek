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

# The conversation surface needs its OWN keys, in different KMS locations from
# the agents'. A DataAgent takes a key in its own location; a Conversation takes
# one in the multi-region's paired primary region -- `us` -> `us-central1`, `eu`
# -> `europe-west1` -- and rejects every other location, including the one
# Google documents (validation-report F8).
#
# The pairing comes from common/gda_common.py, the same map the Layer 1 policy,
# the Layer 4 enforcer and the Layer 5 probe use, so none of them can drift.
#
# Getting this wrong is not correctable: the first key OFFERED to
# CreateConversation is registered permanently for the whole project+location,
# even when that call fails. Layer 1 gates the key for exactly that reason.
log "Cloud KMS keys for the conversation surface"
CONVERSATION_PAIRS="$(python -c 'import sys; sys.path.insert(0, "'"${REPO_ROOT}"'");
from common.gda_common import CONVERSATION_KMS_LOCATION as m
print(" ".join(f"{k}:{v}" for k, v in sorted(m.items())))')"
for PAIR in ${CONVERSATION_PAIRS}; do
  CONV_LOCATION="${PAIR%%:*}"
  CONV_KMS_LOCATION="${PAIR##*:}"
  gcloud kms keyrings create "${KMS_KEYRING}" --location="${CONV_KMS_LOCATION}" \
    --project="${PROJECT_ID}" 2>/dev/null || true
  gcloud kms keys create "${KMS_KEY}" --keyring="${KMS_KEYRING}" \
    --location="${CONV_KMS_LOCATION}" --purpose=encryption \
    --project="${PROJECT_ID}" 2>/dev/null || true
  for MEMBER in "${GDA_SA}" "${AIC_SA}"; do
    gcloud kms keys add-iam-policy-binding "${KMS_KEY}" \
      --keyring="${KMS_KEYRING}" --location="${CONV_KMS_LOCATION}" \
      --project="${PROJECT_ID}" --member="${MEMBER}" \
      --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --quiet >/dev/null
  done
  echo "  ${CONV_KMS_LOCATION} (for conversations in ${CONV_LOCATION}), both service agents granted"
done

# Layer 4 cannot see a conversation without this. Conversations emit nothing
# under geminidataanalytics; their lifecycle appears only as cloudaicompanion
# TopicService.* entries in DATA ACCESS logs, which are off by default
# (validation-report F8). Enabling them is what makes the conversation half of
# the Layer 4 sink match anything at all.
#
# Note the scope: this turns on Data Access logging for the whole
# cloudaicompanion service, which also backs Gemini Code Assist and Cloud
# Assist. Expect log volume from those too, and budget for it.
log "Enabling Data Access audit logs for cloudaicompanion"
POLICY_TMP="$(mktemp)"
gcloud projects get-iam-policy "${PROJECT_ID}" --format=json > "${POLICY_TMP}"
python - "${POLICY_TMP}" <<'PYEOF'
import json, sys

path = sys.argv[1]
with open(path) as handle:
    policy = json.load(handle)

configs = [c for c in policy.get("auditConfigs", [])
           if c.get("service") != "cloudaicompanion.googleapis.com"]
configs.append({
    "service": "cloudaicompanion.googleapis.com",
    "auditLogConfigs": [{"logType": "DATA_WRITE"}, {"logType": "DATA_READ"}],
})
policy["auditConfigs"] = configs

with open(path, "w") as handle:
    json.dump(policy, handle)
PYEOF
gcloud projects set-iam-policy "${PROJECT_ID}" "${POLICY_TMP}" >/dev/null
rm -f "${POLICY_TMP}"
echo "  DATA_READ + DATA_WRITE on cloudaicompanion.googleapis.com"

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

The conversation keys above are already in place. To create a CMEK-protected
conversation on top of them (Layer 3 for the other resource type):

  bash layer3/deploy_conversation.sh
EOF
