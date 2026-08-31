#!/usr/bin/env bash
# Shared preflight for the GDA CMEK framework (design.md §11 Step 1).
# Idempotent; safe to re-run. Assumes ${PROJECT_ID} already exists and is
# billing-linked — project creation is deliberately left manual.
#
# This script is resource-type agnostic: everything in it is needed whether you
# govern agents, conversations or both. The parts that differ per resource type
# live in the two setup scripts that follow, because the two need their CMEK
# keys in DIFFERENT KMS locations and only one of them needs Data Access logs:
#
#   scripts/setup_agents.sh          the agents' key, in ${LOCATION}
#   scripts/setup_conversations.sh   the paired-region keys + the audit logs
#
# Everything here is something a real deployment needs, so this script is safe
# to run against a project you care about. The validation-only negatives are
# behind the --with-fixtures flag on the setup scripts, never here.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

log "Enabling APIs on ${PROJECT_ID}"
# cloudaicompanion is REQUIRED even for an agents-only estate. The CMEK docs
# require its service agent to hold encrypter/decrypter on the key, and that
# agent does not exist until the API is enabled.
gcloud services enable \
  geminidataanalytics.googleapis.com cloudaicompanion.googleapis.com \
  cloudkms.googleapis.com bigquery.googleapis.com logging.googleapis.com \
  pubsub.googleapis.com cloudfunctions.googleapis.com run.googleapis.com \
  cloudbuild.googleapis.com artifactregistry.googleapis.com \
  eventarc.googleapis.com cloudscheduler.googleapis.com \
  cloudasset.googleapis.com iam.googleapis.com \
  --project="${PROJECT_ID}"

# These are Google-managed service agents (P4SAs), not service accounts you
# create or supply. Creating them here rather than in either setup script is
# what lets both of those grant to ${GDA_SERVICE_AGENT} / ${AIC_SERVICE_AGENT}
# without ordering between them.
log "Creating service identities (P4SAs)"
for SVC in geminidataanalytics.googleapis.com cloudaicompanion.googleapis.com; do
  gcloud beta services identity create --service="${SVC}" --project="${PROJECT_ID}"
done
echo "  ${GDA_SERVICE_AGENT}"
echo "  ${AIC_SERVICE_AGENT}"

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

log "Shared preflight complete for ${PROJECT_ID}"
cat <<EOF

No CMEK key exists yet — each resource type needs its own, in its own KMS
location. Set up whichever you are governing:

  bash scripts/setup_agents.sh          # Part 1 — the key in ${LOCATION}
  bash scripts/setup_conversations.sh   # Part 2 — the paired-region keys

Then the shared control plane, and the resource itself:

  bash scripts/deploy_controls.sh       # Layers 2, 4, 5 — once, both types
  bash scripts/deploy_agents.sh         # Layer 3 -> a CMEK agent
  bash scripts/deploy_conversations.sh  # Layer 3 -> a CMEK conversation
EOF
