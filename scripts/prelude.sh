#!/usr/bin/env bash
# Shared bash prelude. Source this from every script in this repo:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"
#
# Loads config/shared.env then config/shared.env.local (.local wins) and exports
# the three standard env vars that form the contract between bash, Python,
# google.cloud.* clients and gcloud subprocesses.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

set -a
# shellcheck disable=SC1091
source "${REPO_ROOT}/config/shared.env"
if [[ -f "${REPO_ROOT}/config/shared.env.local" ]]; then
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/config/shared.env.local"
fi
set +a

# Contract: GOOGLE_APPLICATION_CREDENTIALS / CLOUDSDK_ACTIVE_CONFIG_NAME /
# GOOGLE_CLOUD_PROJECT. Empty GCP_CREDENTIALS_FILE means ambient ADC, so only
# export when actually set.
[[ -n "${GCP_CREDENTIALS_FILE:-}" ]] && export GOOGLE_APPLICATION_CREDENTIALS="${GCP_CREDENTIALS_FILE}"
[[ -n "${GCLOUD_CONFIG_NAME:-}" ]] && export CLOUDSDK_ACTIVE_CONFIG_NAME="${GCLOUD_CONFIG_NAME}"
export GOOGLE_CLOUD_PROJECT="${PROJECT_ID}"

# APPROVED_KMS_PROJECTS defaults to the workload project itself.
export APPROVED_KMS_PROJECTS="${APPROVED_KMS_PROJECTS:-${PROJECT_ID}}"
[[ -z "${APPROVED_KMS_PROJECTS}" ]] && export APPROVED_KMS_PROJECTS="${PROJECT_ID}"

# Fully-qualified key paths, derived so no script hardcodes them. Distinct names
# from KMS_KEY/ROGUE_KMS_KEY so re-sourcing this file stays idempotent.
export APPROVED_KMS_KEY_PATH="projects/${PROJECT_ID}/locations/${LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY}"
export ROGUE_KMS_KEY_PATH="projects/${ROGUE_PROJECT_ID}/locations/${LOCATION}/keyRings/${ROGUE_KMS_KEYRING}/cryptoKeys/${ROGUE_KMS_KEY}"

# The two Google-managed service agents (P4SAs) that CMEK requires on the key.
# Their addresses derive from PROJECT_NUMBER, so nothing here is project-specific
# — but you cannot substitute a service account of your own for either one.
# Both setup scripts grant to both: an agent's key is used by geminidataanalytics,
# a conversation's by cloudaicompanion, and the same key ring name serves both.
export GDA_SERVICE_AGENT="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com"
export AIC_SERVICE_AGENT="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com"

# Create a key ring + key in one KMS location and let both service agents use it.
# Idempotent: create is best-effort, the IAM binding is authoritative.
grant_cmek_key() {  # $1=kms location
  local kms_location="$1" member
  gcloud kms keyrings create "${KMS_KEYRING}" --location="${kms_location}" \
    --project="${PROJECT_ID}" 2>/dev/null || true
  gcloud kms keys create "${KMS_KEY}" --keyring="${KMS_KEYRING}" \
    --location="${kms_location}" --purpose=encryption \
    --project="${PROJECT_ID}" 2>/dev/null || true
  for member in "${GDA_SERVICE_AGENT}" "${AIC_SERVICE_AGENT}"; do
    gcloud kms keys add-iam-policy-binding "${KMS_KEY}" \
      --keyring="${KMS_KEYRING}" --location="${kms_location}" \
      --project="${PROJECT_ID}" --member="${member}" \
      --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --quiet >/dev/null
  done
}
export -f grant_cmek_key

# The `us` -> `us-central1`, `eu` -> `europe-west1` map that conversations need,
# read from common/gda_common.py so the shell cannot drift from the policy, the
# enforcer and the probe. Prints "<conversation location>:<kms location>" pairs.
conversation_kms_pairs() {
  python -c 'import sys; sys.path.insert(0, "'"${REPO_ROOT}"'")
from common.gda_common import CONVERSATION_KMS_LOCATION as m
print(" ".join(f"{k}:{v}" for k, v in sorted(m.items())))'
}
export -f conversation_kms_pairs

# Endpoint that serves ${LOCATION}. Keep in sync with common/gda_common.py.
gda_endpoint() {
  local loc="$1"
  case "$loc" in
    global) echo "geminidataanalytics.googleapis.com" ;;
    us|eu)  echo "geminidataanalytics.${loc}.rep.googleapis.com" ;;
    *)      echo "geminidataanalytics-${loc}.googleapis.com" ;;
  esac
}
export -f gda_endpoint

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
export -f log
