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
export APPROVED_KMS_KEY_PATH="projects/${PROJECT_ID}/locations/${AGENT_LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY}"
export CONVERSATION_KMS_KEY="${CONVERSATION_KMS_KEY:-${KMS_KEY}}"
export ROGUE_KMS_KEY_PATH="projects/${ROGUE_PROJECT_ID}/locations/${AGENT_LOCATION}/keyRings/${ROGUE_KMS_KEYRING}/cryptoKeys/${ROGUE_KMS_KEY}"

# A GDA multi-region is not a deployable region. Catching it here beats a
# gcloud error 400 six minutes into a Cloud Run build.
case "${INFRA_REGION}" in
  us|eu|global)
    echo "INFRA_REGION='${INFRA_REGION}' is a GDA multi-region, not a Cloud Run" >&2
    echo "region. Layers 4 and 5 cannot deploy there. Use a real region such as" >&2
    echo "us-central1 or us-east4, and set AGENT_LOCATION separately." >&2
    return 1 2>/dev/null || exit 1 ;;
esac

# The two Google-managed service agents (P4SAs) that CMEK requires on the key.
# Their addresses derive from PROJECT_NUMBER, so nothing here is project-specific
# — but you cannot substitute a service account of your own for either one.
# Both setup scripts grant to both: an agent's key is used by geminidataanalytics,
# a conversation's by cloudaicompanion, and the same key ring name serves both.
export GDA_SERVICE_AGENT="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com"
export AIC_SERVICE_AGENT="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com"

# Create a key ring + key in one KMS location and let both service agents use it.
# Idempotent: create is best-effort, the IAM binding is authoritative.
grant_cmek_key() {  # $1=kms location  $2=key name (default: the agent key)
  local kms_location="$1" key="${2:-${KMS_KEY}}" member
  gcloud kms keyrings create "${KMS_KEYRING}" --location="${kms_location}" \
    --project="${PROJECT_ID}" 2>/dev/null || true
  gcloud kms keys create "${key}" --keyring="${KMS_KEYRING}" \
    --location="${kms_location}" --purpose=encryption \
    --project="${PROJECT_ID}" 2>/dev/null || true
  for member in "${GDA_SERVICE_AGENT}" "${AIC_SERVICE_AGENT}"; do
    gcloud kms keys add-iam-policy-binding "${key}" \
      --keyring="${KMS_KEYRING}" --location="${kms_location}" \
      --project="${PROJECT_ID}" --member="${member}" \
      --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --quiet >/dev/null
  done
}
export -f grant_cmek_key

# The `us` -> `us-central1`, `eu` -> `europe-west1` map that conversations need,
# read from common/gda_common.py so the shell cannot drift from the policy, the
# enforcer and the probe. Prints "<conversation location>:<kms location>" pairs.
# Honours CONVERSATION_LOCATIONS, which SELECTS from the map rather than
# replacing it: the map is the platform rule (measured, not configurable), the
# config picks which of its entries this estate actually deploys into. An
# unsupported name is rejected here rather than burning a one-shot key slot.
conversation_kms_pairs() {
  python -c 'import sys; sys.path.insert(0, "'"${REPO_ROOT}"'")
from common.gda_common import CONVERSATION_KMS_LOCATION as m
want = [s.strip() for s in "'"${CONVERSATION_LOCATIONS:-}"'".split(",") if s.strip()]
if not want:
    want = sorted(m)
bad = [w for w in want if w not in m]
if bad:
    sys.exit(f"CONVERSATION_LOCATIONS contains {bad}; a conversation can only be "
             f"created in {sorted(m)}")
print(" ".join(f"{k}:{m[k]}" for k in sorted(set(want))))'
}
export -f conversation_kms_pairs

# Endpoint that serves a GDA location. Keep in sync with common/gda_common.py.
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
