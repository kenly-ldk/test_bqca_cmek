#!/usr/bin/env bash
# Preflight for the CONVERSATION surface. Separate from scripts/00_bootstrap.sh
# on purpose — no layer provisions this key, and nothing below is needed to
# deploy or validate the five layers. (Layers 1, 2 and 5 do still cover
# conversations once they exist: rejected from manifests, gated by IAM, and
# reported hourly. Layer 4 cannot see them.)
#
# Separate is not the same as optional. A conversation holds the same customer
# content an agent does, in plainer form: the question, the generated SQL and
# the returned rows. Until this runs, all of it rests under Google-managed
# encryption, and no layer changes that. Run it unless the estate creates no
# conversations at all — which IAM will not guarantee for you, since 16
# predefined roles can create one.
#
# Idempotent; safe to re-run and safe against a project you care about. It
# creates nothing but a KMS key ring, a key, and two service-agent grants.
#
# WHY A SEPARATE KEY AT ALL. A conversation does not accept the key its agents
# use. A DataAgent takes a key in its own location (`us` -> `us`, `eu` ->
# `europe`); a Conversation takes one in the multi-region's PAIRED PRIMARY
# REGION (`us` -> `us-central1`, `eu` -> `europe-west1`) and refuses every other
# KMS location, including the one Google's documentation prescribes. So an
# estate serving both resource types in one multi-region needs two key rings in
# two KMS locations. See validation-report F8.
#
# WHAT THIS SCRIPT DOES NOT DO: create a conversation. Conversations are
# ephemeral runtime resources created per user session by the application, never
# provisioned by a pipeline — Layer 1 rejects any manifest that declares one.
# The deployable part of the conversation surface is exactly this key. Whether a
# conversation then USES it is decided per conversation, by the caller, at
# runtime; CMEK is opt-in and an unkeyed conversation inherits nothing.
#
#   bash scripts/02_conversation_key.sh
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

# One source of truth for the pairing: the same map common/gda_common.py uses
# and the Layer 5 probe measures against, rather than a second copy that could
# drift from it.
PAIRS="$(python -c 'import sys; sys.path.insert(0, "'"${REPO_ROOT}"'");
from common.gda_common import CONVERSATION_KMS_LOCATION as m
print(" ".join(f"{k}:{v}" for k, v in sorted(m.items())))')"

GDA_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com"
AIC_SA="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com"

log "Conversation CMEK keys for ${PROJECT_ID}"
echo "  Conversations can be hosted in: $(echo "${PAIRS}" | tr ' ' '\n' | cut -d: -f1 | tr '\n' ' ')"
echo "  us-east4 is excluded deliberately — it cannot create a conversation at"
echo "  all, with or without a key (validation-report F8)."

for PAIR in ${PAIRS}; do
  CONV_LOCATION="${PAIR%%:*}"
  KMS_LOCATION="${PAIR##*:}"

  log "Key in ${KMS_LOCATION} (for conversations in ${CONV_LOCATION})"
  gcloud kms keyrings create "${KMS_KEYRING}" --location="${KMS_LOCATION}" \
    --project="${PROJECT_ID}" 2>/dev/null || echo "  keyring exists"
  gcloud kms keys create "${KMS_KEY}" --keyring="${KMS_KEYRING}" \
    --location="${KMS_LOCATION}" --purpose=encryption \
    --project="${PROJECT_ID}" 2>/dev/null || echo "  key exists"

  for MEMBER in "${GDA_SA}" "${AIC_SA}"; do
    gcloud kms keys add-iam-policy-binding "${KMS_KEY}" \
      --keyring="${KMS_KEYRING}" --location="${KMS_LOCATION}" \
      --project="${PROJECT_ID}" --member="${MEMBER}" \
      --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --quiet >/dev/null
    echo "  granted ${MEMBER}"
  done
  echo "  projects/${PROJECT_ID}/locations/${KMS_LOCATION}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY}"
done

cat <<'EOF'

Done. Two things to know before your application uses these keys.

1. THE FIRST KEY OFFERED IS REGISTERED PERMANENTLY. The API allows one key per
   project per location for conversations. The first key submitted to
   CreateConversation is registered even if that call then fails, every later
   key is refused, disabling the key does not release the slot, and no API
   resets it. Anyone holding cloudaicompanion.topics.create can burn it. Do not
   "just try" a key to see what happens.

2. CMEK IS OPT-IN PER CONVERSATION. Creating the key protects nothing on its
   own. Each CreateConversation call must set kms_key, and a conversation
   created without one stays readable when the key is disabled. Layer 5 reports
   any location where a conversation is unkeyed; nothing prevents it.

Verify the posture, and that the platform still behaves as F8 records:

  python -m layer5.conversation_cmek_probe
EOF
