#!/usr/bin/env bash
# Deploy Part 2 — Layer 3 on the Conversation surface.
# Idempotent; safe to re-run.
#
# Prerequisites: scripts/00_bootstrap.sh, scripts/setup_conversations.sh, and at
# least one DataAgent (scripts/deploy_agents.sh) for a conversation to reference
# — it may be in another location. This checks each rather than failing halfway.
#
# The control is identical to the agent half; every mechanical detail differs,
# which is why this is a separate script. What it adds on top of the keys is a
# real CMEK-protected conversation in each supported location, created only
# after the key passes the policy check IN-PROCESS. That ordering is the point:
# offering a key to CreateConversation registers it permanently for the whole
# project+location even if the call then fails, so the check cannot be an
# after-the-fact assertion.
#
#   bash scripts/deploy_conversations.sh
#
# Note that in production your APPLICATION creates the real conversations, not a
# deploy step — Layer 1 rejects any manifest that declares one, and the key must
# be supplied per call. What this creates is a demonstrator per location that
# proves the key path works before your app depends on it.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"
cd "${REPO_ROOT}"

log "Checking prerequisites"
MISSING=0
for PAIR in $(conversation_kms_pairs); do
  CONV_LOCATION="${PAIR%%:*}"
  CONV_KMS_LOCATION="${PAIR##*:}"
  if gcloud kms keys describe "${CONVERSATION_KMS_KEY}" --keyring="${KMS_KEYRING}" \
       --location="${CONV_KMS_LOCATION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  ${CONV_KMS_LOCATION} key present (serves conversations in ${CONV_LOCATION})"
  else
    echo "  [MISSING] no key in ${CONV_KMS_LOCATION}, needed for ${CONV_LOCATION}" >&2
    MISSING=1
  fi
done
if [[ "${MISSING}" -ne 0 ]]; then
  echo "Run:  bash scripts/setup_conversations.sh" >&2
  exit 1
fi

# Checked here rather than left to a confusing failure inside create_conversation.
# Reads auditConfigs specifically: a plain IAM binding naming cloudaicompanion
# would satisfy a grep over the whole policy while logging stayed off.
if ! gcloud projects get-iam-policy "${PROJECT_ID}" --format=json \
     | python -c 'import json,sys
policy = json.load(sys.stdin)
cfg = next((c for c in policy.get("auditConfigs", [])
            if c.get("service") == "cloudaicompanion.googleapis.com"), None)
types = {l.get("logType") for l in (cfg or {}).get("auditLogConfigs", [])}
sys.exit(0 if {"DATA_READ", "DATA_WRITE"} <= types else 1)'; then
  echo "  [WARN] cloudaicompanion Data Access audit logs may be off. Conversations"
  echo "         will still be created and encrypted, but Layer 4 will not see"
  echo "         them. Run scripts/setup_conversations.sh to enable them."
else
  echo "  cloudaicompanion audit config present — Layer 4 can see the creates"
fi

bash "${REPO_ROOT}/layer3/deploy_conversation.sh"
