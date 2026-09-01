#!/usr/bin/env bash
# Setup for Part 2 — the Conversation surface. Run after scripts/00_bootstrap.sh.
# Idempotent; safe to re-run.
#
# Two things the agent surface does not need, and one trap:
#
#   1. Keys in DIFFERENT LOCATIONS. A DataAgent takes a key in its own location;
#      a Conversation takes one in the multi-region's paired primary region --
#      `us` -> `us-central1`, `eu` -> `europe-west1` -- and rejects every other
#      location, including the one Google documents (validation-report F8). The
#      pairing is read from common/gda_common.py, the same map the Layer 1
#      policy, the Layer 4 enforcer and the Layer 5 probe use, so none of them
#      can drift.
#
#   2. DATA ACCESS AUDIT LOGS. Conversations emit nothing under
#      geminidataanalytics; their lifecycle appears only as cloudaicompanion
#      TopicService.* entries in Data Access logs, which are off by default.
#      Enabling them is what makes the conversation half of the Layer 4 sink
#      match anything at all.
#
#   The trap: getting the key wrong is not correctable. The first key OFFERED
#   to CreateConversation is registered permanently for the whole
#   project+location, even when that call fails. Layer 1 gates the key for
#   exactly that reason — which is why this script only provisions keys, and
#   scripts/deploy_conversations.sh runs the policy check before any API call.
#
#   bash scripts/setup_conversations.sh                   production preflight
#   bash scripts/setup_conversations.sh --with-fixtures   see below — adds nothing
#
# Nothing here is test-specific, so this is safe to run against a project you
# care about.
source "$(dirname "${BASH_SOURCE[0]}")/prelude.sh"

WITH_FIXTURES=0
for ARG in "$@"; do
  case "${ARG}" in
    --with-fixtures) WITH_FIXTURES=1 ;;
    *) echo "unknown argument: ${ARG}" >&2; exit 2 ;;
  esac
done

log "Cloud KMS keys for the conversation surface"
for PAIR in $(conversation_kms_pairs); do
  CONV_LOCATION="${PAIR%%:*}"
  CONV_KMS_LOCATION="${PAIR##*:}"
  grant_cmek_key "${CONV_KMS_LOCATION}" "${CONVERSATION_KMS_KEY}"
  echo "  ${CONV_KMS_LOCATION} (for conversations in ${CONV_LOCATION}), both service agents granted"
done

# Note the scope: this turns on Data Access logging for the whole
# cloudaicompanion service, which also backs Gemini Code Assist and Cloud
# Assist. Expect log volume from those too, and budget for it.
log "Enabling Data Access audit logs for cloudaicompanion"
POLICY_TMP="$(mktemp)"
trap 'rm -f "${POLICY_TMP}"' EXIT
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
echo "  DATA_READ + DATA_WRITE on cloudaicompanion.googleapis.com"

if [[ "${WITH_FIXTURES}" -eq 1 ]]; then
  log "Test fixtures for the conversation suite: none to add"
  cat <<'EOF'
  The conversation suite provisions no negative fixtures, and the flag is
  accepted only so both setup scripts take the same arguments.

  Its negatives are LOCATIONS, not resources: the Layer 3 gate asserts that the
  documented key path and every non-paired location are rejected, which needs no
  key to exist anywhere. The unapproved-key-in-a-second-project fixture is
  agent-only — it exists to let Layer 4 remediate an agent it could not
  otherwise create, and Layer 4 cannot remediate a conversation at all.

  See scripts/setup_agents.sh --with-fixtures.
EOF
fi

log "Conversation setup complete for ${PROJECT_ID}"
cat <<EOF

Next, if you have not already:

  bash scripts/deploy_controls.sh         # Layers 2, 4, 5 — the shared control plane
  bash scripts/deploy_conversations.sh    # Layer 3 — a CMEK conversation per location

A conversation must reference a DataAgent, though it may be in another location,
so Part 1 has to be deployed at least as far as one agent:

  bash scripts/setup_agents.sh && bash scripts/deploy_agents.sh
EOF
