#!/usr/bin/env bash
# Layer 3 for the conversation surface.
#
# The agent half of Layer 3 is layer3/deploy.sh: it creates a BigQuery
# datasource and a CMEK-protected agent. This is the same layer applied to the
# other resource type, and it is a separate script because the two differ in
# every mechanical detail even though the control is identical.
#
# The keys themselves come from scripts/00_bootstrap.sh, exactly as the agent
# key does — conversations need theirs in the multi-region's PAIRED region
# (`us` -> `us-central1`, `eu` -> `europe-west1`), which is not where the agents'
# key lives (validation-report F8).
#
# What this adds on top is a real CMEK-protected conversation in each supported
# location, created only after the key passes the policy check in-process. That
# ordering is the point: offering a key to CreateConversation registers it
# permanently for the whole project+location even if the call then fails, so the
# check cannot be an after-the-fact assertion.
#
#   bash layer3/deploy_conversation.sh
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

CONVERSATION_LOCATIONS="$(python -c 'import sys; sys.path.insert(0, "'"${REPO_ROOT}"'");
from common.gda_common import CONVERSATION_KMS_LOCATION as m
print(" ".join(sorted(m)))')"

RUN_ID="${RUN_ID:-$(date +%m%d%H%M%S)}"
FAILED=0

for LOCATION_ARG in ${CONVERSATION_LOCATIONS}; do
  log "CMEK conversation in ${LOCATION_ARG}"
  python -m layer3.create_conversation \
    --location "${LOCATION_ARG}" \
    --conversation-id "layer3-cmek-${RUN_ID}" || FAILED=1
done

if [[ "${FAILED}" -ne 0 ]]; then
  cat <<'EOF'

At least one location did not produce a CMEK conversation. The usual causes,
in order of likelihood:

  * APPROVED_KMS_PROJECTS does not list the project holding the key, so the
    policy blocked the call. Set it in config/shared.env.local.
  * No DataAgent exists yet — run `bash layer3/deploy.sh` first. A conversation
    must reference one, though it may be in another location.
  * The paired-region key is missing — re-run `bash scripts/00_bootstrap.sh`.
  * The project+location already has a DIFFERENT key registered. That
    registration is permanent and cannot be reassigned; the only remedy is a
    different project. See validation-report F8.
EOF
  exit 1
fi

cat <<'EOF'

Conversations are CMEK-protected in every supported location.

Verify the key is a real boundary, rather than a field that round-tripped
(this disables a live key version for several minutes):

  python -m layer5.conversation_cmek_probe --revocation

Note what is NOT established by the above: your application still has to set
kms_key on every conversation it creates. CMEK is opt-in per conversation, an
unkeyed one inherits nothing, and Layer 5 reports any location where one exists.
EOF
