#!/usr/bin/env bash
# Layer 4, conversation half.
#
#   BOTH conversations -> must be REPORTED with the caller attributed, must
#                         NOT be judged compliant, and must SURVIVE.
#
# The enforcer cannot read a conversation it did not create -- 404 even with
# roles/cloudaicompanion.topicAdmin -- so it can never verify a key. This gate
# asserts the honest behaviour: detection and attribution, and specifically the
# ABSENCE of a compliance claim.
#
# Separate from run_layer4.sh because the two halves need different estates: the
# agent matrix needs the rogue-key project and run-scoped agent IDs, while this
# needs only an anchor agent and the paired-region key. Both assert the same
# property — the enforcer re-reads the resource rather than trusting the audit
# payload — against a resource type whose payload carries no key at all.
#
# Prerequisites: scripts/00_bootstrap.sh (for the paired-region keys AND the
# cloudaicompanion Data Access logs, without which the sink matches nothing),
# layer4/deploy.sh, and at least one DataAgent to anchor a conversation to.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

RUN_ID="${RUN_ID:-$(date -u +%H%M%S)}"
WINDOW_SECONDS="${WINDOW_SECONDS:-300}"
POLL_SECONDS=15
FAILED=0

check() {  # $1=name $2=condition-result(0/1) $3=detail
  if [[ "$2" -eq 0 ]]; then printf '  [PASS] %s — %s\n' "$1" "$3"
  else printf '  [FAIL] %s — %s\n' "$1" "$3"; FAILED=1; fi
}

CONV_LOCATION="${CONV_LOCATION:-us}"
KEYED_ID="conv-keyed-${RUN_ID}"
UNKEYED_ID="conv-nokey-${RUN_ID}"

log "0. Preconditions"
# Data Access logging is the one that silently produces a green-looking but
# meaningless run: with it off, no conversation event is ever emitted, so
# "nothing was remediated" would look like a pass.
AUDIT_ON="$(gcloud projects get-iam-policy "${PROJECT_ID}" --format=json \
  | python -c "
import json, sys
policy = json.load(sys.stdin)
services = {c.get('service') for c in policy.get('auditConfigs', [])}
print('yes' if 'cloudaicompanion.googleapis.com' in services else 'no')")"
if [[ "${AUDIT_ON}" != "yes" ]]; then
  printf '  [ERROR] Data Access audit logs are NOT enabled for cloudaicompanion.\n'
  printf '          No conversation event will reach the enforcer, so this gate\n'
  printf '          would pass vacuously. Run scripts/00_bootstrap.sh first.\n'
  exit 2
fi
check "cloudaicompanion Data Access logs enabled" 0 "the sink can see conversation creates"

log "1. Create one keyed and one unkeyed conversation in ${CONV_LOCATION}"
python - "${CONV_LOCATION}" "${KEYED_ID}" "${UNKEYED_ID}" <<'PYEOF'
import os
import sys

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import geminidataanalytics

sys.path.insert(0, os.environ["REPO_ROOT"])
from common.gda_common import (  # noqa: E402
    CONVERSATION_KMS_LOCATION,
    api_endpoint,
)
from config._loader import load  # noqa: E402

location, keyed_id, unkeyed_id = sys.argv[1], sys.argv[2], sys.argv[3]
env = load()
project = env["PROJECT_ID"]
parent = f"projects/{project}/locations/{location}"
key = (f"projects/{project}/locations/{CONVERSATION_KMS_LOCATION[location]}"
       f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['KMS_KEY']}")

agents = geminidataanalytics.DataAgentServiceClient(
    client_options=ClientOptions(api_endpoint=api_endpoint(location)))
chat = geminidataanalytics.DataChatServiceClient(
    client_options=ClientOptions(api_endpoint=api_endpoint(location)))

anchor = None
for candidate in dict.fromkeys([location, env.get("LOCATION", location)]):
    try:
        client = geminidataanalytics.DataAgentServiceClient(
            client_options=ClientOptions(api_endpoint=api_endpoint(candidate)))
        anchor = next(iter(client.list_data_agents(
            parent=f"projects/{project}/locations/{candidate}"))).name
        break
    except (GoogleAPICallError, StopIteration):
        continue
if anchor is None:
    sys.exit("no DataAgent to anchor a conversation to; run layer3/deploy.sh")

for conversation_id, kms in ((keyed_id, key), (unkeyed_id, None)):
    conversation = geminidataanalytics.Conversation(
        agents=[anchor], **({"kms_key": kms} if kms else {}))
    created = chat.create_conversation(
        request=geminidataanalytics.CreateConversationRequest(
            parent=parent, conversation_id=conversation_id,
            conversation=conversation))
    print(f"  created {conversation_id} kms_key={created.kms_key or None}")
PYEOF

log "2. Wait for the enforcer to classify both (up to ${WINDOW_SECONDS}s)"
KEYED_VERDICT=""
UNKEYED_VERDICT=""
DEADLINE=$(( SECONDS + WINDOW_SECONDS ))
while [[ "${SECONDS}" -lt "${DEADLINE}" ]]; do
  ENTRIES="$(gcloud logging read \
    "resource.type=cloud_run_revision AND jsonPayload.resource_type=CONVERSATION" \
    --project="${PROJECT_ID}" --freshness=20m --limit=50 \
    --format='value(jsonPayload.resource,jsonPayload.security_event,jsonPayload.status,jsonPayload.action_taken,jsonPayload.caller)' 2>/dev/null || true)"
  KEYED_VERDICT="$(grep -F "${KEYED_ID}" <<<"${ENTRIES}" | head -1 || true)"
  UNKEYED_VERDICT="$(grep -F "${UNKEYED_ID}" <<<"${ENTRIES}" | head -1 || true)"
  [[ -n "${KEYED_VERDICT}" && -n "${UNKEYED_VERDICT}" ]] && break
  sleep "${POLL_SECONDS}"
done

log "3. Verdicts"
# What this can and cannot assert changed once the visibility ceiling was
# measured. A conversation is readable only by the principal that created it,
# so the enforcer -- a different identity -- can never read the key and can
# never rule on compliance. Both conversations must therefore be REPORTED, and
# neither may be judged.
for PAIR in "keyed:${KEYED_VERDICT}" "unkeyed:${UNKEYED_VERDICT}"; do
  LABEL="${PAIR%%:*}"; VERDICT="${PAIR#*:}"
  if [[ -z "${VERDICT}" ]]; then
    check "${LABEL} conversation reported" 1 "no event within ${WINDOW_SECONDS}s"
    continue
  fi
  grep -q "CONVERSATION_CREATED_CMEK_UNVERIFIABLE" <<<"${VERDICT}" \
    && check "${LABEL} conversation reported and attributed" 0 "${VERDICT}" \
    || check "${LABEL} conversation reported and attributed" 1 "unexpected event: ${VERDICT}"
done

# The regression that matters most: the enforcer must never claim a conversation
# is compliant, because it cannot see one well enough to know.
if grep -q "CMEK_POLICY_COMPLIANT" <<<"${KEYED_VERDICT}${UNKEYED_VERDICT}"; then
  check "no false compliance claim" 1 \
    "the enforcer reported a conversation COMPLIANT, which it cannot verify"
else
  check "no false compliance claim" 0 "no conversation was vouched for"
fi

log "4. Both conversations must still exist (alert-only is the default)"
# The regression this guards: an enforcer that hard-deletes on detection would
# destroy a live user session. Deleting is opt-in via CONVERSATION_ACTION.
for CONVERSATION_ID in "${KEYED_ID}" "${UNKEYED_ID}"; do
  if gcloud auth print-access-token >/dev/null 2>&1 && \
     curl -sf -H "Authorization: Bearer $(gcloud auth print-access-token)" \
       "https://$(gda_endpoint "${CONV_LOCATION}")/v1/projects/${PROJECT_ID}/locations/${CONV_LOCATION}/conversations/${CONVERSATION_ID}" \
       >/dev/null 2>&1; then
    check "conversation ${CONVERSATION_ID} survived" 0 "not deleted, as intended"
  else
    check "conversation ${CONVERSATION_ID} survived" 1 "GONE — the enforcer deleted it despite alert-only"
  fi
done

log "5. Cleanup"
for CONVERSATION_ID in "${KEYED_ID}" "${UNKEYED_ID}"; do
  curl -s -X DELETE -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    "https://$(gda_endpoint "${CONV_LOCATION}")/v1/projects/${PROJECT_ID}/locations/${CONV_LOCATION}/conversations/${CONVERSATION_ID}" \
    >/dev/null 2>&1 || true
done
echo "  test conversations deleted (hard delete, no tombstone)"

if [[ "${FAILED}" -ne 0 ]]; then
  log "Layer 4 (conversations) verdict: FAIL"
  exit 1
fi
log "Layer 4 (conversations) verdict: PASS"
