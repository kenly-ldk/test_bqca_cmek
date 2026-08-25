#!/usr/bin/env bash
# Deploy Layer 2: the least-privilege IAM model, as testable principals.
#
# Creates one service account per persona in the design's Layer 2 table and
# binds the corresponding predefined role. tests/run_layer2.sh then impersonates
# each and asserts what it can and cannot do.
#
# Impersonation, not keys: constraints/iam.disableServiceAccountKeyCreation is
# enforced in most regulated orgs, so the caller is granted
# roles/iam.serviceAccountTokenCreator on each persona instead. That is also
# closer to how these identities are used in production (Workload Identity
# Federation, attached service accounts) than a downloaded key would be.
#
# Idempotent; safe to re-run.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

# A least-privilege role for stateful conversations, which no predefined role
# provides. Determined by probing the live API one permission at a time:
#
#   create_conversation  -> cloudaicompanion.topics.create
#                           AND cloudaicompanion.operations.get  (it is an LRO,
#                           and the poll is authorized separately)
#   get_conversation     -> cloudaicompanion.topics.get
#   list_messages        -> cloudaicompanion.topics.get
#   list_conversations   -> nothing; no permission gates it
#   delete_conversation  -> cloudaicompanion.topics.delete
#
# Conversations are NOT governed by geminidataanalytics at all — that service's
# entire surface is 18 permissions and none mention conversations.
#
# `topics.delete` is deliberately absent: it is NOT_SUPPORTED in custom roles,
# so it cannot be granted this way. Deleting conversations requires the
# predefined roles/cloudaicompanion.topicAdmin, which also carries
# topics.setIamPolicy and topics.update — a privilege-escalation surface well
# beyond "clean up my own conversation". Conversations are ephemeral, so this
# persona is create-and-read only and lets them expire rather than taking that
# trade. If your deployment must delete them, grant topicAdmin knowingly and
# scope it.
CONV_ROLE_ID="gdaConversationUser"
CONV_ROLE_PERMISSIONS="cloudaicompanion.topics.create,cloudaicompanion.topics.get,cloudaicompanion.operations.get"

# persona -> predefined role under test. Keep in sync with docs/design.md §6.
declare -A PERSONA_ROLE=(
  [cicd-deployer]=roles/geminidataanalytics.dataAgentCreator
  [app-runtime]=roles/geminidataanalytics.dataAgentStatelessUser
  [analyst]=roles/geminidataanalytics.dataAgentViewer
  [no-access]=""      # control: proves the matrix isn't passing by accident
  # Stateful conversations. Separate from app-runtime on purpose: enabling
  # conversations means reaching into cloudaicompanion, a different service with
  # a different blast radius, and that should be an explicit grant to an
  # explicit identity rather than a quiet widening of the stateless-chat role.
  [conv-user]=roles/geminidataanalytics.dataAgentStatelessUser
)
# Personas that additionally get the custom conversation role above.
declare -A PERSONA_EXTRA_ROLE=(
  [conv-user]="projects/${PROJECT_ID}/roles/${CONV_ROLE_ID}"
)

log "Custom conversation role ${CONV_ROLE_ID}"
if gcloud iam roles describe "${CONV_ROLE_ID}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam roles update "${CONV_ROLE_ID}" --project="${PROJECT_ID}" \
    --permissions="${CONV_ROLE_PERMISSIONS}" --quiet >/dev/null
  echo "  updated"
else
  gcloud iam roles create "${CONV_ROLE_ID}" --project="${PROJECT_ID}" \
    --title="GDA conversation user (least privilege)" \
    --description="Create and read stateful GDA conversations. No delete: cloudaicompanion.topics.delete is NOT_SUPPORTED in custom roles." \
    --permissions="${CONV_ROLE_PERMISSIONS}" --stage=GA --quiet >/dev/null
  echo "  created"
fi

CALLER="${LAYER2_CALLER:-$(gcloud config get-value account 2>/dev/null)}"
if [[ -z "${CALLER}" || "${CALLER}" == "(unset)" ]]; then
  echo "Cannot determine the calling identity. Set LAYER2_CALLER=user:you@example.com" >&2
  exit 1
fi
# gcloud reports a bare email; IAM needs a typed member.
[[ "${CALLER}" == *:* ]] || CALLER="user:${CALLER}"

log "Layer 2 personas in ${PROJECT_ID}"
echo "  impersonating caller: ${CALLER}"

for PERSONA in "${!PERSONA_ROLE[@]}"; do
  SA="layer2-${PERSONA}"
  SA_EMAIL="${SA}@${PROJECT_ID}.iam.gserviceaccount.com"
  ROLE="${PERSONA_ROLE[$PERSONA]}"

  gcloud iam service-accounts create "${SA}" \
    --project="${PROJECT_ID}" \
    --display-name="Layer 2 test persona: ${PERSONA}" >/dev/null 2>&1 \
    && echo "  created ${SA_EMAIL}" || echo "  exists  ${SA_EMAIL}"

  if [[ -n "${ROLE}" ]]; then
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" \
      --condition=None --quiet >/dev/null
    echo "    + ${ROLE}"
  else
    echo "    + (no GDA role — negative control)"
  fi

  EXTRA="${PERSONA_EXTRA_ROLE[$PERSONA]:-}"
  if [[ -n "${EXTRA}" ]]; then
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${SA_EMAIL}" --role="${EXTRA}" \
      --condition=None --quiet >/dev/null
    echo "    + ${EXTRA}"
  fi

  # The personas query BigQuery indirectly through the agent's datasource, and
  # need to read their own project's metadata to call the API at all.
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" --role=roles/serviceusage.serviceUsageConsumer \
    --condition=None --quiet >/dev/null

  gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --member="${CALLER}" --role=roles/iam.serviceAccountTokenCreator \
    --quiet >/dev/null
  echo "    + ${CALLER} may impersonate"
done

cat <<EOF

Personas ready. IAM propagation is not instant — allow ~60-120s before testing,
or expect spurious PERMISSION_DENIED on the first run.

Run the behavioural matrix:
  bash tests/run_layer2.sh
EOF
