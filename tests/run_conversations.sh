#!/usr/bin/env bash
# The conversation suite: every layer's conversation half, in dependency order.
#
# The counterpart of tests/run_agents.sh. It exists because conversation
# coverage would otherwise be invisible — three of the five layers check
# conversations from inside a script named after agents:
#
#   Layer 1  12 policy tests for conversation_keys[], run by run_layer1.sh
#   Layer 2  create/delete probes and the conv-user persona, run by run_layer2.sh
#   Layer 3  run_layer3_conversation.sh          <- dedicated
#   Layer 4  run_layer4_conversation.sh          <- dedicated
#   Layer 5  the posture probe, step 7 of run_layer5.sh
#
# This runs the two dedicated gates plus the Layer 5 probe, and points at where
# the other two live rather than re-running whole agent suites.
#
# Order matters here as it does on the agent side, for two reasons:
#
#   * The Layer 5 posture probe runs FIRST, before anything disables a key. It
#     asserts that a paired-region key is ACCEPTED, so it has to measure an
#     undisturbed estate. Layer 3's gate disables and re-enables a live key
#     version, and KMS takes minutes to propagate either way — the probe itself
#     measures a keyed conversation going dark ~4 minutes after the disable. Run
#     afterwards, it sees its own suite's re-enabled key still rejecting and
#     reports platform drift, which is a false alarm about F8.
#   * Layer 3 before Layer 4, so the revocation window is closed before the
#     enforcer is exercised. Layer 4's conversation half only ever alerts, so
#     unlike the agent suite there is nothing to disarm.
#
# Prerequisites: the Part 2 deployment. Unlike the agent suite this needs no
# negative fixtures — its negatives are locations, not resources.
#   bash scripts/setup_conversations.sh && bash scripts/deploy_conversations.sh
#
#   bash tests/run_conversations.sh
#   SKIP_REVOCATION=1 bash tests/run_conversations.sh   # fast, no key disabled
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILED=0

run_gate() {  # $1=label $2=script
  log "${1}"
  if bash "${HERE}/${2}"; then
    printf '\n  [PASS] %s\n' "${1}"
  else
    printf '\n  [FAIL] %s\n' "${1}"
    FAILED=1
  fi
}

log "Conversation suite — ${PROJECT_ID}"
cat <<'EOF'
  Layer 1 and Layer 2 cover conversations from inside the agent suites:
    Layer 1  bash tests/run_layer1.sh   (12 conversation_keys policy tests)
    Layer 2  bash tests/run_layer2.sh   (conversation cells of the persona matrix)
  Both are offline or persona-scoped and are not repeated here.
EOF

# The gates validate the Part 2 deployment; they do not stand one up. Fail early
# and specifically rather than inside CreateConversation.
log "Preconditions"
for PAIR in $(conversation_kms_pairs); do
  CONV_KMS_LOCATION="${PAIR##*:}"
  if ! gcloud kms keys describe "${KMS_KEY}" --keyring="${KMS_KEYRING}" \
       --location="${CONV_KMS_LOCATION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  No paired-region key in ${CONV_KMS_LOCATION}." >&2
    echo "  Run:  bash scripts/setup_conversations.sh" >&2
    exit 1
  fi
done
echo "  paired-region keys present for: $(conversation_kms_pairs)"

if ! gcloud run services describe "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
     --region="${INFRA_REGION}" >/dev/null 2>&1; then
  echo "  Layer 4 enforcer ${FUNCTION_NAME} is not deployed — its gate below" >&2
  echo "  would pass vacuously.  Run:  bash scripts/deploy_controls.sh" >&2
  exit 1
fi
echo "  Layer 4 enforcer deployed"

# FIRST, on an undisturbed estate — see the ordering note in the header. This is
# the non-destructive half: the paired-region rule, opt-in CMEK and the us-east4
# outage. The revocation half runs inside the Layer 3 gate below.
log "Layer 5 — the platform still behaves the way F8 records"
RC=0; python -m layer5.conversation_cmek_probe || RC=$?
case "${RC}" in
  0) printf '  [PASS] conversation CMEK posture unchanged\n' ;;
  2) printf '  [ERROR] probe INCONCLUSIVE — could not run; re-run\n'; FAILED=1 ;;
  *) printf '  [FAIL] platform drift — re-validate F8\n'; FAILED=1 ;;
esac

run_gate "Layer 3 — the CMEK boundary on a conversation" run_layer3_conversation.sh
run_gate "Layer 4 — the create is detected and attributed" run_layer4_conversation.sh

if [[ "${FAILED}" -ne 0 ]]; then
  log "Conversation suite: FAIL"
  exit 1
fi
log "Conversation suite: PASS"
