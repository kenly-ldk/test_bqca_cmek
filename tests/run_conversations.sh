#!/usr/bin/env bash
# The conversation suite: every layer's conversation half, in dependency order.
#
# The agent suite is run_layer{1,3,4,5,2}.sh. This is its counterpart, and it
# exists because conversation coverage would otherwise be invisible — three of
# the five layers check conversations from inside a script named after agents:
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
# Order matters for the same reason it does on the agent side: Layer 3's test
# revokes a key, and an enforcing Layer 4 must not be reacting to that mid-run.
# Layer 4's conversation half only ever alerts, so unlike the agent suite there
# is nothing to disarm — but Layer 3 still runs first so its revocation window
# is closed before Layer 4 is exercised.
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

run_gate "Layer 3 — the CMEK boundary on a conversation" run_layer3_conversation.sh
run_gate "Layer 4 — the create is detected and attributed" run_layer4_conversation.sh

log "Layer 5 — the platform still behaves the way F8 records"
# Non-destructive: the paired-region rule, opt-in CMEK, and the us-east4 outage.
# The revocation half of this probe already ran inside the Layer 3 gate above.
RC=0; python -m layer5.conversation_cmek_probe || RC=$?
case "${RC}" in
  0) printf '  [PASS] conversation CMEK posture unchanged\n' ;;
  2) printf '  [ERROR] probe INCONCLUSIVE — could not run; re-run\n'; FAILED=1 ;;
  *) printf '  [FAIL] platform drift — re-validate F8\n'; FAILED=1 ;;
esac

if [[ "${FAILED}" -ne 0 ]]; then
  log "Conversation suite: FAIL"
  exit 1
fi
log "Conversation suite: PASS"
