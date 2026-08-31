#!/usr/bin/env bash
# The combination matrix: every agent location x key location pairing, and the
# agent+conversation pairing, measured against the live API.
#
# This is NOT the demo suite. tests/run_agents.sh and tests/run_conversations.sh
# reproduce the ONE combination config/shared.env deploys, and they are what you
# run to check the framework works. This walks the combinations the framework
# has to be *correct across*, and it is the script behind the coverage table in
# the README's "Where the CMEK key goes".
#
# Split out for two reasons. It is slow — it creates and deletes real agents and
# conversations in several locations — and it deliberately ignores
# AGENT_LOCATION / CONVERSATION_LOCATIONS, so it would contradict the demo
# suites if it lived inside them.
#
# What it does NOT re-run, because a cheaper script already proves it:
#   * the 24 rejected KMS locations   -> layer5/conversation_cmek_probe.py
#   * the key as a real boundary      -> tests/run_layer3{,_conversation}.sh
#
# Creates real resources. Agents soft-delete to a 30-day tombstone, so run this
# against a disposable estate only.
#
#   bash tests/run_matrix.sh
#   MATRIX_AGENT_LOCATIONS="us us-east4" bash tests/run_matrix.sh   # narrow it
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"
cd "${REPO_ROOT}"

RUN_ID="${RUN_ID:-$(date -u +%m%d%H%M%S)}"
FAILED=0
declare -a ROWS=()

# `global` is in the list on purpose: it is the negative that must FAIL to take
# a key. A matrix that only tries the combinations expected to work proves much
# less than one that also pins down where the boundary is.
MATRIX_AGENT_LOCATIONS="${MATRIX_AGENT_LOCATIONS:-us us-east4 eu global}"

record() { ROWS+=("$1|$2|$3"); }

check() {  # $1=name $2=rc(0/1) $3=detail
  if [[ "$2" -eq 0 ]]; then printf '  [PASS] %s — %s\n' "$1" "$3"
  else printf '  [FAIL] %s — %s\n' "$1" "$3"; FAILED=1; fi
}

# The KMS location an AGENT in $1 needs. Distinct from the conversation rule in
# common/gda_common.py: an agent's key is co-located with the agent, except that
# `eu` has no Cloud KMS multi-region so it uses `europe`.
agent_kms_location() {
  case "$1" in
    eu)     echo "europe" ;;
    global) echo "" ;;        # no key is accepted at all
    *)      echo "$1" ;;
  esac
}

log "Combination matrix — ${PROJECT_ID}  (run ${RUN_ID})"
cat <<EOF
  Demo suites cover the configured combination only:
    agent         ${AGENT_LOCATION}
    conversation  ${CONVERSATION_LOCATIONS}
  This walks: ${MATRIX_AGENT_LOCATIONS}
EOF

# ---------------------------------------------------------------------------
log "1. DataAgent x key location"
for LOC in ${MATRIX_AGENT_LOCATIONS}; do
  KMS_LOC="$(agent_kms_location "${LOC}")"
  AGENT_ID="matrix-${LOC//[^a-z0-9]/-}-${RUN_ID}"

  # `global` accepts no key at all, so probe it with a real key from elsewhere
  # and assert the REFUSAL. Expecting a refusal is the whole assertion: if this
  # ever starts passing, `global` became encryptable and Layer 5 stops needing
  # to report every global agent as non-compliant.
  EXPECT_REFUSAL=0
  if [[ -z "${KMS_LOC}" ]]; then
    EXPECT_REFUSAL=1
    KMS_LOC="$(agent_kms_location "${AGENT_LOCATION}")"
  fi

  KEY="projects/${PROJECT_ID}/locations/${KMS_LOC}/keyRings/${KMS_KEYRING}/cryptoKeys/${KMS_KEY}"
  grant_cmek_key "${KMS_LOC}" >/dev/null 2>&1 || true

  RESULT="$(python - "${PROJECT_ID}" "${LOC}" "${AGENT_ID}" "${KEY}" <<'PY'
import sys
from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import geminidataanalytics
sys.path.insert(0, __import__("os").environ["REPO_ROOT"])
from common.gda_common import api_endpoint  # noqa: E402

project, loc, aid, key = sys.argv[1:5]
c = geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(loc)))
agent = geminidataanalytics.DataAgent(display_name=f"matrix {loc}")
agent.kms_key = key
try:
    c.create_data_agent(request=geminidataanalytics.CreateDataAgentRequest(
        parent=f"projects/{project}/locations/{loc}", data_agent_id=aid,
        data_agent=agent))
except GoogleAPICallError as exc:
    print(f"FAIL|{(exc.message or str(exc))[:120]}"); raise SystemExit(0)
live = c.get_data_agent(name=f"projects/{project}/locations/{loc}/dataAgents/{aid}")
print(f"OK|{live.kms_key or 'NONE'}" if live.kms_key == key else f"MISMATCH|{live.kms_key or 'NONE'}")
PY
)"
  STATUS="${RESULT%%|*}"; DETAIL="${RESULT#*|}"

  if [[ "${EXPECT_REFUSAL}" -eq 1 ]]; then
    if [[ "${STATUS}" == "FAIL" ]]; then
      check "agent in ${LOC} refuses a CMEK key" 0 "as recorded — ${DETAIL}"
      record "DataAgent in \`${LOC}\`" "none accepted" "Correctly refused — cannot be CMEK-encrypted, so Layer 4/5 must flag it"
    else
      check "agent in ${LOC} refuses a CMEK key" 1 "a key was ACCEPTED (${DETAIL}) — F-series finding has changed"
      record "DataAgent in \`${LOC}\`" "none accepted" "UNEXPECTED — a key was accepted"
    fi
  elif [[ "${STATUS}" == "OK" ]]; then
    check "agent in ${LOC}, key in ${KMS_LOC}" 0 "created; kms_key confirmed on read-back"
    record "DataAgent in \`${LOC}\`" "\`${KMS_LOC}\`" "Pass — created, key confirmed on read-back"
  else
    check "agent in ${LOC}, key in ${KMS_LOC}" 1 "${STATUS}: ${DETAIL}"
    record "DataAgent in \`${LOC}\`" "\`${KMS_LOC}\`" "FAIL — ${DETAIL}"
  fi
done

# ---------------------------------------------------------------------------
log "2. The pairing: an agent and a conversation in the SAME multi-region"
# The production shape, and the one the demo now ships. Its point is that one
# multi-region needs TWO key rings, because the agent rule and the conversation
# rule disagree about where the key goes.
for PAIR in $(CONVERSATION_LOCATIONS="us,eu" conversation_kms_pairs); do
  CONV_LOC="${PAIR%%:*}"; CONV_KMS="${PAIR##*:}"
  AGENT_KMS="$(agent_kms_location "${CONV_LOC}")"
  CONV_ID="matrix-pair-${CONV_LOC}-${RUN_ID}"

  # Needs an agent in the same multi-region to anchor to; step 1 made one.
  RC=0; python -m layer3.create_conversation --location "${CONV_LOC}" \
          --conversation-id "${CONV_ID}" || RC=$?
  if [[ "${RC}" -eq 0 ]]; then
    check "${CONV_LOC} agent + ${CONV_LOC} conversation" 0 \
      "agent key in ${AGENT_KMS}, conversation key in ${CONV_KMS} — two key rings, one multi-region"
    record "\`${CONV_LOC}\` agent + \`${CONV_LOC}\` conversation" \
           "\`${AGENT_KMS}\` **and** \`${CONV_KMS}\`" \
           "Pass — one multi-region, two key locations"
  else
    check "${CONV_LOC} agent + ${CONV_LOC} conversation" 1 "see output above"
    record "\`${CONV_LOC}\` agent + \`${CONV_LOC}\` conversation" \
           "\`${AGENT_KMS}\` **and** \`${CONV_KMS}\`" "FAIL"
  fi
  python - "${PROJECT_ID}" "${CONV_LOC}" "${CONV_ID}" <<'PY' || true
import sys, os
from google.api_core.client_options import ClientOptions
from google.cloud import geminidataanalytics
sys.path.insert(0, os.environ["REPO_ROOT"])
from common.gda_common import api_endpoint  # noqa: E402
p, loc, cid = sys.argv[1:4]
geminidataanalytics.DataChatServiceClient(
    client_options=ClientOptions(api_endpoint=api_endpoint(loc))
).delete_conversation(name=f"projects/{p}/locations/{loc}/conversations/{cid}")
PY
done

# ---------------------------------------------------------------------------
log "3. Cleanup — the agents this run created"
for LOC in ${MATRIX_AGENT_LOCATIONS}; do
  [[ "${LOC}" == "global" ]] && continue
  python - "${PROJECT_ID}" "${LOC}" "matrix-${LOC//[^a-z0-9]/-}-${RUN_ID}" <<'PY' || true
import sys, os
from google.api_core.client_options import ClientOptions
from google.cloud import geminidataanalytics
sys.path.insert(0, os.environ["REPO_ROOT"])
from common.gda_common import api_endpoint  # noqa: E402
p, loc, aid = sys.argv[1:4]
geminidataanalytics.DataAgentServiceClient(
    client_options=ClientOptions(api_endpoint=api_endpoint(loc))
).delete_data_agent(name=f"projects/{p}/locations/{loc}/dataAgents/{aid}")
print(f"  deleted {aid} in {loc} (soft, 30-day tombstone)")
PY
done

# ---------------------------------------------------------------------------
log "Coverage table — paste into README 'What has actually been exercised live'"
printf '\n| Combination | Key location | Result |\n| :--- | :--- | :--- |\n'
for ROW in "${ROWS[@]}"; do
  IFS='|' read -r a b c <<<"${ROW}"
  printf '| %s | %s | %s |\n' "${a}" "${b}" "${c}"
done
printf '\nMeasured %s against %s.\n' "$(date -u +%Y-%m-%d)" "${PROJECT_ID}"

[[ "${FAILED}" -ne 0 ]] && { log "Matrix: FAIL"; exit 1; }
log "Matrix: PASS"
