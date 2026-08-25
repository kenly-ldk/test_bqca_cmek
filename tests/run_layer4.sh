#!/usr/bin/env bash
# Layer 4 end-to-end test matrix.
#
#   compliant     -> must SURVIVE  (regression test: a sink filter matching both
#                                   LRO entries would delete this one, because the
#                                   trailing LRO audit entry carries no
#                                   `request` and thus looks key-less)
#   nokey         -> must be REMEDIATED
#   rogue         -> must be REMEDIATED
#   global-nokey  -> must be REMEDIATED (global cannot be CMEK-encrypted at all)
#
# Also asserts the thing that actually matters for compliance: because
# DeleteDataAgent is only a SOFT delete (30-day tombstone that remains readable
# via GET), the remediated agents' content must have been REDACTED, not merely
# deleted.
#
# Agent IDs are run-scoped: a soft-deleted agent keeps its ID until purgeTime,
# so fixed IDs can only be used once per 30 days.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

RUN_ID="${RUN_ID:-$(date -u +%H%M%S)}"
export RUN_ID
WINDOW_SECONDS="${WINDOW_SECONDS:-420}"
POLL_SECONDS=5

declare -A EXPECT=(
  [compliant]=survive
  [nokey]=remediated
  [rogue]=remediated
  [global-nokey]=remediated
)
declare -A AGENT_ID=(
  [compliant]="agent-compliant-${RUN_ID}"
  [nokey]="agent-nokey-${RUN_ID}"
  [rogue]="agent-rogue-key-${RUN_ID}"
  [global-nokey]="agent-global-nokey-${RUN_ID}"
)
declare -A AGENT_LOC=(
  [compliant]="${LOCATION}"
  [nokey]="${LOCATION}"
  [rogue]="${LOCATION}"
  [global-nokey]=global
)

TOKEN=""
refresh_token() { TOKEN="$(gcloud auth print-access-token --project="${PROJECT_ID}")"; }

agent_url() {  # $1=location $2=agent_id
  echo "https://$(gda_endpoint "$1")/v1beta/projects/${PROJECT_ID}/locations/$1/dataAgents/$2"
}

agent_json() {  # $1=location $2=agent_id -> full resource JSON (incl. tombstones)
  curl -s -H "Authorization: Bearer ${TOKEN}" \
       -H "x-goog-user-project: ${PROJECT_ID}" "$(agent_url "$1" "$2")"
}

# "live" = exists and not soft-deleted.
agent_live() {
  local body; body="$(agent_json "$1" "$2")"
  [[ "$body" != *'"error"'* && "$body" != *'"deleteTime"'* ]]
}

refresh_token

log "Run ID ${RUN_ID} — creating all four fixtures"
START_EPOCH="$(date -u +%s)"
python -m layer3.create_agent --all --run-id "${RUN_ID}"

log "Watching for up to ${WINDOW_SECONDS}s"
declare -A REMEDIATED_AT=()
deadline=$(( $(date -u +%s) + WINDOW_SECONDS ))
while (( $(date -u +%s) < deadline )); do
  refresh_token
  outstanding=0
  for v in "${!AGENT_ID[@]}"; do
    [[ "${EXPECT[$v]}" == "remediated" && -z "${REMEDIATED_AT[$v]:-}" ]] || continue
    if agent_live "${AGENT_LOC[$v]}" "${AGENT_ID[$v]}"; then
      outstanding=$((outstanding + 1))
    else
      REMEDIATED_AT[$v]=$(( $(date -u +%s) - START_EPOCH ))
      echo "  ${v} remediated after ~${REMEDIATED_AT[$v]}s"
    fi
  done
  (( outstanding == 0 )) && break
  sleep "${POLL_SECONDS}"
done

refresh_token
log "Results"
FAILED=0
for v in compliant nokey rogue global-nokey; do
  loc="${AGENT_LOC[$v]}"; id="${AGENT_ID[$v]}"
  if agent_live "$loc" "$id"; then actual=survive; else actual=remediated; fi

  if [[ "$actual" != "${EXPECT[$v]}" ]]; then
    printf '  [FAIL] %-13s expected=%-11s actual=%-11s\n' "$v" "${EXPECT[$v]}" "$actual"
    FAILED=1
    continue
  fi
  printf '  [PASS] %-13s expected=%-11s actual=%-11s %s\n' \
    "$v" "${EXPECT[$v]}" "$actual" "${REMEDIATED_AT[$v]:+(~${REMEDIATED_AT[$v]}s)}"

  # For remediated agents the soft-delete tombstone must contain no content.
  # Checks publishedContext AND lastPublishedContext: publishing an empty
  # context rotates the old one into lastPublishedContext, so a single
  # redaction pass leaves the customer content fully readable there.
  if [[ "$actual" == "remediated" ]]; then
    body="$(agent_json "$loc" "$id")"
    if [[ "$body" == *"Cymbal Bank wealth analytics assistant"* ]]; then
      where=$(grep -o 'lastPublishedContext' <<<"$body" >/dev/null && echo "incl. lastPublishedContext" || echo "publishedContext")
      printf '  [FAIL] %-13s tombstone STILL EXPOSES systemInstruction (%s)\n' "$v" "$where"
      FAILED=1
    elif [[ "$body" == *"cymbal_demo"* ]]; then
      printf '  [FAIL] %-13s tombstone still exposes datasource references\n' "$v"
      FAILED=1
    else
      printf '  [PASS] %-13s tombstone scrubbed (published + lastPublished)\n' "$v"
    fi
  fi
done

log "Remediation log entries"
gcloud logging read \
  'jsonPayload.security_event="CMEK_POLICY_VIOLATION_REMEDIATED"' \
  --project="${PROJECT_ID}" --freshness=1h --limit=10 \
  --format='table(jsonPayload.resource.basename(), jsonPayload.status, jsonPayload.action_taken, jsonPayload.remediation_latency_seconds)'

log "Layer 4 verdict: $([[ $FAILED -eq 0 ]] && echo PASS || echo FAIL)"
exit "${FAILED}"
