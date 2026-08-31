#!/usr/bin/env bash
# The agent suite: every layer's agent half, in dependency order.
#
# The counterpart of tests/run_conversations.sh. It runs the offline gates, then
# the four live ones, and handles the Layer 4 dry-run toggling that the order
# below requires — doing that by hand is easy to get wrong, and getting it wrong
# means the enforcer eats Layer 3's own compliant fixture mid-run.
#
# The order is DEPENDENCY-ordered, not layer-numbered: 1 -> 3 -> 4 -> 5 -> 2.
# Each run_layerN.sh verifies Layer N, but a test usually has to *do* something
# the layer itself never does, and that is what couples them. Two hard
# dependencies, in opposite directions:
#
#   * Layer 3's test must run BEFORE Layer 4 is enforcing. It creates a
#     compliant agent and revokes its CMEK key to prove the key is a real
#     boundary. The enforcer's event for that create arrives ~13-30 s later and
#     does a GET, which fails closed while the key is down — so an enforcing
#     Layer 4 can redact and soft-delete the test's own compliant fixture.
#     See validation-report F10.
#   * Layer 2's test must run AFTER it. Its create probe makes a key-less agent
#     as the pipeline persona, and an enforcing Layer 4 then remediates it,
#     naming layer2-cicd-deployer@... as the caller. That is the
#     defence-in-depth story in one log line, and only this order shows it.
#
# Everything else follows: Layer 4's test before Layer 5's, so the scanner has
# remediation history to reconcile against.
#
# This suite creates its own NON-COMPLIANT agents and lets Layer 4 remediate
# them — that is the whole point — so it leaves soft-deleted tombstones behind.
# Run it against a disposable estate.
#
# Prerequisites: the Part 1 deployment, plus its negative fixtures:
#   bash scripts/setup_agents.sh --with-fixtures
#
#   bash tests/run_agents.sh
#   OFFLINE_ONLY=1 bash tests/run_agents.sh   # unit + Layer 1 only, no GCP
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

set_dry_run() {  # $1=true|false
  gcloud run services update "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
    --region="${INFRA_REGION}" --update-env-vars="DRY_RUN=$1" >/dev/null
  echo "  Layer 4 DRY_RUN=$1"
}

log "Agent suite — ${PROJECT_ID}"

# Offline: no GCP project, no credentials, no network. Run first because a
# policy regression should not cost a live deployment to find.
run_gate "Offline — Python unit tests" run_unit.sh
run_gate "Offline — Layer 1, the policy gate" run_layer1.sh

if [[ -n "${OFFLINE_ONLY:-}" ]]; then
  [[ "${FAILED}" -ne 0 ]] && { log "Agent suite (offline): FAIL"; exit 1; }
  log "Agent suite (offline): PASS"
  exit 0
fi

# The live gates need the deployment the suite validates; they do not stand one
# up. Fail early and specifically rather than inside agent creation.
log "Preconditions"
if ! bq --project_id="${PROJECT_ID}" show \
     "${PROJECT_ID}:${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE}" >/dev/null 2>&1; then
  echo "  ${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} not found in ${PROJECT_ID}." >&2
  echo "  Deploy Part 1 first:  bash scripts/deploy_agents.sh" >&2
  exit 1
fi
echo "  datasource ${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} present"

if ! gcloud kms keys describe "${ROGUE_KMS_KEY}" --keyring="${ROGUE_KMS_KEYRING}" \
     --location="${AGENT_LOCATION}" --project="${ROGUE_PROJECT_ID}" >/dev/null 2>&1; then
  echo "  No unapproved key in ${ROGUE_PROJECT_ID}. The negative tests need it." >&2
  echo "  Run:  bash scripts/setup_agents.sh --with-fixtures" >&2
  exit 1
fi
echo "  unapproved key present in ${ROGUE_PROJECT_ID}"

if ! gcloud run services describe "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
     --region="${INFRA_REGION}" >/dev/null 2>&1; then
  echo "  Layer 4 enforcer ${FUNCTION_NAME} is not deployed." >&2
  echo "  Run:  bash scripts/deploy_controls.sh" >&2
  exit 1
fi
echo "  Layer 4 enforcer deployed"

# Restore enforcing on ANY exit. The suite's steady state is enforcing, and
# leaving a half-run estate in dry run silently disarms the control.
trap 'printf "\n"; log "Restoring Layer 4 to enforcing"; set_dry_run false || true' EXIT

log "Disarming Layer 4 so it cannot race the Layer 3 test"
set_dry_run true

run_gate "Layer 3 — the CMEK boundary on an agent" run_layer3.sh

log "Arming Layer 4"
set_dry_run false

run_gate "Layer 4 — detect, redact, soft-delete" run_layer4.sh
run_gate "Layer 5 — two reconciled sources" run_layer5.sh
run_gate "Layer 2 — the persona matrix, against an enforcing Layer 4" run_layer2.sh

if [[ "${FAILED}" -ne 0 ]]; then
  log "Agent suite: FAIL"
  exit 1
fi
log "Agent suite: PASS"
