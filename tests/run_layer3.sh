#!/usr/bin/env bash
# Layer 3 gate: CMEK is a real cryptographic boundary.
#
# Creates a compliant agent if absent, then runs the key-revocation proof.
#
# This test MUST NOT run while the Layer 4 enforcer is in enforcing mode
# (DRY_RUN=false), and the preflight below checks that rather than trusting a
# comment. The two layers race:
#
#   T+0s      the compliant fixture is created
#   T+~3s     verify_cmek disables the CryptoKeyVersion
#   T+17-27s  the enforcer's sink->Pub/Sub event lands and it GETs the agent
#   T+~60s    the disable actually propagates to GetDataAgent
#
# The enforcer normally wins by ~35s and records COMPLIANT. But if KMS ever
# propagates faster than the log sink delivers, the enforcer's GET raises
# FailedPrecondition, it fails closed (correctly — see layer4/main.py), and it
# redacts and soft-deletes this test's *compliant* fixture mid-run. Layer 3 then
# fails at the final "readable again after RE-ENABLED" assertion, for a reason
# that has nothing to do with Layer 3.
#
# Set ALLOW_ENFORCING_LAYER4=1 to run anyway and accept the race.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

if [[ "${ALLOW_ENFORCING_LAYER4:-0}" != "1" ]]; then
  ENFORCER_DRY_RUN="$(gcloud functions describe "${FUNCTION_NAME}" \
    --project="${PROJECT_ID}" --region="${INFRA_REGION}" \
    --format='value(serviceConfig.environmentVariables.DRY_RUN)' 2>/dev/null || true)"
  if [[ -z "${ENFORCER_DRY_RUN}" ]]; then
    echo "  [OK] Layer 4 enforcer not deployed — no race."
  elif [[ "${ENFORCER_DRY_RUN,,}" == "true" ]]; then
    echo "  [OK] Layer 4 enforcer is in dry-run mode — no race."
  else
    cat >&2 <<EOF
ERROR: the Layer 4 enforcer (${FUNCTION_NAME}) is in ENFORCING mode
(DRY_RUN=${ENFORCER_DRY_RUN}). It can soft-delete this test's compliant fixture
mid-run. Switch it to dry-run first:

  gcloud run services update ${FUNCTION_NAME} --project=${PROJECT_ID} \\
    --region=${INFRA_REGION} --update-env-vars=DRY_RUN=true

...then switch it back with DRY_RUN=false before running tests/run_layer4.sh.
Override with ALLOW_ENFORCING_LAYER4=1 to accept the race.
EOF
    exit 1
  fi
fi

# Run-scoped IDs: DeleteDataAgent is a soft delete, so a previously used agent
# ID stays occupied until purgeTime (~30 days) and cannot be recreated.
RUN_ID="${RUN_ID:-$(date -u +%H%M%S)}"
export RUN_ID

log "Creating the compliant fixture (run ${RUN_ID})"
python -m layer3.create_agent --variant compliant --run-id "${RUN_ID}"

log "Key-revocation proof"
python -m layer3.verify_cmek
