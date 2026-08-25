#!/usr/bin/env bash
# Layer 2 gate: the least-privilege IAM model, verified behaviourally.
#
# Two independent checks:
#   1. Declarative — every predefined role holds the permissions the design
#      claims (`gcloud iam roles describe`).
#   2. Behavioural — each persona actually can/cannot perform each operation,
#      under impersonated credentials against the live API.
#
# The second is the one that matters. A role table is an assertion; a probe that
# tries the call and gets PERMISSION_DENIED is evidence.
#
# Requires layer2/deploy.sh to have been run. IAM propagation takes ~60-120s
# after that, so a first run immediately afterwards may report spurious denials.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

FAILED=0
check() {
  if [[ "$2" -eq 0 ]]; then printf '  [PASS] %s — %s\n' "$1" "$3"
  else printf '  [FAIL] %s — %s\n' "$1" "$3"; FAILED=1; fi
}

# role -> exact expected permission set, verified 2026-08-21.
declare -A ROLE_PERMS=(
  [dataAgentCreator]="geminidataanalytics.dataAgents.create geminidataanalytics.locations.chat geminidataanalytics.operations.get"
  [dataAgentViewer]="geminidataanalytics.dataAgents.get geminidataanalytics.dataAgents.list"
  [dataAgentStatelessUser]="geminidataanalytics.locations.chat geminidataanalytics.locations.useDataEngineeringAgent"
)

log "1. Predefined roles exist"
EXPECTED_ROLES=(admin dataAgentCreator dataAgentEditor dataAgentOwner
                dataAgentStatelessUser dataAgentUser dataAgentViewer
                queryDataUser viewer)
MISSING=()
for R in "${EXPECTED_ROLES[@]}"; do
  gcloud iam roles describe "roles/geminidataanalytics.${R}" --format='value(name)' >/dev/null 2>&1 \
    || MISSING+=("${R}")
done
check "all 9 geminidataanalytics roles present" \
  "$([[ ${#MISSING[@]} -eq 0 ]] && echo 0 || echo 1)" \
  "${#EXPECTED_ROLES[@]} expected, missing: ${MISSING[*]:-none}"

log "2. Role permission sets match the documented model"
for R in "${!ROLE_PERMS[@]}"; do
  ACTUAL="$(gcloud iam roles describe "roles/geminidataanalytics.${R}" \
    --format='value(includedPermissions)' 2>/dev/null | tr ';' '\n' | sort | tr '\n' ' ' | xargs || true)"
  WANT="$(tr ' ' '\n' <<<"${ROLE_PERMS[$R]}" | sort | tr '\n' ' ' | xargs)"
  if [[ "${ACTUAL}" == "${WANT}" ]]; then
    check "${R}" 0 "${ACTUAL}"
  else
    check "${R}" 1 "expected [${WANT}] got [${ACTUAL}]"
  fi
done

# The single most load-bearing fact in Layer 2: dataAgentOwner (held by the
# Layer 4 enforcer) can delete but CANNOT create. If that ever changes, the
# enforcer becomes able to create the very resources it polices.
OWNER_PERMS="$(gcloud iam roles describe roles/geminidataanalytics.dataAgentOwner \
  --format='value(includedPermissions)' 2>/dev/null | tr ';' '\n' || true)"
check "dataAgentOwner can delete" \
  "$(grep -qx 'geminidataanalytics.dataAgents.delete' <<<"${OWNER_PERMS}" && echo 0 || echo 1)" \
  "required by the Layer 4 enforcer"
check "dataAgentOwner CANNOT create" \
  "$(grep -qx 'geminidataanalytics.dataAgents.create' <<<"${OWNER_PERMS}" && echo 1 || echo 0)" \
  "the enforcer must not be able to create what it polices"

log "3. Behavioural probe (impersonating each persona)"
if ! gcloud iam service-accounts describe \
     "layer2-analyst@${PROJECT_ID}.iam.gserviceaccount.com" \
     --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  [SKIP] personas not deployed — run: bash layer2/deploy.sh"
else
  if python -m layer2.probe --matrix; then
    check "persona x operation matrix" 0 "every cell matches the documented model"
  else
    check "persona x operation matrix" 1 "see mismatches marked X above"
  fi
fi

log "Layer 2 verdict: $([[ $FAILED -eq 0 ]] && echo PASS || echo FAIL)"
exit "${FAILED}"
