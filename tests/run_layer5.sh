#!/usr/bin/env bash
# Layer 5 verification.
#
#  1. Report CAI ExportAssets coverage/freshness, and prove that a
#     contentType=RESOURCE export embeds agent content.
#  2. Prove the natural-looking JSON_VALUE form is invalid against the real
#     export schema.
#  3. Run the scanner and assert the compliance view classifies every agent and
#     reconciles against the live API (set comparison, not counts — see
#     layer5/reconcile_check.py for why counts would be wrong).
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

FAILED=0
check() {  # $1=name $2=condition-result(0/1) $3=detail
  if [[ "$2" -eq 0 ]]; then printf '  [PASS] %s — %s\n' "$1" "$3"
  else printf '  [FAIL] %s — %s\n' "$1" "$3"; FAILED=1; fi
}

log "1. CAI coverage, freshness, and the content-leak hazard"
# The export feeds an [INFO] coverage number only — the content-leak hazard is
# asserted against SearchAllResources below — so its failure must be
# informational too. Its output must NOT be discarded under `set -e`: Cloud
# Asset Inventory allows only one export at a time per project, so back-to-back
# runs collide, and a transient failure would otherwise abort the ENTIRE Layer 5
# gate with a bare exit 2 and no message. A gate that dies without saying why is
# the same silent-failure pattern this framework exists to catch.
if EXPORT_OUT="$(gcloud asset export --project="${PROJECT_ID}" \
  --asset-types="geminidataanalytics.googleapis.com/DataAgent,cloudkms.googleapis.com/CryptoKey" \
  --content-type=resource \
  --bigquery-table="projects/${PROJECT_ID}/datasets/${BQ_DATASET}/tables/cai_snapshot" \
  --output-bigquery-force 2>&1)"; then
  EXPORT_RC=0
else
  EXPORT_RC=$?
fi

if [[ "${EXPORT_RC}" -ne 0 ]]; then
  echo "  [INFO] ExportAssets could not run (exit ${EXPORT_RC}): $(tail -1 <<<"${EXPORT_OUT}")"
  echo "  [INFO] Coverage number unavailable this run; the content-leak hazard is"
  echo "         still asserted below against SearchAllResources, so the gate is intact."
  EXPORTED_AGENTS="n/a"
else
  sleep 45
  # Guarded for the same reason the export above is, and it is the same hazard
  # one step later: --output-bigquery-force recreates cai_snapshot, so a slower
  # export leaves no table for this query 45s later. Under `set -euo pipefail`
  # the bare assignment then aborts the ENTIRE Layer 5 gate, and the 2>/dev/null
  # means it does so without printing anything at all. Coverage is an [INFO]
  # number; failing to read it must never be fatal.
  if ! EXPORTED_AGENTS="$(bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false \
    --location="${BQ_LOCATION}" --format=csv \
    "SELECT COUNT(*) FROM ${BQ_DATASET}.cai_snapshot
     WHERE asset_type='geminidataanalytics.googleapis.com/DataAgent'" 2>&1 | tail -1)"; then
    EXPORTED_AGENTS="n/a"
  fi
  # A non-numeric result means the query returned an error message, not a count.
  [[ "${EXPORTED_AGENTS}" =~ ^[0-9]+$ ]] || EXPORTED_AGENTS="n/a"
fi

# Reported, NOT asserted. ExportAssets coverage of DataAgent is unreliable — six
# of seven exports returned zero rows during validation (see validation-report
# F3). Pinning an expected count here would encode whatever the lag happened to
# be on one run. The unreliability IS the finding; the scanner reconciles two
# sources precisely because of it.
echo "  [INFO] ExportAssets DataAgent rows: ${EXPORTED_AGENTS} (coverage unreliable by design — reported, not asserted)"

if [[ "${EXPORTED_AGENTS}" != "0" && "${EXPORTED_AGENTS}" != "n/a" ]]; then
  BQ_LEAKED="$(bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false \
    --location="${BQ_LOCATION}" --format=csv \
    "SELECT COUNTIF(JSON_VALUE(resource.data,'\$.dataAnalyticsAgent.publishedContext.systemInstruction') IS NOT NULL)
     FROM ${BQ_DATASET}.cai_snapshot
     WHERE asset_type='geminidataanalytics.googleapis.com/DataAgent'" 2>/dev/null | tail -1)"
  echo "  [INFO] ...of which ${BQ_LEAKED} carry systemInstruction in plaintext in BigQuery"
fi

# THIS is the asserted form of the content-leak finding, and it deliberately does
# NOT go through ExportAssets. Asserting the leak against the BigQuery export
# would make this check SKIP itself whenever the export happens to return zero
# rows, so the gate would silently run a different set of checks from one run to
# the next. SearchAllResources returns DataAgent consistently, so asserting against
# it makes coverage constant — and it is the closer test anyway, because a
# read_mask on the search API is exactly the mitigation the scanner implements.
SEARCH_LEAK="$(gcloud asset search-all-resources \
  --scope="projects/${PROJECT_ID}" \
  --asset-types=geminidataanalytics.googleapis.com/DataAgent \
  --read-mask='name,versionedResources' \
  --project="${PROJECT_ID}" --format=json 2>/dev/null \
  | python -c "
import json,sys
rows = json.load(sys.stdin) or []
leaked = sum(
    1 for r in rows
    for v in r.get('versionedResources', [])
    if v.get('resource', {}).get('dataAnalyticsAgent', {}).get('publishedContext', {}).get('systemInstruction')
)
print(f'{leaked}/{len(rows)}')
" 2>/dev/null || echo "0/0")"
check "CAI surfaces agent content on request (read_mask=versionedResources)" \
  "$([[ "${SEARCH_LEAK%/*}" != "0" ]] && echo 0 || echo 1)" \
  "${SEARCH_LEAK} agents return systemInstruction in plaintext — the scanner must, and does, use a metadata-only read_mask"

log "2. JSON_VALUE(resource.data.kmsKey) against the real schema"
if bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${BQ_LOCATION}" \
     "SELECT JSON_VALUE(resource.data.kmsKey) FROM ${BQ_DATASET}.cai_snapshot LIMIT 1" >/dev/null 2>&1; then
  check "JSON_VALUE(resource.data.kmsKey) is invalid" 1 "unexpectedly succeeded"
else
  check "JSON_VALUE(resource.data.kmsKey) is invalid" 0 \
    "fails: resource.data is STRING; correct form is JSON_VALUE(resource.data, '\$.kmsKey')"
fi

log "3. Scanner run"
gcloud run jobs execute "${SCANNER_JOB}" --project="${PROJECT_ID}" \
  --region="${INFRA_REGION}" --wait >/dev/null 2>&1
sleep 10

log "4. Compliance view"
bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${BQ_LOCATION}" \
  "SELECT compliance_status, COUNT(*) AS agents
   FROM ${BQ_DATASET}.${COMPLIANCE_VIEW} GROUP BY 1 ORDER BY 2 DESC"

UNCLASSIFIED="$(bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false \
  --location="${BQ_LOCATION}" --format=csv \
  "SELECT COUNT(*) FROM ${BQ_DATASET}.${COMPLIANCE_VIEW}
   WHERE compliance_status IS NULL OR compliance_status=''" 2>/dev/null | tail -1)"
check "view classifies every row" \
  "$([[ "${UNCLASSIFIED}" == "0" ]] && echo 0 || echo 1)" "${UNCLASSIFIED} unclassified"

# Set-based reconciliation. Asserting view_count == api_count would be wrong:
# CAI lags, so the view legitimately carries rows the live API no longer lists,
# classified NON_COMPLIANT_UNVERIFIABLE. See layer5/reconcile_check.py.
log "5. Reconciliation: view vs live API"
# Exit 2 is distinct from exit 1: it means the live-API read was partial, so no
# verdict is possible. Collapsing it into a plain failure makes this gate flaky:
# a transient 503 on one location would report every healthy agent in that
# location as a violation. It still fails the build, but it must not be read as
# a compliance finding.
RC=0; python -m layer5.reconcile_check || RC=$?
case "${RC}" in
  0) check "no under-reporting, and API-invisible rows never reported COMPLIANT" 0 "sets reconcile" ;;
  2) printf '  [ERROR] reconciliation INCOMPLETE — partial live-API read, no verdict (not a compliance finding); re-run\n'
     FAILED=1 ;;
  *) check "no under-reporting, and API-invisible rows never reported COMPLIANT" 1 "see above" ;;
esac

# ---------------------------------------------------------------------------
# The whole justification for reading two sources, demonstrated rather than
# asserted. F4 established that a disabled CMEK key makes the live API omit an
# agent from LIST with no error, so a LIST-only inventory silently under-reports
# exactly when a key's state is suspect. CAI still returns those agents, so the
# scanner should catch every one as NON_COMPLIANT_UNVERIFIABLE.
#
# A healthy estate never reaches that branch, so scheduled scanning alone will
# not exercise it however long it runs (validation-report F9) — the precondition
# has to be created deliberately. Set SKIP_REVOCATION_PROOF=1 to skip; it
# disables a KMS key version for ~2 minutes.
if [[ "${SKIP_REVOCATION_PROOF:-0}" == "1" ]]; then
  log "6. Key-revocation proof — SKIPPED (SKIP_REVOCATION_PROOF=1)"
else
  log "6. Key-revocation proof: agents hidden from the API are caught, not dropped"
  RC=0; python -m layer5.revocation_proof || RC=$?
  case "${RC}" in
    0) check "key-disabled agents surface as UNVERIFIABLE, never COMPLIANT" 0 "two-source reconciliation demonstrated" ;;
    2) printf '  [ERROR] proof INCONCLUSIVE — could not establish the precondition; re-run\n'
       FAILED=1 ;;
    *) check "key-disabled agents surface as UNVERIFIABLE, never COMPLIANT" 1 "see above" ;;
  esac
fi

# ---------------------------------------------------------------------------
log "7. Conversation CMEK: the platform still behaves the way F8 records"
# The conversation verdict rests on three measured behaviours, none of them
# documented: the key must be in the multi-region's paired region, CMEK is
# opt-in per conversation, and us-east4 cannot host a conversation at all
# (validation-report F8). This gate is drift detection over those three — if any
# changes, the verdict in common/gda_common.py is measuring the wrong thing and
# F8 has to be re-validated.
#
# --revocation is deliberately NOT passed: it disables a live KMS key version
# for up to nine minutes. Run it by hand when re-validating F8.
#
# This is the ONE conversation assertion inside the agent suite, and it needs
# Part 2's paired-region keys, which scripts/setup_conversations.sh provisions.
# An agents-only estate does not have them, and the probe would then report the
# resulting PERMISSION_DENIED as platform drift — a false alarm about F8 caused
# by absent setup. Skipped rather than failed in that case; Part 2's own suite
# (tests/run_conversations.sh) is where this assertion is mandatory.
CONV_KEYS_PRESENT=1
for PAIR in $(conversation_kms_pairs); do
  gcloud kms keys describe "${KMS_KEY}" --keyring="${KMS_KEYRING}" \
    --location="${PAIR##*:}" --project="${PROJECT_ID}" >/dev/null 2>&1 || CONV_KEYS_PRESENT=0
done

if [[ "${CONV_KEYS_PRESENT}" -eq 0 ]]; then
  printf '  [SKIP] no paired-region conversation keys in %s — this is an\n' "${PROJECT_ID}"
  printf '         agents-only estate. Run scripts/setup_conversations.sh and\n'
  printf '         tests/run_conversations.sh to cover the conversation surface.\n'
else
  RC=0; python -m layer5.conversation_cmek_probe || RC=$?
  case "${RC}" in
    0) check "conversation CMEK posture unchanged" 0 "paired-region key rule, opt-in CMEK and the us-east4 outage all still hold" ;;
    2) printf '  [ERROR] conversation CMEK probe INCONCLUSIVE — could not run; re-run\n'
       FAILED=1 ;;
    *) check "conversation CMEK posture unchanged" 1 "platform drift — re-validate F8" ;;
  esac
fi

log "8. Conversation compliance (one row per project+location, over all conversations)"
bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${BQ_LOCATION}" \
  "SELECT location, compliance_status, verification_state, kms_key_project
   FROM ${BQ_DATASET}.${COMPLIANCE_VIEW}
   WHERE resource_type='CONVERSATION_KEY' ORDER BY location"

log "Violations (what a regulator would be shown)"
# is_violation, not NOT is_compliant. The latter also sweeps in the UNVERIFIABLE
# statuses and PENDING_CAI_INGESTION, which are operational states rather than
# findings — reporting "we could not check this" as a breach is how a compliance
# report loses its credibility.
bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${BQ_LOCATION}" \
  "SELECT agent_id, location, compliance_status, kms_key_project
   FROM ${BQ_DATASET}.${COMPLIANCE_VIEW} WHERE is_violation ORDER BY compliance_status"

log "Unverified (operational backlog, NOT reported as violations)"
bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${BQ_LOCATION}" \
  "SELECT verification_state, COUNT(*) AS agents
   FROM ${BQ_DATASET}.${COMPLIANCE_VIEW}
   WHERE verification_state IN ('UNVERIFIED','COMPLIANT_PENDING_CORROBORATION')
   GROUP BY 1 ORDER BY 1"

log "Layer 5 verdict: $([[ $FAILED -eq 0 ]] && echo PASS || echo FAIL)"
exit "${FAILED}"
