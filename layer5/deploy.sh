#!/usr/bin/env bash
# Deploy Layer 5: BigQuery inventory + compliance view + scheduled scanner job.
# Idempotent; safe to re-run.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

HERE="${REPO_ROOT}/layer5"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

SA_EMAIL="${SCANNER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

render_sql() {  # substitute ${VAR} placeholders in a .sql file
  sed -e "s|\${PROJECT_ID}|${PROJECT_ID}|g" \
      -e "s|\${BQ_DATASET}|${BQ_DATASET}|g" \
      -e "s|\${INVENTORY_TABLE}|${INVENTORY_TABLE}|g" \
      -e "s|\${COMPLIANCE_VIEW}|${COMPLIANCE_VIEW}|g" "$1"
}

log "BigQuery dataset ${BQ_DATASET} (${BQ_LOCATION})"
bq --project_id="${PROJECT_ID}" mk --location="${BQ_LOCATION}" \
  --dataset "${PROJECT_ID}:${BQ_DATASET}" 2>/dev/null || echo "  exists"

log "Inventory table and compliance view"
for f in "${HERE}/sql/agent_inventory.sql" "${HERE}/sql/v_agent_compliance.sql"; do
  render_sql "$f" | bq --project_id="${PROJECT_ID}" query \
    --use_legacy_sql=false --location="${BQ_LOCATION}" >/dev/null
  echo "  applied $(basename "$f")"
done

log "Scanner service account ${SA_EMAIL}"
gcloud iam service-accounts create "${SCANNER_SA}" \
  --project="${PROJECT_ID}" --display-name="GDA CMEK compliance scanner" 2>/dev/null || echo "  exists"

# Read-only over agents; write only to its own BigQuery dataset.
for ROLE in roles/geminidataanalytics.dataAgentViewer \
            roles/cloudasset.viewer \
            roles/bigquery.dataEditor \
            roles/bigquery.jobUser; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" \
    --condition=None --quiet >/dev/null
  echo "  granted ${ROLE}"
done

log "Building scanner image source"
cp "${HERE}/scanner/main.py" "${HERE}/scanner/requirements.txt" "${BUILD_DIR}/"
cp "${REPO_ROOT}/common/gda_common.py" "${BUILD_DIR}/"
cp "${HERE}/scanner/Procfile" "${BUILD_DIR}/"

# `jobs deploy` (not create/update) is the verb that accepts --source and does
# create-or-update in one shot.
log "Deploying Cloud Run job ${SCANNER_JOB}"
gcloud run jobs deploy "${SCANNER_JOB}" \
  --project="${PROJECT_ID}" \
  --region="${INFRA_REGION}" \
  --source="${BUILD_DIR}" \
  --service-account="${SA_EMAIL}" \
  `# ^@^ switches the delimiter: SCAN_LOCATIONS and APPROVED_KMS_PROJECTS are` \
  `# themselves comma-separated lists, which the default parser would split.` \
  --set-env-vars="^@^PROJECT_ID=${PROJECT_ID}@BQ_DATASET=${BQ_DATASET}@INVENTORY_TABLE=${INVENTORY_TABLE}@APPROVED_KMS_PROJECTS=${APPROVED_KMS_PROJECTS}@SCAN_LOCATIONS=${SCAN_LOCATIONS}" \
  --max-retries=1 \
  --task-timeout=10m \
  --quiet

log "Cloud Scheduler ${SCANNER_JOB}-schedule (${SCANNER_SCHEDULE})"
SCHED_ARGS=(
  --project="${PROJECT_ID}" --location="${INFRA_REGION}"
  --schedule="${SCANNER_SCHEDULE}" --time-zone=Etc/UTC
  --uri="https://${INFRA_REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${PROJECT_ID}/jobs/${SCANNER_JOB}:run"
  --http-method=POST
  --oauth-service-account-email="${SA_EMAIL}"
)
if gcloud scheduler jobs describe "${SCANNER_JOB}-schedule" \
     --project="${PROJECT_ID}" --location="${INFRA_REGION}" >/dev/null 2>&1; then
  gcloud scheduler jobs update http "${SCANNER_JOB}-schedule" "${SCHED_ARGS[@]}" --quiet >/dev/null
  echo "  updated"
else
  gcloud scheduler jobs create http "${SCANNER_JOB}-schedule" "${SCHED_ARGS[@]}" --quiet >/dev/null
  echo "  created"
fi

# The scheduler calls the Run Admin API as the scanner SA, so it needs to be
# able to invoke its own job.
gcloud run jobs add-iam-policy-binding "${SCANNER_JOB}" \
  --project="${PROJECT_ID}" --region="${INFRA_REGION}" \
  --member="serviceAccount:${SA_EMAIL}" --role=roles/run.invoker --quiet >/dev/null
echo "  scanner SA can invoke the job"

log "Deployed."
