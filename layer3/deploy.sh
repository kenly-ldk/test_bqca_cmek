#!/usr/bin/env bash
# Layer 3 in practice: create a data agent encrypted with a CMEK key.
#
# Deploys a BigQuery datasource for the agent to reference, then creates the
# agent itself. The Layer 1 policy checks the manifest first and the API is
# called only if it passes — exactly what a deployment pipeline would do.
# The kms_key is set at creation and is immutable afterwards.
#
# Run after scripts/00_bootstrap.sh, and after Layers 4 and 5 are deployed so
# that the enforcer sees the create event and you can watch it classify the
# agent COMPLIANT before switching it out of dry-run.
#
# This is Layers 1 and 3 in action: the manifest is evaluated against the CMEK
# policy before any API call is made, and the agent it creates carries a
# kms_key that cannot be changed afterwards.
#
# Idempotent — apply_manifest reads back an existing agent and compares its key
# rather than failing.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"
cd "${REPO_ROOT}"

log "BigQuery datasource ${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} in ${LOCATION}"
bq --project_id="${PROJECT_ID}" mk --location="${LOCATION}" \
  --dataset "${PROJECT_ID}:${BQ_SOURCE_DATASET}" 2>/dev/null || echo "  dataset exists"
bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${LOCATION}" \
"CREATE TABLE IF NOT EXISTS ${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} AS
 SELECT * FROM UNNEST([
   STRUCT(1 AS customer_id, 'Alice Tan' AS full_name, 'Singapore' AS city, 125000.50 AS balance_sgd, DATE '2021-03-14' AS joined_date),
   STRUCT(2, 'Bharat Rao', 'Mumbai', 48200.00, DATE '2022-07-01'),
   STRUCT(3, 'Chen Wei', 'Hong Kong', 903400.75, DATE '2019-11-23'),
   STRUCT(4, 'Dewi Sari', 'Jakarta', 15600.20, DATE '2023-01-09'),
   STRUCT(5, 'Emma Lim', 'Singapore', 271900.00, DATE '2020-05-30')
 ])" >/dev/null
echo "  table ready"

# Turns the committed ${VAR} templates into concrete manifests carrying this
# project's IDs, and writes the OPA allowlist from APPROVED_KMS_PROJECTS.
log "Rendering the agent manifest and the policy allowlist"
bash "${REPO_ROOT}/layer1/render.sh"

# The gate runs in-process here, before any API call. A manifest that violates
# the CMEK policy exits non-zero and creates nothing.
log "Checking the manifest against the Layer 1 policy, then creating the agent"
python -m layer1.apply_manifest --manifest "${REPO_ROOT}/layer1/manifests/agents.json"

log "CMEK-protected agent ready in ${PROJECT_ID}"
cat <<EOF

The agent is encrypted with:
  ${APPROVED_KMS_KEY_PATH}

If Layer 4 is deployed in dry-run, its logs should now show this agent
classified COMPLIANT. Confirm that, then switch it to enforcing:

  ( source scripts/prelude.sh
    gcloud run services update "\${FUNCTION_NAME}" --project="\${PROJECT_ID}" \\
      --region="\${LOCATION}" --update-env-vars=DRY_RUN=false )
EOF
