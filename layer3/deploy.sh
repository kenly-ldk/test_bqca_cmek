#!/usr/bin/env bash
# Layer 3 in practice: create a data agent encrypted with a CMEK key.
#
# Deploys a BigQuery datasource for the agent to reference, then creates the
# agent itself. The Layer 1 policy checks the manifest first and the API is
# called only if it passes — exactly what a deployment pipeline would do.
# The kms_key is set at creation and is immutable afterwards.
#
# Invoked by scripts/deploy_agents.sh, which checks the prerequisites first and
# offers --enforce. Run that rather than this directly.
#
# Run after scripts/setup_agents.sh, and after Layers 4 and 5 are deployed so
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

log "BigQuery datasource ${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} in ${AGENT_LOCATION}"
bq --project_id="${PROJECT_ID}" mk --location="${AGENT_LOCATION}" \
  --dataset "${PROJECT_ID}:${BQ_SOURCE_DATASET}" 2>/dev/null || echo "  dataset exists"

# A pre-existing dataset of the same name in a DIFFERENT location is the one
# failure mode here that reads as a bug in this script rather than as estate
# drift: `bq mk` reports only "already exists", and the query below then fails
# because BigQuery will not run a job against a dataset outside --location.
# Checked explicitly so the message names the real problem.
DATASET_LOCATION="$(bq --project_id="${PROJECT_ID}" --format=json show \
  "${PROJECT_ID}:${BQ_SOURCE_DATASET}" 2>/dev/null \
  | python -c 'import json,sys; print(json.load(sys.stdin).get("location",""))' 2>/dev/null || true)"
if [[ -n "${DATASET_LOCATION}" ]] &&
   [[ "${DATASET_LOCATION,,}" != "${AGENT_LOCATION,,}" ]]; then
  cat >&2 <<EOF

  Dataset ${PROJECT_ID}:${BQ_SOURCE_DATASET} is in ${DATASET_LOCATION}, but
  AGENT_LOCATION is ${AGENT_LOCATION}. BigQuery cannot run a job against a dataset outside
  the job's location, so the table below cannot be created.

  A dataset's location is fixed at creation. Either drop and recreate it in
  ${AGENT_LOCATION}, or point BQ_SOURCE_DATASET at a different name in
  config/shared.env.local.
EOF
  exit 1
fi

# Captured rather than sent to /dev/null: bq reports query errors on STDOUT, so
# discarding it turns any failure into a bare non-zero exit with no diagnosis.
# The success output is noise, so it is only printed when something went wrong.
BQ_OUT="$(bq --project_id="${PROJECT_ID}" query --use_legacy_sql=false --location="${AGENT_LOCATION}" \
"CREATE TABLE IF NOT EXISTS ${BQ_SOURCE_DATASET}.${BQ_SOURCE_TABLE} AS
 SELECT * FROM UNNEST([
   STRUCT(1 AS customer_id, 'Alice Tan' AS full_name, 'Singapore' AS city, 125000.50 AS balance_sgd, DATE '2021-03-14' AS joined_date),
   STRUCT(2, 'Bharat Rao', 'Mumbai', 48200.00, DATE '2022-07-01'),
   STRUCT(3, 'Chen Wei', 'Hong Kong', 903400.75, DATE '2019-11-23'),
   STRUCT(4, 'Dewi Sari', 'Jakarta', 15600.20, DATE '2023-01-09'),
   STRUCT(5, 'Emma Lim', 'Singapore', 271900.00, DATE '2020-05-30')
 ])" 2>&1)" || {
  echo "  CREATE TABLE failed:" >&2
  printf '%s\n' "${BQ_OUT}" | sed 's/^/    /' >&2
  exit 1
}
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

  bash scripts/deploy_agents.sh --enforce
EOF
