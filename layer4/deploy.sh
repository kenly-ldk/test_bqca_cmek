#!/usr/bin/env bash
# Deploy Layer 4: log sink -> Pub/Sub -> auto-remediation function.
# Idempotent; safe to re-run.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

HERE="${REPO_ROOT}/layer4"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

SA_EMAIL="${ENFORCER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

log "Service account ${SA_EMAIL}"
gcloud iam service-accounts create "${ENFORCER_SA}" \
  --project="${PROJECT_ID}" \
  --display-name="GDA CMEK auto-remediation enforcer" 2>/dev/null || echo "  exists"

# dataAgentOwner is the narrowest predefined role that includes dataAgents.delete.
for ROLE in roles/geminidataanalytics.dataAgentOwner roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" --role="${ROLE}" \
    --condition=None --quiet >/dev/null
  echo "  granted ${ROLE}"
done

log "Pub/Sub topic ${PUBSUB_TOPIC}"
gcloud pubsub topics create "${PUBSUB_TOPIC}" --project="${PROJECT_ID}" 2>/dev/null || echo "  exists"

# The filter has to cope with TWO different audit shapes, both verified live:
#
#   CreateDataAgent     (LRO)  -> two entries per create. operation.first=true
#                                 carries `request`; operation.last=true carries
#                                 an empty `response`. A filter that matches
#                                 both breaks: since the trailing entry has
#                                 no `request`, its payload-parsing logic reads
#                                 "no kms_key" and deletes a COMPLIANT agent.
#   CreateDataAgentSync        -> ONE entry, no `operation` field at all. This is
#                                 what the Python client library actually calls,
#                                 so a filter requiring operation.first=true
#                                 misses every real creation.
#
# `NOT operation.last=true` keeps both shapes while dropping the LRO tail.
# `NOT protoPayload.status.code>0` drops failed attempts (e.g. ALREADY_EXISTS).
# Two resource types, two services, one sink.
#
# Agents: CreateDataAgent under geminidataanalytics, Admin Activity, always on.
#   `operation.last` drops the trailing LRO entry, which reports no key and
#   would otherwise read as a violation on a compliant agent (F2).
#
# Conversations: there is NO geminidataanalytics audit log for them at all. The
#   create surfaces as cloudaicompanion TopicService.CreateTopic, in DATA ACCESS
#   logs, which are OFF BY DEFAULT — scripts/00_bootstrap.sh enables them, and
#   without that this half of the sink matches nothing. CreateTopic emits the
#   same two-entry LRO pair as CreateDataAgent, so `/topics/` keeps only the
#   entry that names the resource. The payload carries no key; the function
#   re-reads the conversation, exactly as it does for an agent (F8).
SINK_FILTER='(protoPayload.serviceName="geminidataanalytics.googleapis.com"
AND protoPayload.methodName=~"CreateDataAgent"
AND NOT operation.last=true
AND NOT protoPayload.status.code>0)
OR
(protoPayload.serviceName="cloudaicompanion.googleapis.com"
AND protoPayload.methodName=~"TopicService.CreateTopic"
AND protoPayload.resourceName=~"/topics/"
AND NOT protoPayload.status.code>0)'

log "Log sink ${LOG_SINK}"
if gcloud logging sinks describe "${LOG_SINK}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud logging sinks update "${LOG_SINK}" \
    "pubsub.googleapis.com/projects/${PROJECT_ID}/topics/${PUBSUB_TOPIC}" \
    --project="${PROJECT_ID}" --log-filter="${SINK_FILTER}" --quiet >/dev/null
  echo "  updated"
else
  gcloud logging sinks create "${LOG_SINK}" \
    "pubsub.googleapis.com/projects/${PROJECT_ID}/topics/${PUBSUB_TOPIC}" \
    --project="${PROJECT_ID}" --log-filter="${SINK_FILTER}" --quiet >/dev/null
  echo "  created"
fi

SINK_WRITER="$(gcloud logging sinks describe "${LOG_SINK}" \
  --project="${PROJECT_ID}" --format='value(writerIdentity)')"
gcloud pubsub topics add-iam-policy-binding "${PUBSUB_TOPIC}" \
  --project="${PROJECT_ID}" --member="${SINK_WRITER}" \
  --role=roles/pubsub.publisher --quiet >/dev/null
echo "  writer ${SINK_WRITER} can publish"

log "Building function source"
cp "${HERE}/main.py" "${HERE}/requirements.txt" "${BUILD_DIR}/"
cp "${REPO_ROOT}/common/gda_common.py" "${BUILD_DIR}/"

log "Deploying ${FUNCTION_NAME}"
gcloud functions deploy "${FUNCTION_NAME}" \
  --project="${PROJECT_ID}" \
  --gen2 \
  --region="${LOCATION}" \
  --runtime=python312 \
  --source="${BUILD_DIR}" \
  --entry-point=process_audit_log \
  --trigger-topic="${PUBSUB_TOPIC}" \
  --service-account="${SA_EMAIL}" \
  --ingress-settings=internal-only \
  --set-env-vars="APPROVED_KMS_PROJECTS=${APPROVED_KMS_PROJECTS},ENFORCER_SA_EMAIL=${SA_EMAIL},DRY_RUN=${DRY_RUN:-false}" \
  --max-instances=10 \
  --timeout=120s \
  --quiet

# The Eventarc push subscription authenticates to the function as ${SA_EMAIL}.
# With constraints/iam.automaticIamGrantsForDefaultServiceAccounts enforced
# nothing grants it run.invoker automatically, so every push is rejected with
# "The request was not authenticated ... lacks {run.routes.invoke}" and the
# function is never entered. Grant it explicitly, after deploy so the Cloud Run
# service exists.
log "Granting run.invoker to the push identity"
gcloud run services add-iam-policy-binding "${FUNCTION_NAME}" \
  --project="${PROJECT_ID}" --region="${LOCATION}" \
  --member="serviceAccount:${SA_EMAIL}" --role=roles/run.invoker --quiet >/dev/null
echo "  granted roles/run.invoker on ${FUNCTION_NAME}"

log "Deployed. Enforcer identity: ${SA_EMAIL}"
