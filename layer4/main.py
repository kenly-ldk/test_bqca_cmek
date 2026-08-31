"""Layer 4 — real-time detective & corrective guardrail for GDA CMEK.

Triggered by a Cloud Logging sink -> Pub/Sub -> this function. For every
DataAgent creation it decides whether the resource satisfies the two org-policy
equivalents, and deletes it if not.

Design notes (these differ from docs/design.md §3.3 for reasons validated
against the live API):

* **Regional endpoints.** CMEK-capable locations (us-east4, us, eu) are served
  by their own endpoints. Calling the global endpoint with a regional resource
  path returns 403, so the endpoint is derived per-event from the parsed
  location. A `discovery.build("geminidataanalytics", "v1")` client
  always hits the global endpoint and cannot delete a regional agent.

* **GET-then-verify, not payload-parse.** `kms_key` is immutable after creation,
  so the authoritative value is whatever the server reports. Reading it back
  also makes the function immune to the audit-log LRO producing two entries per
  create (only the `first` one carries `request`).

* **Fail closed.** Verified behaviour: if the CMEK key is disabled, the whole
  GetDataAgent RPC raises FailedPrecondition — metadata is not independently
  readable. A resource we cannot verify is treated as non-compliant, falling
  back to the audit payload only to *explain* the violation, never to excuse it.

* **Deletion survives key revocation**, so remediation still works on a resource
  whose key we could not read.

* **Delete is only a SOFT delete.** Verified: DeleteDataAgent moves the resource
  to SOFT_DELETED with purgeTime = deleteTime + 30 days. There is no purge,
  force or undelete method. Crucially, the agent's content remains fully
  readable via GetDataAgent for those 30 days — so "delete the resource" alone
  does NOT remove unencrypted customer content, and is therefore NOT equivalent
  to native CMEK org-policy enforcement. This function first overwrites the
  sensitive context with an empty one (`updateSync`), then soft-deletes.
  Redaction is the part that actually removes the content; the delete stops
  further use.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time

import functions_framework
from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import (
    FailedPrecondition,
    GoogleAPICallError,
    NotFound,
    PermissionDenied,
)
from google.cloud import geminidataanalytics

from gda_common import (
    MISSING_CMEK,
    Verdict,
    api_endpoint,
    evaluate_compliance,
    parse_approved_projects,
    resolve_agent_name,
    resolve_conversation_from_topic,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gda-cmek-enforcer")

APPROVED_KMS_PROJECTS = parse_approved_projects(os.getenv("APPROVED_KMS_PROJECTS"))
# When true, log the verdict but never delete. Use for a shadow-mode rollout.
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
# An empty allowlist approves nothing, so evaluate_compliance would return
# UNAPPROVED_KEY_PROJECT for every correctly-encrypted agent and this function
# would redact and soft-delete the entire estate. That is the exact failure this
# framework was built to catch (docs/validation-report.md F2), so a missing or
# blank APPROVED_KMS_PROJECTS is treated as a misconfiguration and disables
# remediation rather than escalating it. layer4/deploy.sh always sets it; this
# guards hand-edited env vars and partial redeploys.
MISCONFIGURED = not APPROVED_KMS_PROJECTS
UNVERIFIABLE = "NON_COMPLIANT_UNVERIFIABLE"
# Two passes needed to also flush `last_published_context`. See _remediate.
REDACTION_PASSES = 2

# Conversations are DETECT-AND-ATTRIBUTE only, and cannot be otherwise.
#
# A conversation is readable solely by the principal that created it. Measured
# against the live API: this service account, holding
# cloudaicompanion.topics.get, gets an empty ListConversations and a 404 from
# GetConversation for a conversation another principal created -- and granting
# roles/cloudaicompanion.topicAdmin, the most privileged role on the resource,
# changes nothing (validation-report F8).
#
# Two consequences, both structural:
#
#   * The enforcer can never read a conversation's kms_key, so it can never
#     issue a compliance verdict on one. It reports the create and names the
#     caller; that is the whole of what it can honestly claim.
#   * It could not delete one either, for the same reason -- DeleteConversation
#     on an invisible resource is a 404. There is deliberately no remediation
#     path here rather than one that silently no-ops.
#
# The control that actually binds is preventive: Layer 1 gates the key, Layer 2
# restricts who may call CreateConversation at all, and the application sets
# kms_key on every call.


def _client(location: str) -> geminidataanalytics.DataAgentServiceClient:
    return geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _chat_client(location: str) -> geminidataanalytics.DataChatServiceClient:
    return geminidataanalytics.DataChatServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _kms_key_from_audit_payload(proto_payload: dict) -> str | None:
    """Best-effort read of kms_key from the audit request payload.

    Only the `operation.first` log entry carries `request`, and audit payloads
    can be redacted, so this is explanatory context for a violation — never the
    basis for declaring something compliant.
    """
    request = proto_payload.get("request") or {}
    for container in ("dataAgent", "data_agent"):
        node = request.get(container)
        if isinstance(node, dict):
            key = node.get("kmsKey") or node.get("kms_key")
            if key:
                return key
    return None


def _emit(event: str, severity: str, **fields) -> None:
    """Structured log line. Cloud Logging parses jsonPayload from stdout JSON."""
    payload = {"security_event": event, "severity": severity, **fields}
    print(json.dumps(payload, default=str), flush=True)


def _remediate(agent, verdict: Verdict, caller: str, detected_at: float) -> None:
    name = agent.resource_name
    if DRY_RUN:
        _emit(
            "CMEK_POLICY_VIOLATION_DETECTED_DRY_RUN",
            "WARNING",
            resource=name,
            caller=caller,
            status=verdict.status,
            reason=verdict.reason,
            action_taken="NONE_DRY_RUN",
        )
        return

    client = _client(agent.location)
    actions: list[str] = []
    error = None

    # Step 1 — redact, TWICE. Soft-deleted agents stay readable for 30 days, so
    # this is what actually removes the unencrypted content. Must happen BEFORE
    # the delete: a SOFT_DELETED resource can no longer be updated.
    #
    # Two passes are required, verified experimentally. Publishing a new context
    # pushes the previous one into the output-only `last_published_context`
    # field, so a single pass leaves a verbatim copy of the customer content
    # behind:
    #   pass 1: published=<empty>  last=<SECRET>
    #   pass 2: published=<empty>  last=<empty>
    # `last_published_context` is output-only and cannot be cleared directly.
    try:
        for _ in range(REDACTION_PASSES):
            client.update_data_agent_sync(
                request=geminidataanalytics.UpdateDataAgentRequest(
                    data_agent=geminidataanalytics.DataAgent(
                        name=name,
                        display_name="[REDACTED BY CMEK ENFORCER]",
                        description=f"Content scrubbed: {verdict.status}.",
                        data_analytics_agent=geminidataanalytics.DataAnalyticsAgent(
                            published_context=geminidataanalytics.Context()
                        ),
                    ),
                    update_mask={
                        "paths": ["display_name", "description", "data_analytics_agent"]
                    },
                )
            )
        actions.append("CONTENT_REDACTED")
    except NotFound:
        actions.append("ALREADY_ABSENT")
    except GoogleAPICallError as exc:
        # A disabled key blocks updates too. The content is then unreadable
        # anyway, so proceed to the delete rather than aborting.
        actions.append("REDACT_FAILED")
        error = f"redact: {type(exc).__name__}: {exc.message}"
        logger.warning("[REDACTION FAILED] %s: %s", name, error)

    # Step 2 — soft delete. Stops further use and hides the agent from LIST.
    try:
        client.delete_data_agent_sync(name=name)
        actions.append("RESOURCE_SOFT_DELETED")
    except NotFound:
        actions.append("ALREADY_ABSENT")
    except GoogleAPICallError as exc:
        actions.append("DELETE_FAILED")
        error = f"{error + '; ' if error else ''}delete: {type(exc).__name__}: {exc.message}"
        logger.critical("[REMEDIATION FAILURE] %s: %s", name, error)

    failed = "DELETE_FAILED" in actions
    _emit(
        "CMEK_POLICY_VIOLATION_REMEDIATED",
        "CRITICAL" if failed else "WARNING",
        resource=name,
        project=agent.project,
        location=agent.location,
        caller=caller,
        status=verdict.status,
        reason=verdict.reason,
        action_taken="+".join(actions),
        # Soft delete leaves a tombstone that is readable until purgeTime; the
        # redaction above is what makes that tombstone safe.
        residual_retention="soft-deleted until purgeTime (~30 days); content redacted"
        if "CONTENT_REDACTED" in actions
        else "soft-deleted until purgeTime (~30 days); CONTENT NOT REDACTED",
        error=error,
        remediation_latency_seconds=round(time.time() - detected_at, 3),
    )


def _handle_conversation(proto_payload: dict, caller: str, detected_at: float) -> bool:
    """Report a conversation create. Returns False if this is not one.

    Not symmetric with the agent path, and cannot be. The agent path re-reads
    the resource because the audit payload is untrustworthy; here the re-read is
    attempted and expected to fail, because the resource is invisible to every
    principal except its creator (F8). What survives is the part that still has
    value: a conversation was created, here, by this caller, at this time --
    which is otherwise recorded nowhere a compliance team will look.
    """
    conversation = resolve_conversation_from_topic(proto_payload)
    if conversation is None:
        return False

    name = conversation.resource_name
    kms_key = None
    readable = False
    try:
        live = _chat_client(conversation.location).get_conversation(name=name)
        kms_key, readable = live.kms_key or None, True
    except NotFound:
        # The normal outcome, not an error: the enforcer did not create this
        # conversation, so it cannot see it.
        pass
    except (FailedPrecondition, PermissionDenied) as exc:
        logger.info("Read of %s refused (%s)", name, type(exc).__name__)
    except GoogleAPICallError as exc:
        logger.error("Unexpected error reading %s: %s", name, exc.message)
        raise

    if readable:
        # Only reachable for a conversation this identity created. Kept because
        # it costs nothing and is the one case where a real verdict exists.
        verdict = evaluate_compliance(
            conversation.location, kms_key, APPROVED_KMS_PROJECTS
        )
        _emit(
            "CMEK_POLICY_COMPLIANT" if verdict.is_compliant
            else "CMEK_POLICY_VIOLATION_DETECTED_CONVERSATION",
            "INFO" if verdict.is_compliant else "WARNING",
            resource=name,
            resource_type="CONVERSATION",
            project=conversation.project,
            location=conversation.location,
            caller=caller,
            status=verdict.status,
            reason=verdict.reason,
            action_taken="NONE_ALERT_ONLY",
            detection_latency_seconds=round(time.time() - detected_at, 3),
        )
        return True

    _emit(
        "CONVERSATION_CREATED_CMEK_UNVERIFIABLE",
        "WARNING",
        resource=name,
        resource_type="CONVERSATION",
        project=conversation.project,
        location=conversation.location,
        caller=caller,
        status=UNVERIFIABLE,
        reason=(
            "A conversation was created. Its CMEK state cannot be determined by "
            "this or any other principal: a conversation is readable only by "
            "its creator, and even roles/cloudaicompanion.topicAdmin returns 404 "
            "(validation-report F8). Govern this surface preventively — Layer 1 "
            "gates the key, Layer 2 restricts who may create one."
        ),
        action_taken="NONE_CANNOT_READ",
        detection_latency_seconds=round(time.time() - detected_at, 3),
    )
    return True


@functions_framework.cloud_event
def process_audit_log(cloud_event) -> None:
    """Entry point. Receives a Cloud Logging entry via Pub/Sub."""
    detected_at = time.time()

    encoded = (cloud_event.data or {}).get("message", {}).get("data")
    if not encoded:
        logger.warning("Empty event payload received.")
        return

    if MISCONFIGURED:
        _emit(
            "CMEK_ENFORCER_MISCONFIGURED",
            "CRITICAL",
            reason="APPROVED_KMS_PROJECTS is empty or unset. Every agent would be "
            "judged non-compliant and deleted, so remediation is disabled. Set it "
            "and redeploy.",
            action_taken="NONE_MISCONFIGURED",
        )
        return

    log_entry = json.loads(base64.b64decode(encoded).decode("utf-8"))
    proto_payload = log_entry.get("protoPayload", {})
    method = proto_payload.get("methodName", "")
    resource_name = proto_payload.get("resourceName", "")
    caller = proto_payload.get("authenticationInfo", {}).get("principalEmail", "unknown")

    # The enforcer's own deletions must never re-trigger evaluation.
    if caller == os.getenv("ENFORCER_SA_EMAIL", "\0"):
        logger.info("Skipping self-generated event for %s", resource_name)
        return

    # Conversations first: their events come from a different service entirely
    # (cloudaicompanion TopicService), so they can never be resolved as agents.
    service = proto_payload.get("serviceName", "")
    if service == "cloudaicompanion.googleapis.com" or "/topics/" in resource_name:
        if _handle_conversation(proto_payload, caller, detected_at):
            return
        # A topic-shaped event we could not resolve. Most likely the parent-only
        # half of the LRO pair (F2's pattern, which CreateTopic repeats), or a
        # topic belonging to Code Assist rather than to GDA. Neither is a
        # violation, so say so at INFO and stop.
        logger.info("Unresolvable topic event, ignoring: %r (%s)", resource_name, method)
        return

    agent = resolve_agent_name(proto_payload)
    if agent is None:
        # The sink only matches CreateDataAgent, so this should be unreachable.
        # Log loudly rather than returning silently: reaching it means the sink
        # filter and this handler have drifted apart.
        logger.warning(
            "Event matched the sink but is not a resolvable DataAgent: %r (%s)",
            resource_name,
            method,
        )
        return
    resource_name = agent.resource_name

    logger.info("Inspecting %s for %s by %s", method, resource_name, caller)

    try:
        live = _client(agent.location).get_data_agent(name=resource_name)
        verdict = evaluate_compliance(agent.location, live.kms_key, APPROVED_KMS_PROJECTS)
    except NotFound:
        logger.info("[GONE] %s no longer exists; nothing to do.", resource_name)
        return
    except (FailedPrecondition, PermissionDenied) as exc:
        # Verified failure mode: a disabled/inaccessible key fails the whole GET.
        # Fail closed — an unverifiable resource is not a compliant resource.
        payload_key = _kms_key_from_audit_payload(proto_payload)
        verdict = Verdict(
            UNVERIFIABLE,
            f"Could not verify CMEK state ({type(exc).__name__}: {exc.message}). "
            f"Audit payload reported kms_key={payload_key or '<none>'}. "
            "Treating as non-compliant (fail-closed).",
        )
    except GoogleAPICallError as exc:
        logger.error("Unexpected error verifying %s: %s", resource_name, exc.message)
        raise

    if verdict.is_compliant:
        _emit(
            "CMEK_POLICY_COMPLIANT",
            "INFO",
            resource=resource_name,
            caller=caller,
            status=verdict.status,
            reason=verdict.reason,
        )
        return

    logger.error("[NON-COMPLIANCE] %s | %s", resource_name, verdict.reason)
    _remediate(agent, verdict, caller, detected_at)


# Kept for naming parity with the documented architecture; unused by the gen2
# entry point.
__all__ = ["process_audit_log", "MISSING_CMEK"]
