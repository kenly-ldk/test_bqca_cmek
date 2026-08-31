"""Unit tests for the Layer 4 enforcer's pure logic.

Covers the two things that are otherwise provable only by deploying a Cloud
Function and creating live agents:

* `resolve_agent_name` — the audit-log shape handling from F2. The design's
  original logic took `resourceName` at face value, which is unusable for every
  synchronous create (the shape the Python client library actually produces),
  and deleted compliant agents on the LRO trailing entry.
* the empty-allowlist guard — the condition under which the enforcer would
  otherwise redact and soft-delete every agent it saw.

No network, no credentials, no GCP.
"""

from __future__ import annotations

import pytest
from _loader import load_enforcer
from gda_common import resolve_agent_name, resolve_conversation_from_topic

PROJECT, LOCATION, AGENT = "p", "us-east4", "agent-1"
FULL_NAME = f"projects/{PROJECT}/locations/{LOCATION}/dataAgents/{AGENT}"
PARENT = f"projects/{PROJECT}/locations/{LOCATION}"


# --- audit-log shapes (F2) ------------------------------------------------


def test_lro_create_carries_the_full_agent_path():
    """CreateDataAgent (LRO), leading entry: resourceName is the agent."""
    agent = resolve_agent_name(
        {
            "methodName": "google.cloud.geminidataanalytics.v1beta.DataAgentService.CreateDataAgent",
            "resourceName": FULL_NAME,
            "operation": {"first": True},
            "request": {"dataAgent": {"kmsKey": "k"}},
        }
    )
    assert agent.resource_name == FULL_NAME
    assert agent.location == LOCATION


def test_sync_create_resolves_the_agent_from_request_fields():
    """CreateDataAgentSync: resourceName is only the PARENT.

    This is the shape the Python client library produces. Reading resourceName
    directly yields 'projects/p/locations/us-east4', so the design's
    delete(name=resource_name) targeted a resource that does not exist.
    """
    agent = resolve_agent_name(
        {
            "methodName": "google.cloud.geminidataanalytics.v1beta.DataAgentService.CreateDataAgentSync",
            "resourceName": PARENT,
            "request": {"parent": PARENT, "dataAgentId": AGENT},
        }
    )
    assert agent is not None
    assert agent.resource_name == FULL_NAME


def test_sync_create_accepts_snake_case_agent_id():
    agent = resolve_agent_name(
        {"resourceName": PARENT, "request": {"parent": PARENT, "data_agent_id": AGENT}}
    )
    assert agent.resource_name == FULL_NAME


def test_agent_resolved_from_response_name_when_request_is_absent():
    agent = resolve_agent_name({"resourceName": PARENT, "response": {"name": FULL_NAME}})
    assert agent.resource_name == FULL_NAME


def test_lro_trailing_entry_without_request_is_not_resolvable():
    """The entry that makes a naive enforcer delete compliant agents.

    operation.last=true carries no `request`, so there is no agent id. The
    enforcer must resolve nothing here; the sink filter also drops it. Returning
    a name would mean acting on a resource this entry says nothing about.
    """
    assert (
        resolve_agent_name(
            {"resourceName": PARENT, "operation": {"last": True}, "response": {}}
        )
        is None
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"resourceName": ""},
        {"resourceName": PARENT},  # parent only, no agent id anywhere
        {"resourceName": PARENT, "request": {"parent": PARENT}},  # no id
        {"resourceName": "projects/p", "request": {"dataAgentId": AGENT}},  # bad parent
    ],
)
def test_unresolvable_payloads_return_none(payload):
    assert resolve_agent_name(payload) is None


def test_location_is_taken_from_the_resource_not_assumed():
    """Endpoint routing depends on this; a wrong location means a 403."""
    for location in ("us-east4", "us", "eu", "global"):
        agent = resolve_agent_name(
            {"resourceName": f"projects/{PROJECT}/locations/{location}/dataAgents/{AGENT}"}
        )
        assert agent.location == location


# --- the empty-allowlist guard ----------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "   ", ",,"])
def test_missing_allowlist_flags_misconfiguration(monkeypatch, raw):
    """An empty APPROVED_KMS_PROJECTS must disable remediation, not escalate it.

    With no approved projects every correctly-encrypted agent evaluates to
    UNAPPROVED_KEY_PROJECT, so an unguarded enforcer would redact and
    soft-delete the entire estate. MISCONFIGURED is computed at import, so the
    module is re-executed with the environment patched.
    """
    if raw is None:
        monkeypatch.delenv("APPROVED_KMS_PROJECTS", raising=False)
    else:
        monkeypatch.setenv("APPROVED_KMS_PROJECTS", raw)

    assert load_enforcer().MISCONFIGURED is True


def test_populated_allowlist_is_not_misconfigured(monkeypatch):
    monkeypatch.setenv("APPROVED_KMS_PROJECTS", "approved-a,approved-b")

    enforcer = load_enforcer()
    assert enforcer.MISCONFIGURED is False
    assert enforcer.APPROVED_KMS_PROJECTS == frozenset({"approved-a", "approved-b"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("True", True), ("TRUE", True), ("false", False), ("", False)],
)
def test_dry_run_parsing(monkeypatch, raw, expected):
    """Shadow mode is the recommended first rollout, so its flag must be exact."""
    monkeypatch.setenv("DRY_RUN", raw)
    assert load_enforcer().DRY_RUN is expected


def test_dry_run_defaults_to_armed(monkeypatch):
    """Absent DRY_RUN means enforcing. Documented, and worth pinning."""
    monkeypatch.delenv("DRY_RUN", raising=False)
    assert load_enforcer().DRY_RUN is False


# --- conversation audit shapes (F8) ---------------------------------------
#
# Conversations reach Layer 4 through a different service, a different log
# stream and a different resource name from agents, and every translation below
# is measured against the live API rather than inferred:
#
#   * the create is cloudaicompanion TopicService.CreateTopic, in Data Access
#     logs (off by default) -- there is NO geminidataanalytics entry at all;
#   * the resourceName names a *topic*, and the topic ID is the conversation ID;
#   * the audit location is the multi-region's PAIRED region, so a conversation
#     in `us` is logged in `us-central1` and must be mapped back;
#   * request, response and authorizationInfo are all null, so the payload can
#     never supply the key -- the enforcer re-reads the resource instead.


def _topic_event(location, topic="conv-1", project=PROJECT):
    return {
        "serviceName": "cloudaicompanion.googleapis.com",
        "methodName": "google.cloud.cloudaicompanion.v1.TopicService.CreateTopic",
        "resourceName": f"projects/{project}/locations/{location}/topics/{topic}",
        "request": None,
        "response": None,
        "authorizationInfo": None,
    }


def test_us_topic_maps_back_to_a_us_conversation():
    """Audited in us-central1; the conversation lives in `us`."""
    conversation = resolve_conversation_from_topic(_topic_event("us-central1"))
    assert conversation.location == "us"
    assert conversation.resource_name == f"projects/{PROJECT}/locations/us/conversations/conv-1"


def test_eu_topic_maps_back_to_an_eu_conversation():
    conversation = resolve_conversation_from_topic(_topic_event("europe-west1", "c2"))
    assert conversation.location == "eu"
    assert conversation.resource_name == f"projects/{PROJECT}/locations/eu/conversations/c2"


def test_topic_id_is_the_conversation_id():
    """The whole mapping rests on this; measured for us and eu."""
    assert resolve_conversation_from_topic(
        _topic_event("us-central1", "my-conversation-42")
    ).conversation_id == "my-conversation-42"


def test_parent_only_entry_does_not_resolve():
    """CreateTopic emits the same two-entry LRO pair as CreateDataAgent (F2).

    The parent-only half names no topic. Returning None is correct: the sink
    filters it out, and treating it as a resource would invent a violation.
    """
    assert resolve_conversation_from_topic(
        {"resourceName": f"projects/{PROJECT}/locations/us-central1"}
    ) is None


def test_topic_in_a_non_conversation_location_is_ignored():
    """cloudaicompanion also backs Code Assist; those topics are not ours."""
    assert resolve_conversation_from_topic(_topic_event("us-west2")) is None
    assert resolve_conversation_from_topic(_topic_event("global")) is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"resourceName": ""},
        {"resourceName": f"projects/{PROJECT}/locations/us-central1/topics/"},
        # An agent, not a topic.
        {"resourceName": FULL_NAME},
    ],
)
def test_non_topic_payloads_return_none(payload):
    assert resolve_conversation_from_topic(payload) is None


def test_conversation_and_agent_resolvers_do_not_overlap():
    """A topic event must never resolve as an agent, or vice versa."""
    topic = _topic_event("us-central1")
    assert resolve_agent_name(topic) is None
    assert resolve_conversation_from_topic({"resourceName": FULL_NAME}) is None


# --- no remediation path exists ---------------------------------------------


def test_enforcer_has_no_conversation_delete_path():
    """Conversations are detect-and-attribute only, and that is structural.

    The enforcer cannot read another principal's conversation (404 even with
    roles/cloudaicompanion.topicAdmin), so it could not delete one either. A
    delete path would silently no-op on every real conversation, which is worse
    than not having one — it would look like a remediation control.
    """
    enforcer = load_enforcer()
    assert not hasattr(enforcer, "CONVERSATION_DELETE_ENABLED")
    assert not hasattr(enforcer, "_remediate_conversation")
    assert hasattr(enforcer, "_handle_conversation")
