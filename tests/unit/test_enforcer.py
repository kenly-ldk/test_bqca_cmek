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
from gda_common import resolve_agent_name

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
