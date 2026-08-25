"""Shared GDA/CMEK helpers used by Layer 3, Layer 4 and Layer 5.

Single source of truth for the two things every layer must agree on:

  1. Which API endpoint serves a given location. CMEK for the Conversational
     Analytics API is supported only in ``us-east4``, ``us`` and ``eu`` — the
     ``global`` location is not supported — and each location is served by its
     own endpoint. Calling the global endpoint with a regional resource path
     returns ``403 Read access to project ... was denied``, so getting this
     wrong silently breaks remediation.

  2. What "compliant" means. Layer 4 (real-time remediation) and Layer 5
     (periodic reporting) must never disagree about a resource, so both call
     ``evaluate_compliance``.

This module is deployed alongside the Cloud Function and the scanner job by
their respective deploy scripts, so it must not import anything outside the
standard library plus google-cloud-geminidataanalytics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Locations where a CMEK key can actually be attached to a DataAgent.
CMEK_SUPPORTED_LOCATIONS = frozenset({"us-east4", "us", "eu"})

# Multi-regions use a different endpoint template from true regions.
_MULTI_REGIONS = frozenset({"us", "eu"})

_AGENT_NAME_RE = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)/dataAgents/(?P<agent>[^/]+)$"
)
_KMS_KEY_RE = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)"
    r"/keyRings/(?P<key_ring>[^/]+)/cryptoKeys/(?P<key>[^/]+)$"
)

COMPLIANT = "COMPLIANT"
MISSING_CMEK = "NON_COMPLIANT_MISSING_CMEK"
UNAPPROVED_KEY_PROJECT = "NON_COMPLIANT_UNAPPROVED_KEY_PROJECT"
UNSUPPORTED_LOCATION = "NON_COMPLIANT_CMEK_UNSUPPORTED_LOCATION"
# Conversation attestation only: no conversation exists in this project+location,
# so there is no registered key to read and nothing yet to protect. Not a
# violation — an empty surface has no exposure — but not a pass either.
NO_CONVERSATIONS = "NO_CONVERSATIONS"

_CONVERSATION_NAME_RE = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)"
    r"/conversations/(?P<conversation>[^/]+)$"
)


def api_endpoint(location: str) -> str:
    """Return the API endpoint hostname that serves ``location``.

    global      -> geminidataanalytics.googleapis.com
    us | eu     -> geminidataanalytics.<loc>.rep.googleapis.com
    <region>    -> geminidataanalytics-<region>.googleapis.com
    """
    if location == "global":
        return "geminidataanalytics.googleapis.com"
    if location in _MULTI_REGIONS:
        return f"geminidataanalytics.{location}.rep.googleapis.com"
    return f"geminidataanalytics-{location}.googleapis.com"


@dataclass(frozen=True)
class AgentName:
    project: str
    location: str
    agent_id: str

    @property
    def resource_name(self) -> str:
        return (
            f"projects/{self.project}/locations/{self.location}"
            f"/dataAgents/{self.agent_id}"
        )

    @property
    def parent(self) -> str:
        return f"projects/{self.project}/locations/{self.location}"

    @property
    def api_endpoint(self) -> str:
        return api_endpoint(self.location)


def parse_agent_name(resource_name: str) -> AgentName | None:
    """Parse a DataAgent resource name, or return None if it isn't one."""
    match = _AGENT_NAME_RE.match(resource_name or "")
    if not match:
        return None
    return AgentName(
        project=match["project"],
        location=match["location"],
        agent_id=match["agent"],
    )


_PARENT_RE = re.compile(r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)$")


def resolve_agent_name(proto_payload: dict) -> AgentName | None:
    """Work out which DataAgent an audit entry refers to.

    Necessary because the two create methods log differently:

    * ``CreateDataAgent`` (LRO) sets ``resourceName`` to the full agent path.
    * ``CreateDataAgentSync`` sets ``resourceName`` to the **parent** only
      (``projects/P/locations/L``); the agent ID lives in
      ``request.dataAgentId`` and the full path in ``response.name``.

    Taking ``resourceName`` at face value — as docs/design.md does — therefore
    yields an unusable name for every synchronous create, which is what the
    Python client library actually calls.
    """
    resource_name = proto_payload.get("resourceName", "") or ""

    direct = parse_agent_name(resource_name)
    if direct:
        return direct

    response = proto_payload.get("response") or {}
    from_response = parse_agent_name(response.get("name", "") or "")
    if from_response:
        return from_response

    request = proto_payload.get("request") or {}
    agent_id = request.get("dataAgentId") or request.get("data_agent_id")
    parent = request.get("parent") or resource_name
    match = _PARENT_RE.match(parent or "")
    if match and agent_id:
        return AgentName(
            project=match["project"], location=match["location"], agent_id=agent_id
        )
    return None


@dataclass(frozen=True)
class ConversationName:
    project: str
    location: str
    conversation_id: str

    @property
    def resource_name(self) -> str:
        return (
            f"projects/{self.project}/locations/{self.location}"
            f"/conversations/{self.conversation_id}"
        )

    @property
    def parent(self) -> str:
        return f"projects/{self.project}/locations/{self.location}"


def parse_conversation_name(resource_name: str) -> ConversationName | None:
    """Parse a Conversation resource name, or return None if it isn't one."""
    match = _CONVERSATION_NAME_RE.match(resource_name or "")
    if not match:
        return None
    return ConversationName(
        project=match["project"],
        location=match["location"],
        conversation_id=match["conversation"],
    )


def attest_conversation_key(
    location: str,
    conversation_keys: list[str | None],
    approved_kms_projects: set[str] | frozenset[str],
) -> Verdict:
    """Judge the CMEK posture of *conversations* in one project+location.

    Conversations are governed differently from DataAgents, and the difference
    is the whole reason this is a separate function rather than a second call to
    ``evaluate_compliance``.

    **CMEK for conversations is a project+location singleton.** Verified against
    the live API: supplying any key other than the one already registered is
    rejected outright, including a *different key in the same project* --

        Invalid resource state for "conversation.kms_key_name":
        Cannot add a new KMS key. Only 1 KMS keys per project per location
        are allowed.

    That is stricter than ``restrictCmekCryptoKeyProjects``, which constrains
    only the project. It means there is no per-conversation drift to chase: every
    conversation in a project+location shares one key, so the control collapses
    to a single attestation per project+location rather than an inventory of
    ephemeral resources. Conversations are ephemeral by design and are never
    provisioned from a manifest (Layer 1 rejects them), so an inventory would be
    both expensive and meaningless.

    ``conversation_keys`` is the set of ``kms_key`` values observed across the
    conversations currently listed. Passing an empty list means no conversation
    exists, which is reported as NO_CONVERSATIONS rather than a violation: an
    empty surface carries no exposure.
    """
    if not conversation_keys:
        return Verdict(
            NO_CONVERSATIONS,
            f"No conversations exist in '{location}', so no CMEK key is "
            "registered and there is no conversation content to protect.",
        )

    distinct = {k or None for k in conversation_keys}
    if len(distinct) > 1:
        # Should be unreachable while the API enforces the singleton. If it ever
        # fires, the assumption this whole control rests on has changed.
        return Verdict(
            UNAPPROVED_KEY_PROJECT,
            f"Conversations in '{location}' report {len(distinct)} distinct "
            f"kms_key values ({sorted(str(k) for k in distinct)}). The API is "
            "documented and observed to allow only one key per project per "
            "location; this contradicts that, so treat the posture as unknown "
            "and re-verify before relying on any conversation attestation.",
        )

    return evaluate_compliance(location, distinct.pop(), approved_kms_projects)


def kms_key_project(kms_key: str | None) -> str | None:
    """Extract the KMS project ID from a fully-qualified cryptoKey path."""
    if not kms_key:
        return None
    match = _KMS_KEY_RE.match(kms_key)
    return match["project"] if match else None


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str

    @property
    def is_compliant(self) -> bool:
        return self.status == COMPLIANT


def evaluate_compliance(
    location: str,
    kms_key: str | None,
    approved_kms_projects: set[str] | frozenset[str],
) -> Verdict:
    """Apply the two org-policy equivalents to a single DataAgent.

    Mirrors constraints/gcp.restrictNonCmekServices (a key must be present) and
    constraints/gcp.restrictCmekCryptoKeyProjects (the key must live in an
    approved project), plus a location check the native constraints get for
    free: a resource in an unsupported location can never be CMEK-encrypted, so
    a key there is meaningless.
    """
    if location not in CMEK_SUPPORTED_LOCATIONS:
        return Verdict(
            UNSUPPORTED_LOCATION,
            f"Location '{location}' does not support CMEK; supported: "
            f"{sorted(CMEK_SUPPORTED_LOCATIONS)}.",
        )

    if not kms_key:
        return Verdict(MISSING_CMEK, "Missing mandatory CMEK (kms_key) parameter.")

    key_project = kms_key_project(kms_key)
    if key_project is None:
        return Verdict(
            UNAPPROVED_KEY_PROJECT,
            f"Malformed kms_key '{kms_key}'; cannot determine key project.",
        )
    if key_project not in approved_kms_projects:
        return Verdict(
            UNAPPROVED_KEY_PROJECT,
            f"KMS key project '{key_project}' is not in the approved list: "
            f"{sorted(approved_kms_projects)}.",
        )

    return Verdict(COMPLIANT, f"Encrypted with approved CMEK key {kms_key}.")


def parse_approved_projects(raw: str | None) -> frozenset[str]:
    """Parse the comma-separated APPROVED_KMS_PROJECTS setting."""
    if not raw:
        return frozenset()
    return frozenset(p.strip() for p in raw.split(",") if p.strip())
