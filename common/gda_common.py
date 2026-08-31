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

# Conversations do NOT follow the agent rule, and the difference is not
# documented anywhere (validation-report F8). A DataAgent takes a key in its own
# location; a Conversation in a multi-region takes a key in that multi-region's
# paired primary region, and refuses every other KMS location -- including the
# same-named multi-region the documentation prescribes. `us-east4` is absent
# because it cannot host a conversation at all, with or without a key.
CONVERSATION_KMS_LOCATION = {"us": "us-central1", "eu": "europe-west1"}
CONVERSATION_LOCATIONS = frozenset(CONVERSATION_KMS_LOCATION)

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
# Conversations only: none exists in this project+location, so there is nothing
# yet to protect. Not a violation — an empty surface has no exposure — but not a
# pass either.
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


def evaluate_conversation_compliance(
    location: str,
    conversation_keys: list[str | None],
    approved_kms_projects: set[str] | frozenset[str],
) -> Verdict:
    """Judge the CMEK posture of *conversations* in one project+location.

    Conversations are governed differently from DataAgents, and the difference
    is the whole reason this is a separate function rather than a second call to
    ``evaluate_compliance``.

    **CMEK on a conversation is real, and it is opt-in per conversation**
    (validation-report F8, re-measured 2026-08-30). A conversation created with
    a ``kms_key`` is genuinely protected: disable that key and both
    ``GetConversation`` and ``ListMessages`` fail with a Firestore CMEK error,
    within 2-5 minutes. A conversation created *without* one is not protected,
    and — this is the point that drives the logic below — it **does not inherit
    the key registered for its project+location**. It stays readable while that
    key is disabled.

    So the earlier model, one attestation per project+location, does not hold.
    The API's "only 1 KMS keys per project per location" registry constrains
    *which* key may be used; each caller independently decides *whether* to use
    one. Two conversations side by side in the same location can therefore have
    different postures, and reading the key off any one of them says nothing
    about the rest. This function is given every key observed across the
    conversations currently listed, and the location passes only if all of them
    are protected by an approved key.

    That the registry exists is still worth knowing, because it is a squatting
    hazard rather than a protection: the first key *offered* is registered even
    if the create then fails, the caller needs only ``topics.create``, and the
    slot can never be reassigned or freed. See F8.

    ``conversation_keys`` is the list of ``kms_key`` values observed across the
    conversations currently listed, one entry per conversation, ``None`` where
    the conversation carries no key. Passing an empty list means no conversation
    exists, which is reported as NO_CONVERSATIONS rather than a violation: an
    empty surface carries no exposure.

    Note this is a LIST-only view. A conversation whose key is already disabled
    may be absent from LIST entirely (F4 on the agent side, same cause), so an
    all-clear here means "every conversation this scan could see", not "every
    conversation".
    """
    if not conversation_keys:
        return Verdict(
            NO_CONVERSATIONS,
            f"No conversations exist in '{location}', so there is no "
            "conversation content to protect.",
        )

    total = len(conversation_keys)
    unkeyed = sum(1 for key in conversation_keys if not key)
    if unkeyed:
        # The common, expected drift case, and the reason this is checked before
        # the registry anomaly below: it is concrete and actionable, where the
        # anomaly only says the posture is unknown.
        return Verdict(
            MISSING_CMEK,
            f"{unkeyed} of {total} conversations in '{location}' carry no "
            "kms_key. CMEK is opt-in per conversation and an unkeyed "
            "conversation does not inherit the key registered for the "
            "project+location, so its messages rest under Google-managed "
            "encryption.",
        )

    distinct = sorted({key for key in conversation_keys if key})
    if len(distinct) > 1:
        # Should be unreachable: the API registers one key per project+location
        # and refuses every other one, including a key that does not exist. If
        # this ever fires, that invariant has changed and the verdict below
        # would be picking a winner among keys it cannot rank.
        return Verdict(
            UNAPPROVED_KEY_PROJECT,
            f"Conversations in '{location}' report {len(distinct)} distinct "
            f"kms_key values ({distinct}). The API is observed to allow only "
            "one key per project per location; this contradicts that, so treat "
            "the posture as unknown and re-verify before relying on it.",
        )

    return evaluate_compliance(location, distinct[0], approved_kms_projects)


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
