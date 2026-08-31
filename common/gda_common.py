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

This module is deployed alongside the Cloud Run function and the scanner job by
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

# The same paired region is also where the conversation lifecycle is AUDITED.
# `cloudaicompanion` records a conversation created in `us` as a topic in
# `us-central1`, so Layer 4 has to map back the other way to reach the
# conversation. Derived, never written out twice, so the two cannot disagree.
AUDIT_LOCATION_TO_CONVERSATION = {v: k for k, v in CONVERSATION_KMS_LOCATION.items()}

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
# Conversations only, and never a pass. A conversation is visible ONLY to the
# principal that created it: measured against the live API, a service account
# holding cloudaicompanion.topics.get -- and even roles/cloudaicompanion.
# topicAdmin -- gets an empty ListConversations and a 404 on GetConversation for
# a conversation another principal created (validation-report F8).
#
# So a scanner can never enumerate the conversation surface. An empty list means
# "none that I created", which is indistinguishable from "hundreds, created by
# your analysts". Reporting that as a clean bill of health is the exact
# under-reporting failure this framework exists to prevent, so it is reported as
# unverifiable instead.
CONVERSATIONS_UNVERIFIABLE = "NON_COMPLIANT_UNVERIFIABLE_CONVERSATIONS"

# A `cloudaicompanion` topic, which is how a Conversation appears in audit logs.
_TOPIC_NAME_RE = re.compile(
    r"^projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)"
    r"/topics/(?P<topic>[^/]+)$"
)

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


def resolve_conversation_from_topic(proto_payload: dict) -> ConversationName | None:
    """Work out which Conversation a `cloudaicompanion` audit entry refers to.

    Conversations emit no `geminidataanalytics` audit log at all. Creating one
    surfaces as ``TopicService.CreateTopic`` under
    ``cloudaudit.googleapis.com/data_access``, and the entry names a *topic*:

        projects/P/locations/us-central1/topics/CONVERSATION_ID

    Two translations are needed before the resource can be re-read, and both are
    measured rather than assumed (validation-report F8):

    * **The topic ID is the conversation ID.** Verified for conversations
      created in both ``us`` and ``eu``.
    * **The audit location is the paired region, not the conversation's.** A
      conversation in ``us`` is audited in ``us-central1``; one in ``eu``, in
      ``europe-west1``. Same pairing the KMS key follows, applied in reverse.

    As with ``resolve_agent_name``, the create emits two entries (F2's LRO
    pattern): one naming only the parent, one naming the topic. Only the second
    resolves, and None for the first is correct -- the sink filter drops it, and
    a caller that sees None must not read it as a violation.

    The payload carries no key: ``request``, ``response`` and
    ``authorizationInfo`` are all null. Not a blocker, because the enforcer
    re-reads the resource and never trusts the payload.
    """
    match = _TOPIC_NAME_RE.match(proto_payload.get("resourceName", "") or "")
    if not match:
        return None

    location = AUDIT_LOCATION_TO_CONVERSATION.get(match["location"])
    if location is None:
        # A topic in a location that hosts no GDA conversation. cloudaicompanion
        # also backs Code Assist and Cloud Assist, whose topics are not ours.
        return None

    return ConversationName(
        project=match["project"],
        location=location,
        conversation_id=match["topic"],
    )


def evaluate_conversation_compliance(
    location: str,
    conversation_keys: list[str | None],
    approved_kms_projects: set[str] | frozenset[str],
) -> Verdict:
    """Judge the CMEK posture of *conversations* in one project+location.

    **This function can prove a violation. It can never prove compliance**, and
    that asymmetry is a property of the platform rather than a limitation of the
    implementation.

    A conversation is visible only to the principal that created it. Measured
    against the live API: a service account holding
    ``cloudaicompanion.topics.get`` sees ``{}`` from ``ListConversations`` and
    gets 404 from ``GetConversation`` for a conversation created by someone
    else; granting ``roles/cloudaicompanion.topicAdmin`` changes nothing
    (validation-report F8). No IAM configuration lets a scanner enumerate the
    surface, so ``conversation_keys`` is always a partial view -- the
    conversations the scanning identity happened to create, which in a real
    estate is none of the ones that matter.

    What follows:

    * An **empty** list is NOT "no exposure". It is "nothing I can see", which
      is indistinguishable from an estate full of unkeyed analyst conversations.
      Reported as CONVERSATIONS_UNVERIFIABLE.
    * An **unkeyed** conversation in the visible set IS a real violation --
      seeing one proves it exists -- and is reported as MISSING_CMEK.
    * An **all-keyed** visible set is still not a pass, because the invisible
      remainder is unconstrained. Also CONVERSATIONS_UNVERIFIABLE, with the
      count of what was checked.

    The consequence for the framework is that conversation governance is
    preventive, not detective: Layer 1 gates the key, Layer 2 restricts who may
    create a conversation at all, and the application must set ``kms_key`` on
    every call. Layer 5 reports what it could not see rather than vouching for
    it.
    """
    total = len(conversation_keys)
    unkeyed = sum(1 for key in conversation_keys if not key)

    if unkeyed:
        # A violation that is actually provable: this one was seen, and it has
        # no key. Reported ahead of the visibility caveat because it is concrete
        # and actionable.
        return Verdict(
            MISSING_CMEK,
            f"{unkeyed} of {total} conversations visible in '{location}' carry "
            "no kms_key, so their messages rest under Google-managed "
            "encryption. Note this is a partial view: only conversations "
            "created by the scanning identity are visible at all, so the true "
            "count can only be higher.",
        )

    if not total:
        return Verdict(
            CONVERSATIONS_UNVERIFIABLE,
            f"No conversations are visible in '{location}'. This does NOT mean "
            "none exist: a conversation can only be read by the principal that "
            "created it, so a scanner sees only its own. Treat the conversation "
            "surface here as unverified, and govern it preventively (Layer 1 "
            "gates the key, Layer 2 restricts who may create one).",
        )

    distinct = sorted({key for key in conversation_keys if key})
    for key in distinct:
        verdict = evaluate_compliance(location, key, approved_kms_projects)
        if verdict.status != COMPLIANT:
            return verdict

    return Verdict(
        CONVERSATIONS_UNVERIFIABLE,
        f"All {total} conversations visible in '{location}' use an approved "
        "CMEK key, but that is not a pass: only conversations created by the "
        "scanning identity are visible, and any created by another principal "
        "could not be enumerated or read.",
    )


def check_conversation_key(
    location: str,
    kms_key: str | None,
    approved_kms_projects: set[str] | frozenset[str],
) -> Verdict:
    """Pre-flight a conversation's key BEFORE CreateConversation is called.

    The in-process twin of the Layer 1 ``conversation_keys`` rules, so a caller
    that skips CI still cannot get it wrong. This exists as a separate function
    from ``evaluate_compliance`` because of one extra check the agent path does
    not need: the key must sit in the multi-region's paired primary region.

    That check has to happen before the call, not after. Offering a key to
    ``CreateConversation`` registers it permanently for the whole
    project+location -- even when the create then fails for another reason --
    and no API frees the slot (validation-report F8). A wrong key submitted once
    cannot be replaced.
    """
    if location not in CONVERSATION_KMS_LOCATION:
        return Verdict(
            UNSUPPORTED_LOCATION,
            f"Location '{location}' cannot host a CMEK conversation; supported: "
            f"{sorted(CONVERSATION_KMS_LOCATION)}.",
        )

    if not kms_key:
        return Verdict(MISSING_CMEK, "Missing mandatory CMEK (kms_key) parameter.")

    match = _KMS_KEY_RE.match(kms_key)
    if match is None:
        return Verdict(
            UNAPPROVED_KEY_PROJECT,
            f"Malformed kms_key '{kms_key}'; cannot determine key project.",
        )

    if match["project"] not in approved_kms_projects:
        return Verdict(
            UNAPPROVED_KEY_PROJECT,
            f"KMS key project '{match['project']}' is not in the approved list: "
            f"{sorted(approved_kms_projects)}.",
        )

    required = CONVERSATION_KMS_LOCATION[location]
    if match["location"] != required:
        return Verdict(
            UNSUPPORTED_LOCATION,
            f"Conversations in '{location}' need a key in '{required}' (the "
            f"paired region), but this key is in '{match['location']}'. "
            f"Submitting it would permanently register the wrong key for "
            f"'{location}'.",
        )

    return Verdict(COMPLIANT, f"Conversation key {kms_key} is valid for '{location}'.")


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
