"""Layer 2 — behavioural IAM probe.

Answers the question the design's role table only asserts: *can this principal
actually do this?* For each persona it attempts a real API call under
impersonated credentials and reports ALLOWED or DENIED.

Why impersonation rather than keys: constraints/iam.disableServiceAccountKeyCreation
is enforced in most regulated orgs, and it is how these identities are used in
production anyway.

Distinguishing "denied" from "broken" matters. Only an authorization failure
counts as DENIED:

  * PermissionDenied / Forbidden      -> DENIED   (the boundary held)
  * success                           -> ALLOWED
  * InvalidArgument, NotFound, etc.   -> ALLOWED-ish: the call got past the
                                         authorization check and failed on its
                                         own merits. Reported as ALLOWED with
                                         the underlying error, because for a
                                         least-privilege assertion what matters
                                         is whether IAM stopped it.

That last case is the subtle one: a test that treats any exception as "denied"
would report a perfectly open permission as safely closed.

Usage:
    python -m layer2.probe --persona analyst --op create
    python -m layer2.probe --matrix
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path

import google.auth
from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import Forbidden, GoogleAPICallError, PermissionDenied
from google.auth import impersonated_credentials
from google.cloud import geminidataanalytics

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import api_endpoint  # noqa: E402
from config._loader import load  # noqa: E402

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

PERSONAS = ["cicd-deployer", "app-runtime", "analyst", "no-access", "conv-user"]
# "chat" is the stateless inference path (geminidataanalytics.locations.chat),
# which is a DIFFERENT permission from the agent-scoped dataAgents.chat. Without
# it in the matrix, app-runtime looks like it can do nothing at all, when in
# fact stateless chat is the only thing it is meant to do.
OPS = [
    "list", "get", "create", "update", "delete", "chat",
    # Conversations. No conversations.* permission exists anywhere in the
    # geminidataanalytics surface (all 18 of its permissions cover dataAgents,
    # locations, operations and projects). The probe found what actually gates
    # them: cloudaicompanion.topics.* — a DIFFERENT service and a different IAM
    # surface from the nine geminidataanalytics roles this layer documents.
    # Both results below are findings, not endorsements.
    "conv-create", "conv-list", "conv-delete",
]

# Expected outcome per (persona, op). This IS the Layer 2 control statement —
# if reality disagrees, either the model or the documentation is wrong.
# Derived from `gcloud iam roles describe` and confirmed by running this probe:
#
#   dataAgentCreator      create, locations.chat, operations.get
#   dataAgentViewer       get, list
#   dataAgentStatelessUser locations.chat, locations.useDataEngineeringAgent
#
# Note what dataAgentCreator does NOT include: get, list, update. A pipeline
# holding only that role can create an agent but cannot read back what it
# created. See docs/design.md §6.
EXPECTED: dict[tuple[str, str], str] = {
    ("cicd-deployer", "list"): "DENIED",
    ("cicd-deployer", "get"): "DENIED",
    ("cicd-deployer", "create"): "ALLOWED",
    ("cicd-deployer", "update"): "DENIED",
    ("cicd-deployer", "delete"): "DENIED",
    ("cicd-deployer", "chat"): "ALLOWED",
    ("app-runtime", "list"): "DENIED",
    ("app-runtime", "get"): "DENIED",
    ("app-runtime", "create"): "DENIED",
    ("app-runtime", "update"): "DENIED",
    ("app-runtime", "delete"): "DENIED",
    ("app-runtime", "chat"): "ALLOWED",
    ("analyst", "list"): "ALLOWED",
    ("analyst", "get"): "ALLOWED",
    ("analyst", "create"): "DENIED",
    ("analyst", "update"): "DENIED",
    ("analyst", "delete"): "DENIED",
    ("analyst", "chat"): "DENIED",
    ("no-access", "list"): "DENIED",
    ("no-access", "get"): "DENIED",
    ("no-access", "create"): "DENIED",
    ("no-access", "update"): "DENIED",
    ("no-access", "delete"): "DENIED",
    ("no-access", "chat"): "DENIED",
    # --- conversations ------------------------------------------------------
    # create: DENIED for every persona, including app-runtime, whose entire job
    # is chat. Measured failure:
    #   PermissionDenied: Permission 'cloudaicompanion.topics.create' denied on
    #   resource '//cloudaicompanion.googleapis.com/projects/<P>'
    # Stateful conversations are therefore NOT usable by any of the four
    # documented personas. Enabling them means granting a cloudaicompanion role
    # — which also widens the blast radius beyond Gemini Data Analytics, so it
    # should be scoped and reviewed rather than added to an existing persona.
    ("cicd-deployer", "conv-create"): "DENIED",
    ("app-runtime", "conv-create"): "DENIED",
    ("analyst", "conv-create"): "DENIED",
    ("no-access", "conv-create"): "DENIED",
    # list: ALLOWED for every persona INCLUDING no-access, which holds no GDA
    # role whatsoever. Recorded as the measured truth so the matrix stays honest
    # and any future tightening shows up as a diff. Treat it as a finding.
    ("cicd-deployer", "conv-list"): "ALLOWED",
    ("app-runtime", "conv-list"): "ALLOWED",
    ("analyst", "conv-list"): "ALLOWED",
    ("no-access", "conv-list"): "ALLOWED",
    # delete: DENIED for everyone, and not fixable with least privilege.
    # cloudaicompanion.topics.delete is NOT_SUPPORTED in custom roles, so the
    # only way to grant it is the predefined roles/cloudaicompanion.topicAdmin,
    # which also carries topics.setIamPolicy and topics.update. No persona here
    # takes that trade; conversations are ephemeral and are left to expire.
    ("cicd-deployer", "conv-delete"): "DENIED",
    ("app-runtime", "conv-delete"): "DENIED",
    ("analyst", "conv-delete"): "DENIED",
    ("no-access", "conv-delete"): "DENIED",
    ("conv-user", "conv-delete"): "DENIED",
    # --- conv-user: the least-privilege stateful-conversation persona --------
    # dataAgentStatelessUser (chat) + a custom role carrying exactly
    # cloudaicompanion.topics.create, topics.get and operations.get. It can hold
    # a conversation and nothing else: no agent CRUD at all.
    ("conv-user", "list"): "DENIED",
    ("conv-user", "get"): "DENIED",
    ("conv-user", "create"): "DENIED",
    ("conv-user", "update"): "DENIED",
    ("conv-user", "delete"): "DENIED",
    ("conv-user", "chat"): "ALLOWED",
    ("conv-user", "conv-create"): "ALLOWED",
    ("conv-user", "conv-list"): "ALLOWED",
}


@dataclass
class Outcome:
    persona: str
    op: str
    result: str          # ALLOWED | DENIED
    detail: str


def _sa_email(persona: str, project: str) -> str:
    return f"layer2-{persona}@{project}.iam.gserviceaccount.com"


def _client(persona: str, project: str, location: str):
    source, _ = google.auth.default(scopes=SCOPES)
    creds = impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=_sa_email(persona, project),
        target_scopes=SCOPES,
    )
    return geminidataanalytics.DataAgentServiceClient(
        credentials=creds,
        client_options=ClientOptions(api_endpoint=api_endpoint(location)),
    )


def _chat_client(persona: str, project: str, location: str):
    source, _ = google.auth.default(scopes=SCOPES)
    creds = impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=_sa_email(persona, project),
        target_scopes=SCOPES,
    )
    return geminidataanalytics.DataChatServiceClient(
        credentials=creds,
        client_options=ClientOptions(api_endpoint=api_endpoint(location)),
    )


def _attempt(fn) -> tuple[str, str]:
    """Run fn and classify the result as ALLOWED or DENIED."""
    try:
        fn()
        return "ALLOWED", "succeeded"
    except (PermissionDenied, Forbidden) as exc:
        return "DENIED", f"{type(exc).__name__}: {exc.message.splitlines()[0][:120]}"
    except GoogleAPICallError as exc:
        # Passed authorization, failed on its own merits.
        return "ALLOWED", f"not blocked by IAM ({type(exc).__name__}: {exc.message.splitlines()[0][:90]})"


def probe(persona: str, op: str, project: str, location: str, fixture: str) -> Outcome:
    client = _client(persona, project, location)
    parent = f"projects/{project}/locations/{location}"
    fixture_name = f"{parent}/dataAgents/{fixture}"

    if op == "list":
        # list is lazy; force the first page or nothing is actually called.
        result, detail = _attempt(lambda: next(iter(client.list_data_agents(parent=parent)), None))
    elif op == "get":
        result, detail = _attempt(lambda: client.get_data_agent(name=fixture_name))
    elif op == "create":
        # A unique ID per attempt: a name collision would mask the IAM answer.
        # No kms_key on purpose — if IAM lets this through, Layer 4 removes it,
        # which is the layering working as designed.
        probe_id = f"layer2-probe-{persona}-{uuid.uuid4().hex[:8]}"
        result, detail = _attempt(lambda: client.create_data_agent_sync(
            request=geminidataanalytics.CreateDataAgentRequest(
                parent=parent,
                data_agent_id=probe_id,
                data_agent=geminidataanalytics.DataAgent(display_name="layer2 IAM probe"),
            )
        ))
        if result == "ALLOWED" and "succeeded" in detail:
            detail = f"created {probe_id} (Layer 4 should remediate it)"
    elif op == "update":
        result, detail = _attempt(lambda: client.update_data_agent_sync(
            request=geminidataanalytics.UpdateDataAgentRequest(
                data_agent=geminidataanalytics.DataAgent(
                    name=fixture_name, description="layer2 IAM probe"),
                update_mask={"paths": ["description"]},
            )
        ))
    elif op == "chat":
        # Stateless inference with an inline context — no stored DataAgent, so
        # this probes geminidataanalytics.locations.chat in isolation.
        chat_client = _chat_client(persona, project, location)
        result, detail = _attempt(lambda: next(iter(chat_client.chat(
            request=geminidataanalytics.ChatRequest(
                parent=parent,
                messages=[geminidataanalytics.Message(
                    user_message=geminidataanalytics.UserMessage(text="ping"))],
                inline_context=geminidataanalytics.Context(
                    system_instruction="Reply with the single word: pong."),
            )
        )), None))
    elif op == "delete":
        # Deliberately targets a name that does not exist. IAM is evaluated
        # before existence, so PermissionDenied means the boundary held and
        # NotFound means it did not — without ever destroying a real agent.
        result, detail = _attempt(
            lambda: client.delete_data_agent_sync(name=f"{parent}/dataAgents/layer2-probe-absent")
        )
        if result == "ALLOWED":
            detail = f"NOT blocked by IAM — {detail}"
    elif op == "conv-create":
        # Anchored to a real agent: CreateConversation rejects an empty agents
        # list before it evaluates anything else. Authorization is still checked
        # first, so PermissionDenied vs anything-else remains a clean signal even
        # where the conversation backend itself is unavailable.
        chat_client = _chat_client(persona, project, location)
        probe_id = f"layer2-conv-{persona}-{uuid.uuid4().hex[:8]}"
        result, detail = _attempt(lambda: chat_client.create_conversation(
            request=geminidataanalytics.CreateConversationRequest(
                parent=parent,
                conversation_id=probe_id,
                conversation=geminidataanalytics.Conversation(agents=[fixture_name]),
            )
        ))
    elif op == "conv-delete":
        # Targets a name that does not exist: IAM is evaluated before existence,
        # so PermissionDenied means the boundary held and NotFound means it did
        # not — without destroying a real conversation.
        chat_client = _chat_client(persona, project, location)
        result, detail = _attempt(lambda: chat_client.delete_conversation(
            name=f"{parent}/conversations/layer2-probe-absent"
        ))
        if result == "ALLOWED":
            detail = f"NOT blocked by IAM — {detail}"
    elif op == "conv-list":
        # Lazy, like dataAgents.list — force the first page or nothing is called.
        chat_client = _chat_client(persona, project, location)
        result, detail = _attempt(
            lambda: next(iter(chat_client.list_conversations(parent=parent)), None)
        )
    else:
        raise ValueError(f"unknown op {op}")

    return Outcome(persona=persona, op=op, result=result, detail=detail)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--persona", choices=PERSONAS)
    parser.add_argument("--op", choices=OPS)
    parser.add_argument("--matrix", action="store_true", help="run every persona x op")
    parser.add_argument("--fixture", default="", help="existing agent ID for get/update")
    parser.add_argument("--json", action="store_true", help="emit JSON for the test harness")
    args = parser.parse_args()

    env = load()
    project, location = env["PROJECT_ID"], env["LOCATION"]
    fixture = args.fixture or "pipeline-wealth-agent"

    if args.matrix:
        pairs = [(p, o) for p in PERSONAS for o in OPS]
    elif args.persona and args.op:
        pairs = [(args.persona, args.op)]
    else:
        parser.error("pass --matrix, or both --persona and --op")

    outcomes = [probe(p, o, project, location, fixture) for p, o in pairs]

    if args.json:
        print(json.dumps([asdict(o) for o in outcomes], indent=2))
        return 0

    mismatches = 0
    print(f"\n{'persona':<16} {'op':<8} {'expected':<9} {'actual':<9} detail")
    print("-" * 100)
    for o in outcomes:
        expected = EXPECTED.get((o.persona, o.op), "?")
        flag = " " if expected == o.result else "X"
        if flag == "X":
            mismatches += 1
        print(f"{flag}{o.persona:<15} {o.op:<8} {expected:<9} {o.result:<9} {o.detail}")

    print(f"\n{len(outcomes) - mismatches}/{len(outcomes)} match the documented model")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
