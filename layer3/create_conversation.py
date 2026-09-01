"""Layer 3 for the conversation surface: create a CMEK-protected conversation.

The counterpart of ``create_agent.py``, and deliberately not a copy of it. Three
things differ, all of them measured (validation-report F8):

* **The key goes in the paired region.** A conversation in ``us`` takes a key in
  ``us-central1``; one in ``eu``, in ``europe-west1``. The key its own agents
  use -- ``us`` or ``europe`` -- is rejected, and so is the key path Google's
  documentation prescribes, which is the same thing.

* **The key is gated before the call, not after.** Offering a key to
  ``CreateConversation`` registers it permanently for the whole
  project+location, even when the create then fails, and no API frees the slot.
  A wrong key cannot be corrected. So ``check_conversation_key`` runs first and
  the API is not called at all if it fails -- the same in-process gate pattern
  as ``layer1/apply_manifest.py``, for a mistake that is far less forgiving.

* **The anchor agent need not be local.** A conversation may reference an agent
  in another location, and doing so does not change which key it takes. That is
  what makes this work in the default estate, where agents live in ``us-east4``
  -- a location that cannot host a conversation at all.

This creates a real conversation, which is a runtime resource rather than
infrastructure. It exists to demonstrate and verify the key path end to end;
production conversations are created by your application, not by a deploy step,
and Layer 1 rejects any manifest that tries to declare one.

    python -m layer3.create_conversation
    python -m layer3.create_conversation --location eu
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import AlreadyExists, GoogleAPICallError
from google.cloud import geminidataanalytics

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import (  # noqa: E402
    CONVERSATION_KMS_LOCATION,
    api_endpoint,
    check_conversation_key,
    parse_approved_projects,
)
from config._loader import load  # noqa: E402


def _chat(location: str) -> geminidataanalytics.DataChatServiceClient:
    return geminidataanalytics.DataChatServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _agents(location: str) -> geminidataanalytics.DataAgentServiceClient:
    return geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def find_anchor_agent(project: str, conversation_location: str,
                      agent_location: str) -> str | None:
    """Any agent to anchor the conversation to, local or not.

    Tries the conversation's own location first -- an estate that keeps both
    there needs no cross-location reference -- then the configured agent
    location, which in the default estate is ``us-east4`` and cannot host a
    conversation.
    """
    for location in dict.fromkeys([conversation_location, agent_location]):
        parent = f"projects/{project}/locations/{location}"
        try:
            agent = next(iter(_agents(location).list_data_agents(parent=parent)))
        except (GoogleAPICallError, StopIteration):
            continue
        if location != conversation_location:
            print(f"  anchor agent is in '{location}', the conversation in "
                  f"'{conversation_location}' — allowed, and it does not change "
                  f"which key the conversation takes")
        return agent.name
    return None


def create(location: str, conversation_id: str) -> str | None:
    env = load()
    project = env["PROJECT_ID"]
    approved = parse_approved_projects(env.get("APPROVED_KMS_PROJECTS") or project)

    kms_location = CONVERSATION_KMS_LOCATION.get(location)
    if kms_location is None:
        print(f"[BLOCKED] '{location}' cannot host a conversation. "
              f"Supported: {sorted(CONVERSATION_KMS_LOCATION)}.")
        return None

    kms_key = (f"projects/{project}/locations/{kms_location}"
               f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['CONVERSATION_KMS_KEY']}")

    # The gate. Runs before the API is touched, because the API remembers.
    verdict = check_conversation_key(location, kms_key, approved)
    if not verdict.is_compliant:
        print(f"[BLOCKED BY POLICY] {verdict.status}: {verdict.reason}")
        print("  No API call was made, so no key was registered.")
        return None
    print(f"  policy OK: {kms_key}")

    agent = find_anchor_agent(project, location, env.get("AGENT_LOCATION", location))
    if agent is None:
        print(f"[SKIPPED] no DataAgent to anchor a conversation to. "
              f"Run scripts/deploy_agents.sh first.")
        return None

    parent = f"projects/{project}/locations/{location}"
    try:
        created = _chat(location).create_conversation(
            request=geminidataanalytics.CreateConversationRequest(
                parent=parent,
                conversation_id=conversation_id,
                conversation=geminidataanalytics.Conversation(
                    agents=[agent], kms_key=kms_key
                ),
            )
        )
    except AlreadyExists:
        print(f"  conversation {conversation_id} already exists in {location}")
        return f"{parent}/conversations/{conversation_id}"
    except GoogleAPICallError as exc:
        print(f"[FAILED] {type(exc).__name__}: {(exc.message or str(exc))[:200]}")
        return None

    # Read back rather than trust the create response, for the same reason
    # Layer 4 does: the server's value is the only authoritative one.
    live = _chat(location).get_conversation(name=created.name)
    if live.kms_key != kms_key:
        print(f"[WARNING] created, but the server reports kms_key="
              f"{live.kms_key or None}, not the key that was requested.")
    else:
        print(f"  created {created.name.split('/')[-1]} in {location}, "
              f"CMEK-protected by the {kms_location} key")
    return created.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--location", default="us",
                        choices=sorted(CONVERSATION_KMS_LOCATION),
                        help="where the conversation lives (default: us)")
    parser.add_argument("--conversation-id", default="layer3-cmek-conversation")
    args = parser.parse_args()
    return 0 if create(args.location, args.conversation_id) else 1


if __name__ == "__main__":
    raise SystemExit(main())
