"""Layer 5 — prove the conversation CMEK key is pinned, against the live API.

Conversations differ from DataAgents in a way that changes the whole control,
and this is the executable proof of it.

For a DataAgent, `kms_key` is per-resource and arbitrary: Layer 4 exists because
anyone can create an agent pointing at a key in a project you have never heard
of. For a **Conversation**, the key is a **project+location singleton**. The API
registers one key and rejects every other one:

    Invalid resource state for "conversation.kms_key_name":
    Cannot add a new KMS key. Only 1 KMS keys per project per location
    are allowed.

Crucially that rejection covers a different key **in the same project**, so it
is stricter than `restrictCmekCryptoKeyProjects`, which constrains only the
project. There is therefore no per-conversation drift to police, which is why
Layer 5 attests one key per project+location instead of inventorying ephemeral
conversations, and why Layer 1 refuses to provision them at all.

This probe never creates a conversation. It submits candidate keys and reads
which validation stage each one fails at, which is enough to prove the pin:

    <no key>                     -> passes the KMS stage   (CMEK is OPTIONAL: the gap)
    the registered key           -> passes the KMS stage
    a key in another project     -> REJECTED at the KMS stage
    a different key, same project-> REJECTED at the KMS stage

Exit codes:
    0  the pin holds
    1  the pin does NOT hold — a foreign key was accepted (a real finding)
    2  inconclusive — could not run the probe

Usage:
    python -m layer5.conversation_key_probe
"""

from __future__ import annotations

import sys
from pathlib import Path

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import geminidataanalytics

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import api_endpoint  # noqa: E402
from config._loader import load  # noqa: E402

EXIT_OK, EXIT_FAILED, EXIT_INCONCLUSIVE = 0, 1, 2
SINGLETON_MARKER = "Only 1 KMS key"
# Never reused as a real id; every attempt is expected to fail before creation.
PROBE_ID = "cmek-keypin-probe"


def _submit(client, parent: str, agent: str, kms_key: str | None) -> tuple[str, str]:
    """Return (outcome, detail) for one candidate key. Never expects success."""
    conversation = geminidataanalytics.Conversation(
        agents=[agent], **({"kms_key": kms_key} if kms_key else {})
    )
    try:
        client.create_conversation(
            request=geminidataanalytics.CreateConversationRequest(
                parent=parent, conversation_id=PROBE_ID, conversation=conversation
            )
        )
        return "CREATED", "conversation was created"
    except GoogleAPICallError as exc:
        if SINGLETON_MARKER in (exc.message or ""):
            return "REJECTED_BY_KMS_PIN", exc.message.strip()[:150]
        return "PASSED_KMS_STAGE", f"{type(exc).__name__}: {exc.message.strip()[:110]}"


def main() -> int:
    env = load()
    project, location = env["PROJECT_ID"], env["LOCATION"]
    parent = f"projects/{project}/locations/{location}"

    approved = (
        f"projects/{project}/locations/{location}"
        f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['KMS_KEY']}"
    )
    foreign_project = (
        f"projects/{env['ROGUE_PROJECT_ID']}/locations/{location}"
        f"/keyRings/{env['ROGUE_KMS_KEYRING']}/cryptoKeys/{env['ROGUE_KMS_KEY']}"
    )
    same_project_other_key = (
        f"projects/{project}/locations/{location}"
        f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/not-the-registered-key"
    )

    agents = geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )
    chat = geminidataanalytics.DataChatServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )

    try:
        agent = next(iter(agents.list_data_agents(parent=parent))).name
    except (GoogleAPICallError, StopIteration):
        print("  INCONCLUSIVE: no DataAgent available to anchor a conversation.")
        return EXIT_INCONCLUSIVE

    cases = [
        ("no key (CMEK optional?)", None, "PASSED_KMS_STAGE"),
        ("the registered key", approved, "PASSED_KMS_STAGE"),
        ("a key in another project", foreign_project, "REJECTED_BY_KMS_PIN"),
        ("another key, same project", same_project_other_key, "REJECTED_BY_KMS_PIN"),
    ]

    failures = []
    for label, key, expected in cases:
        outcome, detail = _submit(chat, parent, agent, key)
        ok = outcome == expected
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:28} {outcome}")
        if not ok:
            print(f"         expected {expected} — {detail}")
            failures.append((label, outcome))

    if any(o == "CREATED" for _, o in failures):
        print("\n  A probe conversation was CREATED. Delete it before re-running.")

    if failures:
        print("\n  The conversation key pin did NOT behave as validated.")
        return EXIT_FAILED

    print(
        "\n  PROVEN: the conversation CMEK key is pinned per project+location. "
        "A foreign key is rejected, and so is a different key in the same "
        "project — stricter than restrictCmekCryptoKeyProjects. Supplying no "
        "key is still accepted, which is the enforcement gap Layer 5 attests."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
