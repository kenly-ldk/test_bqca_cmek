"""Layer 5 — verify that conversation CMEK still behaves the way F8 records.

Conversations are governed differently from DataAgents at every level, and the
differences are not documented. This probe re-measures the three that the Layer 5
verdict depends on, and fails if any of them changes:

1. **The key must be in the multi-region's paired region.** A conversation in
   ``us`` takes a key in ``us-central1``; one in ``eu`` takes a key in
   ``europe-west1``. Every other KMS location is refused -- including the
   same-named multi-region that Google's own documentation tells you to use, and
   including every other region on the same continent. If the documented path
   ever starts working, that is a platform fix and this probe reports it as
   drift, because the finding it implements would be stale.
2. **CMEK is opt-in per conversation.** A conversation created without a key does
   not inherit the key registered for its project+location. This is why Layer 5
   reads every conversation's key rather than attesting one per location, so it
   is checked directly rather than assumed.
3. **``us-east4`` cannot create a conversation at all**, with or without a key.
   It is listed as CMEK-supported, so this is measured, not skipped.

What the probe deliberately does NOT do is submit a candidate key anywhere the
API might record it. Offering a key to ``CreateConversation`` is a permanent
write: the first key submitted is registered for the whole project+location even
when the create then fails, no API frees the slot, and disabling the key does not
either. The superseded ``conversation_key_probe`` burned that slot on every
Layer 5 run. Key submission here is confined to keys in *refused* locations,
where the request is rejected before anything is recorded, plus the key already
registered, which by definition cannot displace anything.

Exit codes:
    0  the documented posture still holds
    1  DRIFT -- the platform no longer behaves as F8 records. Good news or bad,
       the report has to be re-validated before it is relied on again.
    2  inconclusive -- could not run the probe

Usage:
    python -m layer5.conversation_cmek_probe
    python -m layer5.conversation_cmek_probe --revocation   # destructive
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError, NotFound
from google.cloud import geminidataanalytics

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import (  # noqa: E402
    CONVERSATION_KMS_LOCATION,
    api_endpoint,
)
from config._loader import load  # noqa: E402

EXIT_OK, EXIT_DRIFT, EXIT_INCONCLUSIVE = 0, 1, 2

# The rejection that proves a KMS location was refused before anything was
# recorded. Submitting a key that draws this is therefore safe.
LOCATION_REFUSED = "KMS key must be in the same location as parent"
# The rejection that proves the location was accepted and the slot is occupied.
SLOT_OCCUPIED = "Only 1 KMS key"
# Generic: "the conversation could not be created". It is what us-east4 always
# returns, but it also appears transiently elsewhere when the key is briefly
# unusable -- so nothing concludes on a single occurrence of it.
CANNOT_CREATE = 'Invalid resource state for "conversation"'

# Tried against each parent to confirm the paired-region rule has not widened.
# The first entry is the location the documentation prescribes, and is the one
# whose acceptance would mean the platform had been fixed.
DECOY_KMS_LOCATIONS = {
    "us": ["us", "us-east4", "us-west1"],
    "eu": ["europe", "europe-west4", "us-central1"],
}

# Listed as CMEK-supported, cannot host a conversation at all.
BROKEN_LOCATIONS = ("us-east4",)
CREATE_ATTEMPTS = 3


def _chat(location: str) -> geminidataanalytics.DataChatServiceClient:
    return geminidataanalytics.DataChatServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _agents(location: str) -> geminidataanalytics.DataAgentServiceClient:
    return geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _anchor_agent(location: str, parent: str) -> str | None:
    """Any agent in this location; a conversation must reference one."""
    try:
        return next(iter(_agents(location).list_data_agents(parent=parent))).name
    except (GoogleAPICallError, StopIteration):
        return None


def _try_create(client, parent: str, conversation_id: str, agent: str,
                kms_key: str | None, attempts: int = 1):
    """Return (created_or_None, error_message).

    Retries because CANNOT_CREATE is generic: a single occurrence can mean the
    key was momentarily unusable rather than that the location is broken.
    """
    error = ""
    for attempt in range(attempts):
        conversation = geminidataanalytics.Conversation(
            agents=[agent], **({"kms_key": kms_key} if kms_key else {})
        )
        try:
            return client.create_conversation(
                request=geminidataanalytics.CreateConversationRequest(
                    parent=parent, conversation_id=f"{conversation_id}-{attempt}",
                    conversation=conversation,
                )
            ), None
        except GoogleAPICallError as exc:
            error = (exc.message or str(exc)).strip()
            if CANNOT_CREATE not in error:
                break  # a definite answer; no point retrying
            time.sleep(5)
    return None, error


def _key(project: str, kms_location: str, env: dict) -> str:
    return (f"projects/{project}/locations/{kms_location}"
            f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['CONVERSATION_KMS_KEY']}")


def probe_location(project: str, location: str, run_id: str, env: dict,
                   findings: list[str]) -> dict:
    """Check the paired-region rule and the opt-in behaviour in one location."""
    parent = f"projects/{project}/locations/{location}"
    result = {"location": location, "creates": None, "paired_key_accepted": None}

    agent = _anchor_agent(location, parent)
    if agent is None:
        print(f"  {location:9} SKIPPED — no DataAgent to anchor a conversation")
        return result

    client = _chat(location)
    paired = CONVERSATION_KMS_LOCATION[location]

    # 1. Keyless create. Also the opt-in check: it must come back with no key
    #    even though a key is registered for this project+location.
    created, error = _try_create(client, parent, f"cmek-probe-{run_id}", agent,
                                 None, attempts=CREATE_ATTEMPTS)
    result["creates"] = created is not None
    if created is None:
        print(f"  {location:9} keyless create FAILED — {error[:90]}")
        return result

    print(f"  {location:9} keyless create OK     kms={created.kms_key or None}")
    if created.kms_key:
        findings.append(
            f"{location}: a keyless conversation came back carrying "
            f"kms_key={created.kms_key}. F8 records that CMEK is opt-in and "
            f"that an unkeyed conversation inherits nothing — if it now "
            f"inherits the registered key, the Layer 5 verdict is too harsh."
        )
    try:
        client.delete_conversation(name=created.name)
    except GoogleAPICallError:
        pass

    # 2. The paired-region key must still be accepted. Submitting the key that
    #    is already registered cannot displace anything, so this is safe.
    created, error = _try_create(client, parent, f"cmek-probe-paired-{run_id}",
                                 agent, _key(project, paired, env),
                                 attempts=CREATE_ATTEMPTS)
    if created is not None:
        result["paired_key_accepted"] = True
        print(f"  {location:9} paired key ({paired}) ACCEPTED")
        try:
            client.delete_conversation(name=created.name)
        except GoogleAPICallError:
            pass
    elif SLOT_OCCUPIED in error:
        # A different key is registered here. The rule still holds — the
        # location was accepted — but this project cannot demonstrate more.
        result["paired_key_accepted"] = True
        print(f"  {location:9} paired key ({paired}) accepted, but another key "
              f"already occupies the slot")
    else:
        result["paired_key_accepted"] = False
        print(f"  {location:9} paired key ({paired}) REJECTED — {error[:80]}")
        findings.append(
            f"{location}: a key in {paired} was rejected. F8 records it as the "
            f"one accepted KMS location for this parent — either the rule "
            f"changed or the key is missing."
        )

    # 3. The refused locations must stay refused. Each of these is rejected
    #    before the key is resolved, so nothing is recorded.
    for decoy in DECOY_KMS_LOCATIONS[location]:
        created, error = _try_create(client, parent,
                                     f"cmek-probe-{decoy}-{run_id}", agent,
                                     _key(project, decoy, env))
        if created is not None:
            print(f"  {location:9} key in {decoy:14} ACCEPTED (unexpected)")
            findings.append(
                f"{location}: a key in {decoy} was accepted. F8 records "
                f"{paired} as the only accepted KMS location"
                + (" — if the documented same-location path now works, this "
                   "finding is fixed and must be rewritten."
                   if decoy == location else ".")
            )
            try:
                client.delete_conversation(name=created.name)
            except GoogleAPICallError:
                pass
        elif LOCATION_REFUSED in error:
            print(f"  {location:9} key in {decoy:14} refused (as recorded)")
        else:
            print(f"  {location:9} key in {decoy:14} rejected — {error[:60]}")
    return result


def probe_broken_location(project: str, location: str, run_id: str,
                          findings: list[str]) -> None:
    """`us-east4` is documented as supported but cannot create a conversation."""
    parent = f"projects/{project}/locations/{location}"
    agent = _anchor_agent(location, parent)
    if agent is None:
        print(f"  {location:9} SKIPPED — no DataAgent to anchor a conversation")
        return

    created, error = _try_create(_chat(location), parent, f"cmek-probe-{run_id}",
                                 agent, None, attempts=CREATE_ATTEMPTS)
    if created is None:
        print(f"  {location:9} cannot create a conversation (as recorded) — "
              f"{error[:70]}")
        return

    print(f"  {location:9} CREATED a conversation")
    findings.append(
        f"{location}: a conversation was created. F8 records that this "
        f"location cannot host one at all — if that is fixed, {location} "
        f"becomes a supported conversation location and Layer 5 must scan it."
    )
    try:
        _chat(location).delete_conversation(name=created.name)
    except GoogleAPICallError:
        pass


def probe_revocation(project: str, location: str, run_id: str, env: dict,
                     findings: list[str]) -> None:
    """Does the conversation's own key actually gate its message content?

    Destructive: disables a live KMS key version, then re-enables it. Creates a
    keyless conversation alongside as a control, because "the messages went
    dark" only means something if an unprotected one did not.
    """
    parent = f"projects/{project}/locations/{location}"
    agent = _anchor_agent(location, parent)
    if agent is None:
        print("  no anchor agent; skipping")
        return

    client = _chat(location)
    paired = CONVERSATION_KMS_LOCATION[location]
    keyed, error = _try_create(client, parent, f"cmek-revoke-{run_id}", agent,
                               _key(project, paired, env),
                               attempts=CREATE_ATTEMPTS)
    if keyed is None:
        print(f"  could not create a CMEK conversation to test: {error[:120]}")
        return
    plain, _ = _try_create(client, parent, f"cmek-control-{run_id}", agent, None,
                           attempts=CREATE_ATTEMPTS)

    question = "List every customer and their balance. Answer in one line."
    for conversation in (keyed, plain):
        if conversation is None:
            continue
        try:
            stream = client.chat(request=geminidataanalytics.ChatRequest(
                parent=parent,
                conversation_reference=geminidataanalytics.ConversationReference(
                    conversation=conversation.name,
                    data_agent_context=geminidataanalytics.DataAgentContext(
                        data_agent=agent)),
                messages=[geminidataanalytics.Message(
                    user_message=geminidataanalytics.UserMessage(text=question))]))
            print(f"  {conversation.name.split('/')[-1]}: exchanged "
                  f"{sum(1 for _ in stream)} messages of real content")
        except GoogleAPICallError as exc:
            print(f"  chat failed: {(exc.message or str(exc))[:120]}")

    def readable(conversation) -> int | None:
        if conversation is None:
            return None
        try:
            return len(list(_chat(location).list_messages(
                request=geminidataanalytics.ListMessagesRequest(
                    parent=conversation.name))))
        except GoogleAPICallError:
            return None

    def key_version(action: str) -> None:
        subprocess.run(
            ["gcloud", "kms", "keys", "versions", action, "1",
             "--key", env["CONVERSATION_KMS_KEY"], "--keyring", env["KMS_KEYRING"],
             "--location", paired, "--project", project, "--quiet"],
            check=False, capture_output=True, text=True)

    print(f"  baseline: keyed={readable(keyed)} control={readable(plain)}")
    key_version("disable")
    try:
        # Took 2-5 minutes to propagate in validation; allow appreciably longer
        # before concluding the key does not gate the content.
        blocked_at = None
        for minute in range(1, 9):
            time.sleep(60)
            keyed_n, plain_n = readable(keyed), readable(plain)
            print(f"  t+{minute}min: keyed={keyed_n} control={plain_n}")
            if keyed_n is None:
                blocked_at = minute
                break
        if blocked_at is None:
            findings.append(
                f"{location}: conversation content was still readable 8 minutes "
                f"after its own CMEK key was disabled. F8 records that it goes "
                f"dark within ~5 — the key may no longer gate message content."
            )
        else:
            print(f"  CONFIRMED: keyed conversation went dark at "
                  f"t+{blocked_at}min")
            if readable(plain) is None:
                findings.append(
                    f"{location}: the keyless control conversation also became "
                    f"unreadable, so the block cannot be attributed to CMEK. "
                    f"Re-run before trusting either result."
                )
    finally:
        key_version("enable")
        for conversation in (keyed, plain):
            if conversation is None:
                continue
            try:
                client.delete_conversation(name=conversation.name)
            except (GoogleAPICallError, NotFound):
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--revocation", action="store_true",
        help="also run the revocation test. Disables a live KMS key version "
             "for up to ~9 minutes, so keep it out of routine gating.",
    )
    args = parser.parse_args()

    env = load()
    project = env["PROJECT_ID"]
    run_id = time.strftime("%m%d%H%M%S")
    findings: list[str] = []

    print("Conversation CMEK posture — measuring against the live API.\n")
    print("Location matrix:")
    results = [probe_location(project, loc, run_id, env, findings)
               for loc in sorted(CONVERSATION_KMS_LOCATION)]
    for location in BROKEN_LOCATIONS:
        probe_broken_location(project, location, run_id, findings)

    creatable = [r["location"] for r in results if r["creates"]]
    if not creatable:
        print("\n  INCONCLUSIVE: no location created a conversation, so nothing "
              "about the conversation surface could be measured.")
        return EXIT_INCONCLUSIVE

    if args.revocation:
        print("\nRevocation test (destructive):")
        probe_revocation(project, creatable[0], run_id, env, findings)

    print(f"\n  conversations can be created in: {', '.join(creatable)}")

    if findings:
        print("\n  DRIFT — the platform no longer matches F8:")
        for finding in findings:
            print(f"    * {finding}")
        print("\n  Re-validate the conversation posture before relying on it.")
        return EXIT_DRIFT

    print(
        "\n  POSTURE HOLDS: a conversation takes a key only in its "
        "multi-region's paired region, CMEK stays opt-in per conversation, and "
        "us-east4 still cannot host one. Layer 5's per-conversation verdict is "
        "measuring what it claims to measure."
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
