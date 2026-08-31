"""Unit tests for the conversation CMEK verdict.

Conversations are governed differently from DataAgents, and every test here
exists because of a fact verified against the live API rather than assumed
(validation-report F8, re-measured 2026-08-30):

* `Conversation` carries a `kms_key`, and it is a real cryptographic boundary:
  disable the key and both `GetConversation` and `ListMessages` fail within a
  few minutes. Conversation *messages* are customer content, so this matters.
* **CMEK is opt-in per conversation.** A conversation created without a key does
  NOT inherit the key registered for its project+location — it stays readable
  while that key is disabled. So two conversations side by side can disagree,
  and the location is only as good as its worst one. That is why the verdict
  takes every observed key rather than a single registered one.
* The API still registers **one key per project+location** and refuses every
  other key. That is a squatting hazard rather than a protection, but it does
  mean two distinct keys in one location should be impossible — so the classifier
  treats it as a contradiction rather than picking a winner.
* Cloud Asset Inventory has no Conversation asset type at all, so there is no
  second source to reconcile against.

Rows stay one-per-location rather than one-per-conversation because
conversations are ephemeral and hard-deleted; the verdict is still computed
across all of them.
"""

from __future__ import annotations

import pytest
from _loader import load_scanner
from gda_common import (
    COMPLIANT,
    MISSING_CMEK,
    CONVERSATIONS_UNVERIFIABLE,
    UNAPPROVED_KEY_PROJECT,
    UNSUPPORTED_LOCATION,
    check_conversation_key,
    evaluate_conversation_compliance,
    parse_conversation_name,
)

scanner = load_scanner()

APPROVED = frozenset({"approved-a", "approved-b"})
GOOD = "projects/approved-a/locations/us-east4/keyRings/kr/cryptoKeys/k"
OTHER_APPROVED = "projects/approved-b/locations/us-east4/keyRings/kr/cryptoKeys/k2"
ROGUE = "projects/rogue-project/locations/us-east4/keyRings/kr/cryptoKeys/k"


# --- the verdict ------------------------------------------------------------


def test_unapproved_key_is_a_violation():
    verdict = evaluate_conversation_compliance("us-east4", [ROGUE], APPROVED)
    assert verdict.status == UNAPPROVED_KEY_PROJECT
    assert "rogue-project" in verdict.reason


def test_conversations_with_no_key_are_non_compliant():
    """The gap: the API accepts a conversation with no kms_key."""
    assert evaluate_conversation_compliance("us-east4", [None], APPROVED).status == MISSING_CMEK


def test_one_unkeyed_conversation_condemns_the_location():
    """The opt-in gap, measured: an unkeyed conversation does not inherit the
    registered key, so 49 protected conversations do not cover the 50th."""
    verdict = evaluate_conversation_compliance("us-east4", [GOOD] * 49 + [None], APPROVED)
    assert verdict.status == MISSING_CMEK
    assert "1 of 50" in verdict.reason


# --- the visibility ceiling ------------------------------------------------
#
# These are the tests that were missing when Layer 5's conversation reporting
# was first written, and their absence let it emit a false all-clear.
#
# A conversation is readable only by the principal that created it: measured
# against the live API, a service account with cloudaicompanion.topics.get sees
# {} from ListConversations and 404 from GetConversation for another
# principal's conversation, and roles/cloudaicompanion.topicAdmin does not lift
# it. A scanner therefore CANNOT enumerate the surface, and no result it gets
# can ever mean "compliant".


def test_no_input_can_produce_a_compliant_verdict():
    """The property that matters: this function can prove a violation and can
    never prove compliance. Asserted exhaustively rather than case by case, so
    a future edit cannot reintroduce a pass."""
    for keys in ([], [GOOD], [GOOD] * 50, [None], [GOOD, None],
                 [ROGUE], [GOOD, OTHER_APPROVED]):
        assert not evaluate_conversation_compliance("us", keys, APPROVED).is_compliant


def test_empty_is_unverifiable_not_a_clean_bill_of_health():
    """'I saw nothing' is indistinguishable from 'your analysts have hundreds'."""
    verdict = evaluate_conversation_compliance("us", [], APPROVED)
    assert verdict.status == CONVERSATIONS_UNVERIFIABLE
    assert "does NOT mean" in verdict.reason


def test_all_visible_conversations_keyed_is_still_not_a_pass():
    """The invisible remainder is unconstrained, so a clean visible set proves
    nothing about the location."""
    verdict = evaluate_conversation_compliance("us", [GOOD, GOOD], APPROVED)
    assert verdict.status == CONVERSATIONS_UNVERIFIABLE
    assert "not a pass" in verdict.reason


def test_a_visible_unkeyed_conversation_is_still_a_real_violation():
    """Visibility is partial, but what IS seen is proof. A violation must not be
    downgraded to 'unverifiable' just because the view is incomplete."""
    verdict = evaluate_conversation_compliance("us", [None], APPROVED)
    assert verdict.status == MISSING_CMEK
    assert "only be higher" in verdict.reason


def test_unkeyed_count_is_reported_so_the_row_is_actionable():
    verdict = evaluate_conversation_compliance("us-east4", [None, GOOD, None], APPROVED)
    assert "2 of 3" in verdict.reason


def test_unkeyed_is_reported_before_an_unapproved_key():
    """Both are violations; the concrete, actionable one leads."""
    verdict = evaluate_conversation_compliance("us-east4", [ROGUE, None], APPROVED)
    assert verdict.status == MISSING_CMEK


def test_empty_result_is_never_reported_as_safe():
    verdict = evaluate_conversation_compliance("us-east4", [], APPROVED)
    assert verdict.status == CONVERSATIONS_UNVERIFIABLE
    assert not verdict.is_compliant


def test_unsupported_location_still_wins():
    """A key in a location that cannot host a conversation is a real finding,
    not merely unverifiable."""
    assert evaluate_conversation_compliance("global", [GOOD, None], APPROVED).status == MISSING_CMEK
    assert evaluate_conversation_compliance("global", [ROGUE], APPROVED).status == UNSUPPORTED_LOCATION


# Two distinct keys in one location contradicted the API's one-key registry and
# used to be flagged as an anomaly. That branch is gone, and deliberately: every
# all-keyed result is now UNVERIFIABLE regardless, so there was never a winner
# to pick between keys. The property below is what replaced it.


def test_conflicting_keys_are_still_never_a_pass():
    verdict = evaluate_conversation_compliance("us-east4", [GOOD, OTHER_APPROVED], APPROVED)
    assert not verdict.is_compliant


# --- resource naming --------------------------------------------------------


def test_parse_conversation_name():
    parsed = parse_conversation_name("projects/p/locations/us-east4/conversations/c1")
    assert (parsed.project, parsed.location, parsed.conversation_id) == ("p", "us-east4", "c1")
    assert parsed.parent == "projects/p/locations/us-east4"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "projects/p/locations/l",
        "projects/p/locations/l/dataAgents/a",  # an agent, not a conversation
        "projects/p/locations/l/conversations/c/messages/m",
    ],
)
def test_parse_conversation_name_rejects_others(bad):
    assert parse_conversation_name(bad) is None


# --- scanner rows -----------------------------------------------------------


@pytest.fixture
def conv_rows(monkeypatch):
    def _rows(per_location):
        monkeypatch.setattr(scanner, "scan_conversation_keys", lambda: per_location)
        from datetime import datetime, timezone

        rows = scanner.build_conversation_rows(datetime(2026, 8, 24, tzinfo=timezone.utc))
        return {r["location"]: r for r in rows}

    return _rows


def test_one_row_per_location_not_per_conversation(conv_rows):
    rows = conv_rows({"us-east4": ([GOOD] * 40, None), "eu": ([GOOD], None)})
    assert len(rows) == 2
    assert all(r["resource_type"] == scanner.CONVERSATION_KEY for r in rows.values())
    assert rows["us-east4"]["resource_url"].endswith("/locations/us-east4/conversations")


def test_row_records_an_observed_key(conv_rows):
    """The key seen is still recorded — it is evidence — but the row must not
    be marked compliant on the strength of a partial view."""
    rows = conv_rows({"us-east4": ([GOOD], None)})
    assert rows["us-east4"]["configured_kms_key"] == GOOD
    assert rows["us-east4"]["kms_key_project"] == "approved-a"
    assert rows["us-east4"]["compliance_status"] == CONVERSATIONS_UNVERIFIABLE


def test_row_never_claims_cai_corroboration(conv_rows):
    """CAI has no Conversation asset type; the row must not imply two sources."""
    rows = conv_rows({"us-east4": ([GOOD], None)})
    assert rows["us-east4"]["visible_in_cai"] is False


def test_unreadable_location_yields_scan_error_not_a_clean_bill(conv_rows):
    rows = conv_rows({"us-east4": ([], "ServiceUnavailable: boom")})
    row = rows["us-east4"]
    assert row["compliance_status"] == scanner.SCAN_INCOMPLETE
    assert row["visible_in_api"] is False
    assert row["compliance_status"] != CONVERSATIONS_UNVERIFIABLE


def test_unreadable_location_is_not_confused_with_empty(conv_rows):
    """"We could not ask" must never render as "there is nothing there"."""
    broken = conv_rows({"us-east4": ([], "PermissionDenied: nope")})["us-east4"]
    empty = conv_rows({"us-east4": ([], None)})["us-east4"]
    assert broken["compliance_status"] != empty["compliance_status"]
    assert empty["compliance_status"] == CONVERSATIONS_UNVERIFIABLE


def test_rows_carry_no_conversation_content(conv_rows):
    """Messages are customer content and must never reach the inventory."""
    row = conv_rows({"us-east4": ([GOOD], None)})["us-east4"]
    assert row["agent_id"] is None
    assert set(row) == {
        "scan_time", "resource_type", "resource_url", "project_id", "location",
        "agent_id", "configured_kms_key", "kms_key_project", "compliance_status",
        "reason", "visible_in_cai", "visible_in_api",
    }


# --- Layer 3 pre-flight gate ------------------------------------------------
#
# check_conversation_key runs BEFORE CreateConversation, because that call is
# not idempotent in the way it looks: the first key offered is registered
# permanently for the whole project+location even if the create then fails, and
# no API frees the slot. A wrong key cannot be corrected, so it must never reach
# the API.

CONV_APPROVED = frozenset({"approved-a"})


def _key(kms_location, project="approved-a"):
    return f"projects/{project}/locations/{kms_location}/keyRings/kr/cryptoKeys/k"


def test_paired_region_key_passes_the_gate():
    assert check_conversation_key("us", _key("us-central1"), CONV_APPROVED).is_compliant
    assert check_conversation_key("eu", _key("europe-west1"), CONV_APPROVED).is_compliant


def test_the_documented_key_location_is_blocked():
    """A key in the conversation's own location is what the docs prescribe and
    what the API rejects. The gate has to catch it first."""
    verdict = check_conversation_key("us", _key("us"), CONV_APPROVED)
    assert not verdict.is_compliant
    assert "us-central1" in verdict.reason


def test_the_agents_key_location_is_blocked():
    """`europe` is right for an eu AGENT and wrong for an eu conversation."""
    assert not check_conversation_key("eu", _key("europe"), CONV_APPROVED).is_compliant


def test_unsupported_conversation_locations_are_blocked():
    for location in ("us-east4", "global", "asia"):
        assert not check_conversation_key(
            location, _key("us-central1"), CONV_APPROVED
        ).is_compliant


def test_missing_and_unapproved_and_malformed_keys_are_blocked():
    assert check_conversation_key("us", None, CONV_APPROVED).status == MISSING_CMEK
    assert not check_conversation_key(
        "us", _key("us-central1", project="rogue"), CONV_APPROVED
    ).is_compliant
    assert not check_conversation_key("us", "not-a-key", CONV_APPROVED).is_compliant
