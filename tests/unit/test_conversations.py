"""Unit tests for conversation CMEK attestation.

Conversations are governed differently from DataAgents, and every test here
exists because of a fact verified against the live API rather than assumed:

* `Conversation` carries its own `kms_key`, so it is a second CMEK-bearing
  resource type — conversation *messages* are customer content.
* CMEK for conversations is a **project+location singleton**. Supplying any key
  other than the registered one is rejected, including a different key in the
  *same project*: "Only 1 KMS keys per project per location are allowed." That
  is stricter than restrictCmekCryptoKeyProjects, which constrains only the
  project.
* Cloud Asset Inventory has no Conversation asset type at all, so there is no
  second source to reconcile against.

Together those collapse the control: rather than inventorying ephemeral
conversations, attest one registered key per project+location.
"""

from __future__ import annotations

import pytest
from _loader import load_scanner
from gda_common import (
    COMPLIANT,
    MISSING_CMEK,
    NO_CONVERSATIONS,
    UNAPPROVED_KEY_PROJECT,
    UNSUPPORTED_LOCATION,
    attest_conversation_key,
    parse_conversation_name,
)

scanner = load_scanner()

APPROVED = frozenset({"approved-a", "approved-b"})
GOOD = "projects/approved-a/locations/us-east4/keyRings/kr/cryptoKeys/k"
OTHER_APPROVED = "projects/approved-b/locations/us-east4/keyRings/kr/cryptoKeys/k2"
ROGUE = "projects/rogue-project/locations/us-east4/keyRings/kr/cryptoKeys/k"


# --- attestation ------------------------------------------------------------


def test_registered_approved_key_is_compliant():
    assert attest_conversation_key("us-east4", [GOOD], APPROVED).status == COMPLIANT


def test_many_conversations_sharing_the_singleton_key_is_one_verdict():
    """The point of the singleton: N conversations, one key, one answer."""
    assert attest_conversation_key("us-east4", [GOOD] * 50, APPROVED).status == COMPLIANT


def test_unapproved_registered_key_is_a_violation():
    verdict = attest_conversation_key("us-east4", [ROGUE], APPROVED)
    assert verdict.status == UNAPPROVED_KEY_PROJECT
    assert "rogue-project" in verdict.reason


def test_conversations_with_no_key_are_non_compliant():
    """The gap: the API accepts a conversation with no kms_key."""
    assert attest_conversation_key("us-east4", [None], APPROVED).status == MISSING_CMEK


def test_no_conversations_is_not_a_violation():
    """An empty surface carries no exposure — but it is not a pass either."""
    verdict = attest_conversation_key("us-east4", [], APPROVED)
    assert verdict.status == NO_CONVERSATIONS
    assert not verdict.is_compliant


def test_unsupported_location_still_wins():
    assert attest_conversation_key("global", [GOOD], APPROVED).status == UNSUPPORTED_LOCATION


def test_conflicting_keys_are_flagged_rather_than_averaged():
    """Should be unreachable while the API enforces the singleton.

    If it ever fires, the assumption the whole control rests on has changed, so
    it must be loud rather than silently picking one key.
    """
    verdict = attest_conversation_key("us-east4", [GOOD, OTHER_APPROVED], APPROVED)
    assert not verdict.is_compliant
    assert "distinct" in verdict.reason


def test_conflicting_keys_flagged_even_when_all_are_approved():
    """Both keys are in approved projects; the contradiction is still the story."""
    verdict = attest_conversation_key("us-east4", [GOOD, OTHER_APPROVED], APPROVED)
    assert verdict.status != COMPLIANT


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


def test_one_attestation_row_per_location_not_per_conversation(conv_rows):
    rows = conv_rows({"us-east4": ([GOOD] * 40, None), "eu": ([GOOD], None)})
    assert len(rows) == 2
    assert all(r["resource_type"] == scanner.CONVERSATION_KEY for r in rows.values())
    assert rows["us-east4"]["resource_url"].endswith("/locations/us-east4/conversations")


def test_attestation_row_records_the_observed_key(conv_rows):
    rows = conv_rows({"us-east4": ([GOOD], None)})
    assert rows["us-east4"]["configured_kms_key"] == GOOD
    assert rows["us-east4"]["kms_key_project"] == "approved-a"
    assert rows["us-east4"]["compliance_status"] == COMPLIANT


def test_attestation_never_claims_cai_corroboration(conv_rows):
    """CAI has no Conversation asset type; the row must not imply two sources."""
    rows = conv_rows({"us-east4": ([GOOD], None)})
    assert rows["us-east4"]["visible_in_cai"] is False


def test_unreadable_location_yields_scan_error_not_a_clean_bill(conv_rows):
    rows = conv_rows({"us-east4": ([], "ServiceUnavailable: boom")})
    row = rows["us-east4"]
    assert row["compliance_status"] == scanner.SCAN_INCOMPLETE
    assert row["visible_in_api"] is False
    assert row["compliance_status"] != NO_CONVERSATIONS


def test_unreadable_location_is_not_confused_with_empty(conv_rows):
    """"We could not ask" must never render as "there is nothing there"."""
    broken = conv_rows({"us-east4": ([], "PermissionDenied: nope")})["us-east4"]
    empty = conv_rows({"us-east4": ([], None)})["us-east4"]
    assert broken["compliance_status"] != empty["compliance_status"]
    assert empty["compliance_status"] == NO_CONVERSATIONS


def test_attestation_rows_carry_no_conversation_content(conv_rows):
    """Messages are customer content and must never reach the inventory."""
    row = conv_rows({"us-east4": ([GOOD], None)})["us-east4"]
    assert row["agent_id"] is None
    assert set(row) == {
        "scan_time", "resource_type", "resource_url", "project_id", "location",
        "agent_id", "configured_kms_key", "kms_key_project", "compliance_status",
        "reason", "visible_in_cai", "visible_in_api",
    }
