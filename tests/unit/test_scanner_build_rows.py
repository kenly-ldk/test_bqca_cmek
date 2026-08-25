"""Unit tests for layer5/scanner/main.py::build_rows — the reconciliation matrix.

Why these exist: across 89 scheduled scans spanning three days, the production
scanner never once emitted PENDING_CAI_INGESTION or NON_COMPLIANT_UNVERIFIABLE.
Both branches are the entire justification for reading two sources, and both
were dead code in practice — CAI simply never disagreed with the live API in
that environment. A control whose distinguishing logic has never executed is not
a verified control.

Every quadrant of the CAI x live-API matrix is covered here by injecting the two
scans directly, so the branches are exercised deterministically with no GCP:

    in API   in CAI   key verdict   expected status
    ------   ------   -----------   ---------------------------------
    yes      yes      compliant     COMPLIANT
    yes      yes      bad           NON_COMPLIANT_<reason>
    no       yes      any           NON_COMPLIANT_UNVERIFIABLE
    no       yes      any + scan    NON_COMPLIANT_UNVERIFIABLE_SCAN_ERROR
    yes      no       compliant     PENDING_CAI_INGESTION
    yes      no       bad           NON_COMPLIANT_<reason>   (never masked)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from _loader import load_scanner
from gda_common import (
    COMPLIANT,
    MISSING_CMEK,
    UNAPPROVED_KEY_PROJECT,
    UNSUPPORTED_LOCATION,
)

scanner = load_scanner()

SCAN_TIME = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
PROJECT = "unit-test-project"
GOOD_KEY = "projects/approved-a/locations/us-east4/keyRings/kr/cryptoKeys/k"
ROGUE_KEY = "projects/rogue-project/locations/us-east4/keyRings/kr/cryptoKeys/k"


def name(agent_id: str, location: str = "us-east4") -> str:
    return f"projects/{PROJECT}/locations/{location}/dataAgents/{agent_id}"


def record(kms_key: str | None, location: str = "us-east4") -> dict:
    return {"kms_key": kms_key, "location": location, "create_time": None}


@pytest.fixture
def inject(monkeypatch):
    """Drive build_rows from synthetic CAI / live-API scans."""

    def _inject(cai: dict, api: dict, failed: dict | None = None):
        monkeypatch.setattr(scanner, "scan_cai", lambda: cai)
        monkeypatch.setattr(scanner, "scan_api", lambda: (api, failed or {}))
        # build_rows also appends conversation-key attestations. Stub them out:
        # these tests are about the agent matrix, and an un-stubbed scan would
        # reach the live API and stop being a unit test. Conversation rows are
        # covered in test_conversations.py.
        monkeypatch.setattr(scanner, "scan_conversation_keys", dict)
        rows, failed_locations = scanner.build_rows(SCAN_TIME)
        agents = {
            r["resource_url"]: r for r in rows if r["resource_type"] == scanner.DATA_AGENT
        }
        return agents, failed_locations

    return _inject


# --- both sources agree -----------------------------------------------------


def test_visible_to_both_and_compliant(inject):
    n = name("a")
    rows, _ = inject({n: record(GOOD_KEY)}, {n: record(GOOD_KEY)})
    assert rows[n]["compliance_status"] == COMPLIANT
    assert rows[n]["visible_in_cai"] and rows[n]["visible_in_api"]


@pytest.mark.parametrize(
    ("kms_key", "location", "expected"),
    [
        (None, "us-east4", MISSING_CMEK),
        (ROGUE_KEY, "us-east4", UNAPPROVED_KEY_PROJECT),
        (None, "global", UNSUPPORTED_LOCATION),
    ],
)
def test_visible_to_both_and_violating(inject, kms_key, location, expected):
    n = name("a", location)
    rows, _ = inject({n: record(kms_key, location)}, {n: record(kms_key, location)})
    assert rows[n]["compliance_status"] == expected


# --- in CAI, invisible to the live API (the key-disabled case, F4) ---------


def test_cai_only_is_unverifiable_not_compliant(inject):
    """A disabled CMEK key hides an agent from LIST with no error.

    The agent's last-known key was perfectly good, so the naive verdict would be
    COMPLIANT. It must not be: we cannot see the resource, so we cannot vouch
    for it.
    """
    n = name("hidden")
    rows, _ = inject({n: record(GOOD_KEY)}, {})
    assert rows[n]["compliance_status"] == scanner.INVISIBLE_TO_API
    assert rows[n]["visible_in_cai"] is True
    assert rows[n]["visible_in_api"] is False


def test_cai_only_never_reports_compliant_even_with_a_good_key(inject):
    n = name("hidden")
    rows, _ = inject({n: record(GOOD_KEY)}, {})
    assert rows[n]["compliance_status"] != COMPLIANT


# --- in CAI, but we could not finish reading the API (scan error) -----------


def test_scan_error_is_distinct_from_key_disabled(inject):
    """An outage must not be reported as a customer's key problem."""
    n = name("in-broken-location")
    rows, _ = inject(
        {n: record(GOOD_KEY)},
        {},
        failed={"us-east4": "ServiceUnavailable: transient backend error"},
    )
    assert rows[n]["compliance_status"] == scanner.SCAN_INCOMPLETE
    assert rows[n]["compliance_status"] != scanner.INVISIBLE_TO_API
    assert "ServiceUnavailable" in rows[n]["reason"]
    assert "disabled" not in rows[n]["reason"].lower()


def test_scan_error_only_applies_to_the_failed_location(inject):
    """A failure in us-east4 says nothing about an agent in eu."""
    broken, healthy = name("x", "us-east4"), name("y", "eu")
    rows, _ = inject(
        {broken: record(GOOD_KEY, "us-east4"), healthy: record(GOOD_KEY, "eu")},
        {},
        failed={"us-east4": "ServiceUnavailable: boom"},
    )
    assert rows[broken]["compliance_status"] == scanner.SCAN_INCOMPLETE
    assert rows[healthy]["compliance_status"] == scanner.INVISIBLE_TO_API


def test_failed_locations_are_returned_to_the_caller(inject):
    """main() relies on this to exit non-zero rather than report a clean scan."""
    _, failed = inject({}, {}, failed={"eu": "DeadlineExceeded: slow"})
    assert failed == {"eu": "DeadlineExceeded: slow"}


# --- in the live API, not yet in CAI ----------------------------------------


def test_api_only_and_compliant_is_pending_not_a_violation(inject):
    n = name("brand-new")
    rows, _ = inject({}, {n: record(GOOD_KEY)})
    assert rows[n]["compliance_status"] == scanner.CAI_LAG
    assert rows[n]["visible_in_api"] is True
    assert rows[n]["visible_in_cai"] is False


@pytest.mark.parametrize(
    ("kms_key", "location", "expected"),
    [
        (None, "us-east4", MISSING_CMEK),
        (ROGUE_KEY, "us-east4", UNAPPROVED_KEY_PROJECT),
        (None, "global", UNSUPPORTED_LOCATION),
    ],
)
def test_api_only_and_violating_keeps_its_real_status(inject, kms_key, location, expected):
    """PENDING_CAI_INGESTION can never mask a violation.

    The branch is guarded on verdict.is_compliant, so a non-compliant agent that
    CAI has not ingested keeps its real finding. This is the property the
    compliance view relies on when it declines to count PENDING as a violation.
    """
    n = name("brand-new-bad", location)
    rows, _ = inject({}, {n: record(kms_key, location)})
    assert rows[n]["compliance_status"] == expected
    assert rows[n]["compliance_status"] != scanner.CAI_LAG


# --- shape ------------------------------------------------------------------


def test_rows_carry_no_agent_content(inject):
    """The audit control must not become a second copy of the protected data."""
    n = name("a")
    rows, _ = inject({n: record(GOOD_KEY)}, {n: record(GOOD_KEY)})
    assert set(rows[n]) == {
        "scan_time",
        "resource_type",
        "resource_url",
        "project_id",
        "location",
        "agent_id",
        "configured_kms_key",
        "kms_key_project",
        "compliance_status",
        "reason",
        "visible_in_cai",
        "visible_in_api",
    }


def test_union_of_both_sources_is_reported(inject):
    only_cai, only_api, both = name("c"), name("a"), name("b")
    rows, _ = inject(
        {only_cai: record(GOOD_KEY), both: record(GOOD_KEY)},
        {only_api: record(GOOD_KEY), both: record(GOOD_KEY)},
    )
    assert set(rows) == {only_cai, only_api, both}
