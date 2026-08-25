"""Unit tests for common/gda_common.py — the single compliance decision.

This module is the reason Layer 4 and Layer 5 cannot disagree about a resource,
which makes it the highest-leverage code in the repository and the place where
an untested edge case does the most damage. Until these tests existed it was
covered only by live end-to-end runs needing two GCP projects.

No network, no credentials, no GCP.
"""

from __future__ import annotations

import pytest
from gda_common import (
    COMPLIANT,
    MISSING_CMEK,
    UNAPPROVED_KEY_PROJECT,
    UNSUPPORTED_LOCATION,
    api_endpoint,
    evaluate_compliance,
    kms_key_project,
    parse_agent_name,
    parse_approved_projects,
    resolve_agent_name,
)

APPROVED = frozenset({"approved-a", "approved-b"})


def key(project: str = "approved-a", location: str = "us-east4") -> str:
    return f"projects/{project}/locations/{location}/keyRings/kr/cryptoKeys/k"


# --- api_endpoint -----------------------------------------------------------
# Getting this wrong silently breaks remediation: the global endpoint answers a
# regional path with 403, which reads as a permissions problem, not a routing
# one. Kept in sync with gda_endpoint() in scripts/prelude.sh.


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("global", "geminidataanalytics.googleapis.com"),
        ("us", "geminidataanalytics.us.rep.googleapis.com"),
        ("eu", "geminidataanalytics.eu.rep.googleapis.com"),
        ("us-east4", "geminidataanalytics-us-east4.googleapis.com"),
    ],
)
def test_api_endpoint(location, expected):
    assert api_endpoint(location) == expected


# --- evaluate_compliance ----------------------------------------------------


def test_compliant_key_in_approved_project():
    assert evaluate_compliance("us-east4", key(), APPROVED).status == COMPLIANT


@pytest.mark.parametrize("location", ["us-east4", "us", "eu"])
def test_all_cmek_supported_locations_can_be_compliant(location):
    verdict = evaluate_compliance(location, key(location=location), APPROVED)
    assert verdict.is_compliant


def test_missing_key_is_non_compliant():
    assert evaluate_compliance("us-east4", None, APPROVED).status == MISSING_CMEK


def test_empty_string_key_is_treated_as_missing():
    assert evaluate_compliance("us-east4", "", APPROVED).status == MISSING_CMEK


def test_key_in_unapproved_project_is_non_compliant():
    verdict = evaluate_compliance("us-east4", key("rogue-project"), APPROVED)
    assert verdict.status == UNAPPROVED_KEY_PROJECT
    assert "rogue-project" in verdict.reason


@pytest.mark.parametrize("location", ["global", "us-central1", "asia-east1", ""])
def test_unsupported_location_is_non_compliant(location):
    verdict = evaluate_compliance(location, key(), APPROVED)
    assert verdict.status == UNSUPPORTED_LOCATION


def test_unsupported_location_beats_a_valid_key():
    """`global` can never be CMEK-encrypted, so a key there is meaningless."""
    verdict = evaluate_compliance("global", key(location="global"), APPROVED)
    assert verdict.status == UNSUPPORTED_LOCATION


@pytest.mark.parametrize(
    "malformed",
    [
        "not-a-key-path",
        "projects/p/locations/l/cryptoKeys/k",  # no keyRings segment
        "projects//locations/l/keyRings/r/cryptoKeys/k",  # empty project
        key() + "/cryptoKeyVersions/1",  # version-qualified, not a cryptoKey
    ],
)
def test_malformed_key_fails_closed(malformed):
    """A malformed path must never be read as approved."""
    verdict = evaluate_compliance("us-east4", malformed, APPROVED)
    assert not verdict.is_compliant


def test_empty_allowlist_rejects_a_correctly_encrypted_agent():
    """The mass-deletion precondition.

    An empty allowlist approves nothing, so a perfectly compliant agent is
    judged UNAPPROVED_KEY_PROJECT. layer4/main.py must therefore refuse to
    remediate when APPROVED_KMS_PROJECTS is blank rather than deleting the whole
    estate — see test_enforcer.py::test_missing_allowlist_flags_misconfiguration.
    """
    verdict = evaluate_compliance("us-east4", key(), frozenset())
    assert verdict.status == UNAPPROVED_KEY_PROJECT


# --- parse_approved_projects ------------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "   ", ",", ",,  ,"])
def test_parse_approved_projects_empty_forms(raw):
    assert parse_approved_projects(raw) == frozenset()


def test_parse_approved_projects_strips_and_splits():
    assert parse_approved_projects(" a , b ,,c ") == frozenset({"a", "b", "c"})


# --- kms_key_project --------------------------------------------------------


def test_kms_key_project_extracts_the_capture_group():
    """The capture-group trap: regex.find_n returns 'projects/x/', never 'x'."""
    assert kms_key_project(key("my-kms-project")) == "my-kms-project"


@pytest.mark.parametrize("bad", [None, "", "garbage", "projects/only"])
def test_kms_key_project_returns_none_for_unparseable(bad):
    assert kms_key_project(bad) is None


# --- parse_agent_name -------------------------------------------------------


def test_parse_agent_name_roundtrip():
    parsed = parse_agent_name("projects/p/locations/us-east4/dataAgents/a1")
    assert (parsed.project, parsed.location, parsed.agent_id) == ("p", "us-east4", "a1")
    assert parsed.resource_name == "projects/p/locations/us-east4/dataAgents/a1"
    assert parsed.parent == "projects/p/locations/us-east4"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "projects/p/locations/l",  # parent, not an agent
        "projects/p/locations/l/dataAgents/a/extra",
        "//geminidataanalytics.googleapis.com/projects/p/locations/l/dataAgents/a",
    ],
)
def test_parse_agent_name_rejects_non_agent_names(bad):
    assert parse_agent_name(bad) is None
