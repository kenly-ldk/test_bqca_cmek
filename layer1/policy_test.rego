# Unit tests for the Layer 1 CMEK manifest policy.
#
#   opa test layer1/ -v
#
# These are pure unit tests: no GCP project, no network, no fixtures on disk.
# tests/run_layer1.sh runs them alongside the end-to-end fixture checks.
#
# Every rule gets a positive case (it fires when it should) AND a negative case
# (it stays silent when it should). A deny rule that never fires is the failure
# mode that matters here — it reports false compliance — so the negative cases
# are the important half.

package gda.cmek_test

import rego.v1

import data.gda.cmek

good_key := "projects/example-kms-prod/locations/us-east4/keyRings/kr/cryptoKeys/k"

compliant_agent := {
	"id": "ok-agent",
	"location": "us-east4",
	"kms_key": good_key,
}

# --- allow ------------------------------------------------------------------

test_allow_when_all_agents_compliant if {
	cmek.allow with input as {"agents": [compliant_agent]}
}

test_allow_for_multi_region_us if {
	cmek.allow with input as {"agents": [{
		"id": "us-agent",
		"location": "us",
		"kms_key": "projects/example-kms-shared/locations/us/keyRings/kr/cryptoKeys/k",
	}]}
}

test_allow_for_empty_manifest if {
	cmek.allow with input as {"agents": []}
}

test_not_allow_when_any_agent_violates if {
	not cmek.allow with input as {"agents": [
		compliant_agent,
		{"id": "bad", "location": "us-east4"},
	]}
}

# --- rule 1: missing CMEK ---------------------------------------------------

test_deny_missing_kms_key if {
	count(cmek.deny) == 1 with input as {"agents": [{"id": "no-key", "location": "us-east4"}]}
}

test_no_deny_when_key_present if {
	count(cmek.deny) == 0 with input as {"agents": [compliant_agent]}
}

# --- rule 2: unapproved KMS project -----------------------------------------

test_deny_unapproved_kms_project if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "rogue",
		"location": "us-east4",
		"kms_key": "projects/attacker-proj/locations/us-east4/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Unauthorized KMS Project")
}

# Regression test for the capture-group trap: regex.find_n returns the whole
# match ("projects/example-kms-prod/"), which never equals an allowlist entry, so
# a rule built that way rejects compliant agents. This asserts the capture group
# is extracted correctly.
test_approved_project_is_not_flagged if {
	every msg in cmek.deny {
		not contains(msg, "Unauthorized KMS Project")
	} with input as {"agents": [compliant_agent]}
}

test_kms_key_project_extracts_capture_group if {
	cmek.kms_key_project(good_key) == "example-kms-prod"
}

# --- rule 3: unsupported location -------------------------------------------

test_deny_global_location if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "global-agent",
		"location": "global",
		"kms_key": "projects/example-kms-prod/locations/global/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Unsupported Location")
}

test_deny_arbitrary_unsupported_region if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "syd-agent",
		"location": "australia-southeast1",
		"kms_key": "projects/example-kms-prod/locations/australia-southeast1/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Unsupported Location")
}

test_supported_locations_not_flagged if {
	every msg in cmek.deny {
		not contains(msg, "Unsupported Location")
	} with input as {"agents": [
		{"id": "a", "location": "us-east4", "kms_key": good_key},
		{"id": "b", "location": "us", "kms_key": "projects/example-kms-prod/locations/us/keyRings/kr/cryptoKeys/k"},
		{"id": "c", "location": "eu", "kms_key": "projects/example-kms-prod/locations/eu/keyRings/kr/cryptoKeys/k"},
	]}
}

# --- rule 4: key/agent location mismatch ------------------------------------

test_deny_key_location_mismatch if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "mismatch",
		"location": "us-east4",
		"kms_key": "projects/example-kms-prod/locations/eu/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Key Location Mismatch")
}

test_no_mismatch_when_colocated if {
	every msg in cmek.deny {
		not contains(msg, "Key Location Mismatch")
	} with input as {"agents": [compliant_agent]}
}

# --- rule 5: malformed key path ---------------------------------------------

test_deny_malformed_key if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "malformed",
		"location": "us-east4",
		"kms_key": "just-a-key-name",
	}]}
	contains(msg, "Malformed Key")
}

# A truncated path must not slip through rules 2 and 4 by parsing partially.
test_deny_truncated_key_path if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "truncated",
		"location": "us-east4",
		"kms_key": "projects/example-kms-prod/locations/us-east4/keyRings/kr",
	}]}
	contains(msg, "Malformed Key")
}

test_no_malformed_for_valid_path if {
	every msg in cmek.deny {
		not contains(msg, "Malformed Key")
	} with input as {"agents": [compliant_agent]}
}

# --- multiple violations on one agent ---------------------------------------

test_all_applicable_rules_report if {
	msgs := cmek.deny with input as {"agents": [{
		"id": "global-rogue",
		"location": "global",
		"kms_key": "projects/attacker-proj/locations/eu/keyRings/kr/cryptoKeys/k",
	}]}

	# unapproved project + unsupported location + location mismatch
	count(msgs) == 3
}

# --- malformed manifest -----------------------------------------------------
#
# These cover the gate-bypass class: input the policy cannot read must be
# denied, not silently allowed. Without these rules an agent with no `location`
# passes every check, because the location rules and their sprintf messages both
# go undefined and emit nothing.

test_deny_agent_without_location if {
	count(cmek.deny) > 0 with input as {"agents": [{"id": "a", "kms_key": good_key}]}
}

test_not_allow_agent_without_location if {
	not cmek.allow with input as {"agents": [{"id": "a", "kms_key": good_key}]}
}

test_deny_agent_without_id if {
	count(cmek.deny) > 0 with input as {"agents": [{"location": "us-east4", "kms_key": good_key}]}
}

test_deny_manifest_without_agents_key if {
	count(cmek.deny) > 0 with input as {}
}

test_deny_manifest_with_misspelled_agents_key if {
	count(cmek.deny) > 0 with input as {"dataAgents": [compliant_agent]}
}

test_deny_agents_not_an_array if {
	count(cmek.deny) > 0 with input as {"agents": "not-an-array"}
}

# The empty manifest stays allowed: nothing to deploy is not a violation. Kept
# adjacent to the rules above so the distinction is deliberate, not accidental.
test_allow_empty_agents_array_still if {
	cmek.allow with input as {"agents": []}
}

# --- conversations are never provisionable ----------------------------------
#
# Conversations are ephemeral runtime resources, and their CMEK key is a
# project+location singleton rather than a per-resource field, so a manifest
# can neither meaningfully declare one nor choose its key.

test_deny_top_level_conversations if {
	count(cmek.deny) > 0 with input as {
		"agents": [compliant_agent],
		"conversations": [{"id": "conv-1", "kms_key": good_key}],
	}
}

test_not_allow_manifest_declaring_conversations if {
	not cmek.allow with input as {
		"agents": [compliant_agent],
		"conversations": [{"id": "conv-1"}],
	}
}

test_deny_conversations_nested_under_an_agent if {
	agent := object.union(compliant_agent, {"conversations": [{"id": "c1"}]})
	not cmek.allow with input as {"agents": [agent]}
}

test_conversation_denial_names_the_entry if {
	msgs := cmek.deny with input as {
		"agents": [compliant_agent],
		"conversations": [{"id": "chatty"}],
	}
	some m in msgs
	contains(m, "Conversations Not Provisionable")
	contains(m, "chatty")
}

# An empty conversations key is not a declaration, so it must not trip the rule.
test_allow_empty_conversations_list if {
	cmek.allow with input as {"agents": [compliant_agent], "conversations": []}
}
