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

# Each agent here uses the key location the API actually demands for it, so a
# deployable agent in any supported location must clear the WHOLE policy — not
# merely the location rule. An earlier version asserted only "Unsupported
# Location" and gave the `eu` agent a key at locations/eu; that key cannot exist
# in Cloud KMS, and asserting the narrower thing hid the fact that rule 4 denied
# every real `eu` agent. See validation-report F6.
test_supported_locations_not_flagged if {
	cmek.allow with input as {"agents": [
		{"id": "a", "location": "us-east4", "kms_key": good_key},
		{"id": "b", "location": "us", "kms_key": "projects/example-kms-prod/locations/us/keyRings/kr/cryptoKeys/k"},
		{"id": "c", "location": "eu", "kms_key": "projects/example-kms-prod/locations/europe/keyRings/kr/cryptoKeys/k"},
	]}
}

# --- rule 4: key/agent location mismatch ------------------------------------

test_deny_key_location_mismatch if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "mismatch",
		"location": "us-east4",
		"kms_key": "projects/example-kms-prod/locations/europe/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Key Location Mismatch")
}

test_no_mismatch_when_colocated if {
	every msg in cmek.deny {
		not contains(msg, "Key Location Mismatch")
	} with input as {"agents": [compliant_agent]}
}

# Cloud KMS has no `eu` location — its EU multi-region is `europe` — so an `eu`
# agent takes a `europe` key and the API accepts it. Equality between the two
# strings is therefore the wrong test, and this is the case that proves it.
test_eu_agent_with_a_europe_key_is_allowed if {
	every msg in cmek.deny {
		not contains(msg, "Key Location Mismatch")
	} with input as {"agents": [{
		"id": "eu-agent",
		"location": "eu",
		"kms_key": "projects/example-kms-prod/locations/europe/keyRings/kr/cryptoKeys/k",
	}]}
}

# The corollary: the key path that "co-located" literally asks for cannot exist,
# so it must be denied rather than waved through.
test_eu_agent_with_an_eu_key_is_denied if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "eu-agent",
		"location": "eu",
		"kms_key": "projects/example-kms-prod/locations/eu/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Key Location Mismatch")
}

# `europe` is right for an `eu` agent and wrong for every other location.
test_europe_key_rejected_for_a_us_agent if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "us-agent",
		"location": "us",
		"kms_key": "projects/example-kms-prod/locations/europe/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Key Location Mismatch")
}

# A conversation's paired-region key is not valid on an agent: an agent in `us`
# needs a key in `us`, not `us-central1` (validation-report F8).
test_conversation_paired_region_key_rejected_for_an_agent if {
	some msg in cmek.deny with input as {"agents": [{
		"id": "us-agent",
		"location": "us",
		"kms_key": "projects/example-kms-prod/locations/us-central1/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Key Location Mismatch")
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

# --- conversation keys: the surface a manifest CAN gate --------------------
#
# A conversation itself is never provisionable (above), but the KEY its
# conversations must be created with is a deployment-time decision, and it is
# the one worth gating hardest: the first key offered to CreateConversation is
# registered permanently for the whole project+location, even if that call
# fails. A wrong key here cannot be corrected afterwards.

conv_key(loc, kms_loc) := sprintf(
	"projects/example-kms-prod/locations/%v/keyRings/kr/cryptoKeys/k",
	[kms_loc],
) if {
	loc != ""
}

test_conversation_paired_region_key_allowed if {
	cmek.allow with input as {"conversation_keys": [
		{"location": "us", "kms_key": conv_key("us", "us-central1")},
		{"location": "eu", "kms_key": conv_key("eu", "europe-west1")},
	]}
}

# The documented configuration -- key in the conversation's own location -- is
# what the API rejects, so the gate must reject it first.
test_conversation_same_location_key_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"location": "us", "kms_key": conv_key("us", "us")},
	]}
	contains(msg, "Conversation Key Location Mismatch")
}

test_conversation_eu_documented_key_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"location": "eu", "kms_key": conv_key("eu", "europe")},
	]}
	contains(msg, "Conversation Key Location Mismatch")
}

# The agent rule applied to a conversation is also wrong, in both directions.
test_conversation_rejects_the_agent_key_location if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"location": "us", "kms_key": conv_key("us", "us-east4")},
	]}
	contains(msg, "Conversation Key Location Mismatch")
}

test_conversation_missing_key_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [{"location": "us"}]}
	contains(msg, "Conversation Missing CMEK")
}

test_conversation_unapproved_project_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [{
		"location": "us",
		"kms_key": "projects/attacker-proj/locations/us-central1/keyRings/kr/cryptoKeys/k",
	}]}
	contains(msg, "Conversation Unauthorized KMS Project")
}

# us-east4 cannot create a conversation at all, so a key for it is unusable.
test_conversation_in_us_east4_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"location": "us-east4", "kms_key": conv_key("us-east4", "us-east4")},
	]}
	contains(msg, "Conversation Unsupported Location")
}

test_conversation_in_global_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"location": "global", "kms_key": conv_key("global", "global")},
	]}
	contains(msg, "Conversation Unsupported Location")
}

test_conversation_malformed_key_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"location": "us", "kms_key": "just-a-key-name"},
	]}
	contains(msg, "Conversation Malformed Key")
}

test_conversation_key_without_location_is_denied if {
	some msg in cmek.deny with input as {"conversation_keys": [
		{"kms_key": conv_key("us", "us-central1")},
	]}
	contains(msg, "Malformed Manifest")
}

# A manifest with no conversation_keys at all is fine: an estate may have no
# conversation surface, and this rule set must not invent one.
test_manifest_without_conversation_keys_still_allowed if {
	cmek.allow with input as {"agents": [compliant_agent]}
}

# --- multiple violations on one agent ---------------------------------------

test_all_applicable_rules_report if {
	msgs := cmek.deny with input as {"agents": [{
		"id": "us-rogue",
		"location": "us",
		"kms_key": "projects/attacker-proj/locations/europe/keyRings/kr/cryptoKeys/k",
	}]}

	# unapproved project + location mismatch, both reported
	count(msgs) == 2
	some m1 in msgs
	contains(m1, "Unauthorized KMS Project")
	some m2 in msgs
	contains(m2, "Key Location Mismatch")
}

# An agent in an unsupported location gets ONE finding, not two. There is no
# correct KMS location for `global` — no key works there by any route (F6) — so
# "your key is in the wrong place" is noise on top of "this location can never
# be encrypted", and it would imply a fix that does not exist.
test_unsupported_location_does_not_also_report_a_mismatch if {
	msgs := cmek.deny with input as {"agents": [{
		"id": "global-agent",
		"location": "global",
		"kms_key": "projects/example-kms-prod/locations/us-east4/keyRings/kr/cryptoKeys/k",
	}]}

	count(msgs) == 1
	some m in msgs
	contains(m, "Unsupported Location")
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
# Conversations are ephemeral runtime resources whose CMEK key is chosen per
# conversation at runtime (validation-report F8), so a manifest can neither
# meaningfully declare one nor choose its key — and offering a key is a
# permanent write, so a retrying pipeline must never be able to try.

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
