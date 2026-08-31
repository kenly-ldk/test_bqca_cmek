# METADATA
# title: CMEK validation for Gemini Data Analytics agent manifests
# description: |
#   Layer 1 shift-left gate. Runs in CI against the agent definition files that
#   a deploy step feeds to the Conversational Analytics API.
#
#   It is NOT a `terraform plan` policy: as of hashicorp/google and
#   google-beta v7.45.0 there is no `google_gemini_data_agent` resource
#   (verified with `terraform providers schema -json`), so DataAgents cannot be
#   expressed in Terraform. Nor is it an OPA Gatekeeper ConstraintTemplate:
#   Config Connector has no DataAgent CRD, so there is nothing to admit. The
#   gate therefore has to sit on the manifests.
#
#   Written in Rego v1 (`if` / `contains`), so it runs on OPA >= 1.0 unmodified,
#   and is linted with Regal.
#
#   Input shape (see testdata/):
#     {"agents": [{"id": "...", "location": "us-east4",
#                  "kms_key": "projects/.../cryptoKeys/..."}]}
#
#   Usage:
#     opa eval -d policy.rego -i manifest.json 'data.gda.cmek.deny' --format=pretty
#     opa eval -d policy.rego -i manifest.json 'data.gda.cmek.allow' --format=raw
# authors:
#   - Google Cloud Customer Engineering & Architecture
# related_resources:
#   - https://docs.cloud.google.com/gemini/data-agents/conversational-analytics-api/cmek
package gda.cmek

import rego.v1

# Mirrors constraints/gcp.restrictCmekCryptoKeyProjects. A set, not an array, so
# membership is a direct lookup and safe to negate.
#
# Supplied as data so the same policy file serves every environment:
#
#   opa eval -d policy.rego -d config/approved-kms-projects.json -i manifest.json ...
#
# where the data file is {"config": {"approved_kms_projects": ["proj-a", ...]}}.
# Falls back to the placeholder set below when no data is supplied, so the
# policy still loads and self-tests standalone. The fallback is deliberately a
# non-existent project: an environment that forgets to pass its config fails
# closed (everything denied) rather than silently allowing.
default_approved_kms_projects := {
	"example-kms-prod",
	"example-kms-shared",
}

approved_kms_projects := projects if {
	count(data.config.approved_kms_projects) > 0
	projects := {p | some p in data.config.approved_kms_projects}
} else := default_approved_kms_projects

# Locations where the API can actually attach a CMEK key. `global` cannot, so an
# agent placed there is unencryptable by construction, key or no key.
# Derived from required_key_location, never written out separately: a location
# is supported precisely when we know which KMS location its key belongs in,
# and two hand-maintained lists would eventually disagree.
supported_locations := object.keys(required_key_location)

# METADATA
# title: required_key_location
# description: |
#   The Cloud KMS location a DataAgent's key must live in, per agent location.
#   Same string as the agent location everywhere except `eu`: Cloud KMS has no
#   `eu` location at all, only `europe`, so the "co-located" rule is
#   unsatisfiable as literally stated and `europe` is what the API accepts
#   (validation-report F6). Keyed on the agent location, so an agent in an
#   unsupported location matches nothing here and is caught by the unsupported
#   location rule instead.
required_key_location := {"us-east4": "us-east4", "us": "us", "eu": "europe"}

# METADATA
# title: required_conversation_key_location
# description: |
#   The Cloud KMS location a CONVERSATION's key must live in, per conversation
#   location. Deliberately a second map rather than a reuse of
#   required_key_location: a conversation takes a key in its multi-region's
#   PAIRED primary region, which is a different location from the one the same
#   multi-region's agents use, and the API rejects the other every time
#   (validation-report F8).
#
#   `us-east4` and `global` are absent because neither can host a conversation.
#   Gating this in CI matters more than the agent equivalent: the first key
#   OFFERED to CreateConversation is registered permanently for the whole
#   project+location even when the call fails, so a wrong key here cannot be
#   corrected afterwards.
required_conversation_key_location := {"us": "us-central1", "eu": "europe-west1"}

conversation_locations := object.keys(required_conversation_key_location)

# METADATA
# title: allow
# description: True only when no rule in `deny` fires. This is the CI entrypoint.
# entrypoint: true
default allow := false

allow if count(deny) == 0

# METADATA
# title: Missing CMEK
# description: Equivalent to constraints/gcp.restrictNonCmekServices.
deny contains msg if {
	some agent in input.agents
	not agent.kms_key

	msg := sprintf("REJECTED [Missing CMEK]: agent '%v' must specify 'kms_key'.", [agent.id])
}

# METADATA
# title: Unauthorized KMS project
# description: |
#   Equivalent to constraints/gcp.restrictCmekCryptoKeyProjects.
#
#   Uses find_all_string_submatch_n to get the CAPTURE GROUP. regex.find_n
#   returns whole matches: for a key path it yields "projects/example-kms-prod/",
#   never "example-kms-prod", so a comparison against the allowlist can never
#   match. See .regal/rules/custom/ for the lint rule that blocks the wrong form.
deny contains msg if {
	some agent in input.agents
	agent.kms_key

	kms_proj := kms_key_project(agent.kms_key)
	not approved_kms_projects[kms_proj]

	msg := sprintf(
		"REJECTED [Unauthorized KMS Project]: agent '%v' uses KMS project '%v'. Allowed: %v",
		[agent.id, kms_proj, approved_kms_projects],
	)
}

# METADATA
# title: Unsupported location
# description: |
#   No native equivalent, but required: CMEK is unavailable outside these
#   locations, so an agent elsewhere can never satisfy the control.
deny contains msg if {
	some agent in input.agents
	not supported_locations[agent.location]

	msg := sprintf(
		"REJECTED [Unsupported Location]: agent '%v' is in '%v'; CMEK requires one of %v.",
		[agent.id, agent.location, supported_locations],
	)
}

# METADATA
# title: Key location mismatch
# description: |
#   The key must sit in the KMS location the API demands for the agent's
#   location, or creation fails at the API.
#
#   That is NOT always the same string as the agent's location, which is why
#   this compares against a map rather than testing equality. Cloud KMS has no
#   `eu` location — its EU multi-region is `europe` — so an `eu` agent takes a
#   `europe` key, verified accepted against the live API (validation-report F6).
#   A plain equality test denies every deployable `eu` agent, because the key it
#   demands cannot exist.
#
#   Conversations follow a different rule again (paired region: `us-central1`,
#   `europe-west1`) and are not covered here — they are rejected outright by the
#   conversations rule below.
deny contains msg if {
	some agent in input.agents
	agent.kms_key
	required := required_key_location[agent.location]

	key_loc := kms_key_location(agent.kms_key)
	key_loc != required

	msg := sprintf(
		"REJECTED [Key Location Mismatch]: agent '%v' is in '%v', so its key must be in '%v', but it is in '%v'.",
		[agent.id, agent.location, required, key_loc],
	)
}

# METADATA
# title: Malformed key path
# description: A malformed key path would silently defeat the two rules above.
deny contains msg if {
	some agent in input.agents
	agent.kms_key
	not regex.match(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`, agent.kms_key)

	msg := sprintf(
		"REJECTED [Malformed Key]: agent '%v' kms_key '%v' is not a valid cryptoKey path.",
		[agent.id, agent.kms_key],
	)
}

# METADATA
# title: Conversations must never be provisioned
# description: |
#   Conversations are ephemeral runtime resources, created by the application
#   per user session and discarded. They have no place in a CI/CD manifest, and
#   this rule makes that structural rather than conventional.
#
#   A conversation CAN carry a CMEK key — that is measured, and it is a real
#   boundary (validation-report F8, re-measured 2026-08-30). But the key is
#   chosen by whoever calls CreateConversation at runtime, not by a pipeline:
#   CMEK is opt-in per conversation, and an unkeyed conversation does not
#   inherit the key registered for its project+location. A manifest cannot
#   reach that decision, so declaring a conversation here would pin nothing
#   while looking like it had.
#
#   Two further reasons this must deny rather than warn. The key location
#   differs from the agent rule — a conversation in `us` needs a key in
#   `us-central1`, an agent in `us` needs one in `us` — so rule 4 below would
#   judge a conversation entry by the wrong standard. And offering a key to
#   CreateConversation is a permanent, unprivileged write: the first key
#   submitted is registered for the whole project+location even if the create
#   fails, and the slot can never be reassigned. A pipeline that retries a
#   conversation manifest could burn that slot on a mistake, once, forever.
#
#   Layer 5 covers this surface instead, by reporting every conversation's key.
deny contains msg if {
	some i, conv in input.conversations

	msg := sprintf(
		concat("", [
			"REJECTED [Conversations Not Provisionable]: entry %v ('%v') — ",
			"conversations are ephemeral runtime resources and must not be ",
			"declared in a manifest. Their CMEK key is chosen per conversation ",
			"at runtime, not by a pipeline; Layer 5 reports that posture instead.",
		]),
		[i, object.get(conv, "id", "<no id>")],
	)
}

deny contains msg if {
	some i, agent in input.agents
	some j, conv in agent.conversations

	msg := sprintf(
		concat("", [
			"REJECTED [Conversations Not Provisionable]: agent %v ('%v') ",
			"declares conversation %v — conversations are ephemeral and must ",
			"not be declared in a manifest.",
		]),
		[i, object.get(agent, "id", "<no id>"), j],
	)
}

# METADATA
# title: Malformed manifest
# description: |
#   A gate must be able to tell "compliant" from "I could not read this".
#
#   Every location rule keys off `agent.location`, and every message renders it
#   with sprintf. When the field is absent BOTH the lookup and the sprintf go
#   undefined, the rule body fails, and no denial is emitted — so an entry with
#   no `location` silently PASSED the gate, including past the unsupported-
#   location check. Verified: {"agents":[{"id":"a","kms_key":<valid>}]} returned
#   allow=true. The same holds for a manifest whose top-level `agents` key is
#   missing or misspelled: nothing to iterate means nothing to deny.
#
#   Requiring the fields explicitly closes that, and keeps the failure mode
#   consistent with Layer 4 and Layer 5 — unreadable is not compliant.
#   A manifest that declares only `conversation_keys` is legitimate -- an estate
#   may govern its conversation surface from a file of its own -- so the check is
#   "declares at least one of the two", not "declares agents". A manifest with
#   neither is still a typo, and still fails closed.
deny contains msg if {
	not input.agents
	not input.conversation_keys

	msg := sprintf(
		concat("", [
			"REJECTED [Malformed Manifest]: input declares neither an 'agents' ",
			"array nor a 'conversation_keys' array; nothing would be checked.",
		]),
		[],
	)
}

deny contains msg if {
	input.agents
	not is_array(input.agents)

	msg := "REJECTED [Malformed Manifest]: 'agents' must be an array."
}

deny contains msg if {
	some i, agent in input.agents
	not agent.id

	msg := sprintf("REJECTED [Malformed Manifest]: agent at index %v has no 'id'.", [i])
}

deny contains msg if {
	some i, agent in input.agents
	not agent.location

	msg := sprintf(
		"REJECTED [Malformed Manifest]: agent at index %v ('%v') has no 'location'.",
		[i, object.get(agent, "id", "<no id>")],
	)
}

# METADATA
# title: Conversation key missing
# description: |
#   A declared conversation location must name the key its conversations are to
#   be created with. CMEK is opt-in per conversation, so a location with no key
#   declared is a location whose conversations rest under Google-managed
#   encryption.
deny contains msg if {
	some entry in input.conversation_keys
	not entry.kms_key

	msg := sprintf(
		"REJECTED [Conversation Missing CMEK]: location '%v' declares no 'kms_key'.",
		[object.get(entry, "location", "<no location>")],
	)
}

# METADATA
# title: Conversation unsupported location
# description: |
#   Only `us` and `eu` host conversations. `us-east4` cannot create one at all
#   and `global` supports no CMEK, so a key declared for either is unusable.
deny contains msg if {
	some entry in input.conversation_keys
	entry.location
	not conversation_locations[entry.location]

	msg := sprintf(
		"REJECTED [Conversation Unsupported Location]: '%v' cannot host a CMEK conversation; supported: %v.",
		[entry.location, conversation_locations],
	)
}

# METADATA
# title: Conversation unauthorized KMS project
# description: Equivalent to constraints/gcp.restrictCmekCryptoKeyProjects.
deny contains msg if {
	some entry in input.conversation_keys
	entry.kms_key

	kms_proj := kms_key_project(entry.kms_key)
	not approved_kms_projects[kms_proj]

	msg := sprintf(
		"REJECTED [Conversation Unauthorized KMS Project]: location '%v' uses KMS project '%v'. Allowed: %v",
		[object.get(entry, "location", "<no location>"), kms_proj, approved_kms_projects],
	)
}

# METADATA
# title: Conversation key location mismatch
# description: |
#   The rule this gate exists for. The documented configuration -- a key in the
#   conversation's own location -- is rejected by the API in every supported
#   location; the key belongs in the multi-region's paired primary region. A
#   pipeline that follows the documentation therefore fails at CreateConversation
#   AFTER burning the project's one permanent key registration, so this has to be
#   caught before the call is made.
deny contains msg if {
	some entry in input.conversation_keys
	entry.kms_key
	required := required_conversation_key_location[entry.location]

	key_loc := kms_key_location(entry.kms_key)
	key_loc != required

	msg := sprintf(
		concat("", [
			"REJECTED [Conversation Key Location Mismatch]: conversations in ",
			"'%v' need a key in '%v' (the paired region), but the key is in '%v'.",
		]),
		[entry.location, required, key_loc],
	)
}

# METADATA
# title: Conversation malformed key path
# description: A malformed path would silently defeat the two rules above.
deny contains msg if {
	some entry in input.conversation_keys
	entry.kms_key
	not regex.match(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`, entry.kms_key)

	msg := sprintf(
		"REJECTED [Conversation Malformed Key]: location '%v' kms_key '%v' is not a valid cryptoKey path.",
		[object.get(entry, "location", "<no location>"), entry.kms_key],
	)
}

# METADATA
# title: Conversation key entry without a location
# description: A key with no location cannot be checked against the paired-region rule.
deny contains msg if {
	some i, entry in input.conversation_keys
	not entry.location

	msg := sprintf(
		"REJECTED [Malformed Manifest]: conversation_keys entry %v has no 'location'.",
		[i],
	)
}

kms_key_project(key) := proj if {
	parts := regex.find_all_string_submatch_n(`^projects/([^/]+)/`, key, 1)
	proj := parts[0][1]
}

kms_key_location(key) := loc if {
	parts := regex.find_all_string_submatch_n(`^projects/[^/]+/locations/([^/]+)/`, key, 1)
	loc := parts[0][1]
}
