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
supported_locations := {"us-east4", "us", "eu"}

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
# description: The key must be co-located with the agent, or creation fails at the API.
deny contains msg if {
	some agent in input.agents
	agent.kms_key

	key_loc := kms_key_location(agent.kms_key)
	key_loc != agent.location

	msg := sprintf(
		"REJECTED [Key Location Mismatch]: agent '%v' is in '%v' but its key is in '%v'.",
		[agent.id, agent.location, key_loc],
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
#   There is also nothing to provision. Verified against the live API: CMEK for
#   conversations is a project+location SINGLETON — supplying any key other than
#   the registered one is rejected, including a different key in the same
#   project ("Only 1 KMS keys per project per location are allowed"). So a
#   manifest could not choose a conversation's key even if it wanted to; the key
#   is a property of the project, attested once by Layer 5, not a property of
#   each conversation.
#
#   A manifest that declares conversations therefore reflects a
#   misunderstanding of the model, and silently ignoring the block would let a
#   pipeline believe it had pinned something it had not.
deny contains msg if {
	some i, conv in input.conversations

	msg := sprintf(
		concat("", [
			"REJECTED [Conversations Not Provisionable]: entry %v ('%v') — ",
			"conversations are ephemeral runtime resources and must not be ",
			"declared in a manifest. CMEK for conversations is a ",
			"project+location singleton; attest it with Layer 5 instead.",
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
deny contains msg if {
	not input.agents

	msg := "REJECTED [Malformed Manifest]: input has no 'agents' array."
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

kms_key_project(key) := proj if {
	parts := regex.find_all_string_submatch_n(`^projects/([^/]+)/`, key, 1)
	proj := parts[0][1]
}

kms_key_location(key) := loc if {
	parts := regex.find_all_string_submatch_n(`^projects/[^/]+/locations/([^/]+)/`, key, 1)
	loc := parts[0][1]
}
