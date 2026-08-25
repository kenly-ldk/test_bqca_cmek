package custom.regal.rules.cmek["no-regex-find-n_test"]

import data.custom.regal.rules.cmek["no-regex-find-n"] as rule

# Fixture modules are raw strings, so the sample policies use double-quoted
# regex patterns rather than backtick-quoted ones. Equivalent for this rule,
# which matches on the builtin name, not the pattern literal.

# The exact expression this rule exists to catch.
test_flags_regex_find_n if {
	module := regal.parse_module("policy.rego", `package p

deny contains msg if {
	project_match := regex.find_n("projects/([^/]+)/", input.kms_key, 1)
	msg := project_match[0]
}`)

	r := rule.report with input as module

	count(r) == 1

	some violation in r
	violation.title == "no-regex-find-n"
	violation.category == "cmek"
}

# The correct builtin must not be flagged, or the rule is useless noise.
test_allows_find_all_string_submatch_n if {
	module := regal.parse_module("policy.rego", `package p

kms_key_project(key) := proj if {
	parts := regex.find_all_string_submatch_n("^projects/([^/]+)/", key, 1)
	proj := parts[0][1]
}`)

	r := rule.report with input as module

	count(r) == 0
}

# Other regex builtins are fine — the rule is narrowly about capture-group
# extraction, not regex use in general.
test_allows_regex_match if {
	module := regal.parse_module("policy.rego", `package p

deny if {
	not regex.match("^projects/", input.kms_key)
}`)

	r := rule.report with input as module

	count(r) == 0
}

test_flags_every_occurrence if {
	module := regal.parse_module("policy.rego", `package p

a := regex.find_n("x", "y", 1)

b := regex.find_n("x", "z", 1)`)

	r := rule.report with input as module

	count(r) == 2
}
