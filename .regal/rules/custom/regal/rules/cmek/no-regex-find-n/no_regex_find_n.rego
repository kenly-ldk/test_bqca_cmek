# METADATA
# description: |
#   Forbid regex.find_n when extracting a value from a resource path.
#
#   This is a project-specific regression guard, not a general Rego style rule.
#   The tempting form is:
#
#     project_match := regex.find_n(`projects/([^/]+)/`, kms_key, 1)
#     kms_proj := project_match[0]
#
#   expecting "example-kms-prod". regex.find_n returns WHOLE MATCHES, not capture
#   groups, so it actually yields "projects/example-kms-prod/" — a string that can
#   never equal an allowlist entry. Every agent, including compliant ones, is
#   rejected. The bug is invisible on inspection and the parenthesised
#   group makes it look correct.
#
#   Use regex.find_all_string_submatch_n and index the capture group:
#
#     parts := regex.find_all_string_submatch_n(`^projects/([^/]+)/`, key, 1)
#     proj := parts[0][1]
# schemas:
# - input: schema.regal.ast
package custom.regal.rules.cmek["no-regex-find-n"]

import data.regal.ast
import data.regal.result

report contains violation if {
	some calls in ast.function_calls
	some call in calls

	call.name == "regex.find_n"

	violation := result.fail(rego.metadata.chain(), result.location(call))
}
