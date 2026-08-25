#!/usr/bin/env bash
# Layer 1 gate: the CI/CD shift-left policy and the policy-gated deploy step.
#
# Sections 1-3 are fully offline (no GCP project, no credentials). Section 4
# needs a project and is skipped automatically if the API is unreachable, so
# this script is safe to run in CI.
#
# Also evaluates the two hazardous Rego forms directly, so the guards against
# them stay demonstrable rather than merely asserted.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

# Versions this layer is validated against. Pinned deliberately: the policy is
# Rego v1 (needs OPA >= 1.0), and .regal/ carries a custom rule written against
# Regal's 0.42 rule API. `latest` may not behave identically.
OPA_VERSION="1.19.1"
REGAL_VERSION="0.42.0"

OPA="${OPA:-$(command -v opa || true)}"
if [[ -z "${OPA}" ]]; then
  cat <<EOF
opa not found. Install it somewhere on your PATH — no root required:

  mkdir -p ~/.local/bin
  curl -sL -o ~/.local/bin/opa \\
    https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static
  chmod +x ~/.local/bin/opa

(system-wide instead: same URL, -o /usr/local/bin/opa, with sudo)
Or point at an existing binary: OPA=/path/to/opa bash tests/run_layer1.sh
EOF
  exit 127
fi

POLICY="${REPO_ROOT}/layer1/policy.rego"
POLICY_TEST="${REPO_ROOT}/layer1/policy_test.rego"
DATA="${REPO_ROOT}/layer1/testdata"
MANIFESTS="${REPO_ROOT}/layer1/manifests"

# Prefer the environment's real allowlist; fall back to the committed example.
CONFIG="${REPO_ROOT}/layer1/config/approved-kms-projects.json"
[[ -f "${CONFIG}" ]] || CONFIG="${REPO_ROOT}/layer1/config/approved-kms-projects.example.json"

FAILED=0
check() {
  if [[ "$2" -eq 0 ]]; then printf '  [PASS] %s — %s\n' "$1" "$3"
  else printf '  [FAIL] %s — %s\n' "$1" "$3"; FAILED=1; fi
}

# ---------------------------------------------------------------------------
log "1. Policy compiles and unit-tests (OPA $("${OPA}" version | awk '/^Version/{print $2}'))"

if "${OPA}" check "${POLICY}" >/dev/null 2>&1; then
  check "policy compiles" 0 "opa check clean"
else
  check "policy compiles" 1 "$("${OPA}" check "${POLICY}" 2>&1 | head -3)"
fi

# Regal — the Rego linter. Configuration and the project's own custom rule live
# in .regal/. Skipped rather than failed when absent, so the gate still runs on
# a machine without it.
REGAL="${REGAL:-$(command -v regal || true)}"
if [[ -z "${REGAL}" ]]; then
  echo "  [SKIP] regal not installed — 3 checks below were NOT run, including the"
  echo "         regression guard for the regex.find_n trap. Install with:"
  echo "           curl -sL -o ~/.local/bin/regal \\"
  echo "             https://github.com/StyraInc/regal/releases/download/v${REGAL_VERSION}/regal_Linux_x86_64"
  echo "           chmod +x ~/.local/bin/regal"
else
  if "${REGAL}" lint "${REPO_ROOT}/layer1/" >/dev/null 2>&1; then
    check "regal lint" 0 "no violations ($("${REGAL}" version | awk '/^Version/{print $2}'))"
  else
    check "regal lint" 1 "$("${REGAL}" lint "${REPO_ROOT}/layer1/" 2>&1 | tail -3 | tr '\n' ' ')"
  fi

  REGAL_UNIT="$("${REGAL}" test "${REPO_ROOT}/.regal/rules" 2>&1 | tail -1 || true)"
  check "custom regal rule unit tests" \
    "$(grep -q '^PASS' <<<"${REGAL_UNIT}" && echo 0 || echo 1)" "${REGAL_UNIT}"

  # The custom rule exists to stop one specific regression: regex.find_n used
  # for capture-group extraction, which silently returns the wrong string.
  # Prove it still fires by linting that exact expression.
  # Must live inside the repo so .regal/ (config + custom rules) is discovered,
  # and must NOT be a dotfile — Regal skips those.
  LEGACY_DIR="${REPO_ROOT}/.regal-regression-check"
  mkdir -p "${LEGACY_DIR}"
  cat > "${LEGACY_DIR}/legacy.rego" <<'EOF'
package legacy.regression.check

import rego.v1

violation contains msg if {
	some resource in input.resource_changes
	project_match := regex.find_n(`projects/([^/]+)/`, resource.change.after.kms_key, 1)
	msg := project_match[0]
}
EOF
  # Capture first: `regal ... | grep -q` would close the pipe early, and
  # prelude.sh sets pipefail, so the whole condition would read as false.
  LEGACY_OUT="$("${REGAL}" lint "${LEGACY_DIR}" 2>&1 || true)"
  if grep -q "no-regex-find-n" <<<"${LEGACY_OUT}"; then
    check "custom rule catches the regex.find_n trap" 0 "regression guard active"
  else
    check "custom rule catches the regex.find_n trap" 1 "rule did NOT fire"
  fi
  rm -rf "${LEGACY_DIR}"
fi

# Explicit .rego paths: `opa test layer1/` would also load testdata/*.json as
# data documents and fail with a merge error.
UNIT="$("${OPA}" test "${POLICY}" "${POLICY_TEST}" 2>&1 | tail -1 || true)"
check "policy unit tests" "$(grep -q '^PASS' <<<"${UNIT}" && echo 0 || echo 1)" "${UNIT}"

# ---------------------------------------------------------------------------
# These fixtures are written against the policy's BUILT-IN default allowlist, so
# they stay meaningful with no environment config present. The environment's own
# allowlist is exercised in section 4 against the real manifests.
log "2. Offline fixtures (built-in default allowlist)"

ALLOW="$("${OPA}" eval -d "${POLICY}" -i "${DATA}/compliant.json" 'data.gda.cmek.allow' --format=raw 2>/dev/null || true)"
check "compliant fixture allowed" "$([[ "${ALLOW}" == "true" ]] && echo 0 || echo 1)" "allow=${ALLOW}"

DENY_JSON="$("${OPA}" eval -d "${POLICY}" -i "${DATA}/violations.json" 'data.gda.cmek.deny' --format=json 2>/dev/null || true)"
DENY_COUNT="$(python -c "
import json,sys
try:
    print(len(json.load(sys.stdin)['result'][0]['expressions'][0]['value']))
except Exception:
    print(0)
" <<<"${DENY_JSON}")"
check "all 5 violation classes denied" "$([[ "${DENY_COUNT}" == "5" ]] && echo 0 || echo 1)" "${DENY_COUNT} denials"

for EXPECTED in "Missing CMEK" "Unauthorized KMS Project" "Unsupported Location" \
                "Key Location Mismatch" "Malformed Key"; do
  if grep -q "${EXPECTED}" <<<"${DENY_JSON}"; then
    printf '    - %s\n' "${EXPECTED}"
  else
    check "violation class '${EXPECTED}'" 1 "not reported"
  fi
done

# The allowlist must come from data, not from the policy file.
OVERRIDE="$(mktemp --suffix=.json)"
printf '{"config":{"approved_kms_projects":["some-other-project"]}}' > "${OVERRIDE}"
OVERRIDDEN="$("${OPA}" eval -d "${POLICY}" -d "${OVERRIDE}" -i "${DATA}/compliant.json" \
  'data.gda.cmek.allow' --format=raw 2>/dev/null || true)"
rm -f "${OVERRIDE}"
check "allowlist is data-driven, not hardcoded" \
  "$([[ "${OVERRIDDEN}" == "false" ]] && echo 0 || echo 1)" \
  "same fixture with a different allowlist -> allow=${OVERRIDDEN}"

# ---------------------------------------------------------------------------
log "3. The two Rego hazards, evaluated directly"

ORIG="$(mktemp --suffix=.rego)"
trap 'rm -f "${ORIG}"' EXIT
cat > "${ORIG}" <<'EOF'
package terraform.cmek_validation
default allow = false
gda_resource_types := {"google_gemini_data_agent", "google_gemini_data_analytics_data_agent"}
approved_kms_projects := ["example-kms-prod", "example-kms-shared"]
allow { count(violation) == 0 }
violation[msg] {
    resource := input.resource_changes[_]
    gda_resource_types[resource.type]
    not resource.change.after.kms_key
    msg := sprintf("REJECTED [Missing CMEK]: %v '%v' must specify a valid 'kms_key'.", [resource.type, resource.address])
}
violation[msg] {
    resource := input.resource_changes[_]
    gda_resource_types[resource.type]
    kms_key := resource.change.after.kms_key
    project_match := regex.find_n(`projects/([^/]+)/`, kms_key, 1)
    kms_proj := project_match[0]
    not approved_kms_projects[_] == kms_proj
    msg := sprintf("REJECTED [Unauthorized KMS Project]: %v uses unapproved KMS project '%v'.", [resource.address, kms_proj])
}
EOF
if "${OPA}" check --v0-compatible "${ORIG}" >/dev/null 2>&1; then
  check "wildcard inside a negation fails to compile" 1 "it compiled — re-check this finding"
else
  # `|| true`: prelude.sh sets -euo pipefail, and a non-matching grep would
  # otherwise abort the script mid-assertion.
  ERR="$("${OPA}" check --v0-compatible "${ORIG}" 2>&1 | grep -o 'rego_unsafe_var_error.*' | head -1 || true)"
  check "wildcard inside a negation fails to compile" 0 "${ERR:-unsafe var error}"
fi

SUBMATCH="$("${OPA}" eval 'regex.find_n(`projects/([^/]+)/`, "projects/example-kms-prod/locations/us-east4/keyRings/kr/cryptoKeys/k", 1)' --format=raw 2>/dev/null | tr -d '[]" ' || true)"
check "regex.find_n returns the whole match, not the capture group" \
  "$([[ "${SUBMATCH}" == "projects/example-kms-prod/" ]] && echo 0 || echo 1)" \
  "returned '${SUBMATCH}' — never equals an allowlist entry"

# ---------------------------------------------------------------------------
# Concrete manifests are gitignored (they carry real project IDs); render them
# from the committed *.example.json templates if they are not present yet.
if [[ ! -f "${MANIFESTS}/agents.json" ]]; then
  bash "${REPO_ROOT}/layer1/render.sh" >/dev/null
  CONFIG="${REPO_ROOT}/layer1/config/approved-kms-projects.json"
fi

log "4. Real manifests against this environment's allowlist ($(basename "${CONFIG}"))"

# Mirrors exactly what the CI job in .github/workflows/cmek-policy.yml runs.
M_ALLOW="$("${OPA}" eval -d "${POLICY}" -d "${CONFIG}" -i "${MANIFESTS}/agents.json" \
  'data.gda.cmek.allow' --format=raw 2>/dev/null || true)"
check "agents.json is allowed" "$([[ "${M_ALLOW}" == "true" ]] && echo 0 || echo 1)" "allow=${M_ALLOW}"

M_BAD="$("${OPA}" eval -d "${POLICY}" -d "${CONFIG}" -i "${MANIFESTS}/agents-violating.json" \
  'data.gda.cmek.allow' --format=raw 2>/dev/null || true)"
check "agents-violating.json is rejected" "$([[ "${M_BAD}" == "false" ]] && echo 0 || echo 1)" "allow=${M_BAD}"

log "5. Policy-gated deploy step (layer1/apply_manifest.py)"

if ! python -c "
import sys
sys.path.insert(0, '${REPO_ROOT}')
from google.cloud import geminidataanalytics  # noqa: F401
" 2>/dev/null; then
  echo "  [SKIP] google-cloud-geminidataanalytics not installed"
else
  # The in-process gate must reject before any API call is made.
  if python -m layer1.apply_manifest --manifest "${MANIFESTS}/agents-violating.json" >/dev/null 2>&1; then
    check "in-process gate rejects a violating manifest" 1 "exit 0 — violations were applied"
  else
    check "in-process gate rejects a violating manifest" 0 "non-zero exit, no API call attempted"
  fi

  if python -m layer1.apply_manifest --manifest "${MANIFESTS}/agents.json" --dry-run >/dev/null 2>&1; then
    check "compliant manifest passes the in-process gate" 0 "dry-run exit 0"
  else
    check "compliant manifest passes the in-process gate" 1 "dry-run failed"
  fi
fi

log "Layer 1 verdict: $([[ $FAILED -eq 0 ]] && echo PASS || echo FAIL)"
exit "${FAILED}"
