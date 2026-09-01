#!/usr/bin/env bash
# Layer 3, conversation half — the CMEK boundary on a Conversation.
#
# The agent equivalent is tests/run_layer3.sh, and this asserts the same thing
# the same way: not that a `kms_key` field round-tripped, but that disabling the
# key makes the content unreadable. Three differences follow from the platform:
#
#   * the key lives in the multi-region's PAIRED region, not the conversation's
#   * the gate runs BEFORE CreateConversation, because the first key offered is
#     registered permanently even on a failed call
#   * a keyless CONTROL conversation runs alongside, because CMEK is opt-in per
#     conversation and "the messages went dark" means nothing unless an
#     unprotected one stayed readable
#
# Prerequisites: scripts/setup_conversations.sh (paired-region keys) and at least one
# DataAgent to anchor a conversation to — it may be in any location.
#
# The revocation half disables a live KMS key version for several minutes. Skip
# it with SKIP_REVOCATION=1 for a fast structural check.
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/prelude.sh"

FAILED=0
check() {  # $1=name $2=condition-result(0/1) $3=detail
  if [[ "$2" -eq 0 ]]; then printf '  [PASS] %s — %s\n' "$1" "$3"
  else printf '  [FAIL] %s — %s\n' "$1" "$3"; FAILED=1; fi
}

log "1. The pre-flight gate rejects the documented key path"
# The documented configuration -- a key in the conversation's own location -- is
# what the API refuses, and offering it would burn the project's one permanent
# key registration. The gate must stop it without an API call.
python - <<'PYEOF'
import os
import sys

sys.path.insert(0, os.environ["REPO_ROOT"])
from common.gda_common import (  # noqa: E402
    CONVERSATION_KMS_LOCATION,
    check_conversation_key,
    parse_approved_projects,
)
from config._loader import load  # noqa: E402

env = load()
project = env["PROJECT_ID"]
approved = parse_approved_projects(env.get("APPROVED_KMS_PROJECTS") or project)


def key(kms_location):
    return (f"projects/{project}/locations/{kms_location}"
            f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['CONVERSATION_KMS_KEY']}")


failures = []
for location, paired in CONVERSATION_KMS_LOCATION.items():
    # documented (same location as the conversation) -> must be blocked
    if check_conversation_key(location, key(location), approved).is_compliant:
        failures.append(f"{location}: the documented same-location key was ALLOWED")
    # paired region -> must pass
    verdict = check_conversation_key(location, key(paired), approved)
    if not verdict.is_compliant:
        failures.append(f"{location}: the paired-region key was blocked — {verdict.reason}")

# a location that cannot host a conversation at all
if check_conversation_key("us-east4", key("us-east4"), approved).is_compliant:
    failures.append("us-east4 was allowed, but it cannot host a conversation")

for failure in failures:
    print(f"  [FAIL] {failure}")
sys.exit(1 if failures else 0)
PYEOF
check "gate blocks the documented key, allows the paired region" $? \
  "checked every supported location, plus us-east4"

log "2. Create a CMEK conversation in every supported location"
bash "${REPO_ROOT}/layer3/deploy_conversation.sh"
check "CMEK conversation created per location" $? "see output above"

log "3. The key round-trips on read-back"
python - <<'PYEOF'
import os
import sys

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import geminidataanalytics

sys.path.insert(0, os.environ["REPO_ROOT"])
from common.gda_common import (  # noqa: E402
    CONVERSATION_KMS_LOCATION,
    api_endpoint,
)
from config._loader import load  # noqa: E402

env = load()
project = env["PROJECT_ID"]
problems = []
for location, paired in CONVERSATION_KMS_LOCATION.items():
    client = geminidataanalytics.DataChatServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location)))
    parent = f"projects/{project}/locations/{location}"
    try:
        keyed = [c for c in client.list_conversations(parent=parent) if c.kms_key]
    except GoogleAPICallError as exc:
        problems.append(f"{location}: list failed — {exc.message[:80]}")
        continue
    if not keyed:
        problems.append(f"{location}: no conversation carries a kms_key")
        continue
    expected = f"/locations/{paired}/"
    wrong = [c.name for c in keyed if expected not in c.kms_key]
    if wrong:
        problems.append(f"{location}: key is not in {paired} — {wrong[0]}")
    else:
        print(f"  {location}: {len(keyed)} conversation(s) keyed in {paired}")

for problem in problems:
    print(f"  [FAIL] {problem}")
sys.exit(1 if problems else 0)
PYEOF
check "conversations report a paired-region key on GET" $? "read back from the API"

if [[ -n "${SKIP_REVOCATION:-}" ]]; then
  log "4. Revocation proof SKIPPED (SKIP_REVOCATION set)"
  printf '  [INFO] the boundary itself is unproven in this run\n'
else
  log "4. The key is a real boundary, proven by revoking it"
  # Disables a live key version for several minutes, creates a keyless control
  # alongside, and requires the keyed conversation to go dark while the control
  # stays readable. Exits non-zero on any drift from that.
  python -m layer5.conversation_cmek_probe --revocation
  check "revoking the key makes conversation content unreadable" $? \
    "keyless control stayed readable throughout"
fi

if [[ "${FAILED}" -ne 0 ]]; then
  log "Layer 3 (conversations) verdict: FAIL"
  exit 1
fi
log "Layer 3 (conversations) verdict: PASS"
