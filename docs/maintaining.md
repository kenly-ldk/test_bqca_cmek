# Working on this repo

Traps in the build, the scripts and the test suites. These are not platform
behaviours — they are properties of *this* codebase and the tooling it runs on,
and none of them matter to someone adopting the framework. The platform findings
an adopter has to design around are in
[Appendix A of design.md](design.md#appendix-a--platform-behaviours-that-will-cost-you-time)
and, in full, in [validation-report.md](validation-report.md).

Each entry below cost a diagnosis cycle at least once.

## Bash

* **`VAR="$(cmd 2>/dev/null)"` under `set -euo pipefail` aborts the script with
  no output at all.** The assignment inherits the command's exit status, `-e`
  acts on it, and the redirect has already thrown away the reason. This bit
  `tests/run_layer5.sh` twice: `ExportAssets` allows one export at a time per
  project and `--output-bigquery-force` recreates the destination table, so a
  slow export leaves the follow-up query with no table to read — and an
  informational coverage number killed the entire gate silently. Guard every
  such assignment with `if ! VAR="$(...)"; then` and keep stderr.
* **A `subprocess` call captured with `check=False` fails the same way in
  Python.** In `layer5/revocation_proof.py` a failed `jobs execute` was
  swallowed, so the scanner never re-ran, the inventory kept the PREVIOUS scan's
  rows, and the proof then reported agents COMPLIANT that it had just hidden — a
  false pass in one direction and a false failure in the other. The file carries
  a comment at the call site; leave it there.

## Configuration

* **One "location" variable cannot serve GDA and Cloud Run.** A GDA location is
  `us-east4`, `us`, `eu` or `global`; a Cloud Run region is `us-east4`,
  `us-central1` and so on. They overlap at `us-east4` — which is exactly why a
  single `LOCATION` variable appears to work until someone sets it to the `us`
  multi-region, at which point `gcloud run`, `gcloud functions` and
  `gcloud scheduler` all reject it. The variable is now split three ways —
  `AGENT_LOCATION`, `CONVERSATION_LOCATIONS` and `INFRA_REGION` — and
  `scripts/prelude.sh` refuses a multi-region in the last. Do not reintroduce a
  shared one.

## Cloud Run functions

* **`logger.info` is invisible in a Cloud Run function.** `functions_framework`
  configures logging first, so a `logging.basicConfig(level=INFO)` in the
  function is a no-op and the root logger stays at WARNING. `logger.error` and
  plain `print` both show up; INFO silently does not. Diagnosing "the function
  ran but logged nothing" costs an hour.
* **`gcloud run services delete` does not delete a Cloud Run function.** A
  function is backed by a Cloud Run service, so it answers to `gcloud run` — but
  deleting the service leaves the *function* resource behind, and the next
  deploy warns *"the service was not found, redeployed with default values"* and
  comes back with its Eventarc trigger broken, so it is never invoked again. Use
  `gcloud functions delete`.

## Test suites

* **A freshly created log sink does not route reliably for the first few
  minutes**, and a detection test's failure signal — "no event arrived" — looks
  identical to a real detection bug. Measured 2026-08-31: the Layer 4
  conversation gate run immediately after `deploy_controls.sh` saw the keyed
  conversation's create event but not the unkeyed one; both arrived when the
  same test ran six minutes later, and both had passed twice earlier that day
  against a warm sink. `tests/run_layer4_conversation.sh` now waits for the sink
  to reach `SINK_SETTLE_SECONDS` (default 300) before creating anything.
* **A CMEK posture probe must run before anything in the same suite revokes a
  key.** Re-enabling a key version propagates on the same multi-minute timescale
  as disabling one — the revocation proof measures a keyed conversation going
  dark two to five minutes after the disable (t+5min in `us`, t+2min in `eu`).
  A probe that asserts "a paired-region key is accepted" and runs *after* the
  revocation test therefore sees the suite's own re-enabled key still being
  rejected, and reports it as platform drift. `tests/run_conversations.sh` runs
  the probe first for exactly this reason. A drift alarm straight after a
  revocation test is the test order, not the platform.
* **Never "just try" a KMS key against `CreateConversation` to see what
  happens.** The first key offered is registered permanently for the project and
  location even when the create fails, and no API resets it — so a throwaway
  probe burns a real estate's only slot. The superseded
  `conversation_key_probe.py` did exactly that on every run, which is why it was
  removed. Use `scripts/repro_conversation_cmek.py` against a disposable
  project. Background in
  [F8](validation-report.md#f8-conversation-cmek-works-but-only-with-an-undocumented-key-location).
