# Twenty-five things that will cost you time

Practical surprises from building and validating this framework against the live
API — the things that are obvious in hindsight and expensive in the moment. Each
one cost time on this project.

This is the short form. The measured evidence behind these, and the reasoning
they feed into, live elsewhere:

* **[validation-report.md](validation-report.md)** — what was actually run, and
  the platform behaviours `F1`–`F10` any control of this class must design
  around. Most of the entries below are a one-line distillation of a finding
  there.
* **[design.md](design.md)** — why the framework is shaped the way it is.

---

* **Delete is a soft delete** — for *agents*. 30-day tombstone, content still
  readable via GET, no purge or undelete. Agent IDs stay occupied, so tests use
  run-scoped IDs. Conversations behave the opposite way (below).
* **Redaction needs two passes.** One pass moves the content into the read-only
  `lastPublishedContext`.
* **Regional endpoints are mandatory.** `global` cannot be CMEK-encrypted, and
  the global endpoint returns a misleading `403` for regional paths.
* **CAI `ExportAssets` returns DataAgents only intermittently** (1 of 7 exports
  in testing); `SearchAllResources` returned them every time. Build the
  inventory on the search API.
* **`VAR="$(cmd 2>/dev/null)"` under `set -euo pipefail` aborts the script with
  no output at all.** The assignment inherits the command's exit status, `-e`
  acts on it, and the redirect has already thrown away the reason. This bit
  `tests/run_layer5.sh` twice: `ExportAssets` allows one export at a time per
  project and `--output-bigquery-force` recreates the destination table, so a
  slow export leaves the follow-up query with no table to read — and an
  informational coverage number killed the entire gate silently. Guard every
  such assignment with `if ! VAR="$(...)"; then` and keep stderr.
* **A disabled key hides an agent from `LIST` with no error.**
* **`dataAgentCreator` grants `create` and nothing else** — no `get`, `list` or
  `update`. Pair it with `dataAgentViewer` or your pipeline cannot read back
  what it deployed.
* **A conversation's CMEK key goes in the *paired* region, not the documented
  one.** A conversation in `us` needs a key in **`us-central1`**; one in `eu`
  needs **`europe-west1`**. Every other KMS location is refused — including the
  same-named multi-region the documentation tells you to use, and every other
  region on the same continent. Follow the docs exactly and you get *"KMS key
  must be in the same location as parent"* every time, which reads like your key
  path is wrong. It isn't. Don't take this on trust —
  `python scripts/repro_conversation_cmek.py --project YOUR_PROJECT --setup`
  runs both key paths side by side in your own project and prints replayable
  `curl` lines.
* **Agents and conversations want their keys in *different* places.** A
  `DataAgent` in `us` takes a key in `us` and rejects `us-central1`; a
  `Conversation` in `us` is the exact reverse. Same project, same endpoint, one
  documented rule covering both. Budget for two key rings per multi-region.
* **Conversation CMEK is opt-in, per conversation.** A conversation created
  without `kms_key` does **not** inherit the key registered for its
  project + location, and stays readable when that key is disabled. So a
  correctly configured, correctly permissioned key tells you nothing about
  whether anything is using it — which is why Layer 5 reads every conversation
  rather than attesting one key per location.
* **Offering a conversation key is a permanent write, even when the call
  fails.** The first key submitted is registered for the whole project +
  location — **including the key name**, measured 2026-09-01: in a location
  pinned to `.../cryptoKeys/agent-key`, an otherwise identical path ending
  `.../cryptoKeys/conversation-key` is refused with `Invalid resource state for
  "conversation.kms_key_name": Cannot add a new KMS key`. Renaming the key is
  therefore not possible after the first conversation, only reconfiguring the
  name you point at. Every later key is refused, disabling the key does not free
  the slot, and no API resets it. Anyone who can call `CreateConversation` can burn
  it — so do not "just try" a key to see what happens, and note that the
  superseded `conversation_key_probe.py` did exactly that on every run.
* **`us-east4` cannot create a conversation at all** — 0 of 13 attempts, with or
  without a key, despite being listed as CMEK-supported. If `us-east4` is your
  default location, conversations simply do not work there.
* **`Invalid resource state for "conversation"` is a generic error.** It is what
  `us-east4` always returns, but it also appears transiently elsewhere when a
  KMS key is briefly unusable — right after re-enabling a key version, for
  instance. Retry before concluding a location is broken.
* **A freshly created log sink does not route reliably for the first few
  minutes**, and a detection test's failure signal — "no event arrived" — looks
  identical to a real detection bug. Measured 2026-08-31: the Layer 4
  conversation gate run immediately after `deploy_controls.sh` saw the keyed
  conversation's create event but not the unkeyed one; both arrived when the
  same test ran six minutes later, and both had passed twice earlier that day
  against a warm sink. `run_layer4_conversation.sh` now waits for the sink to
  reach `SINK_SETTLE_SECONDS` (default 300) before creating anything.
* **One "location" variable cannot serve GDA and Cloud Run.** A GDA location is
  `us-east4`, `us`, `eu` or `global`; a Cloud Run region is `us-east4`,
  `us-central1` and so on. They overlap at `us-east4` — which is exactly why a
  single `LOCATION` variable appears to work until someone sets it to the `us`
  multi-region, at which point `gcloud run`, `gcloud functions` and
  `gcloud scheduler` all reject it. This repo now splits them into
  `AGENT_LOCATION` and `INFRA_REGION`, and `prelude.sh` refuses a multi-region
  in the latter. The failure is worse than a plain error: in
  `layer5/revocation_proof.py` the failed `jobs execute` was captured with
  `check=False`, so the scanner never re-ran, the inventory kept the PREVIOUS
  scan's rows, and the proof then reported agents COMPLIANT that it had just
  hidden — a false pass in one direction and a false failure in the other.
* **A CMEK posture probe must run before anything in the same suite revokes a
  key.** Re-enabling a key version propagates on the same multi-minute timescale
  as disabling one — the revocation proof measures a keyed conversation going
  dark about four minutes after the disable. A probe that asserts "a
  paired-region key is accepted" and runs *after* the revocation test therefore
  sees the suite's own re-enabled key still being rejected, and reports it as
  platform drift. `tests/run_conversations.sh` runs the probe first for exactly
  this reason. A drift alarm straight after a revocation test is the test
  order, not the platform.
* **`DeleteConversation` is a *hard* delete** — unlike agents. `NotFound`
  immediately, gone from `LIST`, and the ID is reusable at once. No tombstone,
  so conversation IDs do not need to be run-scoped.
* **A conversation can only be read by whoever created it.** Not an IAM gap —
  `roles/cloudaicompanion.topicAdmin`, which carries `topics.delete` and
  `topics.setIamPolicy`, still gets `{}` from LIST and **404** from GET for
  another principal's conversation. So no scanner can inventory the surface and
  no enforcer can verify a key. Govern it before creation, not after.
* **`logger.info` is invisible in a Cloud Run function.** `functions_framework`
  configures logging first, so your `logging.basicConfig(level=INFO)` is a no-op
  and the root logger stays at WARNING. `logger.error` and plain `print` both
  show up; INFO silently does not. Diagnosing "the function ran but logged
  nothing" costs an hour.
* **`gcloud run services delete` does not delete a Cloud Run function.** A
  function is backed by a Cloud Run service, so it answers to `gcloud run`
  — but deleting the service leaves the *function* resource behind, and the
  next deploy warns *"the service was not found, redeployed with default
  values"* and comes back with its Eventarc trigger broken, so it is never
  invoked again. Use `gcloud functions delete`.
* **Conversation lifecycle logs are Data Access, under `cloudaicompanion`.**
  `CreateConversation` emits nothing under `geminidataanalytics`; it appears as
  `TopicService.CreateTopic`, in a log stream that is **off by default**, with
  null request and response payloads. Layer 4's sink can never see it.
* **Conversations are gated by `cloudaicompanion.topics.*`, not by any
  `geminidataanalytics` permission.** None of the nine GDA roles can create one.
  The minimum is a custom role with `topics.create` + `topics.get` +
  **`operations.get`** (create is an LRO and the poll is authorized separately —
  easy to miss). `layer2/deploy.sh` ships it as `gdaConversationUser`.
* **You cannot grant conversation *delete* at least privilege.**
  `cloudaicompanion.topics.delete` is `NOT_SUPPORTED` in custom roles; only
  `topicAdmin` has it, and that drags in `setIamPolicy`. Let conversations
  expire instead.
* **Nothing can gate `ListConversations`** — there is no `topics.list`
  permission at all, so a principal with no role can enumerate them.
* **`cloudaicompanion` is shared across Gemini for Google Cloud**, not private
  to GDA. Of 2,387 predefined roles, 16 can create a conversation — including
  **`bigquery.studioUser`** and **`iam.dataScientist`**. In a data estate that
  is most of your analysts. And `cloudaicompanion` **cannot be restricted to
  GDA** — it is one service, so org policy and API enablement are all-or-nothing
  across Code Assist, Cloud Assist and Agentspace. The only per-principal lever
  is an IAM deny policy (org/folder-level `denyAdmin` required). Note
  `restrictServiceUsage` is a blunt instrument here: the same service backs
  Gemini Code Assist, so denying it org-wide disables that for everyone. Contain
  the data — dedicated projects for agents and conversations — and pair it with
  CMEK on the conversations themselves, which does hold once the key is in the
  right region (above).
