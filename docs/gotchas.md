# Twenty things that will cost you time

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
  location; every later key is refused, disabling the key does not free the
  slot, and no API resets it. Anyone who can call `CreateConversation` can burn
  it — so do not "just try" a key to see what happens, and note that the
  superseded `conversation_key_probe.py` did exactly that on every run.
* **`us-east4` cannot create a conversation at all** — 0 of 13 attempts, with or
  without a key, despite being listed as CMEK-supported. If `us-east4` is your
  default location, conversations simply do not work there.
* **`Invalid resource state for "conversation"` is a generic error.** It is what
  `us-east4` always returns, but it also appears transiently elsewhere when a
  KMS key is briefly unusable — right after re-enabling a key version, for
  instance. Retry before concluding a location is broken.
* **`DeleteConversation` is a *hard* delete** — unlike agents. `NotFound`
  immediately, gone from `LIST`, and the ID is reusable at once. No tombstone,
  so conversation IDs do not need to be run-scoped.
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
