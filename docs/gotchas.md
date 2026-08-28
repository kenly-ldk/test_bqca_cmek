# Eleven things that will cost you time

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

* **Delete is a soft delete.** 30-day tombstone, content still readable via GET,
  no purge or undelete. Agent IDs stay occupied, so tests use run-scoped IDs.
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
* **Conversation CMEK is one key per project per location**, not per resource.
  The API rejects any second key, even another key in the same project — so
  there is nothing per-conversation to enforce, and conversations are never
  provisioned from a manifest. Layer 1 rejects them; Layer 5 attests the key.
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
  the data — dedicated projects for agents and conversations — and let the CMEK
  attestation be the backstop.
