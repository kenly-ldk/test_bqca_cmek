# GDA CMEK Enforcement Framework — Validation Report

* **Date:** 2026-08-25
* **Validates:** [design.md](design.md) — the framework as implemented in this
  repository
* **Disclaimer:** **MVP reference implementation, not an officially supported
  Google product.** The verdicts below are real and reproducible, but they
  attest to this implementation in one test estate — not to a supported
  offering. Re-run them in your own environment.
* **Method:** every layer built and executed against two purpose-created GCP
  projects. The Layer 1 test additionally runs offline against OPA 1.19.1, Regal 0.42.0
  and the Google Terraform provider v7.45.0.
* **Verdict:** **All five layers PASS.** Each layer's verdict below is produced
  by a test in `tests/` that you can re-run; none of it is asserted from
  inspection alone.

This report is the evidence behind design.md. It is organised around what an
adopter has to design around: the verdicts, the product behaviours that
constrain the control, and the residual risk that must be disclosed to a risk
and compliance function.

## 1. Verdict

| Layer | Verdict | What produces it |
| :--- | :--- | :--- |
| 1 — CI/CD policy-as-code | **PASS** 14/14 | `tests/run_layer1.sh`; Rego v1 policy, Regal-linted, 46 policy unit tests, gated deploy step |
| 2 — IAM least privilege | **PASS** 45/45 | `tests/run_layer2.sh`; 45-cell persona × operation matrix executed live under impersonation |
| 3 — CMEK at rest | **PASS** 6/6 | `tests/run_layer3.sh`; proven by key revocation, not field inspection |
| 4 — Real-time remediation | **PASS** 7/7 | `tests/run_layer4.sh`; 13–30 s detect → redact → soft-delete across six runs |
| 5 — Continuous compliance | **PASS** | `tests/run_layer5.sh`; two reconciled sources, proven by a live key-revocation proof |

Cutting across all five, **`tests/run_unit.sh` passes 118/118** offline, with no
GCP project: the shared compliance verdict, the enforcer's audit-log parsing and
every quadrant of the scanner's reconciliation matrix. It is not a layer — it is
the unit suite for the logic the layers share.

> **These verdicts are about DataAgents.** The other resource type carrying
> customer content — **Conversations** — is invisible to the Layer 4 sink and to
> Cloud Asset Inventory, and is governed by different rules throughout. CMEK
> **does** hold on conversation content, but only with a key in the
> multi-region's paired region (`us` → `us-central1`, `eu` → `europe-west1`),
> which is not the location Google documents; and it is **opt-in per
> conversation**, so a registered key protects nothing until each caller asks
> for it. `us-east4` cannot host a conversation at all. Read
> [F8](#f8-conversation-cmek-works-but-only-with-an-undocumented-key-location)
> before presenting this report as covering the GDA surface.

| Environment | |
| :--- | :--- |
| Workload project | purpose-created, disposable (`WORKLOAD_PROJECT` below) |
| Unapproved-KMS project | purpose-created, holds only an out-of-allowlist key (`ROGUE_PROJECT`) |
| Organization | Google Cloud sandbox org with common guardrail policies enforced |
| Location | `us-east4`, `us` and `eu`, plus `global` as a negative control |
| Approved key | `projects/WORKLOAD_PROJECT/locations/us-east4/.../cryptoKeys/agent-key`, with `us` and `europe` counterparts |
| Unapproved key | `projects/ROGUE_PROJECT/locations/us-east4/.../cryptoKeys/rogue-key` |

Agent IDs in the evidence below carry a run-scoped numeric suffix, because soft
delete keeps an ID occupied until `purgeTime` (see [F1](#f1-delete-is-a-soft-delete-with-a-30-day-readable-tombstone)).

## 2. What each layer proves

**Layer 1 — the policy rejects what it claims to reject.** Five violation
classes are denied against offline fixtures: missing CMEK, unapproved KMS
project, unsupported location, key/agent location mismatch, and a malformed key
path. The allowlist is proven data-driven, not hardcoded, by re-evaluating the
same compliant fixture against a different allowlist and getting `allow=false`.
The in-process gate in `layer1/apply_manifest.py` is then shown to reject a
violating manifest **before any API call is attempted**.

**Layer 2 — least privilege is behavioural, not declarative.** A role table is
an assertion; a probe that makes the call and gets `PERMISSION_DENIED` is
evidence. Five personas × nine operations are executed live under impersonated
credentials, and all 45 cells match the documented model. The single most
load-bearing cell: `dataAgentOwner` — the role held by the Layer 4 enforcer —
can `delete` but **cannot `create`**, so the enforcer cannot create the
resources it polices.

**Layer 3 — CMEK is a real cryptographic boundary.** Not proven by reading the
`kmsKey` field back, which only shows that a string round-tripped. Proven by
disabling the key version and observing the content become unreadable, then
re-enabling it and observing recovery:

```
[PASS] kms_key round-trips on GET
[PASS] context readable while key ENABLED — 153 chars
-- revoking key access --
[PASS] context UNREADABLE while key DISABLED — FailedPrecondition: ... is not enabled, current state is: DISABLED
[PASS] GET fails closed while key DISABLED — the whole RPC raises; metadata is NOT independently readable
[PASS] LIST silently omits the key-disabled agent — 3 agents visible, the fixture hidden without error
-- restoring key access --
[PASS] context readable again after key RE-ENABLED — 153 chars
```

**Layer 4 — remediation works, and does not over-reach.** Four fixtures, one of
which must survive:

```
[PASS] compliant     expected=survive     actual=survive
[PASS] nokey         expected=remediated  actual=remediated  (~17s)
[PASS] nokey         tombstone scrubbed (published + lastPublished)
[PASS] rogue         expected=remediated  actual=remediated  (~26s)
[PASS] rogue         tombstone scrubbed (published + lastPublished)
[PASS] global-nokey  expected=remediated  actual=remediated  (~14s)
[PASS] global-nokey  tombstone scrubbed (published + lastPublished)

RESOURCE                   STATUS                                   ACTION_TAKEN                            LATENCY_S
agent-rogue-key-031543     NON_COMPLIANT_UNAPPROVED_KEY_PROJECT     CONTENT_REDACTED+RESOURCE_SOFT_DELETED  2.762
agent-nokey-031543         NON_COMPLIANT_MISSING_CMEK               CONTENT_REDACTED+RESOURCE_SOFT_DELETED  1.083
agent-global-nokey-031543  NON_COMPLIANT_CMEK_UNSUPPORTED_LOCATION  CONTENT_REDACTED+RESOURCE_SOFT_DELETED  4.287
```

The compliant fixture surviving is the important assertion. A control of this
class fails dangerously when its filter is too broad, and the tombstone checks
confirm the remediated agents' content is gone rather than merely hidden.

**Cross-layer evidence.** Because `tests/run_layer2.sh` runs last, its `create`
probe makes a key-less agent as the pipeline persona and the enforcing Layer 4 then
remediates it, naming the caller:

```
layer2-probe-cicd-deployer-fa8b9470  NON_COMPLIANT_MISSING_CMEK  \
  caller=layer2-cicd-deployer@WORKLOAD_PROJECT.iam.gserviceaccount.com  \
  CONTENT_REDACTED+RESOURCE_SOFT_DELETED
```

Layer 2 restricts who can create a non-compliant agent; Layer 4 catches the one
that still gets created. That is the defence-in-depth claim in one log line.

**Layer 5 — the report reconciles two independent sources.** The compliance view
classifies every row, and a set-based reconciliation against the live API
confirms no under-reporting. The justification for reading two sources is then
*demonstrated* rather than asserted: with the key disabled, 34 agents vanished
from the live API and all 34 were caught via the Cloud Asset Inventory
cross-check and reported `NON_COMPLIANT_UNVERIFIABLE` — none silently absent,
none reported `COMPLIANT`.

## 3. Findings to design around

These are properties of the platform, not of this implementation. Any control of
this class has to account for them.

### F1. Delete is a soft delete, with a 30-day readable tombstone

`DeleteDataAgent` moves the resource to `SOFT_DELETED` with
`purgeTime = deleteTime + 30 days`. There is **no purge, force or undelete
parameter** — `?force=true`, `?purge=true`, `:purge` and `:undelete` were all
probed and rejected. The soft-deleted agent's content stays fully readable via
`GetDataAgent` for those 30 days: a `dataAgents.get` on a "remediated" agent
returned its complete `systemInstruction` and BigQuery datasource references.
Default `LIST` hides it, so a naive report shows "0 non-compliant" while
unencrypted content is still resident and readable.

**Mitigation implemented and verified:** remediation **redacts before deleting**.
This requires **two passes** — publishing an empty context rotates the previous
one into the output-only `lastPublishedContext` field, which cannot be cleared
directly. A single-pass redaction leaves the customer content fully readable
there. Agent IDs also stay occupied until `purgeTime`, so any automated test
must use run-scoped IDs.

### F2. CreateDataAgent emits two different audit-log shapes

A log-sink-based control must handle both, and both were observed live:

* `CreateDataAgent` is a **long-running operation (LRO)** — it returns an
  `Operation` you poll rather than the finished resource — and produces **two**
  audit entries. The `operation.first=true` entry carries `request`; the
  `operation.last=true` entry carries an empty `response` and **no `request`**.
  A filter that matches both will read the trailing entry as "no `kms_key`" and
  delete a **compliant** agent.
* `CreateDataAgentSync` produces **one** entry with no `operation` field at all.
  This is what the Python client library actually calls, so a filter requiring
  `operation.first=true` misses every real creation.

The working filter keeps both shapes while dropping the LRO tail with
`NOT operation.last=true`, and drops failed attempts with
`NOT protoPayload.status.code>0`.

### F3. ExportAssets coverage of DataAgent is unreliable

Across **seven** Cloud Asset Inventory exports of the same project, filtered to
DataAgent + CryptoKey, **six returned 0 DataAgent rows** and **one returned all
15** with `kmsKey` and full `publishedContext` populated. Each zero-result run
polled the export operation to `done=True` before querying, so this is not a
read-before-write race.

An intermittently-populated source is *worse* than an empty one: a report built
on it renders "0 non-compliant" most of the time and looks like it is working.
`SearchAllResources` returned DataAgent consistently on every attempt, so the
inventory is built on the search API and cross-checked against the live API.
(The asset type is absent from the public supported-asset-types page but works
in the live API.)

Note also that `resource.data` in the BigQuery export is a JSON **string**:
`JSON_VALUE(resource.data.kmsKey)` fails with *"Cannot access field kmsKey on a
value with type STRING"*. The correct form is
`JSON_VALUE(resource.data, '$.kmsKey')`.

### F4. A disabled key hides an agent from LIST, with no error

The CMEK documentation says metadata (`display_name`, `description`) stays under
Google default encryption. In practice, with the key version disabled:

* `GetDataAgent` fails **entirely** with `FAILED_PRECONDITION` — metadata is not
  independently readable, so a control that inspects an agent must fail closed.
* `ListDataAgents` **silently omits the agent**, with no error.

This is the single strongest argument against building a compliance inventory
from `LIST` alone: it under-reports precisely when a key's state is suspect,
which is exactly when you need the report to be right.

### F5. Cloud Asset Inventory will return agent content in plaintext

A `SearchAllResources` call with `read_mask=versionedResources` returns
`publishedContext.systemInstruction` in plaintext for every agent — 39 of 39 in
the most recent run — and a `contentType=RESOURCE` export lands the same content
in BigQuery. A compliance scanner that persists this has copied the protected
material into an unprotected store.

The scanner therefore requests a metadata-only read mask
(`name,assetType,location,kmsKeys,createTime,updateTime,project`) and never
persists `versionedResources`.

### F6. Per-location endpoints are mandatory; global cannot be CMEK-encrypted

CMEK supports `us-east4`, `us` and `eu` only — one region and two
multi-regions, so "regional" is the wrong shorthand; the line that matters is
global versus everything else. Agents **can** be created in `global`, they
simply can never carry a key, so they must surface as violations rather than be
excluded from the scan.

Each location is addressed through its own endpoint (`global` →
`geminidataanalytics.googleapis.com`, `us`/`eu` →
`geminidataanalytics.<loc>.rep.googleapis.com`, a region →
`geminidataanalytics-<region>.googleapis.com` — note the hyphen). Calling the
global endpoint with a non-global resource path returns a misleading `403`,
which is easy to misread as a permissions problem.

**`global` is closed off in both directions**, probed directly rather than taken
from the documentation:

| Attempt | Result |
| :--- | :--- |
| `global` agent + a **regional** key | `InvalidArgument`: *"KMS key location must match agent location."* |
| `global` agent + a **global** KMS key | `InvalidArgument`: *"Global KMS keys are not allowed for Data Agent."* |

The first rejection alone would be ambiguous — it is the generic
location-matching rule, not a statement about `global`. The second closes the
remaining door explicitly. So an agent at `global` can never carry a key by any
route, which is why Layer 1 denies the location outright and Layers 4 and 5
treat every `global` agent as a violation on sight.

**Scope of what was exercised:** every *compliant* CMEK agent in the original
validation ran in `us-east4`, and `global` was exercised as a negative control on
every Layer 4 run. `us` and `eu` were both measured during the conversations
work — a key-bearing agent was created successfully in each — so all three CMEK
locations are measured rather than documented.

**`eu` needs a `europe` key, not an `eu` one.** Cloud KMS has no `eu` location —
its EU multi-region is `europe` — so the obvious key path for an `eu` agent does
not exist, and asking for one fails with a misleading `NOT_FOUND: The request
concerns location 'eu' but was sent to location 'europe'`, which reads like a
client bug. A `europe` key **is** accepted for an `eu` agent by the API. The same
same mismatch bites differently on the conversation surface, which does not want
a same-location key at all: an `eu` conversation needs a key in `europe-west1`,
and an `eu` agent needs one in `europe`. Two resource types, two KMS locations,
one documented rule covering both — see F8.

**This broke the Layer 1 gate, and the gate's own tests hid it.** Rule 4
(*Key Location Mismatch*) tested the key location for equality with the agent
location, so a real `eu` agent was rejected before it ever reached the API:

```
$ opa eval -d layer1/policy.rego -i eu-agent.json 'data.gda.cmek.deny'
[
  "REJECTED [Key Location Mismatch]: agent 'eu-agent' is in 'eu' but its key is in 'europe'."
]
```

`test_supported_locations_not_flagged` passed only because its `eu` fixture used
a key at `locations/eu`, which cannot exist in Cloud KMS, and because it
asserted only that no *Unsupported Location* message fired rather than that the
manifest was allowed. `layer1/testdata/compliant.json` carried the same
impossible key path, so the fixture the pipeline treats as its reference for
"compliant" described an agent that could never be deployed.

**Fixed.** Rule 4 now resolves the required KMS location through a map,
`required_key_location := {"us-east4": "us-east4", "us": "us", "eu": "europe"}`,
and `supported_locations` is derived from that map's keys so the two cannot
drift apart. The fixtures use `europe`, and
`test_supported_locations_not_flagged` now asserts `allow` over the whole
policy, so a deployable agent in any supported location has to clear every rule
rather than one. Re-verified against the live API on 2026-08-30: an `eu` agent
with a `europe` key is created and reads back carrying that key, while the same
agent with a `locations/eu` key fails with the `404` above.

One deliberate behaviour change came with it: an agent in an **unsupported**
location no longer also draws a *Key Location Mismatch*. There is no correct KMS
location for `global`, so naming one would imply a fix that does not exist;
*Unsupported Location* is the whole finding.

### F7. The cloudaicompanion service must be enabled

CMEK for data agents requires `cloudaicompanion.googleapis.com` to be enabled
and its service agent
(`service-<NUM>@gcp-sa-cloudaicompanion.iam.gserviceaccount.com`) to hold
`cryptoKeyEncrypterDecrypter` on every key. The service agent does not exist
until the API is enabled, so this is a bootstrap ordering requirement.

### F8. Conversation CMEK works, but only with an undocumented key location

Conversations are not data agents, and the agent controls do not cover them.
This finding has been measured three times and the middle reading was wrong, so
the history matters as much as the result:

| Measured | Reading | Status |
| :--- | :--- | :--- |
| 2026-08-21 | The conversation key is a protective "project+location singleton" | Wrong — the pin is real but protects nothing by itself |
| 2026-08-27 | CMEK cannot be attached to a conversation in any location | **Wrong — withdrawn** |
| 2026-08-30 | CMEK attaches and holds, with the key in the multi-region's **paired region** | Current |

The 2026-08-27 measurement failed for a real reason, but not the one it
recorded. Every attempt supplied the key path the documentation prescribes — a
key in the *same location as the conversation* — and that path is rejected in
every location. The conclusion drawn from it ("the feature is unreachable") did
not survive trying a key path the documentation never mentions.

**The rule the API actually implements.** A conversation in a GDA multi-region
takes a key in that multi-region's paired primary region, and in nothing else.
Probed by submitting a candidate key and reading which rejection comes back —
`KMS key must be in the same location as parent` means the location was refused,
`Only 1 KMS keys per project per location` means the location was accepted and
the request then hit the key registry. Neither outcome writes anything, and the
key need not exist, because the location check fires first:

| Conversation parent | KMS location accepted | KMS locations refused |
| :--- | :--- | :--- |
| `us` | **`us-central1`** — and only this | `us-east1`, `us-east4`, `us-east5`, `us-west1..4`, `us-south1`, `northamerica-northeast1`, `nam4`, `global`, and **`us`** |
| `eu` | **`europe-west1`** — and only this | `europe-west2/3/4/9`, `europe-north1`, `europe-central2`, `eur3`, `us-central1`, `global`, and **`europe`** |

Thirteen KMS locations were probed for `us` and eleven for `eu`. Exactly one is
accepted in each case. This is not "any regional key": every other region on the
same continent is refused with the same message as a key on the wrong continent.

**"Parent" is the project and location, not the agent.** The error text says the
key must match the *parent*, and a conversation's parent is
`projects/PROJECT/locations/LOCATION` — where the conversation itself is
created. It is **not** the agent the conversation references; the agent is a
field in the request body (`agents[]`) and plays no part in the key rule.

Measured, holding the conversation in `us` and varying everything else:

| `parent` | `agents[0]` | `kms_key` | Result |
| :--- | :--- | :--- | :--- |
| `.../locations/us` | agent in `us` | `us-central1` | created |
| `.../locations/us` | agent in **`eu`** | `us-central1` | **created** — follows the parent |
| `.../locations/us` | agent in **`eu`** | `europe-west1` | **rejected**, same location message |
| `.../locations/us` | agent in `us` / `eu` / `us-east4` | none | created in all three cases |

Two consequences. A `us-east4` agent is still usable conversationally even
though `us-east4` cannot host a conversation — host the conversation in `us`.
And an agent's `kms_key` and a conversation's `kms_key` are independent fields
on independent resources: the anchor agents in this project carry no key while
the conversations they serve carry one, so a CMEK-protected agent does not imply
CMEK-protected conversations.

**The documented configuration fails 100% of the time.** The
[CMEK page](https://docs.cloud.google.com/gemini/data-agents/conversational-analytics-api/cmek)
states plainly that *"The Cloud KMS key and the Conversational Analytics API
resource must be in the same location"* and *"A CMEK key must be in the same
region as the resource that it protects"*, and its sample body interpolates a
single `{location}` into both the conversation parent and the key path:

```python
conversation_payload = {
    "agents": [f"projects/{billing_project}/locations/{location}/dataAgents/{data_agent_id}"],
    "name":   f"projects/{billing_project}/locations/{location}/conversations/{conversation_id}",
    "kms_key": f"projects/{key_project}/locations/{location}/keyRings/{key_ring_name}/cryptoKeys/{key_name}",
}
```

For a `us` conversation that yields a key in `us`, which the API refuses. The
paired region is documented nowhere on the page. **Anyone following the
documentation exactly will conclude the feature is broken** — which is precisely
what happened here on 2026-08-27. The defect is now a documentation and
API-contract mismatch rather than a missing capability, but it is still a defect
worth raising, and it is the reason this finding was wrong for three days.

**The boundary is real.** The key is not a stored string. Measured in a fresh
project with a keyless conversation as a control, both loaded with real content
(ten messages: the generated SQL, the BigQuery job reference and the returned
customer rows), then key version 1 disabled:

| | `us`, key in `us-central1` | `eu`, key in `europe-west1` |
| :--- | :--- | :--- |
| baseline | 10 messages readable | 10 messages readable |
| key disabled | **blocked at t+5min** | **blocked at t+2min** |
| keyless control conversation | readable throughout | readable throughout |

`GetConversation` and `ListMessages` both fail, and the error names the
mechanism:

```
failed to enumerate messages in InteractionHistoryService: generic::failed_precondition:
fetch message from Firestore: rpc error: code = FailedPrecondition desc = The
customer-managed encryption key required by the requested resource is not accessible.
```

The key was independently confirmed unusable during the window (`gcloud kms
encrypt` returned `FAILED_PRECONDITION ... KEY_DISABLED`), so this is revocation
taking effect, not an unrelated outage. Conversation message content — the
questions, the generated SQL and the returned rows — is genuinely
crypto-shreddable.

**A keyless conversation is not covered by the registered key.** This is the
governance point that matters most, and it is the reverse of what a "one key per
project per location" registry suggests. In a project + location where a key
*is* registered, a conversation created without `kms_key` comes back with
`kmsKey` unset and **stays fully readable while the registered key is disabled**
— that is the control row in the table above. CMEK is therefore **opt-in per
conversation**, not a property of the project + location. The registry decides
*which* key may be used; each caller decides *whether* to use one.

Two consequences follow. There **is** per-conversation drift to chase, so the
conversation surface needs an inventory rather than a single attestation. And a
project can hold a correctly registered, correctly permissioned key while every
conversation in it is unencrypted, with nothing in the key's own configuration
to reveal that.

**`us-east4` still cannot create a conversation at all.** Unchanged from the
2026-08-27 reading and re-measured in the new project: **0 of 13** keyless
`CreateConversation` attempts succeeded, against a confirmed-existing anchor
agent, with `FailedPrecondition: Invalid resource state for "conversation":
failed to create conversation` every time. This is not a CMEK defect — it is the
conversation surface being unavailable in the region, which takes CMEK down with
it. `us` in the same project was 10/10 on the same request shape.

**That error string is generic — do not read it as a regional outage.** The same
`Invalid resource state for "conversation"` message appeared transiently in `us`
immediately after a KMS key version was re-enabled (two failures, then success on
an identical request), while keyless creates in `us` were 10/10 in the same
period. It means "the conversation could not be created", including "the key is
not usable right now". Only its persistence across repeated attempts
distinguishes the `us-east4` outage from a key-state transient, which is why both
probes retry before concluding anything.

**The one-key-per-project-per-location registry is real, and now matters more.**
Confirmed independently of the earlier reading: submitting a *different* key in
the accepted location — including a key that does not exist — returns

```
Invalid resource state for "conversation.kms_key_name": Cannot add a new KMS key.
Only 1 KMS keys per project per location are allowed.
```

The squatting analysis from the previous reading stands unchanged, and its
consequences are worse now that the key does real work:

* **Offering a key is a permanent, unprivileged write.** The first key submitted
  is registered even when the create then fails. Anyone who can call
  `CreateConversation` can permanently pin a project + location to a key of
  their choosing — including a key in a project they control, since they can
  grant the victim's service agent on it — and `topics.create` comes free with
  `bigquery.studioUser` (below).
* **The registered key cannot be replaced, even once it is useless.** Rotating
  the key *version* is fine: the registry pins the `cryptoKey`, not the version,
  and a new primary version is accepted. Changing the *key* is impossible, and
  disabling every version does not free the slot. A project + location can be
  pinned permanently to a key that no longer works — and now that the key
  genuinely encrypts, that pin can render the whole surface unusable rather than
  merely untidy.

**DataAgent and Conversation have opposite key-location rules.** Same project,
same endpoint, same key ring name — and the two resource types disagree about
where the key must live:

| Resource in `us` | key in `us` | key in `us-central1` |
| :--- | :--- | :--- |
| `DataAgent` | **accepted** | rejected, HTTP 400 |
| `Conversation` | rejected, HTTP 400 | **accepted** |

A `us-east4` agent takes a `us-east4` key; an `eu` agent rejects a
`europe-west1` key and needs one in `europe` (F6). So an estate running agents
and conversations in the same multi-region needs **two** key rings in **two**
KMS locations to cover both, and neither key covers the other resource type.
Nothing in the documentation distinguishes the two rules; the page presents one
same-location rule for both.

The remaining conversation behaviours are unchanged from the previous reading and
were re-confirmed:

* **The lifecycle is audited only as Data Access, under a different service —
  but that is enough for Layer 4.** `CreateConversation`, `GetConversation`,
  `ListConversations` and `DeleteConversation` emit nothing under
  `geminidataanalytics.googleapis.com`. They appear as
  `cloudaicompanion.v1.TopicService.CreateTopic` / `GetTopic` /
  `FindReadableTopics` / `DeleteTopic` — in
  `cloudaudit.googleapis.com/data_access`, which is **off by default** and has
  to be enabled per service. Even then the entries carry `request: null`,
  `response: null` and `authorizationInfo: null`: no key, no agent, no content.

  An earlier reading concluded from that payload that **Layer 4 could never
  cover conversations**. That was wrong, and wrong by the same mistake twice:
  it assumed the control needs the key to be *in* the event. Layer 4 has never
  trusted the audit payload for agents either — it re-reads the resource,
  because `kms_key` is immutable and the server's value is the only
  authoritative one. Measured on 2026-08-31, every link the re-read needs is
  present:

  | Needed | Present? |
  | :--- | :--- |
  | A create event | **Yes** — `TopicService.CreateTopic`, in the same two-entry LRO pair as `CreateDataAgent` (F2) |
  | Something that identifies the resource | **Yes** — the topic ID *is* the conversation ID, verified in `us` and `eu` |
  | Its location | The **paired** region: a `us` conversation is audited in `us-central1`, an `eu` one in `europe-west1`. Invert the key mapping to recover it |
  | The caller | **Yes** — `authenticationInfo.principalEmail` |
  | The key | **No** — and it does not matter; `GetConversation` supplies it |

  Two real constraints remain. The Data Access logs must be enabled, and they
  cover the whole `cloudaicompanion` service — Code Assist and Cloud Assist
  included — so the volume is not GDA's alone. And **remediation is not
  symmetric with the agent path**: a conversation has no updatable content field
  to redact and `DeleteConversation` is a hard delete, so the only available
  action destroys a live session irreversibly. The enforcer therefore defaults
  to alerting (`CONVERSATION_ACTION=alert`) and deletes only when told to.
* **Delete is a hard delete** — the opposite of `DeleteDataAgent` (F1).
  Immediately after `DeleteConversation`: `GetConversation` returns `NotFound`,
  `ListMessages` returns `NotFound`, the conversation is absent from
  `ListConversations`, and **the ID is immediately reusable**. There is no
  tombstone and no purge window, so conversation IDs do not need to be
  run-scoped the way agent IDs do.
* **Access is gated by `cloudaicompanion.topics.*`, not by any
  `geminidataanalytics` permission.** None of the nine GDA roles can create a
  conversation. The minimum viable custom role is `topics.create` +
  `topics.get` + **`operations.get`** — create is an LRO and the poll is
  authorized separately.
* **Delete cannot be granted at least privilege.**
  `cloudaicompanion.topics.delete` is `NOT_SUPPORTED` in custom roles; only
  `topicAdmin` carries it, and that drags in `setIamPolicy`.
* **Nothing can gate `ListConversations`** — there is no `topics.list`
  permission, so a principal with no role can enumerate them.
* **The service is shared across Gemini for Google Cloud.** Of 2,387 predefined
  roles, **16 can create a conversation**, including `bigquery.studioUser` and
  `iam.dataScientist`. It **cannot be restricted to GDA** — it is one service,
  so org policy and API enablement are all-or-nothing across Code Assist, Cloud
  Assist and Agentspace. `restrictServiceUsage` is a blunt instrument here:
  denying it org-wide disables Gemini Code Assist for everyone. The only
  per-principal lever is an IAM deny policy, which requires org- or
  folder-level `denyAdmin`.

**Consequence for the framework.** Conversation content *can* be brought under
CMEK governance, so Layer 5 attests a real protection rather than reporting an
exposure. Three things follow from *how* it works:

1. **Report per conversation, not per project + location.** Because CMEK is
   opt-in per conversation, one keyed conversation says nothing about the next
   one. The scanner reads the key off every conversation it can list and reports
   the location non-compliant if *any* of them is unkeyed.
2. **The right key is the paired region.** `us` → `us-central1`, `eu` →
   `europe-west1`. An estate that provisions keys by copying the agent-side
   convention will register the wrong key, and — because the first key offered
   is permanent — will not get a second attempt.
3. **The residual exposure is real but bounded.** Layer 4 still cannot see
   conversations, the lifecycle is invisible unless Data Access logs are enabled
   on `cloudaicompanion.googleapis.com`, and `us-east4` cannot host them at all.
   Containment is still partly non-cryptographic: dedicate projects to agents and
   conversations, and rely on hard delete for the content's short life.

**What to raise with Google.** Two distinct defects, neither of which is "the
feature does not work":

1. **The documented key location is wrong, and the working one is undocumented.**
   The page requires the key to share the resource's location and demonstrates
   exactly that in its sample. That configuration is rejected in every supported
   location. The rule the API implements — the multi-region's paired primary
   region, `us-central1` for `us` and `europe-west1` for `eu` — appears nowhere.
   The page also gives one same-location rule for both resource types, while
   `DataAgent` and `Conversation` in fact require keys in different locations.
2. **`us-east4` cannot create a conversation at all**, with or without a key,
   despite being listed as a supported location.

**`scripts/repro_conversation_cmek.py` is the artefact to attach to that
report.** It is standalone, takes `--project`, provisions every documented
prerequisite with `--setup`, and *verifies* each one before attempting anything,
so "the setup was wrong" can be excluded before "the platform is broken" is
proposed. For each attempt it prints the request body, the verbatim response and
a replayable `curl` line, and it tries the documented key path and the paired
region side by side so the difference between them is the output rather than the
conclusion. `--revocation` adds the proof that the key holds and that a keyless
conversation in the same location does not.

`layer5/conversation_cmek_probe.py` re-measures this posture on demand and exits
non-zero if the platform stops matching it — including if the documented key
path *starts* working, which is what a fix would look like.

### F9. A partial read must never become a confident verdict

The recurring failure mode in controls of this class is that an unreadable or
partial input collapses into a confident answer, and the answer is "compliant".
Three places where this framework makes "could not determine" a first-class
outcome, in the controls *and* in the tests that verify them:

* Layer 4 **fails closed** — if the `GET` it performs raises, it does not
  conclude the agent is fine.
* Layer 5 **reconciles two sources**, and classifies API-invisible rows
  `NON_COMPLIANT_UNVERIFIABLE` rather than dropping or vouching for them.
* `layer5/reconcile_check.py` exits **INCOMPLETE (exit 2)** rather than guessing
  when the live-API read was partial. That still fails the build, but it must
  not be read as a compliance finding.

The same rule applies to the tests: a gate that silently tests less than it did
last run is worse than one that fails. The content-leak assertion (F5) is made
against `SearchAllResources` rather than `ExportAssets` specifically so it
cannot skip itself when coverage happens to be zero.

### F10. The verification harness must not race the enforcer

The Layer 3 test creates a *compliant* agent and then disables its key, to prove
the key is a real boundary. An enforcing Layer 4 receives the create event
~13–30 s later and performs a `GET`, which fails closed while the key is down —
so it can redact and soft-delete the test's own fixture mid-run.
`tests/run_layer3.sh` therefore checks the enforcer's `DRY_RUN` state and aborts
rather than race. The dependency runs the other way for the Layer 2 test, which
needs Layer 4 enforcing to produce the cross-layer evidence in §2 — which is why
the documented test order is 3 → 4 → 5 → 2.

## 4. Control equivalence and residual risk

**This framework is not equivalent to native CMEK org-policy enforcement, and
must not be presented as such.** Native enforcement prevents a non-compliant
resource from ever existing. This framework detects one seconds after it exists,
scrubs its content, and soft-deletes it.

| | Native org policy | This framework |
| :--- | :--- | :--- |
| Non-compliant resource exists? | Never | Yes, for 13–30 s with content intact |
| After remediation | n/a | Redacted tombstone, retained 30 days, no purge available |
| Failure mode | Request rejected | Detection gap if the sink lags or the key is disabled |

The honest claim is **detection and neutralisation in ~13–30 seconds, with a
redacted tombstone retained for 30 days**. Disclose both the exposure window and
the residual retention to risk and compliance.

**This covers DataAgents only.** The table above, and every number in it, is
about agents. Conversations — the questions, the generated SQL and the returned
rows — sit outside those numbers. They *can* be CMEK-encrypted, but only with a
key in the paired region and only when the caller opts in per conversation, and
Cloud Asset Inventory cannot enumerate them at all (F8). The enforcer does see
them, once Data Access logging is enabled on `cloudaicompanion`, but what it can
*do* differs: there is no content field to redact and delete is irreversible, so
it alerts by default. The agent-side guarantee is "non-compliant for 13–30 s,
then neutralised"; the conversation-side guarantee is "detected in seconds and
reported, neutralised only if you have accepted that deleting a live session is
the right response". Their one favourable property is that `DeleteConversation` is a
**hard** delete, so unlike an agent there is no 30-day readable tombstone and no
residual retention to disclose. Do not let the agent-side numbers be read as
covering the conversation surface; state the two separately.

Two mitigations reduce the exposure rather than eliminate it, and both are
recommended:

1. **Adopt `gcp.resourceLocations`.** It is one of only two org-policy
   constraints the API supports (with `gcp.restrictServiceUsage`). Pinning
   agents to `us-east4`/`us`/`eu` closes the `global` hole natively instead of
   relying on Layer 4 to clean up after the fact.
2. **Keep both Layer 4 and Layer 5.** Layer 4 has real gaps — misconfiguration,
   sink lag, key-disabled invisibility. Layer 5 found five agents Layer 4 missed
   during this exercise alone. `common/gda_common.py` is shared by both so the
   real-time and periodic controls cannot disagree about the same resource.

**Deploy Layer 4 with `DRY_RUN=true` first.** A filter bug in this class of
control deletes compliant production agents (F2). Shadow-mode the enforcer
before switching it to enforcing mode.

## 5. Open questions on conversations

**All four questions below were closed on 2026-08-27**, along with a fifth added
during that work — and **questions 3 and 5 were then answered the other way on
2026-08-30**, when the key was finally supplied in the location the API wants
rather than the one the documentation names. The blocker that had held them open
was misdiagnosed as the validation project lacking Gemini onboarding; it is in
fact that `us-east4` — the framework's default location — cannot create
conversations at all, while `us`, `eu` and `global` can. Once the probes moved to
`us`, everything below became measurable. The answers are folded into F8; they
are summarised here because several of them reverse what earlier sections
assumed.

| Question | Answer |
| :--- | :--- |
| 1. Does `CreateConversation` emit an Admin Activity audit log? | **No.** Nothing under `geminidataanalytics`. The lifecycle appears as `cloudaicompanion` `TopicService.*` **Data Access** logs, off by default, with null request/response payloads. Layer 4 covers it anyway by re-reading the resource, as it already does for agents — the topic ID is the conversation ID. |
| 2. Is `DeleteConversation` soft or hard? | **Hard.** `NotFound` immediately, absent from LIST, and the ID is instantly reusable. No tombstone, no purge window — the opposite of `DeleteDataAgent` (F1). |
| 3. Does key revocation block message content? | **Yes, for a conversation that carries its own key** — blocked at t+5min in `us`, t+2min in `eu`, with the Firestore CMEK error. The *anchor agent's* key does not cover messages; the conversation's own key does. The 2026-08-27 "no" tested only the former, because no conversation could then be given a key. |
| 4. Can the registered key be rotated? | **Version yes, key no.** A new primary key version is accepted. A different key is refused, and disabling every version of the registered key does not free the slot. |
| 5. What encryption does a keyless conversation get? | **Google-managed — and keyless conversations still exist alongside keyed ones.** A conversation created without `kms_key` in a location where a key *is* registered does not inherit it, and stays readable while that key is disabled. |

Question 5 was raised on the assumption that a keyless conversation might
silently inherit a registered key, making "CMEK is optional" cosmetic rather than
real. Measured directly, the opposite is true: the registry constrains *which*
key may be used, and each caller independently decides *whether* to use one. CMEK
on conversations is real, and it is opt-in — which is exactly the combination
that needs a detective control, because nothing about a correctly configured key
reveals that no conversation is using it.

**Still not established.** Whether the two defects behind all of this are
permanent or transient. Google documents conversation CMEK as working in
`us-east4`, `us` and `eu`, so the measured behaviour is a regression against the
published contract rather than a design boundary — which makes "permanent" the
less likely reading of the two. `us-east4`'s inability to create a conversation
reproduced in two unrelated projects on 2026-08-27, one freshly onboarded, which
rules out project-level state but not a regional fault. Re-run
`layer5/conversation_cmek_probe.py` before treating any of it as settled; if
`us-east4` starts creating conversations, or `us`/`eu` start accepting a
same-region key, the key-slot behaviour becomes reachable in a CMEK-capable
location and the whole finding needs re-validation.

## 6. Reproducing

Full prerequisites and the two-project requirement are in
[§10 of design.md](design.md#10-reproducing-this); the command sequence and the
reason the test order is dependency-ordered rather than layer-numbered are in
the [README](../README.md#reproduce-the-validation-tests).

**Expected nondeterminism.** Two things legitimately vary between runs and are
reported rather than asserted: the `ExportAssets` DataAgent row count (F3), and
Layer 4's wall-clock remediation latency (13–30 s observed; the sink → Pub/Sub
hop dominates). Everything else is a hard assertion. A `[SKIP]` in Layer 1 means
OPA or Regal is missing; a `[SKIP]` in Layer 2 means the personas are not
deployed. Layer 5 exiting 2 means the live-API read was partial — re-run it;
that is not a compliance finding.
