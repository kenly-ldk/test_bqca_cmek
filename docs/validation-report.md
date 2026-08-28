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
| 1 — CI/CD policy-as-code | **PASS** 14/14 | `tests/run_layer1.sh`; Rego v1 policy, Regal-linted, 30 policy unit tests, gated deploy step |
| 2 — IAM least privilege | **PASS** 45/45 | `tests/run_layer2.sh`; 45-cell persona × operation matrix executed live under impersonation |
| 3 — CMEK at rest | **PASS** 6/6 | `tests/run_layer3.sh`; proven by key revocation, not field inspection |
| 4 — Real-time remediation | **PASS** 7/7 | `tests/run_layer4.sh`; 13–30 s detect → redact → soft-delete across six runs |
| 5 — Continuous compliance | **PASS** | `tests/run_layer5.sh`; two reconciled sources, proven by a live key-revocation proof |

Cutting across all five, **`tests/run_unit.sh` passes 93/93** offline, with no
GCP project: the shared compliance verdict, the enforcer's audit-log parsing and
every quadrant of the scanner's reconciliation matrix. It is not a layer — it is
the unit suite for the logic the layers share.

| Environment | |
| :--- | :--- |
| Workload project | purpose-created, disposable (`WORKLOAD_PROJECT` below) |
| Unapproved-KMS project | purpose-created, holds only an out-of-allowlist key (`ROGUE_PROJECT`) |
| Organization | Google Cloud sandbox org with common guardrail policies enforced |
| Location | `us-east4` and `us`, plus `global` as a negative control |
| Approved key | `projects/WORKLOAD_PROJECT/locations/us-east4/.../cryptoKeys/agent-key`, with a `us` counterpart |
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
every Layer 4 run. `us` was measured subsequently — a key-bearing agent was
created successfully in the multi-region — so `us-east4` and `us` are both
measured. **`eu` is in the API's documented CMEK set and is swept by the Layer 5
scanner, but no key-bearing agent was created there: treat it as documented
rather than measured.**

### F7. The cloudaicompanion service must be enabled

CMEK for data agents requires `cloudaicompanion.googleapis.com` to be enabled
and its service agent
(`service-<NUM>@gcp-sa-cloudaicompanion.iam.gserviceaccount.com`) to hold
`cryptoKeyEncrypterDecrypter` on every key. The service agent does not exist
until the API is enabled, so this is a bootstrap ordering requirement.

### F8. Conversations are a second CMEK surface, governed differently

Conversations are not data agents and the agent controls do not cover them:

* **The conversation CMEK key is a singleton per project + location** — not per
  resource. The API rejects any second key, including another key in the same
  project. Verified: a foreign key and a same-project-other key are both
  `REJECTED_BY_KMS_PIN`. This is *stricter* than
  `restrictCmekCryptoKeyProjects`. Supplying **no** key is still accepted, which
  is the residual gap. There is therefore nothing per-conversation to enforce:
  the control is an attestation of the one registered key.
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

The practical containment is to dedicate projects to agents and conversations
and let the CMEK attestation be the backstop.

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
about agents. Do not let them be read as covering any other resource type.

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

The validation project had no conversation surface onboarded, so the following
require confirmation in an onboarded project before the conversation posture is
claimed complete:

1. Does `CreateConversation` emit an Admin Activity audit log? If conversations
   are not audited, Layer 4 can never cover them — largely moot given the
   singleton key, but it should be stated rather than assumed.
2. Is `DeleteConversation` soft or hard? If it is soft like `DeleteDataAgent`
   (F1), "ephemeral" is not what it appears and the retention story changes.
3. Does key revocation block message content? Proven for agent context (§2);
   unproven for messages.
4. Can the singleton key be rotated, and what happens to conversations
   encrypted under the previous key?

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
