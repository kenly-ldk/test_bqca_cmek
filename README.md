# GDA CMEK Enforcement Framework

> **This is an MVP, not an officially supported Google product.** It is a
> reference implementation, built and validated by hand against two disposable
> projects. There is no SLA, no support commitment and no warranty. Review it,
> adapt it, and validate it in your own environment before relying on it for
> anything that matters.

A working, tested MVP that brings Gemini Data Analytics (Conversational
Analytics) under organization-wide **CMEK governance**.

GDA supports CMEK today, and the key holds as a real cryptographic boundary:
revoke it and the agent content becomes unreadable. The piece still to come from
the platform is *org-policy* enforcement — `geminidataanalytics.googleapis.com`
is not yet accepted by `constraints/gcp.restrictNonCmekServices`, so a key is
supplied per resource rather than mandated centrally. This framework supplies
that governance, in five layers.

## The five layers

| Layer | What it does |
| :--- | :--- |
| 1 — CI/CD policy-as-code | Rejects a non-compliant agent manifest in the pipeline, before it reaches the API |
| 2 — IAM least privilege | Limits who can create an agent at all, so there are fewer ways to bypass the pipeline |
| 3 — CMEK at rest | Encrypts agent content under your key, so revoking the key makes it unreadable |
| 4 — Real-time remediation | Catches an agent created outside the pipeline, redacts its content and soft-deletes it |
| 5 — Continuous compliance | Reports the standing CMEK posture for audit, and flags what it could not verify |

Layers 1 and 2 are preventive, 4 and 5 are detective, and 3 is the cryptographic
boundary the other four exist to keep enforced.

**This is not equivalent to native CMEK org-policy enforcement.** Native
enforcement stops a non-compliant resource from ever existing. This framework
detects one seconds after it exists, scrubs its content, and soft-deletes it —
leaving a redacted tombstone for 30 days, because the API has no purge.
Disclose the exposure window and the residual retention to risk and
compliance. See
[§8 Control Equivalence Matrix](docs/design.md#8-control-equivalence-matrix).

**Scope: the five layers are built around `DataAgent` resources.** Stateless
chat creates no resource, so there is nothing for CMEK to hold — Layer 2 governs
who may call it. Stateful **conversations** are a second CMEK-bearing resource
type, and three of the layers do reach them: Layer 1 rejects them from
manifests, Layer 2 gates who may create one, and Layer 5 reports their posture.
Layer 4 cannot see them at all.

What no layer does is provision a conversation's key, because that key is
chosen per conversation at runtime and belongs in a different KMS location from
the agents'. That is why conversations get their own
[deploy step](#part-2--conversations) and
[validation suite](#validating-conversations--a-separate-suite) rather than a
layer. The measured detail is in
[F8](docs/validation-report.md#f8-conversation-cmek-works-but-only-with-an-undocumented-key-location).

## Quick start — Deploy the solution

Stands up a **working demo**: the controls, plus a real CMEK-protected agent
created only after the Layer 1 policy passes its manifest.
[Reproduce the validation tests](#reproduce-the-validation-tests) then runs
against this deployment rather than building its own. The full runbook is
[§11 of design.md](docs/design.md#11-deployment--cutover-runbook); this is the
short form.

Two parts, in order: **[Part 1 — GDA agents](#part-1--gda-agents)** stands up
the five layers, and **[Part 2 — Conversations](#part-2--conversations)** covers
the second resource type, whose key no layer provisions. The install block below
serves both. Which KMS location each resource type needs is tabulated in
[Where the CMEK key goes](#where-the-cmek-key-goes).

Deploying needs `gcloud`, `bq` and Python: `layer3/deploy.sh` evaluates the CMEK
policy in-process, in Python, before it calls the API. OPA and Regal are only
used by the Layer 1 policy's own tests, but the block below installs everything
in one go.

**Install** — versions are pinned deliberately: the policy is Rego v1 (OPA ≥1.0)
and `.regal/` carries a custom rule written against Regal's 0.42 rule API.

```bash
# Layer 1 needs no install. Its CI half ships as a GitHub Actions workflow —
# one implementation of the control, not the control itself. To watch it fire,
# the code has to live in a repo you own: fork this one and clone your fork, or
# repoint this clone afterwards:
#   git remote set-url origin https://github.com/<you>/<your-repo>.git
#   git push -u origin main
# On any other CI you port the same two steps — see "Layer 1" under How it
# works. Everything else here runs fine from a plain clone.
git clone https://github.com/kenly-ldk/test_bqca_cmek.git
cd test_bqca_cmek

# An isolated interpreter, so these client libraries cannot collide with
# anything else on the machine. 3.12 matches the Cloud Function runtime that
# Layer 4 deploys to, so local behaviour and deployed behaviour agree.
pyenv virtualenv 3.12.7 gda-cmek-val && pyenv local gda-cmek-val

# The Google client libraries the local scripts and tests import:
#   layer4/           geminidataanalytics + functions-framework (the enforcer)
#   layer5/scanner/   asset, bigquery      (the compliance scanner)
#   tests/            pytest
# Cloud Build installs the first two again at deploy time; this copy is what
# lets you run layer3/deploy.sh, the probes and the unit tests from your shell.
pip install -r layer4/requirements.txt \
            -r layer5/scanner/requirements.txt \
            -r tests/requirements-dev.txt

# OPA evaluates the Rego policy; Regal lints it and runs the custom rule that
# blocks the regex.find_n trap. Layer 1 is the only layer that needs them, and
# ~/.local/bin keeps the install off the system path — no root required.
mkdir -p ~/.local/bin
curl -sL -o ~/.local/bin/opa   https://github.com/open-policy-agent/opa/releases/download/v1.19.1/opa_linux_amd64_static
curl -sL -o ~/.local/bin/regal https://github.com/StyraInc/regal/releases/download/v0.42.0/regal_Linux_x86_64
chmod +x ~/.local/bin/opa ~/.local/bin/regal
```

### Part 1 — GDA agents

**Deploy.** Configure the estate, then bring the layers up in dependency order.
Each step says which layer it is standing up:

```bash
cp config/shared.env config/shared.env.local   # then edit it; see below

# 1. Preflight — APIs, both Google-managed service agents, the KMS key, and
#    the build roles Layers 4 and 5 need.
bash scripts/00_bootstrap.sh

# 2. Layer 2 — the least-privilege personas. Early on purpose: IAM takes
#    ~60-120 s to propagate, which then overlaps with everything below.
bash layer2/deploy.sh

# 3. Layer 4 — detection and remediation. Always dry-run first: a filter bug in
#    this class of control deletes compliant production agents.
DRY_RUN=true bash layer4/deploy.sh

# 4. Layer 5 — continuous compliance reporting.
bash layer5/deploy.sh

# 5. Layer 3 — a BigQuery datasource, then a CMEK-protected agent. The Layer 1
#    policy checks the manifest first and the API is called only if it passes,
#    which is exactly what a deployment pipeline would do.
bash layer3/deploy.sh

# 6. Layer 4 is watching by now. Confirm from its logs that the new agent was
#    classified COMPLIANT, then switch the enforcer on.
( source scripts/prelude.sh
  gcloud run services update "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
    --region="${LOCATION}" --update-env-vars=DRY_RUN=false )
```

**What you have to change.** `config/shared.env` ships working defaults for
everything except your own identity, and `config/shared.env.local` (gitignored)
overrides only what you set in it:

| Variable | Read by | Notes |
| :--- | :--- | :--- |
| `PROJECT_ID` | everything | The workload project holding the agents, the key and Layers 4–5 |
| `PROJECT_NUMBER` | preflight | Derives the two Google-managed service agents and the Cloud Build identity |
| `APPROVED_KMS_PROJECTS` | Layers 1, 4, 5 | The CMEK allowlist. The policy, the enforcer and the scanner all read the same value, so they cannot disagree |
| `ROGUE_PROJECT_ID` | validation only | A second disposable project. Leave the placeholder unless you are running the test suite |

Everything else — `LOCATION`, `KMS_KEYRING`/`KMS_KEY`, `BQ_DATASET`,
`SCAN_LOCATIONS`, the Pub/Sub topic and function names — comes with a default in
`config/shared.env`. Override any of them in `shared.env.local` if the defaults
do not suit your estate.

### Part 2 — Conversations

**Separate, not optional.** It is separate because no layer provisions this
key, and the agent flow does not depend on any of it — you can deploy, validate
and run all five layers without coming here. Three of them still reach
conversations once those exist: Layer 1 rejects them from manifests, Layer 2
gates who may create one, and Layer 5 reports their posture. Layer 4 cannot see
them. It is not optional because a conversation holds the same customer content
an agent does,
in plainer form: the analyst's question, the generated SQL and the returned
rows. Until this is done, all of it rests under Google-managed encryption, and
no layer above changes that.

It applies to any estate where a conversation can be created. Creation is gated
by `cloudaicompanion.topics.create`, which 16 predefined roles carry, including
`bigquery.studioUser` and `iam.dataScientist`, and no `geminidataanalytics`
permission controls it ([§6.2](docs/design.md#62-persona-model)).

There is exactly one deployable thing here — the key, in the paired region the
conversation surface requires rather than the agents' locations
([Where the CMEK key goes](#where-the-cmek-key-goes)):

```bash
bash scripts/02_conversation_key.sh   # paired-region keys + service-agent grants
```

**There is no conversation to deploy.** Conversations are ephemeral runtime
resources, created per user session by your application and hard-deleted;
Layer 1 rejects any manifest that declares one. So the pipeline provisions the
key, and the application decides — per conversation, at runtime — whether to use
it. That is the whole difference from the agent flow, where the key is
immutable, set at creation by the pipeline, and therefore knowable in advance.

In your application, the part that matters:

```python
client = geminidataanalytics.DataChatServiceClient(   # the `us` endpoint,
    client_options=ClientOptions(                     # not the global one
        api_endpoint="geminidataanalytics.us.rep.googleapis.com"))

conversation = geminidataanalytics.Conversation(
    agents=[f"projects/{project}/locations/us/dataAgents/{agent_id}"],
)
conversation.kms_key = (
    f"projects/{kms_project}/locations/us-central1"    # the PAIRED region.
    f"/keyRings/gda-kr/cryptoKeys/agent-key"           # `us` is rejected here.
)

client.create_conversation(
    request=geminidataanalytics.CreateConversationRequest(
        parent=f"projects/{project}/locations/us",
        conversation_id=conversation_id,
        conversation=conversation,
    )
)
```

**Omit `kms_key` and the conversation is simply unencrypted.** It does not
inherit the key registered for the project and location — it stays readable
while that key is disabled. CMEK on conversations is opt-in per conversation,
which is why this is a detective control rather than a preventive one:

| | Agents | Conversations |
| :--- | :--- | :--- |
| Layer 1 gates the manifest | yes | n/a — rejects them outright |
| Layer 4 detects and remediates | yes, 13–30 s | **never** — the create emits no `geminidataanalytics` audit log |
| Layer 5 reports the posture | yes | yes, hourly, per location |

So an unkeyed conversation is *reported* and never remediated. Contain the rest
with project segregation and an IAM deny policy on
`cloudaicompanion.topics.create` — the permission model lives in a different
service, and 16 predefined roles carry it
([§6.2](docs/design.md#62-persona-model)).

## How it works

The commands above stand up all five layers. Taken in layer order rather than
run order, this is what each one does.

### Layer 1 — the policy gate

Layer 1 has no deploy step because it is code, not infrastructure. It runs in
two places:

* **Locally**, inside `layer3/deploy.sh`, which calls `layer1/render.sh` and
  then `layer1/apply_manifest.py`. The policy is evaluated in-process and the
  API is never called at all if the manifest violates it.
* **In CI**, where `.github/workflows/cmek-policy.yml` runs the same policy on
  every pull request. Its `policy` and `unit` jobs need no configuration, so a
  fork goes green on the first push.

**The control is the rule, not the runner.** The goal is that no manifest
violating the CMEK policy ever reaches the API; GitHub Actions is only how this
repo demonstrates it. Two portable pieces carry it to any other system:
`opa eval` against `layer1/policy.rego` for the pre-merge check, and
`python -m layer1.apply_manifest` for the apply step. The second re-evaluates
the same rules in-process, so the gate still holds if the CI check is skipped or
misconfigured — wire those into GitLab CI, Cloud Build, Jenkins or a pre-commit
hook and Layer 1 is intact.

That workflow also has an optional `deploy` job which applies manifests on push
to `main`. Enable it with four GitHub repository variables — `WIF_PROVIDER`,
`DEPLOY_SERVICE_ACCOUNT`, `PROJECT_ID` and `APPROVED_KMS_PROJECTS`. Without them
it skips cleanly rather than failing, so the workflow is useful with or without
a GCP connection.

### Layer 2 — the personas

`layer2/deploy.sh` creates five service accounts and a `gdaConversationUser`
custom role, which exists because no predefined role can create a conversation
at least privilege. The behavioural probe then impersonates each persona in turn
and records what it actually can and cannot do.

Those five are *throwaway* identities (`layer2-analyst`, `layer2-no-access`, …)
built for the probe. Right for a demo estate, wrong for a production one — see
[Adapting this to your own estate](#adapting-this-to-your-own-estate).

### Layer 3 — how the agent gets its key

`00_bootstrap.sh` creates the key and grants it to the two service agents that
need it. Those are **Google-managed** —
`service-<PROJECT_NUMBER>@gcp-sa-geminidataanalytics.iam.gserviceaccount.com`
and `...@gcp-sa-cloudaicompanion.iam.gserviceaccount.com`. They are derived from
your `PROJECT_NUMBER`, so nothing is hardcoded to any one project, but you
cannot substitute a service account of your own: CMEK requires the grant on
those exact identities.

`layer3/deploy.sh` then creates an agent that uses the key. Between those two
steps, Layer 3 is simply a rule about how agents get created: every agent
carries a `kms_key` in an approved project, in a location that supports CMEK
(`us-east4`, `us`, `eu` — never `global`). The script renders
`layer1/manifests/agents.json` from the committed template, runs it through the
CMEK policy, and only then calls the API — so it exercises Layers 1 and 3
together. In code, the part that matters:

```python
agent = geminidataanalytics.DataAgent(
    display_name="Wealth Management Analytics Agent",
    data_analytics_agent=geminidataanalytics.DataAnalyticsAgent(
        published_context=published_context,
    ),
)
agent.kms_key = (
    f"projects/{kms_project}/locations/us-east4"
    f"/keyRings/gda-kr/cryptoKeys/agent-key"
)

client.create_data_agent_sync(       # target this location's own endpoint,
                                     # never the global one
    request=geminidataanalytics.CreateDataAgentRequest(
        parent=f"projects/{project}/locations/us-east4",
        data_agent_id="wealth-management-agent",
        data_agent=agent,
    )
)
```

**The key can only be set at creation** — it cannot be added or changed
afterwards, which is exactly what makes Layer 4's read-back check trustworthy.
Endpoint selection is covered in
[§4.1](docs/design.md#41-supported-locations-and-endpoints--mandatory).

**CMEK is not an access control**, and assuming otherwise is the most common way
to misread this. Encryption at rest is orthogonal to who may call the API: the
two Google-managed service agents decrypt on your behalf, so a caller needs no
KMS permission at all. The Layer 2 matrix proves it — the `analyst` persona
holds `dataAgentViewer` and no KMS binding of any kind, and reads the
CMEK-encrypted agent successfully.

What the key gives you instead is a **kill switch**: disable it and nobody can
read that agent — not the analyst, not an admin, not the service itself — and
`LIST` stops returning it at all. That is revocation, crypto-shredding, key
custody and an audit trail on key use. It is not authorization. Layer 2 decides
who may call the API; Layer 3 decides whether the data is readable at all, and
you need both.

### Layer 4 — detect and remediate

A log sink matches `CreateDataAgent` audit entries and publishes them to
Pub/Sub, which triggers a Cloud Function. The function does **not** trust the
audit payload: it re-reads the agent on its regional endpoint, because
`kms_key` is immutable after creation and the server's value is therefore
authoritative. If that read fails it fails closed rather than assuming
compliance. A non-compliant agent has its content redacted — twice, since one
pass only rotates it into the read-only `lastPublishedContext` — and is then
soft-deleted. End to end, 13–30 s.

It runs in one of two modes, set by the `DRY_RUN` environment variable on its
Cloud Run service:

| Mode | `DRY_RUN` | Behaviour |
| :--- | :--- | :--- |
| **Enforcing** | `false` | Actually redacts and soft-deletes non-compliant agents |
| **Dry-run** | `true` | Logs what it *would* do, changes nothing |

`layer4/deploy.sh` deploys in **enforcing** mode unless you set `DRY_RUN=true`,
which is why the quick start sets it explicitly. Dry-run first is not caution
for its own sake: a filter that matches both audit entries of a long-running
operation (LRO) reads the trailing one as "no key" and deletes a **compliant**
agent —
[F2](docs/validation-report.md#f2-createdataagent-emits-two-different-audit-log-shapes).
Watch it classify your own agents correctly before giving it the power to act.

This is why the agent goes in *before* the enforcer is switched on: Layer 4 is
already running in shadow mode when the agent is created, so you get to watch a
real create event flow through it and be judged COMPLIANT before it has the
power to delete anything.

### Layer 5 — continuous compliance

An hourly Cloud Run job builds an inventory from two independent sources — Cloud
Asset Inventory (with a metadata-only read mask, so it never copies agent
content into BigQuery) and the live API — writes them to BigQuery, and
classifies every row in the `v_agent_compliance` view. Two sources rather than
one because a disabled key removes an agent from the live `LIST` with no error;
anything the API cannot show is reported `NON_COMPLIANT_UNVERIFIABLE` rather
than dropped or vouched for.

It also emits one row per location for **conversations**, if any exist. That
half is single-sourced by necessity — Cloud Asset Inventory has no Conversation
asset type — and it reads every conversation's key rather than one of them,
because CMEK there is opt-in per conversation. A location fails if any single
conversation in it is unkeyed.

> Layers 1, 2 and 4 exist to make Layer 3's rule hold. Layer 5 is how you know
> whether it did.

## Reproduce the validation tests

These tests validate **the deployment you just made** — they do not stand up a
second one. They do add two things on top of it: a second project holding a
deliberately unapproved key, and their own *non-compliant* agents, because
proving Layer 4 removes those is the whole point of the exercise. Expect
soft-deleted tombstones afterwards, so run this against a disposable estate.
Verdicts are in [Test status](#test-status) below.

**Offline first.** No GCP project, no credentials — the toolchain from
[Deploy](#quick-start--deploy-the-solution) is all you need. This covers the
Layer 1 policy and the in-process gate that enforces it, plus every Python unit
test. The one thing it cannot cover is the CI wiring itself: only a real pull
request proves the workflow fires.

In this repo that wiring is **GitHub Actions**
(`.github/workflows/cmek-policy.yml`), which is how the demo happens to run
Layer 1 — not part of the control. The two portable pieces are `opa eval`
against `layer1/policy.rego` and `python -m layer1.apply_manifest`; port those
to GitLab CI, Cloud Build, Jenkins or a pre-commit hook and Layer 1 is intact.
See [Layer 1](#layer-1--the-policy-gate).

```bash
bash tests/run_unit.sh            # 96 unit tests
bash tests/run_layer1.sh          # policy: compile, lint, unit tests, gate
```

**Add what the tests need.** The personas are already up from the deployment
above. The one thing still missing is a second, disposable project holding a
deliberately unapproved key — set `ROGUE_PROJECT_ID` in
`config/shared.env.local` first.

```bash
bash scripts/01_test_fixtures.sh   # the unapproved key the negative tests need
```

**Run the suite.** The order below is **dependency-ordered, not
layer-numbered** — the two dependencies that fix it are explained right after
the block.

```bash
# Layer 3's test must not race an enforcing Layer 4, so put it in dry-run first.
# The subshell keeps prelude.sh's `set -euo pipefail` out of your own shell.
( source scripts/prelude.sh
  gcloud run services update "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
    --region="${LOCATION}" --update-env-vars=DRY_RUN=true )

bash tests/run_layer3.sh

( source scripts/prelude.sh
  gcloud run services update "${FUNCTION_NAME}" --project="${PROJECT_ID}" \
    --region="${LOCATION}" --update-env-vars=DRY_RUN=false )

bash tests/run_layer4.sh
bash tests/run_layer5.sh          # incl. the key-revocation proof
bash tests/run_layer2.sh          # last: needs Layer 4 enforcing

bash scripts/99_teardown.sh       # deletes both projects; prompts
```

### Why the test order jumps 3 → 4 → 5 → 2

Each `tests/run_layerN.sh` verifies Layer N — but a test usually has to *do*
something the layer itself never does, and that is what couples them. Two hard
dependencies, in opposite directions:

* **The Layer 3 test must run before Layer 4 is enforcing.** It creates a
  *compliant* agent and then revokes its CMEK key, to prove the key is a real
  boundary. The enforcer's event for that create arrives ~13–30 s later and does
  a `GET`, which fails closed while the key is down — so an enforcing Layer 4
  can redact and soft-delete the test's own compliant fixture mid-run.
  `tests/run_layer3.sh` aborts rather than race.
  See [F10](docs/validation-report.md#f10-the-verification-harness-must-not-race-the-enforcer).
* **The Layer 2 test must run after it.** Its `create` probe makes a key-less
  agent as the pipeline persona, and an enforcing Layer 4 then remediates it —
  naming `layer2-cicd-deployer@...` as the caller. That is the defence-in-depth
  story in one log line, and you only see it in this order.

Everything else follows: the Layer 4 test before the Layer 5 test, so the
scanner has remediation history to reconcile against.

### Validating conversations — a separate suite

Pairs with
[the conversation deploy step](#part-2--conversations).
Nothing here is part of the five-layer suite above, and none of it has to run in
any particular order relative to it — but if you deployed the conversation key,
run this too. It is the only thing that tells you the key is doing anything.

```bash
# Posture check: is the paired-region rule still the rule, is CMEK still opt-in,
# and can us-east4 still not host a conversation? Non-destructive. Exits
# non-zero on drift, so it is safe to wire into CI.
python -m layer5.conversation_cmek_probe
```

The agent equivalent of `run_layer3.sh` — proving the key is a real boundary by
revoking it rather than by reading a field back — is a separate flag, because it
disables a live KMS key version for several minutes:

```bash
python -m layer5.conversation_cmek_probe --revocation
```

It creates a keyed conversation **and a keyless control**, puts real content in
both, then disables the key. The keyed one goes dark within a few minutes; the
control stays readable throughout. Both halves matter: the first shows CMEK
holds, the second shows it only holds for conversations that asked for it.

To reproduce the platform defects themselves — the rejected documented key path
and the `us-east4` outage — in a project of your own, and get output you can
attach to a support case:

```bash
python scripts/repro_conversation_cmek.py --project YOUR_PROJECT --setup
```

It is standalone (two pip packages, raw REST, nothing from this repo), verifies
every documented prerequisite before testing anything, runs the documented key
path and the paired region side by side, prints replayable `curl` lines, and
exits non-zero if a documented case succeeds — so it doubles as the check for
whether this finding has gone stale.

## Test status

Every layer was built and executed against two purpose-created GCP projects —
nothing here is designed but untested. Each layer has a test in `tests/` that
you can re-run yourself.

* **Five-layer end-to-end run: 2026-08-25, all passing.** The offline gates
  (`run_unit.sh`, `run_layer1.sh`) have been re-run since; the live layer tests
  have not been re-executed against a deployed estate after the conversation
  work below.
* **Conversation surface: measured 2026-08-30** in a third, purpose-created
  project — the paired-region key rule, the revocation proof with a keyless
  control, and the `us-east4` outage. `layer5/conversation_cmek_probe.py` and
  `scripts/repro_conversation_cmek.py` were both run end to end there.

| Test | What it verifies | Result |
| :--- | :--- | :--- |
| `run_unit.sh` | The shared compliance verdict, audit-log parsing and reconciliation matrix — offline, no GCP project needed | 96/96 |
| `run_layer1.sh` | Layer 1 — Regal-linted policy, 35 policy unit tests, policy-gated deploy step | 14/14 |
| `run_layer2.sh` | Layer 2 — 45-cell persona × operation matrix, live under impersonation, incl. conversations | 45/45 |
| `run_layer3.sh` | Layer 3 — proven by revoking the key, not by inspecting a field | 6/6 |
| `run_layer4.sh` | Layer 4 — ~13–30 s detect → redact → soft-delete, incl. a compliant agent that must survive | 7/7 |
| `run_layer5.sh` | Layer 5 — two reconciled sources, proven by key revocation; conversation CMEK rules re-measured | Passing |

## Where the CMEK key goes

`DataAgent` and `Conversation` take their CMEK keys in different KMS locations.

The two services use different location names. Cloud KMS has `global`, the
multi-regions `us`, `europe` and `asia`, and regions such as `us-central1`;
it has no `eu`. GDA has `global`, the multi-regions `us` and `eu`, and regions,
of which `us-east4` is the one that supports CMEK.

**Where the key must live:**

| GDA resource location | `DataAgent` key | `Conversation` key |
| :--- | :--- | :--- |
| `global` | none accepted; the resource can be created without one | none accepted; the resource can be created without one |
| `us` (multi-region) | key in `us` (multi-region) | key in `us-central1` |
| `eu` (multi-region) | key in `europe` (multi-region) | key in `europe-west1` |
| `us-east4` (region) | key in `us-east4` | n/a — `us-east4` does not create conversations |

**What that means per KMS location type:**

| KMS location | Accepted for a `DataAgent`? | Accepted for a `Conversation`? |
| :--- | :--- | :--- |
| `global` | No — `Global KMS keys are not allowed for Data Agent` | No |
| Multi-region `us` | Yes, for a `us` agent | No — rejected for a `us` conversation |
| Multi-region `europe` | Yes, for an `eu` agent | No — rejected for an `eu` conversation |
| Multi-region `eu` | Does not exist in Cloud KMS | Does not exist in Cloud KMS |
| Region `us-central1` | No — rejected for a `us` agent | Yes, for a `us` conversation |
| Region `europe-west1` | No — rejected for an `eu` agent | Yes, for an `eu` conversation |
| Region `us-east4` | Yes, for a `us-east4` agent | n/a |
| Any other region | No | No |

### "A `us` conversation" means the conversation's own location — not its agent's

The first column above is the location of the resource **being created**. For a
conversation that is the `parent` argument of `CreateConversation`, and `parent`
is a project-and-location path. **A conversation's parent is not its agent.**
The agent is a reference carried in the request body, and it has no bearing on
which key is accepted:

```text
parent     projects/PROJECT/locations/us
           the conversation's own location — this is what sets the key rule

agents[0]  projects/PROJECT/locations/eu/dataAgents/AGENT
           a reference, not the parent — any location, no effect on the key

kms_key    projects/PROJECT/locations/us-central1/keyRings/KR/cryptoKeys/K
           accepted: us-central1 is the paired region of the PARENT, `us`
```

Measured: that exact combination is created successfully. Swapping `kms_key` to
`europe-west1` — the paired region of the *agent* — is rejected with `KMS key
must be in the same location as parent`. Keyless creates in `us` succeed against
agents in `us`, `eu` and `us-east4` alike.

Two consequences follow:

* **A `us-east4` agent can still be used conversationally**, even though
  `us-east4` cannot host a conversation. Host the conversation in `us` and key
  it with `us-central1`; reference the `us-east4` agent from it.
* **An agent's `kms_key` and a conversation's `kms_key` are separate fields on
  separate resources.** Neither supplies nor implies the other, and a
  CMEK-protected agent does not make its conversations CMEK-protected.

The two resource types reject with different messages. A `Conversation` returns
`The request was invalid: KMS key must be in the same location as parent`. A
`DataAgent` returns `KMS key location must match agent location.`, wrapped in a
`BadRequestException`, except for a `global` key, which returns the message
quoted in the table. All are HTTP 400 at creation, and `kms_key` can only be set
at creation. Serving both resource types in one multi-region therefore takes two
key rings, in two KMS locations.

Google's CMEK documentation gives one rule for both resource types — the key and
the resource in the same location — and its sample conversation body builds the
key path from the conversation's own location. That path is rejected in `us` and
`eu`. The paired regions in the `Conversation` column above are measured, across
13 KMS locations for `us` and 11 for `eu`; see
[F8](docs/validation-report.md#f8-conversation-cmek-works-but-only-with-an-undocumented-key-location)
and [§4.1](docs/design.md#41-supported-locations-and-endpoints--mandatory).

Two API behaviours to know before submitting a conversation key:

* The API holds **one registered key per project per location**. The first key
  submitted to `CreateConversation` is registered, including when that call
  fails for another reason. Later keys are rejected. Disabling the key does not
  release the registration, and no API call resets it. The permission required
  is `cloudaicompanion.topics.create`, which 16 predefined roles carry.
* Key *versions* rotate normally — the registration pins the `cryptoKey`, not
  the version.

## Repository layout

| Path | Purpose |
| :--- | :--- |
| `config/` | `shared.env` (committed) + `shared.env.local` (gitignored) + loader |
| `scripts/prelude.sh` | Bash counterpart of the Python env loader |
| `scripts/00_bootstrap.sh` | Production preflight: APIs, service agents, KMS key, build IAM |
| `scripts/01_test_fixtures.sh` | Validation-only: the unapproved key and CAI export grants |
| `scripts/02_conversation_key.sh` | The paired-region KMS keys the conversation surface needs (separate from the five layers) |
| `common/gda_common.py` | Endpoint resolution + the single compliance verdict |
| `layer1/` | OPA policy, unit tests, manifests, policy-gated deploy step |
| `.regal/` | Regal lint config + a custom rule blocking the `regex.find_n` capture-group trap |
| `layer2/` | Persona service accounts and the IAM behavioural probe |
| `layer3/` | Agent deploy (`deploy.sh`), CMEK fixtures and the key-revocation proof |
| `layer4/` | Remediation function, log sink, deploy |
| `layer5/` | Compliance scanner, BigQuery DDL and view, deploy |
| `tests/` | Per-layer gates + `unit/` (offline Python tests) |
| `.github/workflows/` | Reference CI pipeline for Layers 1 and 2 |

`common/gda_common.py` is deliberately the only place compliance is decided, so
the real-time enforcer and the periodic report cannot disagree about the same
resource. The deploy scripts copy it into each build context.

## Adapting this to your own estate

This repo is built as a validation estate, so not all of it is meant to be
reused as-is. What transfers directly, what needs adapting, and what must never
run against a project you care about:

| Component | Reuse as-is? | Notes |
| :--- | :--- | :--- |
| `layer1/policy.rego`, `layer1/apply_manifest.py` | **Yes** | `.github/workflows/cmek-policy.yml` is a runnable **GitHub Actions reference pipeline** — copy it and adapt the auth step. Point `layer1/config/approved-kms-projects.json` at your own KMS projects |
| `scripts/00_bootstrap.sh` | **Yes** | Production preflight only: APIs, the two service agents, the approved KMS key, and the build roles Layers 4 and 5 need |
| `layer3/deploy.sh` | **Sample** | The table and agent it creates are samples. Replace them with your own datasource and manifest; keep the `render.sh` → `apply_manifest.py` pattern |
| `scripts/01_test_fixtures.sh` | **No** | Validation only — the deliberately unapproved "rogue" key and CAI export grants. Never run it against a project you care about |
| `scripts/02_conversation_key.sh` | **Yes** | Production preflight for the conversation surface: paired-region key rings and the two service-agent grants. Independent of the five layers, but not optional if any conversation is ever created in the estate |
| `layer2/deploy.sh` | **No** | It creates five *test personas* for the behavioural probe. Apply the persona model from [§6.2](docs/design.md#62-persona-model) to your real principals instead. The one piece worth lifting is the `gdaConversationUser` custom role it defines |
| `layer4/` | **Yes** | Log sink → Pub/Sub → remediation function. Nothing to change beyond `config/shared.env.local` |
| `layer5/` | **Yes** | Set `SCAN_LOCATIONS` and `APPROVED_KMS_PROJECTS` for your estate |
| `tests/run_layer*.sh` | **As acceptance tests** | They create and delete real agents, so point them at a non-production project |

## Going deeper

This README is the overview. The three documents below are the detail behind it.

* **[docs/design.md](docs/design.md)** — the deep dive. Architecture, per-layer
  component detail, the IAM persona model, which org-policy constraints the API
  actually supports, a control-equivalence matrix, and a cutover runbook for
  when native enforcement ships.
* **[docs/validation-report.md](docs/validation-report.md)** — the evidence.
  What was measured, the ten platform behaviours any control of this class has
  to design around (`F1`–`F10`), and the residual risk to put in front of risk
  and compliance.
* **[docs/gotchas.md](docs/gotchas.md)** — twenty things that will cost you
  time. The practical surprises, in one line each: soft delete, two-pass
  redaction, the endpoint rules, and the conversation permission and CMEK model
  that live in a different service entirely and follow their own key-location
  rule.
