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

## Quick start — Deploy the solution

Stands up a **working demo**: the controls, plus a real CMEK-protected agent
created only after the Layer 1 policy passes its manifest.
[Reproduce the validation tests](#reproduce-the-validation-tests) then runs
against this deployment rather than building its own. The full runbook is
[§11 of design.md](docs/design.md#11-deployment--cutover-runbook); this is the
short form.

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

```bash
bash tests/run_unit.sh            # 93 unit tests
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

## Test status

Every layer was built and executed against two purpose-created GCP projects —
nothing here is designed but untested. Each layer has a test in `tests/` that
you can re-run yourself. Last full end-to-end run: **2026-08-25, all passing.**

| Test | What it verifies | Result |
| :--- | :--- | :--- |
| `run_unit.sh` | The shared compliance verdict, audit-log parsing and reconciliation matrix — offline, no GCP project needed | 93/93 |
| `run_layer1.sh` | Layer 1 — Regal-linted policy, 30 policy unit tests, policy-gated deploy step | 14/14 |
| `run_layer2.sh` | Layer 2 — 45-cell persona × operation matrix, live under impersonation, incl. conversations | 45/45 |
| `run_layer3.sh` | Layer 3 — proven by revoking the key, not by inspecting a field | 6/6 |
| `run_layer4.sh` | Layer 4 — ~13–30 s detect → redact → soft-delete, incl. a compliant agent that must survive | 7/7 |
| `run_layer5.sh` | Layer 5 — two reconciled sources, proven by key revocation; conversation key attested | Passing |

## Repository layout

| Path | Purpose |
| :--- | :--- |
| `config/` | `shared.env` (committed) + `shared.env.local` (gitignored) + loader |
| `scripts/prelude.sh` | Bash counterpart of the Python env loader |
| `scripts/00_bootstrap.sh` | Production preflight: APIs, service agents, KMS key, build IAM |
| `scripts/01_test_fixtures.sh` | Validation-only: the unapproved key and CAI export grants |
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
| `layer2/deploy.sh` | **No** | It creates five *test personas* for the behavioural probe. Apply the persona model from [§6.2](docs/design.md#62-persona-model) to your real principals instead. The one piece worth lifting is the `gdaConversationUser` custom role it defines |
| `layer4/` | **Yes** | Log sink → Pub/Sub → remediation function. Nothing to change beyond `config/shared.env.local` |
| `layer5/` | **Yes** | Set `SCAN_LOCATIONS` and `APPROVED_KMS_PROJECTS` for your estate |
| `tests/run_layer*.sh` | **As acceptance tests** | They create and delete real agents, so point them at a non-production project |

## Going deeper

This README is the overview. The two documents below are the detail behind it.

* **[docs/design.md](docs/design.md)** — the deep dive. Architecture, per-layer
  component detail, the IAM persona model, which org-policy constraints the API
  actually supports, a control-equivalence matrix, and a cutover runbook for
  when native enforcement ships.
* **[docs/validation-report.md](docs/validation-report.md)** — the evidence.
  What was measured, the ten platform behaviours any control of this class has
  to design around (`F1`–`F10`), and the residual risk to put in front of risk
  and compliance.

## Eleven things that will cost you time

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
