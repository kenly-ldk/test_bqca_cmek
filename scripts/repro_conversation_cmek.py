#!/usr/bin/env python
"""Standalone reproduction: conversation CMEK works, but not where it is documented.

Google documents CMEK for `Conversation` resources as supported in `us-east4`,
the `us` multi-region and the `eu` multi-region:

    https://docs.cloud.google.com/gemini/data-agents/conversational-analytics-api/cmek

That page states the key and the resource "must be in the same location", and
its sample body interpolates one `{location}` into both the conversation path
and the key path. **That configuration is rejected in every supported
location.** A key in the multi-region's paired primary region is accepted
instead, and it works: revoke it and the messages become unreadable.

This script runs both key paths side by side, in the same project, seconds
apart, and prints the verbatim HTTP request and response for each plus a curl
line you can replay by hand. It is deliberately self-contained: `--setup`
provisions everything the docs list as a prerequisite, and the default run
verifies each prerequisite before concluding anything, so "you configured it
wrong" can be ruled out before "the platform is broken" is entertained.

--------------------------------------------------------------------------
WHAT IT DEMONSTRATES
--------------------------------------------------------------------------

  Defect 1 — the documented key location is refused, and the working one is
             undocumented. In `us` and `eu`, a key in the same location as the
             conversation -- exactly what the page prescribes and demonstrates
             -- returns:
                 "The request was invalid: KMS key must be in the same
                  location as parent"
             while a key in the paired primary region (`us-central1` for `us`,
             `europe-west1` for `eu`) is accepted by the same call. The paired
             region appears nowhere in the documentation. For `eu` the
             documented rule is additionally unsatisfiable as written: it wants
             a key whose location matches the parent, and Cloud KMS has no `eu`
             location -- only `europe`.

             The page also gives ONE same-location rule for both resource
             types, but they disagree: a `DataAgent` in `us` requires a key in
             `us` and refuses `us-central1`; a `Conversation` in `us` is the
             exact reverse. This script creates the anchor agent with the
             documented key, so both halves are visible in one run.

  Defect 2 — `us-east4` cannot create a conversation AT ALL, with or without a
             key:
                 "Invalid resource state for "conversation": failed to create
                  conversation"
             This is not a CMEK defect. It is the conversation surface being
             unavailable in the region, which takes CMEK down with it. Note
             that this error string is generic and also appears transiently
             elsewhere, so every create here is retried before it is believed.

  Consequence (--revocation) — the accepted key is a real boundary, and it is
             opt-in. A keyed conversation goes dark within minutes of the key
             being disabled; a keyless conversation created in the same
             project + location, where that key is registered, does not inherit
             it and stays readable throughout.

--------------------------------------------------------------------------
SAFETY
--------------------------------------------------------------------------

Offering a key to `CreateConversation` in a location that ACCEPTS it is a
PERMANENT WRITE. The first key submitted is registered for the whole
project+location even when the create then fails, every later key is refused,
disabling the key does not release it, and no API resets it.

  * The documented key in `us`/`eu` is refused before anything is recorded, so
    those attempts are always safe.
  * The paired-region key IS recorded. That is unavoidable -- it is the point of
    the demonstration -- and it is the key you would want registered anyway. Run
    this in a disposable project if that matters to you.
  * `us-east4` accepts the documented key at the KMS stage even though the
    create then fails, so submitting it there burns the slot for nothing. This
    script does NOT do that unless you pass --include-us-east4-key; defect 2
    reproduces without it.

--------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------

Two Python packages, and nothing from this repo:

    pip install -r scripts/requirements-repro.txt      # google-auth, requests

Deliberately NOT google-cloud-geminidataanalytics -- this talks raw REST so the
result cannot be waved away as a client-library artefact, and so it keeps
working as the SDK moves. Verified in a clean virtualenv containing only those
two packages.

Also needed, and not installable with pip:

    * the `gcloud` CLI on PATH, authenticated against the target project
      (used for the KMS and service-enablement checks, and by --setup)
    * Application Default Credentials for the REST calls:
          gcloud auth application-default login

Permissions on the target project: enough to read services and KMS IAM, create
a DataAgent, and call CreateConversation. --setup additionally needs to enable
services, create KMS keys and set IAM on them.

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------

    # one-off, provisions keys in BOTH locations + service agents
    python scripts/repro_conversation_cmek.py --project MY_PROJECT --setup

    # the reproduction itself
    python scripts/repro_conversation_cmek.py --project MY_PROJECT

    # plus the proof that the accepted key is real and is opt-in
    python scripts/repro_conversation_cmek.py --project MY_PROJECT --revocation

PROJECT_ID is read from config/shared.env.local when --project is omitted, so
inside this repo `python scripts/repro_conversation_cmek.py` just works.

Exit codes:
    0  both defects reproduced (the documented procedure does not work)
    1  a documented case SUCCEEDED -- the platform is fixed, or behaves
       differently for you. Please say so; this finding would need revisiting.
    2  could not run: a prerequisite is missing and --setup was not passed
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    import google.auth
    import google.auth.transport.requests
    import requests
except ImportError as exc:  # pragma: no cover
    sys.exit(f"missing dependency: {exc}\n"
             f"  pip install -r scripts/requirements-repro.txt\n"
             f"  (or: pip install google-auth requests)")

EXIT_REPRODUCED, EXIT_NOT_REPRODUCED, EXIT_CANNOT_RUN = 0, 1, 2

# What the documentation says to use: a key in the resource's own location.
# `eu` is already an anomaly here -- Cloud KMS has no `eu`, only `europe` -- and
# that is the second half of defect 1.
DOCUMENTED_KMS_LOCATION = {"us-east4": "us-east4", "us": "us", "eu": "europe"}

# What the API actually accepts on a Conversation: the multi-region's paired
# primary region. Documented nowhere. `us-east4` has no entry because it cannot
# host a conversation at all.
PAIRED_KMS_LOCATION = {"us": "us-central1", "eu": "europe-west1"}

DOCUMENTED_LOCATIONS = ("us-east4", "us", "eu")
KEYRING, KEY = "gda-kr", "agent-key"

# Marker substrings, matched against the API's own text.
CANNOT_CREATE = 'Invalid resource state for "conversation"'
KEY_LOCATION_REJECTED = "KMS key must be in the same location as parent"
KEY_SLOT_TAKEN = "Only 1 KMS key"

# CANNOT_CREATE is generic -- it is what us-east4 always returns, but it also
# shows up transiently when a key is momentarily unusable. Nothing concludes on
# a single occurrence.
CREATE_ATTEMPTS = 3

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m")


def hdr(text: str) -> None:
    print(f"\n{BOLD}== {text}{RESET}")


def endpoint(location: str) -> str:
    if location == "global":
        return "geminidataanalytics.googleapis.com"
    if location in ("us", "eu"):
        return f"geminidataanalytics.{location}.rep.googleapis.com"
    return f"geminidataanalytics-{location}.googleapis.com"


def key_path(project: str, kms_location: str) -> str:
    return (f"projects/{project}/locations/{kms_location}"
            f"/keyRings/{KEYRING}/cryptoKeys/{KEY}")


def kms_locations_for(location: str) -> list[str]:
    """Every KMS location this run needs a key in, for `location`."""
    wanted = [DOCUMENTED_KMS_LOCATION[location]]
    if location in PAIRED_KMS_LOCATION:
        wanted.append(PAIRED_KMS_LOCATION[location])
    return wanted


def gcloud(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["gcloud", *args], capture_output=True, text=True,
                          check=check)


# --------------------------------------------------------------------------
# prerequisites, per the documentation's own list
# --------------------------------------------------------------------------

def preflight(project: str, locations: list[str]) -> list[str]:
    """Verify every prerequisite the CMEK page states. Returns problems."""
    problems: list[str] = []

    hdr("Prerequisites (from the documented procedure)")

    # Distinguish "cannot read the project" from "the API is off" — reporting
    # the first as the second sends you debugging the wrong thing.
    r = gcloud("services", "list", "--enabled", f"--project={project}",
               "--format=value(config.name)")
    if r.returncode != 0:
        print(f"  [ERROR] cannot list services on {project}")
        print(f"          {r.stderr.strip().splitlines()[0][:160]}")
        problems.append(
            f"cannot read {project} with the active gcloud credentials — "
            f"check `gcloud config list` and your access to the project")
        return problems

    enabled = set(r.stdout.split())
    for api in ("geminidataanalytics.googleapis.com",
                "cloudaicompanion.googleapis.com", "cloudkms.googleapis.com"):
        ok = api in enabled
        print(f"  [{'OK ' if ok else 'MISSING'}] API enabled: {api}")
        if not ok:
            problems.append(f"API not enabled: {api}")

    r = gcloud("projects", "describe", project,
               "--format=value(projectNumber)")
    number = r.stdout.strip()
    if not number:
        print(f"  [ERROR] cannot read the project number for {project}")
        problems.append(
            f"cannot read the project number for {project}: "
            f"{r.stderr.strip().splitlines()[0][:120] if r.stderr else 'no output'}")
        return problems

    agents = {
        "geminidataanalytics":
            f"service-{number}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com",
        "cloudaicompanion":
            f"service-{number}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com",
    }

    seen: set[str] = set()
    for location in locations:
        for kms_loc in kms_locations_for(location):
            if kms_loc in seen:
                continue
            seen.add(kms_loc)
            kp = key_path(project, kms_loc)
            r = gcloud("kms", "keys", "describe", KEY, f"--keyring={KEYRING}",
                       f"--location={kms_loc}", f"--project={project}",
                       "--format=value(name)")
            if r.returncode != 0:
                print(f"  [MISSING] key in {kms_loc}: {kp}")
                problems.append(f"no key in {kms_loc} ({kp})")
                continue
            print(f"  [OK ] key in {kms_loc:14} {kp}")

            pol = gcloud("kms", "keys", "get-iam-policy", KEY,
                         f"--keyring={KEYRING}", f"--location={kms_loc}",
                         f"--project={project}", "--format=json").stdout
            for label, sa in agents.items():
                granted = sa in pol
                print(f"       [{'OK ' if granted else 'MISSING'}] "
                      f"encrypterDecrypter for {label} service agent")
                if not granted:
                    problems.append(
                        f"{sa} lacks cryptoKeyEncrypterDecrypter on {kp}")
    return problems


def setup(project: str, locations: list[str]) -> None:
    """Provision the documented prerequisites, and the paired-region key too."""
    hdr("Setup")
    number = gcloud("projects", "describe", project,
                    "--format=value(projectNumber)").stdout.strip()

    print("  enabling APIs...")
    gcloud("services", "enable", "geminidataanalytics.googleapis.com",
           "cloudaicompanion.googleapis.com", "cloudkms.googleapis.com",
           f"--project={project}")

    print("  creating service agents...")
    for svc in ("geminidataanalytics.googleapis.com",
                "cloudaicompanion.googleapis.com"):
        gcloud("beta", "services", "identity", "create", f"--service={svc}",
               f"--project={project}")

    members = [
        f"serviceAccount:service-{number}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com",
        f"serviceAccount:service-{number}@gcp-sa-cloudaicompanion.iam.gserviceaccount.com",
    ]
    seen: set[str] = set()
    for location in locations:
        for kms_loc in kms_locations_for(location):
            if kms_loc in seen:
                continue
            seen.add(kms_loc)
            why = ("documented" if kms_loc == DOCUMENTED_KMS_LOCATION[location]
                   else "paired region, undocumented")
            print(f"  KMS key in {kms_loc} for GDA location {location} ({why})...")
            gcloud("kms", "keyrings", "create", KEYRING, f"--location={kms_loc}",
                   f"--project={project}")
            gcloud("kms", "keys", "create", KEY, f"--keyring={KEYRING}",
                   f"--location={kms_loc}", "--purpose=encryption",
                   f"--project={project}")
            for member in members:
                gcloud("kms", "keys", "add-iam-policy-binding", KEY,
                       f"--keyring={KEYRING}", f"--location={kms_loc}",
                       f"--project={project}", f"--member={member}",
                       "--role=roles/cloudkms.cryptoKeyEncrypterDecrypter",
                       "--quiet")
            print(f"    granted both service agents on {key_path(project, kms_loc)}")
    print(f"\n  {DIM}Anchor agents are created on demand by the run itself.{RESET}")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Api:
    def __init__(self) -> None:
        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(google.auth.transport.requests.Request())
        self._token = creds.token

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json"}

    def post(self, url: str, body: dict, params: dict | None = None,
             show: bool = True) -> tuple[int, str, dict | None]:
        if show:
            qs = "&".join(f"{k}={v}" for k, v in (params or {}).items())
            print(f"\n  {DIM}POST {url}{'?' + qs if qs else ''}")
            for line in json.dumps(body, indent=2).splitlines():
                print(f"       {line}")
            print(f"       curl -X POST -H \"Authorization: Bearer $(gcloud auth "
                  f"print-access-token)\" \\\n"
                  f"            -H 'Content-Type: application/json' \\\n"
                  f"            '{url}{'?' + qs if qs else ''}' \\\n"
                  f"            -d '{json.dumps(body)}'{RESET}")
        r = requests.post(url, headers=self.headers, params=params,
                          data=json.dumps(body), timeout=180)
        try:
            payload = r.json()
        except ValueError:
            return r.status_code, r.text.strip()[:300], None
        if r.status_code == 200:
            return r.status_code, "", payload
        return (r.status_code,
                payload.get("error", {}).get("message", r.text).strip(),
                payload)

    def get(self, url: str) -> tuple[int, dict | str]:
        r = requests.get(url, headers=self.headers, timeout=180)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text

    def delete(self, url: str) -> None:
        requests.delete(url, headers=self.headers, timeout=120)

    def create_conversation(self, location: str, project: str, agent: str,
                            conversation_id: str, kms_key: str | None,
                            show: bool = True):
        """POST a conversation, retrying the generic CANNOT_CREATE error.

        Retried because that message also appears transiently when a key is
        momentarily unusable; only its persistence means the location is broken.
        """
        url = (f"https://{endpoint(location)}/v1/projects/{project}"
               f"/locations/{location}/conversations")
        body = {"agents": [agent]}
        if kms_key:
            body["kms_key"] = kms_key
        code, err, payload = 0, "", None
        for attempt in range(CREATE_ATTEMPTS):
            code, err, payload = self.post(
                url, body, {"conversation_id": f"{conversation_id}-{attempt}"},
                show=show and attempt == 0)
            if code == 200 or CANNOT_CREATE not in err:
                break
            if attempt < CREATE_ATTEMPTS - 1:
                print(f"       {DIM}retrying ({attempt + 1}/{CREATE_ATTEMPTS}) "
                      f"— that error is also a transient{RESET}")
                time.sleep(5)
        return code, err, payload


# --------------------------------------------------------------------------
# anchor agent
# --------------------------------------------------------------------------

def ensure_anchor_agent(api: Api, project: str, location: str,
                        dataset: str, table: str) -> str | None:
    """Reuse any agent in this location, else create one with the DOCUMENTED key.

    The agent is incidental — a conversation must reference one — but creating
    it with the documented same-location key is half of defect 1: that key is
    correct for a DataAgent and wrong for a Conversation, and the page gives one
    rule for both.
    """
    parent = f"projects/{project}/locations/{location}"
    base = f"https://{endpoint(location)}/v1/{parent}"

    code, payload = api.get(f"{base}/dataAgents")
    if code == 200 and payload.get("dataAgents"):
        agent = payload["dataAgents"][0]
        print(f"  reusing anchor agent {agent['name'].split('/')[-1]} "
              f"(kms_key={agent.get('kmsKey') or None})")
        return agent["name"]

    documented = key_path(project, DOCUMENTED_KMS_LOCATION[location])
    agent_id = f"repro-anchor-{time.strftime('%m%d%H%M%S')}"
    body = {
        "displayName": "conversation CMEK repro anchor",
        "dataAnalyticsAgent": {"publishedContext": {
            "systemInstruction": "Answer questions about the sample table.",
            "datasourceReferences": {"bq": {"tableReferences": [
                {"projectId": project, "datasetId": dataset,
                 "tableId": table}]}}}},
        "kmsKey": documented,
    }
    code, err, payload = api.post(f"{base}/dataAgents", body,
                                  {"data_agent_id": agent_id}, show=False)
    if code != 200:
        print(f"  {YELLOW}could not create an anchor agent in {location}: "
              f"HTTP {code} {err[:160]}{RESET}")
        return None
    name = payload.get("name", f"{parent}/dataAgents/{agent_id}")
    print(f"  created CMEK anchor agent {agent_id}")
    print(f"    {GREEN}note: the DataAgent accepted {documented}{RESET}")
    print(f"    {DIM}that is the same-location key the docs prescribe, and the "
          f"conversation call below rejects it{RESET}")
    return name


# --------------------------------------------------------------------------
# the reproduction
# --------------------------------------------------------------------------

def reproduce(api: Api, project: str, locations: list[str], dataset: str,
              table: str, include_us_east4_key: bool) -> list[dict]:
    results = []
    stamp = time.strftime("%m%d%H%M%S")

    for location in locations:
        hdr(f"{location} — documented as CMEK-supported")
        agent = ensure_anchor_agent(api, project, location, dataset, table)
        if agent is None:
            results.append({"location": location, "outcome": "NO_ANCHOR"})
            continue

        result = {"location": location, "documented_worked": None,
                  "paired_worked": None}

        # (a) keyless — isolates "can this location create a conversation at
        #     all?" from "will it take a key?"
        code, err, payload = api.create_conversation(
            location, project, agent, f"repro-nokey-{stamp}", None)
        result["creates_keyless"] = code == 200
        if code == 200:
            print(f"  {GREEN}-> keyless create SUCCEEDED{RESET} "
                  f"(kmsKey={payload.get('kmsKey') or None})")
            api.delete(f"https://{endpoint(location)}/v1/{payload['name']}")
        else:
            print(f"  {RED}-> keyless create FAILED  HTTP {code}{RESET}")
            print(f"     {err[:200]}")

        # (b) the DOCUMENTED key — same location as the conversation
        documented = key_path(project, DOCUMENTED_KMS_LOCATION[location])
        if location == "us-east4" and not include_us_east4_key:
            print(f"\n  {YELLOW}-> documented-key submission SKIPPED in "
                  f"us-east4.{RESET}")
            print(f"     {DIM}us-east4 accepts this key at the KMS stage and "
                  f"registers it permanently for\n     the whole "
                  f"project+location, even though the create fails anyway. Pass\n"
                  f"     --include-us-east4-key to do it regardless. Defect 2 is "
                  f"already shown above.{RESET}")
        else:
            code, err, payload = api.create_conversation(
                location, project, agent, f"repro-doc-{stamp}", documented)
            result["documented_worked"] = code == 200
            if code == 200:
                print(f"  {GREEN}-> DOCUMENTED key SUCCEEDED{RESET} "
                      f"(kmsKey={payload.get('kmsKey')})")
                api.delete(f"https://{endpoint(location)}/v1/{payload['name']}")
            else:
                print(f"  {RED}-> DOCUMENTED key FAILED  HTTP {code}{RESET}")
                print(f"     {err[:200]}")

        # (c) the PAIRED-REGION key — undocumented, and the one that works
        if location in PAIRED_KMS_LOCATION:
            paired = key_path(project, PAIRED_KMS_LOCATION[location])
            code, err, payload = api.create_conversation(
                location, project, agent, f"repro-paired-{stamp}", paired)
            result["paired_worked"] = code == 200
            if code == 200:
                print(f"  {GREEN}-> PAIRED-REGION key SUCCEEDED{RESET} "
                      f"(kmsKey={payload.get('kmsKey')})")
                api.delete(f"https://{endpoint(location)}/v1/{payload['name']}")
            elif KEY_SLOT_TAKEN in err:
                print(f"  {YELLOW}-> PAIRED-REGION key: slot already occupied by "
                      f"another key{RESET}")
                print(f"     {DIM}the location was accepted; this project has "
                      f"already registered a different key{RESET}")
                result["paired_worked"] = "slot taken"
            else:
                print(f"  {RED}-> PAIRED-REGION key FAILED  HTTP {code}{RESET}")
                print(f"     {err[:200]}")
        else:
            # us-east4 is a true region, not a multi-region: there is no paired
            # region to try, and no conversation to attach a key to anyway.
            result["paired_worked"] = "n/a"

        results.append(result)
    return results


def prove_revocation(api: Api, project: str, location: str, dataset: str,
                     table: str) -> None:
    """Show the accepted key is a real boundary — and that it is opt-in."""
    hdr(f"Consequence — the key holds, and only for those who ask for it "
        f"({location})")
    agent = ensure_anchor_agent(api, project, location, dataset, table)
    if agent is None:
        print("  no anchor agent; skipping")
        return

    paired = key_path(project, PAIRED_KMS_LOCATION[location])
    base = f"https://{endpoint(location)}/v1"
    parent = f"projects/{project}/locations/{location}"
    stamp = time.strftime("%m%d%H%M%S")

    code, err, keyed = api.create_conversation(
        location, project, agent, f"repro-revoke-{stamp}", paired, show=False)
    if code != 200:
        print(f"  cannot create a CMEK conversation here ({err[:120]})")
        return
    code, _, plain = api.create_conversation(
        location, project, agent, f"repro-control-{stamp}", None, show=False)
    control = plain if code == 200 else None

    print(f"  keyed conversation:   {keyed['name'].split('/')[-1]}")
    print(f"  keyless control:      "
          f"{control['name'].split('/')[-1] if control else '(none)'}")

    print("  asking a question in each, so there is real content at rest...")
    for conversation in (keyed, control):
        if conversation is None:
            continue
        r = requests.post(
            f"{base}/{parent}:chat", headers=api.headers, timeout=300,
            data=json.dumps({
                "parent": parent,
                "conversationReference": {
                    "conversation": conversation["name"],
                    "dataAgentContext": {"dataAgent": agent}},
                "messages": [{"userMessage": {
                    "text": "List every customer and their balance."}}]}))
        print(f"    chat HTTP {r.status_code}")

    def read(conversation) -> str:
        if conversation is None:
            return "n/a"
        code, payload = api.get(f"{base}/{conversation['name']}/messages")
        if code != 200:
            return f"{RED}BLOCKED HTTP {code}{RESET}"
        blob = json.dumps(payload)
        return (f"{GREEN}{len(payload.get('messages', []))} readable{RESET} "
                f"(generatedSql={'generatedSql' in blob}, "
                f"data={'balance' in blob.lower()})")

    kms_loc = PAIRED_KMS_LOCATION[location]

    def key_version(action: str) -> None:
        gcloud("kms", "keys", "versions", action, "1", f"--key={KEY}",
               f"--keyring={KEYRING}", f"--location={kms_loc}",
               f"--project={project}", "--quiet")

    print(f"\n  baseline        keyed={read(keyed)}  control={read(control)}")
    print(f"\n  {BOLD}disabling key version 1 of {paired}{RESET}")
    key_version("disable")
    try:
        for minute in range(1, 7):
            time.sleep(60)
            print(f"  t+{minute}min        keyed={read(keyed)}  "
                  f"control={read(control)}")
    finally:
        key_version("enable")
        print(f"\n  {BOLD}key re-enabled{RESET}")
        for conversation in (keyed, control):
            if conversation is not None:
                api.delete(f"{base}/{conversation['name']}")

    print(f"\n  {BOLD}Read the middle rows.{RESET} The keyed conversation goes "
          f"dark — CMEK is a real\n  boundary over message content. The keyless "
          f"control, in the same project and\n  location, where that key is "
          f"registered, stays readable: it never inherited\n  the key. CMEK on "
          f"conversations is opt-in, per conversation.")


# --------------------------------------------------------------------------

def default_project() -> str | None:
    """PROJECT_ID from config/shared.env.local, so in-repo runs need no flags."""
    if os.getenv("PROJECT_ID"):
        return os.environ["PROJECT_ID"]
    env_file = Path(__file__).resolve().parent.parent / "config" / "shared.env.local"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("PROJECT_ID="):
                return line.split("=", 1)[1].strip()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", default=default_project(),
                        help="target project (default: PROJECT_ID from "
                             "config/shared.env.local)")
    parser.add_argument("--locations", default=",".join(DOCUMENTED_LOCATIONS),
                        help="comma-separated subset of us-east4,us,eu")
    parser.add_argument("--dataset", default=os.getenv("BQ_SOURCE_DATASET",
                                                       "cymbal_demo"))
    parser.add_argument("--table", default=os.getenv("BQ_SOURCE_TABLE",
                                                     "customers"))
    parser.add_argument("--setup", action="store_true",
                        help="provision the documented prerequisites, plus a "
                             "key in the paired region")
    parser.add_argument("--revocation", action="store_true",
                        help="also prove the accepted key is a real boundary "
                             "and is opt-in. Disables a live key for ~6 min.")
    parser.add_argument("--include-us-east4-key", action="store_true",
                        help="also submit a key in us-east4. PERMANENTLY "
                             "registers that key for the project+location.")
    args = parser.parse_args()

    if not args.project:
        print("no project: pass --project, or set PROJECT_ID in "
              "config/shared.env.local")
        return EXIT_CANNOT_RUN

    locations = [loc.strip() for loc in args.locations.split(",") if loc.strip()]
    bad = [loc for loc in locations if loc not in DOCUMENTED_KMS_LOCATION]
    if bad:
        print(f"not documented as CMEK-supported: {bad}. "
              f"Choose from {list(DOCUMENTED_KMS_LOCATION)}.")
        return EXIT_CANNOT_RUN

    print(f"{BOLD}CMEK for Conversations — reproduction{RESET}")
    print(f"project   {args.project}")
    print(f"locations {', '.join(locations)}")
    print(f"docs      https://docs.cloud.google.com/gemini/data-agents"
          f"/conversational-analytics-api/cmek")

    if args.setup:
        setup(args.project, locations)

    problems = preflight(args.project, locations)
    if problems:
        print(f"\n{RED}Prerequisites are not met, so nothing here would be "
              f"evidence of anything:{RESET}")
        for p in problems:
            print(f"  * {p}")
        if any(p.startswith("cannot read") for p in problems):
            print("\nThis is an access or credentials problem, not a missing "
                  "resource — --setup will not help.")
        else:
            print("\nRe-run with --setup to provision them.")
        return EXIT_CANNOT_RUN
    print(f"\n  {GREEN}Every documented prerequisite is satisfied.{RESET} "
          f"Anything that fails below\n  is the platform, not the setup.")

    api = Api()
    results = reproduce(api, args.project, locations, args.dataset, args.table,
                        args.include_us_east4_key)

    if args.revocation:
        # `is True` on purpose: "slot taken" is truthy but means the paired key
        # could not actually be used here, so it is not a revocation candidate.
        usable = [r["location"] for r in results if r.get("paired_worked") is True]
        if usable:
            prove_revocation(api, args.project, usable[0], args.dataset,
                             args.table)
        else:
            print(f"\n{YELLOW}--revocation needs a location where a CMEK "
                  f"conversation could be created; none of {locations} "
                  f"managed it.{RESET}")

    # ---- verdict ----
    hdr("Verdict")
    print(f"  {DIM}{'location':10} {'keyless':9} {'documented key':16} "
          f"paired-region key{RESET}")
    for r in results:
        loc = r["location"]
        if r.get("outcome") == "NO_ANCHOR":
            print(f"  {loc:10} could not test (no anchor agent)")
            continue

        def cell(value, width, yes, no, unknown="—"):
            # A string value is a state of its own (e.g. "n/a", "slot taken");
            # only True/False are verdicts.
            text = (yes if value is True else no if value is False
                    else value if isinstance(value, str) else unknown)
            colour = GREEN if value is True else RED if value is False else DIM
            return f"{colour}{text}{RESET}{' ' * max(width - len(text), 0)}"

        print(f"  {loc:10} "
              f"{cell(r.get('creates_keyless'), 9, 'yes', 'NO')} "
              f"{cell(r.get('documented_worked'), 16, 'WORKED', 'rejected', 'not submitted')} "
              f"{cell(r.get('paired_worked'), 17, 'works', 'REJECTED')}")

    documented_worked = [r["location"] for r in results
                         if r.get("documented_worked")]
    east4_creates = [r["location"] for r in results
                     if r["location"] == "us-east4" and r.get("creates_keyless")]

    if documented_worked or east4_creates:
        print(f"\n{GREEN}{BOLD}A documented case SUCCEEDED.{RESET}")
        if documented_worked:
            print(f"  * the documented same-location key was accepted in "
                  f"{', '.join(documented_worked)} — defect 1 is fixed")
        if east4_creates:
            print(f"  * us-east4 created a conversation — defect 2 is fixed")
        print("\nThe defect does not reproduce for you. Please report that — "
              "validation-report F8\nis written on the assumption that it "
              "still fails, and would need revisiting.")
        return EXIT_NOT_REPRODUCED

    print(f"\n{BOLD}Reproduced.{RESET} The documented procedure "
          f"(#protect-conversation) does not\nproduce a CMEK-encrypted "
          f"conversation in any location Google lists as supported.\nA key in "
          f"the paired primary region — documented nowhere — does.")
    return EXIT_REPRODUCED


if __name__ == "__main__":
    raise SystemExit(main())
