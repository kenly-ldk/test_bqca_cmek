"""Layer 5 proof — the two-source design, demonstrated against the live API.

Layer 5 reads Cloud Asset Inventory *and* the live API and reconciles them. The
justification is F4: disabling a CMEK key makes `ListDataAgents` silently omit
the agent — no error, no warning, it is simply gone. An inventory built from
LIST alone therefore under-reports precisely when a key's state is suspect,
which is the worst possible moment to lose visibility.

That claim was asserted everywhere and demonstrated nowhere. The scanner's
`NON_COMPLIANT_UNVERIFIABLE` branch never executed once in 89 scheduled scans,
because Cloud Asset Inventory never disagreed with the live API in a healthy
environment. Unit tests now cover the branch deterministically
(tests/unit/test_scanner_build_rows.py); this covers the *precondition* — that
the disagreement is real, and that the scanner resolves it correctly end to end.

What it does:

  1. Record which agents the live API lists and which CAI knows about.
  2. Disable the CryptoKeyVersion; poll until the API starts hiding agents.
  3. Assert CAI still returns them — the precondition for the branch.
  4. Run the scanner and assert every hidden agent is classified
     NON_COMPLIANT_UNVERIFIABLE, and that none is reported COMPLIANT.
  5. Re-enable the key, always, via try/finally.

Exit codes:
    0  proven
    1  the scanner did NOT behave as designed (a real finding)
    2  inconclusive — the precondition never materialised, no verdict

Usage:
    python -m layer5.revocation_proof
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import bigquery, geminidataanalytics, kms

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import api_endpoint  # noqa: E402
from config._loader import load  # noqa: E402

EXIT_OK, EXIT_FAILED, EXIT_INCONCLUSIVE = 0, 1, 2
UNVERIFIABLE = "NON_COMPLIANT_UNVERIFIABLE"

POLL_ATTEMPTS = 18
POLL_SECONDS = 10


def _api_agent_ids(project: str, location: str) -> set[str]:
    client = geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )
    return {
        a.name.rsplit("/", 1)[-1]
        for a in client.list_data_agents(parent=f"projects/{project}/locations/{location}")
    }


def _cai_agent_ids(project: str) -> set[str]:
    """CAI's view. Metadata-only read_mask, as the scanner uses."""
    out = subprocess.run(
        [
            "gcloud", "asset", "search-all-resources",
            f"--scope=projects/{project}",
            "--asset-types=geminidataanalytics.googleapis.com/DataAgent",
            "--read-mask=name",
            f"--project={project}",
            "--format=json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(f"CAI search failed: {out.stderr.strip()[:200]}")
    return {r["name"].rsplit("/", 1)[-1] for r in (json.loads(out.stdout or "[]"))}


def _set_key_enabled(key_path: str, enabled: bool) -> None:
    client = kms.KeyManagementServiceClient()
    state = (
        kms.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
        if enabled
        else kms.CryptoKeyVersion.CryptoKeyVersionState.DISABLED
    )
    client.update_crypto_key_version(
        request={
            "crypto_key_version": {"name": f"{key_path}/cryptoKeyVersions/1", "state": state},
            "update_mask": {"paths": ["state"]},
        }
    )
    print(f"  key version {'ENABLED' if enabled else 'DISABLED'}")


def _run_scanner(project: str, infra_region: str, job: str) -> None:
    """Run the scanner job and REPORT a failure rather than swallowing it.

    The region here is INFRA_REGION -- where the Cloud Run job is deployed --
    not the agent's GDA location. They are different variables precisely
    because a GDA multi-region such as `us` is not a deployable Cloud Run
    region, and passing one here fails the execute.

    check=False with the output captured used to hide that completely: the job
    never ran, the inventory kept the PREVIOUS scan's rows, and the caller then
    compared against stale verdicts and reported agents COMPLIANT that it had
    just hidden. A failure to re-scan must be loud, because every assertion
    downstream assumes the scan happened.
    """
    result = subprocess.run(
        ["gcloud", "run", "jobs", "execute", job,
         f"--project={project}", f"--region={infra_region}", "--wait"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(
            f"scanner job '{job}' did not run in region '{infra_region}' "
            f"(exit {result.returncode}): {tail[-1] if tail else 'no output'}. "
            "Every verdict below would have been read from the previous scan."
        )


def _view_statuses(project: str, dataset: str, view: str) -> dict[str, str]:
    client = bigquery.Client(project=project)
    rows = client.query(
        f"SELECT agent_id, compliance_status FROM `{project}.{dataset}.{view}`"
    ).result()
    return {r["agent_id"]: r["compliance_status"] for r in rows}


def main() -> int:
    env = load()
    # Two different things, and conflating them is what this file used to do:
    # `location` is the GDA location whose agents are listed and whose CMEK key
    # is disabled; `infra_region` is the Cloud Run region the scanner job lives
    # in. With AGENT_LOCATION=us the first is a multi-region and the second
    # cannot be.
    project = env["PROJECT_ID"]
    location = env["AGENT_LOCATION"]
    infra_region = env["INFRA_REGION"]
    key_path = (
        f"projects/{project}/locations/{location}"
        f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['KMS_KEY']}"
    )

    before_api = _api_agent_ids(project, location)
    before_cai = _cai_agent_ids(project)
    print(f"  baseline: api={len(before_api)} cai={len(before_cai)}")
    if not before_api:
        print("  INCONCLUSIVE: no agents in the live API to hide.")
        return EXIT_INCONCLUSIVE

    _set_key_enabled(key_path, enabled=False)
    try:
        hidden: set[str] = set()
        for attempt in range(1, POLL_ATTEMPTS + 1):
            time.sleep(POLL_SECONDS)
            hidden = before_api - _api_agent_ids(project, location)
            if hidden:
                print(f"  API hid {len(hidden)} agent(s) after ~{attempt * POLL_SECONDS}s")
                break
        else:
            print(
                f"  INCONCLUSIVE: the API never hid an agent within "
                f"{POLL_ATTEMPTS * POLL_SECONDS}s. Key propagation may have changed."
            )
            return EXIT_INCONCLUSIVE

        still_in_cai = hidden & _cai_agent_ids(project)
        print(f"  of those, still visible to CAI: {len(still_in_cai)}")
        if not still_in_cai:
            print("  INCONCLUSIVE: CAI dropped them too, so there is no disagreement to resolve.")
            return EXIT_INCONCLUSIVE

        print("  running the scanner while the key is disabled...")
        _run_scanner(project, infra_region, env["SCANNER_JOB"])
        statuses = _view_statuses(project, env["BQ_DATASET"], env["COMPLIANCE_VIEW"])

        missing = sorted(a for a in still_in_cai if a not in statuses)
        wrong = sorted(
            (a, statuses[a]) for a in still_in_cai
            if a in statuses and statuses[a] != UNVERIFIABLE
        )
        compliant = [a for a, s in wrong if s == "COMPLIANT"]

        print(f"  hidden-but-in-CAI agents: {len(still_in_cai)}")
        print(f"    classified {UNVERIFIABLE}: {len(still_in_cai) - len(missing) - len(wrong)}")
        print(f"    absent from the report   : {len(missing)}  <-- under-reporting")
        print(f"    reported COMPLIANT       : {len(compliant)}  <-- vouching for the unreadable")

        if missing:
            print(f"  FAIL: dropped entirely: {missing[:5]}")
        for agent, status in wrong[:5]:
            print(f"  FAIL: {agent} classified {status}, expected {UNVERIFIABLE}")

        if missing or wrong:
            return EXIT_FAILED

        print(
            f"  PROVEN: all {len(still_in_cai)} agent(s) hidden from the live API were "
            f"caught by the CAI cross-check and reported {UNVERIFIABLE}. "
            "A LIST-only inventory would have shown them as simply absent."
        )
        return EXIT_OK
    except GoogleAPICallError as exc:
        print(f"  INCONCLUSIVE: {type(exc).__name__}: {exc.message}")
        return EXIT_INCONCLUSIVE
    finally:
        _set_key_enabled(key_path, enabled=True)
        # Leave the inventory truthful. The scan above ran while agents were
        # deliberately unreadable, so the latest rows say UNVERIFIABLE for
        # resources that are now perfectly healthy — and the compliance view
        # reports the latest scan only. Without this the regulator-facing view
        # would carry a wall of false "unverified" entries until the next
        # scheduled run, caused by the test rather than by the estate.
        print("  waiting for key re-enable to propagate, then rescanning...")
        for _ in range(POLL_ATTEMPTS):
            time.sleep(POLL_SECONDS)
            try:
                if not before_api - _api_agent_ids(project, location):
                    break
            except GoogleAPICallError:
                continue
        _run_scanner(project, infra_region, env["SCANNER_JOB"])
        print("  inventory rescanned with the key enabled")


if __name__ == "__main__":
    raise SystemExit(main())
