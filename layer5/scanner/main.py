"""Layer 5 — continuous compliance inventory for GDA DataAgents.

Writes one row per agent per scan into BigQuery, from two independent sources,
and reconciles them. Run as a Cloud Run job on a schedule.

Why not the obvious approach (CAI ExportAssets -> BigQuery, query
`cloud_asset_inventory.latest_resources`): verified against a live project,
`ExportAssets` returns `geminidataanalytics.googleapis.com/DataAgent` only
intermittently. Seven exports of the same project, filtered to DataAgent +
CryptoKey: six returned zero DataAgent rows, one returned all fifteen. The six
empty runs each polled the export operation to done=True first, so this is not a
read-before-write race. A report built on that source reads "fully compliant"
most of the time while looking like it works.

`SearchAllResources` returned DataAgent consistently on every attempt, including
a `kmsKeys` field, so that is used instead. Two further properties matter:

* A metadata-only `read_mask` is used deliberately. Requesting
  `versionedResources` would copy each agent's `publishedContext` — the very
  customer content CMEK protects — into a BigQuery table. Building the
  compliance report that way would create a second, unencrypted copy of the
  protected data: the audit control would itself become the breach.

* CAI is eventually consistent and cannot see an agent whose CMEK key is
  disabled (the live API omits those from LIST without error). So the live API
  is scanned too and the two sources are diffed; anything visible to only one
  of them is surfaced rather than silently dropped.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import asset_v1, bigquery, geminidataanalytics

from gda_common import (
    api_endpoint,
    attest_conversation_key,
    evaluate_compliance,
    kms_key_project,
    parse_agent_name,
    parse_approved_projects,
)

DATA_AGENT = "DATA_AGENT"
CONVERSATION_KEY = "CONVERSATION_KEY"

ASSET_TYPE = "geminidataanalytics.googleapis.com/DataAgent"
# Metadata only — never versionedResources. See module docstring.
READ_MASK = "name,assetType,location,kmsKeys,createTime,updateTime,project"

PROJECT_ID = os.environ["PROJECT_ID"]
BQ_DATASET = os.environ["BQ_DATASET"]
INVENTORY_TABLE = os.getenv("INVENTORY_TABLE", "agent_inventory")
APPROVED = parse_approved_projects(os.environ["APPROVED_KMS_PROJECTS"])
SCAN_LOCATIONS = [
    loc.strip() for loc in os.getenv("SCAN_LOCATIONS", "us-east4,us,eu,global").split(",") if loc.strip()
]

# Reconciliation outcomes beyond the shared compliance verdicts.
CAI_LAG = "PENDING_CAI_INGESTION"
INVISIBLE_TO_API = "NON_COMPLIANT_UNVERIFIABLE"
# Distinct from INVISIBLE_TO_API on purpose. "The API would not list this agent"
# and "we could not finish asking the API" look identical in the data but have
# completely different causes and remedies, and only the first is evidence about
# the agent. Conflating them attributes an outage to a customer's key state.
SCAN_INCOMPLETE = "NON_COMPLIANT_UNVERIFIABLE_SCAN_ERROR"

# A transient list failure must not be mistaken for "this location is empty".
LIST_ATTEMPTS = 3
LIST_BACKOFF_SECONDS = 5


def scan_cai() -> dict[str, dict]:
    """Agents as Cloud Asset Inventory sees them, keyed by resource name."""
    client = asset_v1.AssetServiceClient()
    found: dict[str, dict] = {}
    request = asset_v1.SearchAllResourcesRequest(
        scope=f"projects/{PROJECT_ID}", asset_types=[ASSET_TYPE], read_mask=READ_MASK
    )
    for asset in client.search_all_resources(request=request):
        # CAI prefixes the service host; strip it to match the API's own naming.
        resource_name = asset.name.split("//geminidataanalytics.googleapis.com/")[-1]
        found[resource_name] = {
            "kms_key": asset.kms_keys[0] if asset.kms_keys else None,
            "location": asset.location,
            "create_time": asset.create_time,
        }
    return found


def _list_location(location: str) -> dict[str, dict]:
    """List one location, retrying transient errors. Raises if all attempts fail."""
    client = geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )
    parent = f"projects/{PROJECT_ID}/locations/{location}"
    last: GoogleAPICallError | None = None
    for attempt in range(1, LIST_ATTEMPTS + 1):
        try:
            # show_deleted stays False: soft-deleted agents are remediated
            # tombstones, not live exposure.
            agents = client.list_data_agents(
                request=geminidataanalytics.ListDataAgentsRequest(
                    parent=parent, show_deleted=False
                )
            )
            return {
                agent.name: {
                    "kms_key": agent.kms_key or None,
                    "location": location,
                    "create_time": agent.create_time,
                }
                for agent in agents
            }
        except GoogleAPICallError as exc:
            last = exc
            if attempt < LIST_ATTEMPTS:
                print(
                    f"  retrying list for {location} after {type(exc).__name__} "
                    f"(attempt {attempt}/{LIST_ATTEMPTS})"
                )
                time.sleep(LIST_BACKOFF_SECONDS)
    raise last  # type: ignore[misc]


def scan_api() -> tuple[dict[str, dict], dict[str, str]]:
    """Agents as the live API sees them, plus any location we could not read.

    Returns (agents, {location: error}) — never a silently partial dict.
    Swallowing a per-location error and returning what came back would let a
    single transient 503 make every agent in that location look absent from the
    live API. Those agents would then be written to the regulator-facing table
    as NON_COMPLIANT_UNVERIFIABLE, blaming a disabled CMEK key for what was
    actually an API blip — and any agent CAI had not yet ingested would vanish
    from the inventory altogether, which is the under-reporting failure this
    layer exists to prevent.
    """
    found: dict[str, dict] = {}
    failed: dict[str, str] = {}
    for location in SCAN_LOCATIONS:
        try:
            found.update(_list_location(location))
        except GoogleAPICallError as exc:
            failed[location] = f"{type(exc).__name__}: {exc.message}"
            print(f"ERROR: list failed for {location} after {LIST_ATTEMPTS} attempts: {failed[location]}")
    return found, failed


def scan_conversation_keys() -> dict[str, tuple[list[str | None], str | None]]:
    """The registered conversation CMEK key per location.

    Cloud Asset Inventory cannot help here — it has no Conversation asset type
    at all:

        INVALID_ARGUMENT: No supported asset type matches:
        geminidataanalytics.googleapis.com/Conversation

    so unlike DataAgents there is no second source to reconcile against. That
    would normally be a problem (a LIST-only inventory under-reports, F4), but
    it is not, because there is nothing to inventory: CMEK for conversations is
    a project+location singleton, so reading the key off any one conversation
    tells you the key for all of them. This lists conversations only to read
    that key, never to track them — they are ephemeral by design.

    Returns {location: (observed keys, error or None)}.
    """
    found: dict[str, tuple[list[str | None], str | None]] = {}
    for location in SCAN_LOCATIONS:
        client = geminidataanalytics.DataChatServiceClient(
            client_options=ClientOptions(api_endpoint=api_endpoint(location))
        )
        parent = f"projects/{PROJECT_ID}/locations/{location}"
        try:
            keys = [c.kms_key or None for c in client.list_conversations(parent=parent)]
            found[location] = (keys, None)
        except GoogleAPICallError as exc:
            # Recorded, not swallowed. An unreadable location yields no
            # attestation rather than a false clean bill of health.
            found[location] = ([], f"{type(exc).__name__}: {exc.message}")
            print(f"WARNING: list_conversations failed for {location}: {found[location][1]}")
    return found


def build_conversation_rows(scan_time: datetime) -> list[dict]:
    """One attestation row per project+location, not one per conversation."""
    rows = []
    for location, (keys, error) in scan_conversation_keys().items():
        if error:
            status = SCAN_INCOMPLETE
            reason = (
                f"Could not list conversations in '{location}' ({error}). The "
                "registered CMEK key could not be read, so conversation posture "
                "was NOT verified this scan."
            )
            observed = None
        else:
            verdict = attest_conversation_key(location, keys, APPROVED)
            status, reason = verdict.status, verdict.reason
            observed = next((k for k in keys if k), None)

        rows.append(
            {
                "scan_time": scan_time.isoformat(),
                "resource_type": CONVERSATION_KEY,
                "resource_url": f"projects/{PROJECT_ID}/locations/{location}/conversations",
                "project_id": PROJECT_ID,
                "location": location,
                "agent_id": None,
                "configured_kms_key": observed,
                "kms_key_project": kms_key_project(observed),
                "compliance_status": status,
                "reason": reason,
                # CAI has no Conversation asset type, so this is single-source by
                # necessity. Recorded honestly rather than implying corroboration.
                "visible_in_cai": False,
                "visible_in_api": error is None,
            }
        )
    return rows


def build_rows(scan_time: datetime) -> tuple[list[dict], dict[str, str]]:
    cai = scan_cai()
    api, failed_locations = scan_api()
    rows = []

    for resource_name in sorted(set(cai) | set(api)):
        in_cai, in_api = resource_name in cai, resource_name in api
        record = api.get(resource_name) or cai[resource_name]
        parsed = parse_agent_name(resource_name)
        location = parsed.location if parsed else record["location"]
        kms_key = record["kms_key"]

        verdict = evaluate_compliance(location, kms_key, APPROVED)
        status, reason = verdict.status, verdict.reason

        if in_cai and not in_api and location in failed_locations:
            # We never finished asking the API about this location, so its
            # absence from `api` is our failure, not evidence about the agent.
            # Still fail closed, but say what actually happened.
            status = SCAN_INCOMPLETE
            reason = (
                f"Live-API list for location '{location}' failed after "
                f"{LIST_ATTEMPTS} attempts ({failed_locations[location]}). "
                "Compliance state for this agent was NOT verified this scan; "
                "treat as unverifiable pending a successful scan."
            )
        elif in_cai and not in_api:
            # CAI knows about it but the API will not list it. The verified
            # cause is a disabled/inaccessible CMEK key, which hides the agent
            # from LIST with no error. Never let this pass as compliant.
            status = INVISIBLE_TO_API
            reason = (
                "Present in Cloud Asset Inventory but not returned by the live "
                "API. A disabled or inaccessible CMEK key silently hides an "
                "agent from LIST; treat as unverifiable, not absent."
            )
        elif in_api and not in_cai and verdict.is_compliant:
            # Listed AND verified compliant by the live API; only the CAI
            # cross-check is missing. Note the `verdict.is_compliant` guard: an
            # agent absent from CAI that is NOT compliant keeps its real
            # violation status, so this label can never mask a finding. The view
            # therefore counts it as neither compliant nor a violation — see
            # verification_state in layer5/sql/v_agent_compliance.sql.
            status, reason = CAI_LAG, (
                "Compliant per the live API; awaiting Cloud Asset Inventory "
                "corroboration. Not counted as a violation: only the second "
                "source is missing, and the authoritative one verified the key."
            )

        rows.append(
            {
                "scan_time": scan_time.isoformat(),
                "resource_type": DATA_AGENT,
                "resource_url": resource_name,
                "project_id": parsed.project if parsed else PROJECT_ID,
                "location": location,
                "agent_id": parsed.agent_id if parsed else None,
                "configured_kms_key": kms_key,
                "kms_key_project": kms_key_project(kms_key),
                "compliance_status": status,
                "reason": reason,
                "visible_in_cai": in_cai,
                "visible_in_api": in_api,
            }
        )

    # One attestation per project+location, appended to the same table so the
    # compliance view has a single source. See build_conversation_rows.
    rows.extend(build_conversation_rows(scan_time))
    return rows, failed_locations


def main() -> None:
    scan_time = datetime.now(timezone.utc)
    rows, failed_locations = build_rows(scan_time)

    client = bigquery.Client(project=PROJECT_ID)
    table_id = f"{PROJECT_ID}.{BQ_DATASET}.{INVENTORY_TABLE}"
    errors = client.insert_rows_json(table_id, rows) if rows else []
    if errors:
        raise RuntimeError(f"BigQuery insert failed: {errors}")

    summary: dict[str, int] = {}
    for row in rows:
        summary[row["compliance_status"]] = summary.get(row["compliance_status"], 0) + 1
    print(f"scan_time={scan_time.isoformat()} rows={len(rows)}")
    for status, count in sorted(summary.items()):
        print(f"  {status}: {count}")

    # Rows are written first so the incomplete scan leaves a record, then the
    # run is failed. A scan that could not read every location produced an
    # inventory that may under-report — agents in the unreadable location that
    # CAI has not ingested appear nowhere at all — so it must not be reported as
    # a clean run. Exiting non-zero marks the Cloud Run job execution failed and
    # surfaces on the schedule instead of hiding in the logs.
    if failed_locations:
        print(
            "SCAN INCOMPLETE: "
            + "; ".join(f"{loc}: {err}" for loc, err in failed_locations.items()),
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
