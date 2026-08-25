"""Layer 5 verification — reconcile the compliance view against the live API.

Compares SETS of resource names, not counts.

Asserting `view_count == api_count` would be wrong by design. Cloud Asset
Inventory is eventually consistent, so immediately after a Layer 4 remediation
the view legitimately still carries a row the live API no longer lists — the
scanner classifies those NON_COMPLIANT_UNVERIFIABLE, which is the entire point
of reconciling two sources. An equality assertion turns that correct behaviour
into an intermittent failure.

The two properties that actually matter:

  1. **No under-reporting.** Every agent the live API lists must appear in the
     view. A regulator-facing inventory that silently drops agents is the worst
     possible outcome, and is exactly what a LIST-only inventory does when a
     CMEK key is disabled.
  2. **Fail closed.** Anything in the view that the API cannot see must not be
     reported COMPLIANT.

Both properties are judged against the set of agents the live API reports, so a
**partial** API read invalidates the comparison rather than weakening it. The
naive shape — catch a per-location `GoogleAPICallError`, log a warning to stderr
and carry on with whatever came back — fails badly here: a single transient 503
on one location moves every agent in that location from "live" to
"API-invisible", and property 2 then reports a dozen healthy COMPLIANT agents as
violations. That is the same silent-partial-data failure this framework exists
to catch, so the API read retries and, if a location still cannot be listed, the
run exits INCOMPLETE (exit 2) rather than returning a compliance verdict it
cannot support.

Exit codes:
    0  reconciled
    1  reconciliation failed (a real finding)
    2  incomplete input — no verdict possible (not a compliance failure)

Usage:
    python -m layer5.reconcile_check          # human-readable
    python -m layer5.reconcile_check --json   # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import GoogleAPICallError
from google.cloud import bigquery, geminidataanalytics

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import api_endpoint  # noqa: E402
from config._loader import load  # noqa: E402

EXIT_OK, EXIT_FAILED, EXIT_INCOMPLETE = 0, 1, 2
# A transient list failure must not be mistaken for "this location is empty".
LIST_ATTEMPTS = 3
LIST_BACKOFF_SECONDS = 5


def _list_location(project: str, location: str) -> set[str]:
    """List one location, retrying transient errors. Raises if all attempts fail."""
    client = geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )
    last: GoogleAPICallError | None = None
    for attempt in range(1, LIST_ATTEMPTS + 1):
        try:
            return {
                agent.name
                for agent in client.list_data_agents(
                    request=geminidataanalytics.ListDataAgentsRequest(
                        parent=f"projects/{project}/locations/{location}", show_deleted=False
                    )
                )
            }
        except GoogleAPICallError as exc:
            last = exc
            if attempt < LIST_ATTEMPTS:
                print(
                    f"  retrying list for {location} after {type(exc).__name__} "
                    f"(attempt {attempt}/{LIST_ATTEMPTS})",
                    file=sys.stderr,
                )
                time.sleep(LIST_BACKOFF_SECONDS)
    raise last  # type: ignore[misc]


def live_agents(project: str, locations: list[str]) -> tuple[set[str], dict[str, str]]:
    """Return (agent names, {location: error}) — never a silently partial set."""
    found: set[str] = set()
    failed: dict[str, str] = {}
    for location in locations:
        try:
            found |= _list_location(project, location)
        except GoogleAPICallError as exc:
            failed[location] = f"{type(exc).__name__}: {exc.message}"
    return found, failed


def view_rows(project: str, dataset: str, view: str) -> dict[str, str]:
    """DataAgent rows only.

    The view also carries CONVERSATION_KEY rows — one attestation per
    project+location, not a resource the DataAgent API lists. Including them
    would make every one look "missing from the API" and break a reconciliation
    that is specifically about agents.
    """
    client = bigquery.Client(project=project)
    query = (
        f"SELECT resource_url, compliance_status FROM `{project}.{dataset}.{view}` "
        "WHERE resource_type = 'DATA_AGENT'"
    )
    return {r["resource_url"]: r["compliance_status"] for r in client.query(query).result()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    env = load()
    project = env["PROJECT_ID"]
    locations = [loc.strip() for loc in env["SCAN_LOCATIONS"].split(",") if loc.strip()]

    api, failed = live_agents(project, locations)
    view = view_rows(project, env["BQ_DATASET"], env["COMPLIANCE_VIEW"])

    missing = sorted(api - set(view))
    api_invisible = sorted(set(view) - api)
    wrongly_compliant = [n for n in api_invisible if view[n] == "COMPLIANT"]

    # An unlistable location makes both properties unjudgeable: its agents look
    # "API-invisible" purely because we could not read them. Report INCOMPLETE
    # rather than manufacturing a verdict from a partial set.
    incomplete = bool(failed)

    result = {
        "api_count": len(api),
        "view_count": len(view),
        "locations_scanned": locations,
        "locations_failed": failed,
        "incomplete": incomplete,
        "missing_from_view": missing,
        "api_invisible": api_invisible,
        "api_invisible_reported_compliant": [] if incomplete else wrongly_compliant,
        "ok": not incomplete and not missing and not wrongly_compliant,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    elif incomplete:
        print(f"  INCOMPLETE — could not list {len(failed)} of {len(locations)} location(s) "
              f"after {LIST_ATTEMPTS} attempts each:")
        for location, err in failed.items():
            print(f"    {location}: {err}")
        print("  No verdict: the live-API set is partial, so every agent in the "
              "unlistable location(s) would be misreported as API-invisible.")
    else:
        print(f"  api={len(api)} view={len(view)} (locations: {', '.join(locations)})")
        print(f"  missing from view: {len(missing)} {missing or ''}")
        print(f"  API-invisible rows: {len(api_invisible)} "
              f"(classified: {sorted({view[n] for n in api_invisible}) or 'n/a'})")
        if wrongly_compliant:
            print(f"  WRONGLY COMPLIANT: {wrongly_compliant}")

    if incomplete:
        return EXIT_INCOMPLETE
    return EXIT_OK if result["ok"] else EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
