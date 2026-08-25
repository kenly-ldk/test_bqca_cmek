"""Layer 1 — the policy-gated deploy step.

This is the second half of Layer 1. `policy.rego` decides whether a manifest is
acceptable; this applies an accepted manifest to the Conversational Analytics
API. It exists because there is no Terraform resource for DataAgents (see
docs/design.md §5.1), so "apply the desired state" has to be a script.

Two gates, deliberately redundant:

  1. CI runs `opa eval` against policy.rego and fails the build on any deny.
  2. This script re-evaluates the same rules in-process via
     common.gda_common.evaluate_compliance before every create.

The second gate exists because the first can be skipped — someone runs the
deploy job directly, the OPA step is misconfigured, a pipeline is edited. A
deploy path that trusts an upstream check it cannot verify is not a control.
The two gates share their location and key-project logic with the Layer 4
enforcer, so all three agree by construction.

Manifest format (see manifests/):

    {
      "agents": [
        {
          "id": "wealth-management-agent",
          "location": "us-east4",
          "kms_key": "projects/.../cryptoKeys/agent-key",
          "display_name": "...",
          "description": "...",
          "system_instruction": "...",
          "bigquery_tables": [
            {"project_id": "...", "dataset_id": "...", "table_id": "..."}
          ]
        }
      ]
    }

Usage:
    python -m layer1.apply_manifest --manifest layer1/manifests/agents.json
    python -m layer1.apply_manifest --manifest ... --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import AlreadyExists, GoogleAPICallError, PermissionDenied
from google.cloud import geminidataanalytics

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.gda_common import (  # noqa: E402
    api_endpoint,
    evaluate_compliance,
    parse_approved_projects,
)
from config._loader import load  # noqa: E402


class PolicyViolation(Exception):
    """Raised when a manifest entry fails the in-process gate."""


def _client(location: str) -> geminidataanalytics.DataAgentServiceClient:
    return geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _context(spec: dict) -> geminidataanalytics.Context:
    tables = [
        geminidataanalytics.BigQueryTableReference(
            project_id=t["project_id"], dataset_id=t["dataset_id"], table_id=t["table_id"]
        )
        for t in spec.get("bigquery_tables", [])
    ]
    return geminidataanalytics.Context(
        system_instruction=spec.get("system_instruction", ""),
        datasource_references=geminidataanalytics.DatasourceReferences(
            bq=geminidataanalytics.BigQueryTableReferences(table_references=tables)
        ),
    )


def check(spec: dict, approved: frozenset[str]) -> None:
    """In-process gate. Raises PolicyViolation; never returns a soft failure."""
    # Required fields first. Everything below reads them, and an entry missing
    # `id` or `location` must be reported as a policy violation, not raised as a
    # KeyError from somewhere deeper — a traceback reads as "the tool is broken"
    # rather than "your manifest is non-compliant".
    for field in ("id", "location"):
        if not spec.get(field):
            raise PolicyViolation(
                f"{spec.get('id', '<no id>')}: MALFORMED_MANIFEST — "
                f"required field '{field}' is missing or empty."
            )

    verdict = evaluate_compliance(spec.get("location", ""), spec.get("kms_key"), approved)
    if not verdict.is_compliant:
        raise PolicyViolation(f"{spec.get('id', '<no id>')}: {verdict.status} — {verdict.reason}")


def apply_agent(spec: dict, project: str, approved: frozenset[str], dry_run: bool) -> str:
    # Gate BEFORE dereferencing anything. Reading spec["id"] or spec["location"]
    # first would make a manifest missing either crash with an uncaught KeyError
    # instead of raising the PolicyViolation this gate promises.
    check(spec, approved)

    agent_id = spec["id"]
    location = spec["location"]

    parent = f"projects/{project}/locations/{location}"
    name = f"{parent}/dataAgents/{agent_id}"
    if dry_run:
        print(f"  [DRY-RUN] would create {name} (kms_key={spec['kms_key']})")
        return name

    agent = geminidataanalytics.DataAgent(
        display_name=spec.get("display_name", agent_id),
        description=spec.get("description", ""),
        kms_key=spec["kms_key"],
        data_analytics_agent=geminidataanalytics.DataAnalyticsAgent(
            published_context=_context(spec)
        ),
    )

    client = _client(location)
    try:
        created = client.create_data_agent_sync(
            request=geminidataanalytics.CreateDataAgentRequest(
                parent=parent, data_agent_id=agent_id, data_agent=agent
            )
        )
        print(f"  created {created.name} (kms_key={created.kms_key})")
        return created.name
    except AlreadyExists:
        # kms_key is immutable, so an existing agent cannot be brought into
        # compliance by updating it. Try to read it back and compare.
        #
        # roles/geminidataanalytics.dataAgentCreator grants ONLY create,
        # locations.chat and operations.get — NOT get or list (verified in
        # tests/run_layer2.sh). A pipeline running with just that role therefore
        # cannot read back what it created. Rather than crash, say so plainly:
        # "I could not verify" must never be printed as "compliant".
        try:
            existing = client.get_data_agent(name=name)
        except PermissionDenied:
            print(
                f"  exists {name} (UNVERIFIED — this identity lacks "
                "dataAgents.get; add roles/geminidataanalytics.dataAgentViewer "
                "to confirm its key)"
            )
            return name

        state = "compliant" if existing.kms_key == spec["kms_key"] else "MISMATCHED KEY"
        print(f"  exists {name} ({state}; kms_key={existing.kms_key or '<none>'})")
        if state != "compliant":
            raise PolicyViolation(
                f"{agent_id}: already exists with kms_key={existing.kms_key or '<none>'}, "
                f"manifest wants {spec['kms_key']}. Keys are immutable after creation — "
                "the agent must be recreated under a new ID."
            ) from None
        return name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    env = load()
    project = env["PROJECT_ID"]
    approved = parse_approved_projects(
        os.environ.get("APPROVED_KMS_PROJECTS") or env.get("APPROVED_KMS_PROJECTS") or project
    )

    manifest = json.loads(args.manifest.read_text())
    agents = manifest.get("agents", [])
    print(f"Applying {len(agents)} agent(s) from {args.manifest}")
    print(f"  approved KMS projects: {sorted(approved)}")

    failures: list[str] = []
    for spec in agents:
        try:
            apply_agent(spec, project, approved, args.dry_run)
        except PolicyViolation as exc:
            print(f"  REJECTED {exc}")
            failures.append(str(exc))
        except GoogleAPICallError as exc:
            print(f"  FAILED {spec.get('id')}: {type(exc).__name__}: {exc.message}")
            failures.append(f"{spec.get('id')}: {exc.message}")

    if failures:
        print(f"\n{len(failures)} of {len(agents)} agent(s) not applied.")
        return 1
    print(f"\nAll {len(agents)} agent(s) applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
