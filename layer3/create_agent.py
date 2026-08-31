"""Layer 3 — create DataAgent resources with (and deliberately without) CMEK.

Exercises the resource-level CMEK capability the enforcement framework rests on,
and simultaneously demonstrates the org-policy enforcement gap: the API happily
accepts an agent with no ``kms_key`` at all, and one whose key lives in an
arbitrary project.

Usage:
    python -m layer3.create_agent --variant compliant
    python -m layer3.create_agent --variant nokey
    python -m layer3.create_agent --variant rogue
    python -m layer3.create_agent --variant global-nokey
    python -m layer3.create_agent --all
"""

from __future__ import annotations

import argparse
import os
import sys

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import AlreadyExists, GoogleAPICallError
from google.cloud import geminidataanalytics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.gda_common import api_endpoint  # noqa: E402
from config._loader import load, require  # noqa: E402


def _client(location: str) -> geminidataanalytics.DataAgentServiceClient:
    """Client pinned to the endpoint that serves ``location``."""
    return geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _published_context() -> geminidataanalytics.Context:
    """Agent context. This is the payload CMEK actually protects at rest."""
    project = require("PROJECT_ID")
    table = geminidataanalytics.BigQueryTableReference(
        project_id=project,
        dataset_id=require("BQ_SOURCE_DATASET"),
        table_id=require("BQ_SOURCE_TABLE"),
    )
    return geminidataanalytics.Context(
        system_instruction=(
            "You are the Cymbal Bank wealth analytics assistant. Answer questions "
            "about customers using the customers table. Be concise and prefer a "
            "single SQL query."
        ),
        datasource_references=geminidataanalytics.DatasourceReferences(
            bq=geminidataanalytics.BigQueryTableReferences(table_references=[table])
        ),
    )


# variant -> (agent_id_stem, location_override, kms_key_builder)
VARIANTS = {
    "compliant": ("agent-compliant", None, lambda env: env["APPROVED_KMS_KEY_PATH"]),
    "nokey": ("agent-nokey", None, lambda env: None),
    "rogue": ("agent-rogue-key", None, lambda env: env["ROGUE_KMS_KEY_PATH"]),
    # `global` cannot be CMEK-encrypted by any route, so a key is not even
    # offered: a regional key is rejected for location mismatch, and a global
    # KMS key with "Global KMS keys are not allowed for Data Agent"
    # (validation-report F6).
    "global-nokey": ("agent-global-nokey", "global", lambda env: None),
}


def agent_id_for(variant: str, run_id: str | None) -> str:
    """Agent IDs are run-scoped because deletion is only a SOFT delete.

    A deleted DataAgent sits in SOFT_DELETED state until purgeTime (30 days
    later) and continues to occupy its resource ID, so re-running a test with
    fixed IDs fails with AlreadyExists. Pass RUN_ID to get fresh IDs.
    """
    stem = VARIANTS[variant][0]
    return f"{stem}-{run_id}" if run_id else stem


def _derived_key_paths(env: dict[str, str]) -> dict[str, str]:
    location = env["AGENT_LOCATION"]
    return {
        "APPROVED_KMS_KEY_PATH": (
            f"projects/{env['PROJECT_ID']}/locations/{location}"
            f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['KMS_KEY']}"
        ),
        "ROGUE_KMS_KEY_PATH": (
            f"projects/{env['ROGUE_PROJECT_ID']}/locations/{location}"
            f"/keyRings/{env['ROGUE_KMS_KEYRING']}/cryptoKeys/{env['ROGUE_KMS_KEY']}"
        ),
    }


def create(variant: str, run_id: str | None = None) -> str | None:
    env = load()
    env.update(_derived_key_paths(env))

    _, location_override, key_fn = VARIANTS[variant]
    agent_id = agent_id_for(variant, run_id)
    project = env["PROJECT_ID"]
    location = location_override or env["AGENT_LOCATION"]
    kms_key = key_fn(env)

    agent = geminidataanalytics.DataAgent(
        display_name=f"CMEK validation — {variant}",
        description=f"Layer 3 CMEK validation fixture (variant={variant}).",
        data_analytics_agent=geminidataanalytics.DataAnalyticsAgent(
            published_context=_published_context()
        ),
    )
    if kms_key:
        agent.kms_key = kms_key

    parent = f"projects/{project}/locations/{location}"
    print(f"[{variant}] creating {parent}/dataAgents/{agent_id}")
    print(f"[{variant}]   endpoint = {api_endpoint(location)}")
    print(f"[{variant}]   kms_key  = {kms_key or '<none>'}")

    client = _client(location)
    try:
        created = client.create_data_agent_sync(
            request=geminidataanalytics.CreateDataAgentRequest(
                parent=parent, data_agent_id=agent_id, data_agent=agent
            )
        )
    except AlreadyExists:
        print(f"[{variant}] already exists, reusing")
        created = client.get_data_agent(name=f"{parent}/dataAgents/{agent_id}")
    except GoogleAPICallError as exc:
        print(f"[{variant}] FAILED: {type(exc).__name__}: {exc.message}")
        return None

    print(f"[{variant}] created. kms_key on server = {created.kms_key or '<none>'}")
    return created.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=sorted(VARIANTS))
    parser.add_argument("--all", action="store_true", help="create every variant")
    parser.add_argument(
        "--run-id",
        default=os.getenv("RUN_ID"),
        help="suffix for agent IDs; required to re-run, since delete is soft "
        "and the old ID stays occupied until purgeTime",
    )
    args = parser.parse_args()

    if not args.all and not args.variant:
        parser.error("pass --variant or --all")

    variants = sorted(VARIANTS) if args.all else [args.variant]
    failures = [v for v in variants if create(v, args.run_id) is None]
    if failures:
        print(f"\nFAILED variants: {failures}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
