"""Layer 3 — prove CMEK is a real cryptographic boundary, not a config echo.

A `kms_key` field echoed back on GET proves nothing about encryption. The only
honest test is key revocation: disable the CryptoKeyVersion and confirm the
protected content (`data_analytics_agent.published_context`) becomes
unreadable, then re-enable and confirm recovery.

Per the CMEK docs, only the agent *context* is protected by the key; `name`,
`display_name`, `description` and `kms_key` itself stay under Google default
encryption. This script asserts that asymmetry too, because it is exactly what
makes Layer 4 remediation possible while a key is disabled.

Usage:
    python -m layer3.verify_cmek
"""

from __future__ import annotations

import os
import sys
import time

from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import FailedPrecondition, GoogleAPICallError
from google.cloud import geminidataanalytics, kms

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.gda_common import api_endpoint  # noqa: E402
from config._loader import load  # noqa: E402

# Run-scoped, matching layer3.create_agent: deletion is soft, so an agent ID
# stays occupied until purgeTime (~30 days) and cannot be reused.
_RUN_ID = os.getenv("RUN_ID")
AGENT_ID = f"agent-compliant-{_RUN_ID}" if _RUN_ID else "agent-compliant"
# Cloud KMS enable/disable is not instantaneous end-to-end; poll rather than
# asserting on a single read.
POLL_ATTEMPTS = 12
POLL_SECONDS = 10


class Result:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.checks)


def _agent_client(location: str) -> geminidataanalytics.DataAgentServiceClient:
    return geminidataanalytics.DataAgentServiceClient(
        client_options=ClientOptions(api_endpoint=api_endpoint(location))
    )


def _set_key_version_state(key_path: str, enabled: bool) -> None:
    """Enable or disable primary version 1 of the CryptoKey."""
    client = kms.KeyManagementServiceClient()
    version_name = f"{key_path}/cryptoKeyVersions/1"
    state = (
        kms.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
        if enabled
        else kms.CryptoKeyVersion.CryptoKeyVersionState.DISABLED
    )
    client.update_crypto_key_version(
        request={
            "crypto_key_version": {"name": version_name, "state": state},
            "update_mask": {"paths": ["state"]},
        }
    )
    print(f"  key version {'ENABLED' if enabled else 'DISABLED'}: {version_name}")


def _read_context(client, name: str) -> tuple[bool, str]:
    """Try to read the CMEK-protected context. Returns (readable, detail)."""
    try:
        agent = client.get_data_agent(name=name)
    except FailedPrecondition as exc:
        return False, f"FailedPrecondition: {exc.message}"
    except GoogleAPICallError as exc:
        return False, f"{type(exc).__name__}: {exc.message}"

    instruction = agent.data_analytics_agent.published_context.system_instruction
    if not instruction:
        return False, "context returned empty (content withheld)"
    return True, f"context readable ({len(instruction)} chars)"


def _poll_until(client, name: str, want_readable: bool) -> tuple[bool, str]:
    detail = ""
    for attempt in range(1, POLL_ATTEMPTS + 1):
        readable, detail = _read_context(client, name)
        if readable == want_readable:
            return True, f"after {attempt} attempt(s): {detail}"
        time.sleep(POLL_SECONDS)
    return False, f"still {'readable' if not want_readable else 'unreadable'}: {detail}"


def main() -> int:
    env = load()
    project, location = env["PROJECT_ID"], env["AGENT_LOCATION"]
    key_path = (
        f"projects/{project}/locations/{location}"
        f"/keyRings/{env['KMS_KEYRING']}/cryptoKeys/{env['KMS_KEY']}"
    )
    name = f"projects/{project}/locations/{location}/dataAgents/{AGENT_ID}"
    client = _agent_client(location)
    result = Result()

    print(f"\n== Layer 3: CMEK verification for {name}")

    agent = client.get_data_agent(name=name)
    result.add(
        "kms_key round-trips on GET",
        agent.kms_key == key_path,
        f"{agent.kms_key or '<none>'}",
    )
    readable, detail = _read_context(client, name)
    result.add("context readable while key ENABLED", readable, detail)

    print("\n-- revoking key access --")
    _set_key_version_state(key_path, enabled=False)
    try:
        blocked, detail = _poll_until(client, name, want_readable=False)
        result.add("context UNREADABLE while key DISABLED", blocked, detail)

        # Observed behaviour, contrary to what the CMEK docs imply: revocation
        # does not merely withhold the protected context, it fails the whole
        # GetDataAgent RPC. Metadata the docs list as "Google default
        # encryption" (display_name, description) is unreachable too.
        try:
            meta = client.get_data_agent(name=name)
            result.add(
                "GET fails closed while key DISABLED",
                False,
                f"unexpectedly succeeded: display_name={meta.display_name!r}",
            )
        except FailedPrecondition:
            result.add(
                "GET fails closed while key DISABLED",
                True,
                "whole RPC raises FailedPrecondition — metadata is NOT "
                "independently readable, so Layer 4 must fail closed",
            )

        # LIST does not fail — it silently drops the agent. An inventory built
        # from LIST alone therefore under-reports, which is the worst possible
        # failure mode for a regulator-facing completeness claim.
        listed = {a.name for a in client.list_data_agents(parent=f"projects/{project}/locations/{location}")}
        result.add(
            "LIST silently omits the key-disabled agent",
            name not in listed,
            f"{len(listed)} agent(s) visible; {AGENT_ID} hidden without error",
        )
    finally:
        print("\n-- restoring key access --")
        _set_key_version_state(key_path, enabled=True)

    recovered, detail = _poll_until(client, name, want_readable=True)
    result.add("context readable again after key RE-ENABLED", recovered, detail)

    print(f"\n== Layer 3 verdict: {'PASS' if result.ok else 'FAIL'}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
