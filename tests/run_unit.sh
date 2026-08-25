#!/usr/bin/env bash
# Python unit tests. Fully offline: no GCP project, no credentials, no network.
#
# These cover the logic the per-layer gates can only reach by deploying to two
# live projects — the shared compliance verdict, the enforcer's audit-log
# parsing, and the scanner's reconciliation matrix. Two of the scanner branches
# they exercise are the "could not determine" paths (validation-report F9),
# which a healthy live estate does not reach — so this is the only place they
# are proven at all.
#
# Deliberately does NOT source scripts/prelude.sh. The prelude exports this
# workstation's real APPROVED_KMS_PROJECTS, which would redefine "compliant"
# underneath tests whose expectations are written against a fixed fake
# allowlist. tests/unit/conftest.py pins the environment for the same reason.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! python -c "import pytest" 2>/dev/null; then
  echo "pytest not installed. Install the dev dependencies with:"
  echo "  pip install -r tests/requirements-dev.txt"
  exit 127
fi

printf '\n\033[1m== Python unit tests\033[0m\n'
cd "${REPO_ROOT}"
exec python -m pytest tests/unit "$@"
