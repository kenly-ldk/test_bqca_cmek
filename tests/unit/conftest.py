"""Import paths and environment for the unit tests.

The deploy scripts copy `common/gda_common.py` into each build context, so
`layer4/main.py` and `layer5/scanner/main.py` both import it flat, as
`gda_common`. Reproduce that layout here rather than changing the modules —
the flat import is what actually runs in Cloud Run, so the tests should
exercise it.

Both modules also read configuration at import time, so the environment has to
be set before they are imported. The values are deliberately fake: nothing here
touches GCP.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

for path in (REPO_ROOT, REPO_ROOT / "common", REPO_ROOT / "layer5" / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

# Assigned, NOT setdefault. These tests must be hermetic: their expected
# verdicts are written against this fixed allowlist, so inheriting a real
# APPROVED_KMS_PROJECTS from config/shared.env.local (which any script sourcing
# scripts/prelude.sh exports) would silently change what "compliant" means and
# fail tests that are actually correct. Caught exactly that way — the first run
# of tests/run_unit.sh picked up the workstation's live project ID.
#
# Nothing here is a real resource; no test touches GCP.
os.environ["PROJECT_ID"] = "unit-test-project"
os.environ["BQ_DATASET"] = "unit_test_dataset"
os.environ["INVENTORY_TABLE"] = "agent_inventory"
os.environ["APPROVED_KMS_PROJECTS"] = "approved-a,approved-b"
os.environ["SCAN_LOCATIONS"] = "us-east4,us,eu,global"
os.environ.pop("DRY_RUN", None)
