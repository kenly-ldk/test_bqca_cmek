"""Load the deployable modules by path, under unambiguous names.

`layer4/main.py` and `layer5/scanner/main.py` are BOTH called `main` — each is
the entry point of its own container image, so neither can be renamed without
diverging from what actually ships. Importing them as `main` makes the test
suite order-dependent: whichever ran first would win `sys.modules['main']`, and
the second would silently exercise the wrong module.

Loading each from its file under a distinct name removes the collision. It also
re-executes the module body on every call, which is what makes it possible to
test import-time configuration (the enforcer computes MISCONFIGURED at import)
by patching the environment and reloading.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(module_name: str, relative_path: str) -> ModuleType:
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise ImportError(f"cannot load {module_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_scanner() -> ModuleType:
    """layer5/scanner/main.py — the compliance inventory job."""
    return _load("gda_scanner_main", "layer5/scanner/main.py")


def load_enforcer() -> ModuleType:
    """layer4/main.py — the real-time remediation function.

    Re-executed on each call so import-time settings (APPROVED_KMS_PROJECTS,
    DRY_RUN, MISCONFIGURED) reflect the environment at call time.
    """
    return _load("gda_enforcer_main", "layer4/main.py")
