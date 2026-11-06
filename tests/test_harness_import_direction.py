"""D69 H2: the harness's import rules (P-2 of docs/D69_IMPLEMENTATION_PLAN.md).

Two of the three rules are testable as *directions*, and they are the two that can be
broken silently, by one import added in a hurry:

* nothing under ``agents/`` or ``control_plane/`` may import ``harness``. The harness is
  the proposing side: it reads the roles and the control plane's function API, and if the
  dependency ran the other way the control plane would be executing the harness's idea of
  what is allowed instead of its own;
* ``harness`` may not import ``control_plane.scheduler``. The harness proposes and the
  scheduler dispatches what a person approved; a harness that could reach into the
  scheduler could dispatch its own proposal, which is the one thing the split is for.

The third rule -- the harness *may* import ``agents.*`` and the function API -- needs no
test: :mod:`harness.action_allowlist` and :mod:`harness.registry_view` do it, and they
import.

Both tests read imports with :mod:`ast` rather than importing anything, so a module that
cannot be imported in this environment is still checked. Modelled on
``tests/test_scheduler_structure.py``'s
``test_nothing_the_agents_or_tools_run_can_import_the_scheduler``, which is the same shape
of rule for the scheduler.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _imports(path: Path) -> set[str]:
    """Every name a module imports, as ``module.name`` (``import x`` as ``x``)."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def _modules(top: str) -> list[Path]:
    """The Python files under one top-level package, sorted. Never empty: an empty walk
    would make the test below pass by looking at nothing."""
    found = sorted((ROOT / top).rglob("*.py"))
    assert found, f"no Python files found under {top}/"
    return found


def test_nothing_under_agents_or_the_control_plane_imports_the_harness():
    offenders = []
    for top in ("agents", "control_plane"):
        for path in _modules(top):
            if any(name == "harness" or name.startswith("harness.") for name in _imports(path)):
                offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_nothing_under_the_harness_imports_the_scheduler():
    offenders = []
    for path in _modules("harness"):
        if any(name.startswith("control_plane.scheduler") for name in _imports(path)):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []
