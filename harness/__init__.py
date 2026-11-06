"""The production harness (D69): the proposing side, in a top-level package of its own.

Why a package rather than a module under ``agents/`` or ``control_plane/``: P-2 of
``docs/D69_IMPLEMENTATION_PLAN.md``. Three import rules hold, each pinned by a test in
``tests/test_harness_import_direction.py``:

* ``harness`` may import ``agents.*`` and the control plane's function API;
* nothing under ``agents/`` or ``control_plane/`` may import ``harness``;
* ``harness`` must not import ``control_plane.scheduler`` -- the harness proposes, the
  scheduler dispatches what a person approved, and neither may reach into the other.

H2, the stage this package starts with, is the action allowlist and nothing else:
:mod:`harness.action_allowlist` holds the closed list, the candidate builder and the two
checks; :mod:`harness.registry_view` is a read-only view of the Scope Registry. Nothing
here creates a task, claims one, or proposes an action.
"""
