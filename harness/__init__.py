"""The production harness (D69): the proposing side, in a top-level package of its own.

Why a package rather than a module under ``agents/`` or ``control_plane/``: P-2 of
``docs/D69_IMPLEMENTATION_PLAN.md``. Three import rules hold; two are pinned by a test in
``tests/test_harness_import_direction.py``:

* ``harness`` may import ``agents.*`` and the control plane's function API. This one is a
  permission, not a direction a test can pin, so no test holds it: that the modules here
  do it and import is the whole of the evidence;
* nothing under ``agents/`` or ``control_plane/`` may import ``harness``
  (``test_nothing_under_agents_or_the_control_plane_imports_the_harness``);
* ``harness`` must not import ``control_plane.scheduler`` -- the harness proposes, the
  scheduler dispatches what a person approved, and neither may reach into the other
  (``test_nothing_under_the_harness_imports_the_scheduler``).

H2, the stage this package starts with, is the action allowlist and nothing else:
:mod:`harness.action_allowlist` holds the closed list, the candidate builder and the two
checks; :mod:`harness.registry_view` is a read-only view of the Scope Registry. Nothing
here creates a task, claims one, or proposes an action.
"""
