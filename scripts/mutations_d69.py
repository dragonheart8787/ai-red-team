# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations of D69 H2, the harness's action allowlist, as runnable checks (see ``mutation_check.py``).

``python scripts/mutations_d69.py --list`` names them. H2 is the allowlist (D69-6 A'): the harness
offers ``network.scan`` and ``network.recon`` and refuses every other action, both by filtering the
candidates a role is offered and by checking what a role returned before the control plane is
called. Each mutation breaks one rule of that, and a named test must be red.

Two of them are about *import direction* rather than about a value, so they are shaped differently:

* D69-H2-5 writes a temporary module under ``agents/`` that imports ``harness`` -- the direction P-2
  forbids. There is nothing to edit, because the offending import does not exist anywhere in the
  tree; the mutation is the file. It is removed before the next mutation runs, when the run ends,
  and at the start of a run that was killed before it could clean up, so it is never left behind.
* D69-H2-6 adds an import of ``control_plane.scheduler`` to a module under ``harness/``.

What is deliberately *not* in this catalogue, and why:

* "widen ``ALLOWED_ACTIONS`` to three actions" -- the same mutant as H2-1 as far as the filter is
  concerned (a wider list is a filter that lets more through), and already covered by the test that
  pins the constant, which asserts the tuple itself;
* "offer a candidate the registry does not have" -- that is the base classes' ``scope_object_id``
  check, which D68's catalogue already covers; H2 changed nothing about it;
* "call ``create_task`` / ``propose_action`` from the harness" -- H2 contains no such call, so there
  is no line to mutate. The stage that adds them brings its own mutations.
"""

from __future__ import annotations

import atexit
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import ROOT, Edit, Mutation, main  # noqa: E402

ALLOWLIST = "harness/action_allowlist.py"
REGISTRY_VIEW = "harness/registry_view.py"
ACTION_TESTS = ("tests/test_harness_action_allowlist.py",)
DIRECTION_TESTS = ("tests/test_harness_import_direction.py",)

#: D69-H2-5's mutation is a file, not an edit. Written under ``agents/`` so that the rule it breaks
#: -- nothing under ``agents/`` or ``control_plane/`` imports ``harness`` -- is broken in the place
#: it is about, and removed again by ``_remove_probe`` below.
PROBE = ROOT / "agents" / "_d69_h2_import_probe.py"
PROBE_SOURCE = '''"""Temporary: written by scripts/mutations_d69.py for D69-H2-5, and removed again.

A module under ``agents/`` that imports ``harness``, which is the import direction P-2 forbids. If
this file is in the tree and no mutation is running, a mutation run was killed before it could
clean up: delete it.
"""

import harness  # noqa: F401
'''


def _remove_probe() -> None:
    PROBE.unlink(missing_ok=True)


def _with_probe() -> dict[str, str]:
    """D69-H2-5: the offending module exists while its test runs, and only then."""
    _remove_probe()
    PROBE.write_text(PROBE_SOURCE)
    return {}


def _without_probe() -> dict[str, str]:
    """Every other mutation runs with no probe in the tree, whatever ran before it."""
    _remove_probe()
    return {}


_remove_probe()                      # a previous run that was killed leaves nothing for this one
atexit.register(_remove_probe)       # and this one leaves nothing behind either


CATALOGUE = [
    Mutation("D69-H2-1", "the candidate builder does not filter allowed_actions",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '        actions = tuple(a for a in tuple(scope_object.allowed_actions) if a in ALLOWED_ACTIONS)\n',
                         '        actions = tuple(scope_object.allowed_actions)\n'),),
             prepare=_without_probe,
             targets=('test_a_worker_naming_an_excluded_action_is_refused_only_once_the_candidates_are_filtered',
                      'test_a_supervisor_planning_an_excluded_action_is_refused_once_the_candidates_are_filtered')),
    Mutation("D69-H2-2", "the Supervisor-side check is gone: any planned action passes",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '    if action not in ALLOWED_ACTIONS:\n        return _refused(counter, side=SIDE_TASK, reason=REASON_ACTION_NOT_ALLOWED)\n',
                         ''),),
             prepare=_without_probe,
             targets=('test_a_task_whose_action_is_outside_the_allowlist_is_refused_counted_and_not_re_asked',)),
    Mutation("D69-H2-3", "the Worker-side check is gone: any proposed action passes",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '    if action not in ALLOWED_ACTIONS:\n        return _refused(counter, side=SIDE_PROPOSAL, reason=REASON_ACTION_NOT_ALLOWED)\n',
                         ''),),
             prepare=_without_probe,
             targets=('test_a_proposal_whose_action_is_outside_the_allowlist_is_refused_counted_and_not_re_asked',)),
    Mutation("D69-H2-4", "a candidate with no allowed action left is offered anyway",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '        if not actions:\n            continue\n',
                         ''),),
             prepare=_without_probe,
             targets=('test_a_scope_object_whose_only_actions_are_excluded_is_not_offered_at_all',)),
    Mutation("D69-H2-5", "a module under agents/ imports harness",
             DIRECTION_TESTS,
             prepare=_with_probe,
             targets=('test_nothing_under_agents_or_the_control_plane_imports_the_harness',)),
    Mutation("D69-H2-6", "a module under harness/ imports control_plane.scheduler",
             DIRECTION_TESTS,
             edits=(Edit(REGISTRY_VIEW,
                         'from control_plane.registry.scope_registry import list_scope_objects\n',
                         'from control_plane.registry.scope_registry import list_scope_objects\nfrom control_plane.scheduler import vocab  # noqa: F401\n'),),
             prepare=_without_probe,
             targets=('test_nothing_under_the_harness_imports_the_scheduler',)),
]

if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
