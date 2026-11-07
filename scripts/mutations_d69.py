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


OBSERVATIONS = "harness/observations.py"
OBS_TESTS = ("tests/test_harness_observations.py",)
OBS_DB_TESTS = ("tests/test_harness_observations_db.py",)

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
    Mutation("D69-H2-7", "the refusal counter does not check the reason code",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '        if reason not in REASON_CODES:\n            raise ValueError(\n                f"{reason!r} is not one of the closed refusal reasons {list(REASON_CODES)}"\n            )\n',
                         ''),),
             prepare=_without_probe,
             targets=('test_a_refusal_record_takes_a_reason_code_and_not_a_string_a_model_produced',)),
    Mutation("D69-H2-8a", "the missing-or-non-string branch is gone: such an action is refused as not allowed",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '    if not isinstance(action, str) or not action:\n        return _refused(counter, side=SIDE_TASK, reason=REASON_ACTION_MISSING)\n',
                         ''),
                    Edit(ALLOWLIST,
                         '    if not isinstance(action, str) or not action:\n        return _refused(counter, side=SIDE_PROPOSAL, reason=REASON_ACTION_MISSING)\n',
                         '')),
             prepare=_without_probe,
             targets=('test_both_checks_refuse_a_missing_action_and_each_refusal_is_counted_on_its_own_side',)),
    Mutation("D69-H2-8b", "a missing or non-string action is let through by both checks",
             ACTION_TESTS,
             edits=(Edit(ALLOWLIST,
                         '    if not isinstance(action, str) or not action:\n        return _refused(counter, side=SIDE_TASK, reason=REASON_ACTION_MISSING)\n',
                         '    if not isinstance(action, str) or not action:\n        return ActionCheck(allowed=True, reason=None)\n'),
                    Edit(ALLOWLIST,
                         '    if not isinstance(action, str) or not action:\n        return _refused(counter, side=SIDE_PROPOSAL, reason=REASON_ACTION_MISSING)\n',
                         '    if not isinstance(action, str) or not action:\n        return ActionCheck(allowed=True, reason=None)\n')),
             prepare=_without_probe,
             targets=('test_both_checks_refuse_a_missing_action_and_each_refusal_is_counted_on_its_own_side',)),
    Mutation("D69-H3-a", "a hostname that is not an IP literal is kept as an observed identity",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '        identity = _canonical_ip(host)\n        if identity is None:\n            continue\n', '        identity = _canonical_ip(host)\n        if identity is None:\n            identity = host\n'),),
             prepare=_without_probe,
             targets=('test_a_the_name_of_a_resolved_host_is_not_an_observed_identity',)),
    Mutation("D69-H3-b", "the requested target is counted as an observed identity",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    found: list[str] = []\n', '    found: list[str] = [row.requested_target] if row.requested_target else []\n'),),
             prepare=_without_probe,
             targets=('test_d_a_requested_target_with_no_responder_is_not_an_observed_identity',)),
    Mutation("D69-H3-c", "the content is transformed after it is built (backslashes stripped)",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    content = json.dumps(row.derived_view, sort_keys=True, default=str)\n', '    content = json.dumps(row.derived_view, sort_keys=True, default=str).replace("\\\\", "")\n'),),
             prepare=_without_probe,
             targets=('test_c_the_prompt_content_is_the_observation_content_byte_for_byte',)),
    Mutation("D69-H3-d", "a connect or version scan's hosts are collected too",
             OBS_TESTS + OBS_DB_TESTS,
             edits=(Edit(OBSERVATIONS, '    if row.scan_type != PING_SCAN_TYPE:\n        return ()\n', '    if row.scan_type not in (PING_SCAN_TYPE, "connect", "version"):\n        return ()\n'),),
             prepare=_without_probe,
             targets=('test_a_anything_but_the_exact_ping_value_observes_nothing',
                      'test_b_a_connect_or_version_run_observes_nothing_from_the_same_output')),
    Mutation("D69-H3-e", "an unknown scan type collects hosts instead of nothing",
             OBS_TESTS + OBS_DB_TESTS,
             edits=(Edit(OBSERVATIONS, '    if row.scan_type != PING_SCAN_TYPE:\n        return ()\n', '    if row.scan_type is not None and row.scan_type != PING_SCAN_TYPE:\n        return ()\n'),),
             prepare=_without_probe,
             targets=('test_a_anything_but_the_exact_ping_value_observes_nothing',
                      'test_b_an_evidence_row_with_no_run_observes_nothing')),
    Mutation("D69-H3-f", "the scan type is read from the proposal's target instead of the run",
             OBS_DB_TESTS,
             edits=(Edit(OBSERVATIONS, "           r.normalized_params->>'scan_type' AS scan_type,\n", "           p.target->>'scan_type' AS scan_type,\n"),
                    Edit(OBSERVATIONS, '      LEFT JOIN tool_runs r ON r.run_id = e.run_id\n', '      LEFT JOIN tool_runs r ON r.run_id = e.run_id\n      LEFT JOIN action_proposals p ON p.proposal_id = r.proposal_id\n')),
             prepare=_without_probe,
             targets=('test_b_a_run_whose_scan_type_differs_from_the_request_observes_nothing',)),
    Mutation("D69-H3-g", "the window returns one target's rows instead of the engagement's",
             OBS_DB_TESTS,
             edits=(Edit(OBSERVATIONS, '     ORDER BY e.created_at DESC, e.evidence_id DESC\n', "     WHERE r.normalized_params->>'target' = (SELECT normalized_params->>'target' FROM tool_runs ORDER BY created_at DESC LIMIT 1)\n     ORDER BY e.created_at DESC, e.evidence_id DESC\n"),),
             prepare=_without_probe,
             targets=('test_b_the_window_is_newest_first_and_the_limit_bounds_it',)),
    Mutation("D69-H3-h", "source carries the requested target as well as the tool",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '        source=f"tool:{row.tool}",\n', '        source=f"tool:{row.tool} target:{row.requested_target}",\n'),),
             prepare=_without_probe,
             targets=('test_e_source_and_description_carry_no_target_and_no_derived_text',)),
    Mutation("D69-H3-i", "an address is used as nmap printed it, without normalize_ip",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    try:\n        return normalize_ip(value)\n    except CanonicalizationError:\n        return None\n', '    return value\n'),),
             prepare=_without_probe,
             targets=('test_a_an_ipv6_address_is_canonicalized',)),
]

if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
