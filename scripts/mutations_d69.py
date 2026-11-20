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
             edits=(Edit(OBSERVATIONS, '    content = json.dumps(\n        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n    )\n', '    content = json.dumps(\n        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n    ).replace("\\\\", "")\n'),),
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
    Mutation("D69-H3-j", "the content is lower-cased after it is built",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    content = json.dumps(\n        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n    )\n', '    content = json.dumps(\n        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n    ).lower()\n'),),
             prepare=_without_probe,
             targets=('test_content_is_the_derived_view_dumped_once_and_never_transformed',)),
    Mutation("D69-H3-k", "the content is cut at 200 characters",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    content = json.dumps(\n        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n    )\n', '    content = json.dumps(\n        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n    )[:200]\n'),),
             prepare=_without_probe,
             targets=('test_content_is_the_derived_view_dumped_once_and_never_transformed',)),
    Mutation("D69-H3-l", "an address reported twice is kept twice",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '        if identity not in found:\n            found.append(identity)\n', '        found.append(identity)\n'),),
             prepare=_without_probe,
             targets=('test_a_a_repeated_address_is_kept_once_in_report_order',)),
    Mutation("D69-H3-m", "the tool is not checked: any tool's hosts are collected on a ping run",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    if row.tool != NMAP_TOOL:\n        return ()\n', ''),),
             prepare=_without_probe,
             targets=('test_f_a_row_from_another_tool_keeps_its_content_and_observes_nothing',)),
    Mutation("D69-H3-n", "the limit is not validated",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    if isinstance(limit, bool) or not isinstance(limit, int):\n        raise ValueError(f"limit must be an int, got {type(limit).__name__}")\n    if limit < 1:\n        raise ValueError(f"limit must be at least 1, got {limit}")\n', ''),),
             prepare=_without_probe,
             targets=('test_t6_a_refused_limit_is_refused_before_any_query_is_sent',)),
    Mutation("D69-H3-o", "the type of hosts is not checked",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '    if not isinstance(hosts, Sequence) or isinstance(hosts, str | bytes):\n        return ()\n', ''),),
             prepare=_without_probe,
             targets=('test_a_hosts_value_that_is_not_a_list_of_addresses_observes_nothing',)),
    Mutation("D69-H3-p", "the content goes back to json.dumps' default, escaping every non-ASCII character",
             OBS_TESTS,
             edits=(Edit(OBSERVATIONS, '        row.derived_view, sort_keys=True, default=str, ensure_ascii=False,\n', '        row.derived_view, sort_keys=True, default=str,\n'),),
             prepare=_without_probe,
             targets=('test_content_is_the_derived_view_dumped_once_and_never_transformed',
                      'test_t7_a_banner_naming_a_host_with_a_non_ascii_letter_introduces_it')),
    Mutation("D69-H4-1", "a cidr with no prefix length is no longer refused",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '        if _is_cidr_without_prefix(task):\n            counter.record(side=SIDE_TASK, reason=REASON_CIDR_WITHOUT_PREFIX)\n            continue\n', ''),),
             prepare=_without_probe,
             targets=('test_f_a_cidr_without_a_prefix_is_refused_and_counted_and_the_rest_pass',)),
    Mutation("D69-H4-2", "the Supervisor is asked again after a planning failure",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '    if planned is None:\n        return PlanOutcome(failure=PLAN_RETURNED_NONE)\n', '    if planned is None:\n        supervisor.plan(state=state, candidates=candidates)\n        return PlanOutcome(failure=PLAN_RETURNED_NONE)\n'),),
             prepare=_without_probe,
             targets=('test_e_a_plan_that_gives_nothing_is_asked_once_creates_nothing_and_records_a_code',)),
    Mutation("D69-H4-3", "a task refused for its action is not counted",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '        if not check_task_action(task.action, counter=counter).allowed:\n', '        if not check_task_action(task.action).allowed:\n'),),
             prepare=_without_probe,
             targets=('test_g_an_action_outside_the_allowlist_is_refused_and_counted_by_the_check',)),
    Mutation("D69-H4-4", "observations_for_task returns the window without its last row",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/round_snapshot.py", '        return self.observations\n', '        return self.observations[:-1]\n'),),
             prepare=_without_probe,
             targets=('test_b_everything_the_supervisor_sees_is_in_the_set_a_worker_is_judged_against',
                      'test_c_a_task_on_a_host_only_another_scan_names_is_introduced_by_untrusted_text')),
    Mutation("D69-H4-5", "supervisor_evidence cuts the derived view",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/round_snapshot.py", '                derived_view=row.derived_view,\n', '                derived_view=str(row.derived_view)[:60],\n'),),
             prepare=_without_probe,
             targets=('test_b_everything_the_supervisor_sees_is_in_the_set_a_worker_is_judged_against',
                      'test_b_the_supervisors_view_is_the_row_as_read_and_nothing_is_cut')),
    Mutation("D69-H4-6", "the state summary carries a finding",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/round_snapshot.py", '    EvidenceRecord,\n    StateSummary,\n', '    EvidenceRecord,\n    FindingRecord,\n    StateSummary,\n'),
                    Edit("harness/round_snapshot.py", '        findings=(),\n', '        findings=(FindingRecord(finding_id="F-1", claim="x", state="open"),),\n')),
             prepare=_without_probe,
             targets=('test_d_findings_are_always_empty_and_tasks_and_decisions_default_to_empty',)),
    Mutation("D69-H4-7", "observations_for_task reads the window again",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/round_snapshot.py", '    limit: int\n\n    def supervisor_evidence', '    limit: int\n    conn: object = None\n\n    def supervisor_evidence'),
                    Edit("harness/round_snapshot.py", '        limit=limit,\n    )\n', '        limit=limit,\n        conn=conn,\n    )\n'),
                    Edit("harness/round_snapshot.py", '        return self.observations\n', '        return observations_from_window(read_evidence_window(self.conn, limit=self.limit))\n')),
             prepare=_without_probe,
             targets=('test_a_the_snapshot_sends_one_query_when_taken_and_none_after',)),
    Mutation("D69-H4-8", "the exception create_task raises is caught and swallowed",
             ("tests/test_harness_task_source.py", "tests/test_harness_task_source_db.py"),
             edits=(Edit("harness/task_source.py", '            task_id = create_task(\n                conn, engagement_id=engagement_id, task=task, created_by=created_by,\n            )\n', '            try:\n                task_id = create_task(\n                    conn, engagement_id=engagement_id, task=task, created_by=created_by,\n                )\n            except Exception:\n                continue\n'),),
             prepare=_without_probe,
             targets=('test_k_a_stand_in_create_task_that_raises_propagates_and_earlier_tasks_stay',
                      'test_k_an_exception_from_create_task_propagates_and_earlier_tasks_stay')),
    Mutation("D69-H4-9", "the task id is added to the ledger before the transaction commits",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '            )\n        ledger.add(task_id)\n', '            )\n            ledger.add(task_id)\n'),),
             prepare=_without_probe,
             targets=('test_k2_a_task_whose_transaction_does_not_commit_is_not_in_the_ledger',)),
    Mutation("D69-H4-10", "the action check is gone: any planned action is created",
             ("tests/test_harness_task_source.py", "tests/test_harness_task_source_db.py"),
             edits=(Edit("harness/task_source.py", '        if not check_task_action(task.action, counter=counter).allowed:\n            continue\n', ''),),
             prepare=_without_probe,
             targets=('test_g_an_action_outside_the_allowlist_is_refused_and_counted_by_the_check',
                      'test_h_a_refused_task_does_not_affect_the_other_tasks_of_the_plan',
                      'test_j_a_refused_task_has_no_row_and_the_others_do')),
    Mutation("D69-H4-10b", "the filter order is reversed: the cidr rule runs before the action rule",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '        if not check_task_action(task.action, counter=counter).allowed:\n            continue\n', ''),
                    Edit("harness/task_source.py", '        allowed.append(task)\n', '        if not check_task_action(task.action, counter=counter).allowed:\n            continue\n        allowed.append(task)\n')),
             prepare=_without_probe,
             targets=('test_g_when_both_rules_apply_the_action_is_what_is_counted',)),
    Mutation("D69-H4-11", "a cidr refused for its missing prefix is not counted",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '            counter.record(side=SIDE_TASK, reason=REASON_CIDR_WITHOUT_PREFIX)\n', ''),),
             prepare=_without_probe,
             targets=('test_f_a_cidr_without_a_prefix_is_refused_and_counted_and_the_rest_pass',)),
    Mutation("D69-H4-12", "the not-canonical check is removed",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '        try:\n            normalize_target(dict(task.target))\n        except CanonicalizationError:\n            counter.record(side=SIDE_TASK, reason=REASON_TARGET_NOT_CANONICAL)\n            continue\n', ''),),
             prepare=_without_probe,
             targets=('test_t9_a_target_that_does_not_canonicalize_is_refused_counted_and_the_rest_pass',)),
    Mutation("D69-H4-13", "a target refused as not canonical is not counted",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '            counter.record(side=SIDE_TASK, reason=REASON_TARGET_NOT_CANONICAL)\n', ''),),
             prepare=_without_probe,
             targets=('test_t9_a_target_that_does_not_canonicalize_is_refused_counted_and_the_rest_pass',)),
    Mutation("D69-H4-14", "after a refusal the Supervisor is asked once more, and its second refusal swallowed",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '    except SupervisorRefusal:\n        return PlanOutcome(failure=PLAN_REFUSED)\n', '    except SupervisorRefusal:\n        try:\n            supervisor.plan(state=state, candidates=candidates)\n        except SupervisorRefusal:\n            pass\n        return PlanOutcome(failure=PLAN_REFUSED)\n'),),
             prepare=_without_probe,
             targets=('test_e_a_plan_that_gives_nothing_is_asked_once_creates_nothing_and_records_a_code',)),
    Mutation("D69-H4-15", "any exception from plan is taken for a refusal",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '    except SupervisorRefusal:\n', '    except Exception:\n'),),
             prepare=_without_probe,
             targets=('test_e_an_exception_other_than_a_refusal_is_not_swallowed',)),
    Mutation("D69-H4-16", "the planning failure recorded is the Supervisor's own failure text",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '    if planned is None:\n        return PlanOutcome(failure=PLAN_RETURNED_NONE)\n', '    if planned is None:\n        return PlanOutcome(failure=supervisor.calls[-1].failure)\n'),),
             prepare=_without_probe,
             targets=('test_t12_the_failure_text_exists_where_it_could_be_copied_and_is_in_neither_record',
                      'test_e_a_plan_that_gives_nothing_is_asked_once_creates_nothing_and_records_a_code')),
    Mutation("D69-H4-17", "the not-canonical filter catches any exception, not only CanonicalizationError",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '        except CanonicalizationError:\n', '        except Exception:\n'),),
             prepare=_without_probe,
             targets=('test_t14_the_not_canonical_filter_catches_only_canonicalization_error',)),
    Mutation("D69-H4-18", "an empty plan is taken for a planning failure",
             ("tests/test_harness_task_source.py",),
             edits=(Edit("harness/task_source.py", '    if planned is None:\n', '    if not planned:\n'),),
             prepare=_without_probe,
             targets=('test_t15_an_empty_plan_creates_nothing_and_is_not_a_planning_failure',)),
    Mutation('D69-H5-6', 'derive_key puts a clock into the key, so the same input no longer gives the same key',
             ('tests/test_harness_h5a1_idempotency.py',),
             edits=(Edit('harness/idempotency.py', '    return f"{KEY_PREFIX}:{task_id}:{attempt}"\n', '    return f"{KEY_PREFIX}:{task_id}:{attempt}:{__import__(\'time\').monotonic_ns()}"\n'),),
             targets=('test_the_same_input_gives_the_same_key_every_time',)),
    Mutation('D69-H5-19', 'derive_key ignores the task id',
             ('tests/test_harness_h5a1_idempotency.py',),
             edits=(Edit('harness/idempotency.py', '    return f"{KEY_PREFIX}:{task_id}:{attempt}"\n', '    return f"{KEY_PREFIX}:{attempt}"\n'),),
             targets=('test_different_tasks_have_different_keys',)),
    Mutation('D69-H5-8', 'the round cap and the model-call cap checks are removed',
             ('tests/test_harness_h5a1_bounds.py',),
             edits=(Edit('harness/bounds.py', '        return self._rounds_started < self._max_rounds\n', '        return True\n'), Edit('harness/bounds.py', '        return self._model_calls < self._max_model_calls\n', '        return True\n'),),
             targets=('test_a_round_may_start_only_while_fewer_than_max_rounds_have_started', 'test_a_model_call_may_be_made_only_while_fewer_than_the_cap_are_recorded',)),
    Mutation('D69-H5-9', 'the no-progress check is removed from stop_reason',
             ('tests/test_harness_h5a1_bounds.py',),
             edits=(Edit('harness/bounds.py', '        if self._without_progress >= self._no_progress_limit:\n', '        if False:\n'),),
             targets=('test_the_run_of_rounds_without_progress_stops_at_its_limit',)),
    Mutation('D69-H5-11', 'build_summary folds the failure text into the summary of an unknown outcome',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    if state == STATE_UNKNOWN_OUTCOME:\n        return STATE_UNKNOWN_OUTCOME\n', '    if state == STATE_UNKNOWN_OUTCOME:\n        return f"{STATE_UNKNOWN_OUTCOME}:{outcome.failure}" if outcome.failure else STATE_UNKNOWN_OUTCOME\n'),),
             targets=('test_a_failure_with_free_text_becomes_other_and_the_text_is_nowhere_in_the_summary',)),
    Mutation('D69-H5-23', 'is_valid_summary accepts any string, not only the closed set',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    return isinstance(summary, str) and summary in VALID_SUMMARIES\n', '    return isinstance(summary, str)\n'),),
             targets=('test_a_string_outside_the_closed_set_is_not_a_valid_summary',)),
    Mutation('D69-H5-34', 'a failure outside the vocabulary is put into the summary as it is instead of other',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    return TOKEN_OTHER\n', '    return failure\n'),),
             targets=('test_a_failure_with_free_text_becomes_other_and_the_text_is_nowhere_in_the_summary',)),
    Mutation('D69-H5-18', 'two stop reasons share one exit code',
             ('tests/test_harness_h5a1_exit_codes.py',),
             edits=(Edit('harness/exit_codes.py', '    StopReason.LOCK_LOST: EXIT_LOCK_LOST,\n', '    StopReason.LOCK_LOST: EXIT_LOCK_HELD,\n'),),
             targets=('test_the_table_is_injective_no_two_reasons_share_a_code',)),
    Mutation('D69-H5-24', 'the banner leaves out its last required field, and a facts dict without that field passes the missing-field check',
             ('tests/test_harness_h5a1_banner.py',),
             edits=(Edit('harness/banner.py', '    missing = [f for f in REQUIRED_FIELDS if f not in facts]\n', '    missing = [f for f in REQUIRED_FIELDS[:-1] if f not in facts]\n'), Edit('harness/banner.py', '    lines = [f"{name}: {_RENDER[name](facts[name])}" for name in REQUIRED_FIELDS]\n', '    lines = [f"{name}: {_RENDER[name](facts[name])}" for name in REQUIRED_FIELDS[:-1]]\n'),),
             targets=('test_every_required_field_has_its_own_line_in_the_fixed_order', 'test_a_missing_field_is_refused',)),
    Mutation('D69-H5-35', 'RunCounters.increment accepts a name outside the closed vocabulary',
             ('tests/test_harness_h5a1_bounds.py',),
             edits=(Edit('harness/bounds.py', '        if name not in COUNTER_NAMES:\n            raise ValueError(f"unknown counter {name!r}")\n        self._counts[name] = self._counts.get(name, 0) + 1\n', '        self._counts[name] = self._counts.get(name, 0) + 1\n'),),
             targets=('test_a_counter_name_outside_the_closed_vocabulary_is_refused',)),
    Mutation('D69-H5-36', 'executed_state takes a run id alone for an executed action',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    if has_run:\n        return STATE_UNKNOWN_OUTCOME\n', '    if has_run:\n        return STATE_EXECUTED\n'),),
             targets=('test_the_state_is_executed_unknown_outcome_or_not_executed_from_the_two_ids',)),
    Mutation('D69-H5-37', 'is_key_conflict is always False',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    return KEY_CONFLICT_REASON in tuple(outcome.deny_reasons or ())\n', '    return False\n'),),
             targets=('test_a_deny_reason_of_a_reused_key_is_a_key_conflict_and_only_that',)),
    Mutation('D69-H5-38', 'the deduplicated branch is removed, so a dedup hit is an unknown outcome again',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    if has_run and failure == FAILURE_DEDUP_HIT:\n        return STATE_DEDUPLICATED\n', ''),),
             targets=('test_a_dedup_hit_with_only_a_run_id_is_deduplicated_and_its_summary_is_dedup_hit',)),
    Mutation('D69-H5-39', 'the deduplicated test ignores the failure, so any run id alone is a dedup hit',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    if has_run and failure == FAILURE_DEDUP_HIT:\n', '    if has_run:\n'),),
             targets=('test_only_a_run_id_without_exactly_dedup_hit_stays_unknown_outcome',)),
    Mutation('D69-H5-40', 'build_summary folds the failure text into the summary of an executed action',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    if state == STATE_EXECUTED:\n        return STATE_EXECUTED\n', '    if state == STATE_EXECUTED:\n        return f"{STATE_EXECUTED}:{outcome.failure}" if outcome.failure else STATE_EXECUTED\n'),),
             targets=('test_free_text_reaches_the_summary_in_none_of_the_four_states',)),
    Mutation('D69-H5-41', 'build_summary folds the failure text into the summary of an ALLOW that was not executed',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    if decision == DECISION_ALLOW:\n        return STATE_NOT_EXECUTED\n', '    if decision == DECISION_ALLOW:\n        return f"{STATE_NOT_EXECUTED}:{outcome.failure}" if outcome.failure else STATE_NOT_EXECUTED\n'),),
             targets=('test_free_text_reaches_the_summary_in_none_of_the_four_states',)),
    Mutation('D69-H5-42', 'is_valid_summary no longer requires a string: a non-string passes as valid',
             ('tests/test_harness_h5a1_result_summary.py',),
             edits=(Edit('harness/result_summary.py', '    return isinstance(summary, str) and summary in VALID_SUMMARIES\n', '    return not isinstance(summary, str) or summary in VALID_SUMMARIES\n'),),
             targets=('test_a_string_outside_the_closed_set_is_not_a_valid_summary',)),
    Mutation('D69-H5-2', "the policy is read by a call of the loop's own instead of through _load_policy",
             ('tests/test_harness_h5a2_structure.py',),
             edits=(Edit('harness/loop.py', '        policy = _load_policy(self.ports, engagement_id)\n', '        policy = self.ports.load_policy(engagement_id)\n'),),
             prepare=_without_probe,
             targets=('test_policy_is_read_only_in_load_policy_and_the_proposal_gets_that_value',)),
    Mutation('D69-H5-4', 'the Worker is called a second time after it refused or returned nothing',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/loop.py', '        step = decide_after_work(result, self.refusals)\n', '        step = decide_after_work(result, self.refusals)\n        if step == STEP_NOT_RUN:\n            self.ports.work(engagement_id, task_id, snapshot)\n'),),
             prepare=_without_probe,
             targets=('test_work_is_called_exactly_once_per_task_also_when_the_worker_returns_nothing',)),
    Mutation('D69-H5-10', 'a claimed task is not completed on the path where the engagement stopped accepting work',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/loop.py', '            self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)\n            self.complete_not_run(engagement_id, task_id)\n', '            self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)\n'),),
             prepare=_without_probe,
             targets=('test_every_claimed_task_is_completed_exactly_once',)),
    Mutation('D69-H5-12', 'the start-up check is removed',
             ('tests/test_harness_h5a2_startup.py',),
             edits=(Edit('harness/loop.py', '        if decide_startup(self.ports.live_tasks(engagement_id)) == STARTUP_REFUSE:\n', '        if False:\n'),),
             prepare=_without_probe,
             targets=('test_a_live_task_on_the_engagement_refuses_the_start_with_code_10_and_nothing_else_is_called',)),
    Mutation('D69-H5-13', "the check that a claimed id is one of the loop's own tasks is removed",
             ('tests/test_harness_h5a2_stops.py',),
             edits=(Edit('harness/loop.py', '            if not owns(task_id, self.unclaimed[engagement_id]):\n                raise _FaultStop(StopReason.FOREIGN_TASK)\n', ''),),
             prepare=_without_probe,
             targets=('test_a_claim_that_returns_a_foreign_task_id_stops_with_code_11_and_proposes_nothing',)),
    Mutation('D69-H5-14', 'the start-up check is moved to after the first claim',
             ('tests/test_harness_h5a2_startup.py',),
             edits=(Edit('harness/loop.py', '            self.start_check(engagement_id)\n            snapshot = self.ports.take_snapshot(engagement_id)\n', '            snapshot = self.ports.take_snapshot(engagement_id)\n'), Edit('harness/loop.py', '            task_id = self.ports.claim(engagement_id)\n            if task_id is None:\n', '            task_id = self.ports.claim(engagement_id)\n            self.start_check(engagement_id)\n            if task_id is None:\n'),),
             prepare=_without_probe,
             targets=('test_the_start_up_check_comes_before_snapshot_plan_creation_and_claim',)),
    Mutation('D69-H5-15', 'the start-up check is made once for the process, not once for each engagement on its first visit',
             ('tests/test_harness_h5a2_startup.py',),
             edits=(Edit('harness/loop.py', '        if engagement_id in self.checked:\n', '        if self.checked:\n'),),
             prepare=_without_probe,
             targets=('test_an_engagement_enrolled_between_rounds_is_checked_before_it_is_visited',)),
    Mutation('D69-H5-20', 'the loop ignores the model-call cap: the three checks before a model call are removed',
             ('tests/test_harness_h5a2_bounds_in_loop.py',),
             edits=(Edit('harness/loop.py', '        if not self.bounds.call_may_be_made():\n            raise _ControlledStop(StopReason.CAP_REACHED)\n        result = self.ports.plan(engagement_id, snapshot)\n', '        if False:\n            raise _ControlledStop(StopReason.CAP_REACHED)\n        result = self.ports.plan(engagement_id, snapshot)\n'), Edit('harness/loop.py', '        if not self.bounds.call_may_be_made():\n            self.complete_not_run(engagement_id, task_id)\n            raise _ControlledStop(StopReason.CAP_REACHED)\n        result = self.ports.work(engagement_id, task_id, snapshot)\n', '        if False:\n            self.complete_not_run(engagement_id, task_id)\n            raise _ControlledStop(StopReason.CAP_REACHED)\n        result = self.ports.work(engagement_id, task_id, snapshot)\n'), Edit('harness/loop.py', '        if not self.bounds.call_may_be_made():\n            self.complete_not_run(engagement_id, task_id)\n            raise _ControlledStop(StopReason.CAP_REACHED)\n        policy = _load_policy(self.ports, engagement_id)\n', '        if False:\n            self.complete_not_run(engagement_id, task_id)\n            raise _ControlledStop(StopReason.CAP_REACHED)\n        policy = _load_policy(self.ports, engagement_id)\n'),),
             prepare=_without_probe,
             targets=('test_the_cap_of_n_model_calls_gives_exactly_n_calls_to_the_supervisor_worker_and_proposal',)),
    Mutation('D69-H5-21', 'the stop flag is read in the middle of a task, right after the Worker answered',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/loop.py', '        result = self.ports.work(engagement_id, task_id, snapshot)\n        self.bounds.record_model_call()\n', '        result = self.ports.work(engagement_id, task_id, snapshot)\n        self.bounds.record_model_call()\n        self.safe_point()\n'),),
             prepare=_without_probe,
             targets=('test_a_stop_flag_set_in_the_middle_of_a_task_is_seen_after_the_task_is_completed',)),
    Mutation('D69-H5-22', 'the start-up decision looks only at queued tasks and ignores claimed and running ones',
             ('tests/test_harness_h5a2_modules.py',),
             edits=(Edit('harness/startup_check.py', '    if rows:\n        return STARTUP_REFUSE\n', '    if any(getattr(row, "status", None) == "queued" for row in rows):\n        return STARTUP_REFUSE\n'),),
             prepare=_without_probe,
             targets=('test_any_live_task_whatever_its_status_refuses_the_start',)),
    Mutation('D69-H5-30', "a controlled stop leaves the loop's own unclaimed tasks as they are",
             ('tests/test_harness_h5a2_stops.py',),
             edits=(Edit('harness/loop.py', '        if not cleans_up_unclaimed(reason):\n', '        if True:\n'),),
             prepare=_without_probe,
             targets=('test_a_controlled_stop_completes_the_loops_own_unclaimed_tasks_as_not_run',)),
    Mutation('D69-H5-31', 'a round in which tasks were created counts as progress, whatever happened to them',
             ('tests/test_harness_h5a2_bounds_in_loop.py',),
             edits=(Edit('harness/loop.py', '            created = self.plan(engagement_id, snapshot)\n', '            created = self.plan(engagement_id, snapshot)\n            progress = progress or created\n'),),
             prepare=_without_probe,
             targets=('test_rounds_that_created_tasks_but_proposed_nothing_are_rounds_without_progress',)),
    Mutation('D69-H5-32a', 'the pause and kill check before the Supervisor call is removed',
             ('tests/test_harness_h5a2_pause_kill.py',),
             edits=(Edit('harness/loop.py', '            if not self.ports.accepts_work(engagement_id):\n                self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)\n                continue\n', ''),),
             prepare=_without_probe,
             targets=('test_position_1_a_closed_engagement_is_not_planned_for_and_nothing_follows',)),
    Mutation('D69-H5-32b', 'the pause and kill check before a claim is removed',
             ('tests/test_harness_h5a2_pause_kill.py',),
             edits=(Edit('harness/loop.py', '            if not self.ports.accepts_work(engagement_id):\n                self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)\n                break\n', ''),),
             prepare=_without_probe,
             targets=('test_position_2_an_engagement_closed_after_planning_is_not_claimed_from',)),
    Mutation('D69-H5-32c', 'the pause and kill check before the proposal is removed',
             ('tests/test_harness_h5a2_pause_kill.py',),
             edits=(Edit('harness/loop.py', '        if not self.ports.accepts_work(engagement_id):\n            self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)\n            self.complete_not_run(engagement_id, task_id)\n            return False\n', ''),),
             prepare=_without_probe,
             targets=('test_position_3_an_engagement_closed_after_the_worker_answered_is_not_proposed_to',)),
    Mutation('D69-H5-33', 'whether an action ran is judged by the decision of the outcome and not by its two ids',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/loop.py', '        self.count(summary)\n', '        if outcome.decision != "ALLOW":\n            self.counters.increment(COUNTER_NOT_EXECUTED)\n'),),
             prepare=_without_probe,
             targets=('test_the_counters_follow_the_ids_of_the_outcome_and_not_its_decision',)),
    Mutation('D69-H5-43', 'the idempotency key of a proposal does not contain the task id',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/loop.py', '        key = derive_key(task_id, _ATTEMPT)\n', '        key = derive_key("run", _ATTEMPT)\n'),),
             prepare=_without_probe,
             targets=('test_the_idempotency_key_of_a_proposal_is_derive_key_of_the_task_id_and_1',)),
    Mutation('D69-H5-44', 'the function that completes a task no longer asks is_valid_summary first',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/loop.py', '    if not is_valid_summary(summary):\n        raise ValueError("a result summary outside the closed set")\n', ''),),
             prepare=_without_probe,
             targets=('test_complete_refuses_a_summary_outside_the_closed_set_and_writes_nothing',)),
    Mutation('D69-H5-45', 'a ValueError of the summary builder is swallowed and the task is completed as not_run',
             ('tests/test_harness_h5a2_stops.py',),
             edits=(Edit('harness/loop.py', '        summary = build_summary(outcome)\n', '        try:\n            summary = build_summary(outcome)\n        except ValueError:\n            summary = TOKEN_NOT_RUN\n'),),
             prepare=_without_probe,
             targets=('test_an_outcome_the_summary_builder_refuses_stops_with_code_12_and_does_not_clean_up',)),
    Mutation('D69-H5-46', 'a key conflict is taken for an ordinary result, not for a fault',
             ('tests/test_harness_h5a2_stops.py',),
             edits=(Edit('harness/loop.py', '        if is_key_conflict(outcome):\n', '        if False:\n'),),
             prepare=_without_probe,
             targets=('test_a_key_conflict_is_a_fault_with_code_12_not_a_result',)),
    Mutation('D69-H5-47', 'an exception from propose is swallowed and the loop goes on',
             ('tests/test_harness_h5a2_stops.py',),
             edits=(Edit('harness/loop.py', '        outcome = self.ports.propose(engagement_id, task_id, result.proposal, policy, key)\n', '        try:\n            outcome = self.ports.propose(engagement_id, task_id, result.proposal, policy, key)\n        except Exception:\n            return False\n'),),
             prepare=_without_probe,
             targets=('test_an_exception_from_any_port_stops_with_code_12_and_is_not_swallowed',)),
    Mutation('D69-H5-48', 'a proposal whose action is outside the allowlist is counted as refused and then proposed anyway',
             ('tests/test_harness_h5a2_tasks.py',),
             edits=(Edit('harness/worker_step.py', '    if not check_proposal_action(result.action, counter=refusals).allowed:\n        return STEP_NOT_RUN\n', '    check_proposal_action(result.action, counter=refusals)\n'),),
             prepare=_without_probe,
             targets=('test_a_proposal_with_an_action_outside_the_allowlist_is_not_proposed',)),
    Mutation('D69-H5-27', 'the guard trigger of harness_enrolment is disabled: a withdrawn row can be made live again',
             ('tests/test_harness_h5b_enrolment_db.py', 'tests/test_harness_h5b_schema.py'),
             sql_up=('ALTER TABLE harness_enrolment DISABLE TRIGGER harness_enrolment_guard',),
             sql_down=('ALTER TABLE harness_enrolment ENABLE TRIGGER harness_enrolment_guard',),
             prepare=_without_probe,
             targets=('test_a_withdrawn_row_cannot_be_made_live_again_through_the_cli_functions',)),
    Mutation('D69-H5-28', 'a reader role (scheduler_reader) is granted INSERT on harness_enrolment',
             ('tests/test_harness_h5b_schema.py',),
             sql_up=('GRANT INSERT ON harness_enrolment TO scheduler_reader',),
             sql_down=('REVOKE INSERT ON harness_enrolment FROM scheduler_reader',),
             prepare=_without_probe,
             targets=('test_no_role_but_cyberorch_app_and_the_owner_has_any_privilege_on_the_table',)),
    Mutation('D69-H5-49', 'the reader of the enrolment list does not filter on the purpose',
             ('tests/test_harness_h5b_enrolment_db.py',),
             edits=(Edit('harness/enrolment_db.py', '    "WHERE withdrawn_at IS NULL AND purpose = \'harness_lab\' "\n', '    "WHERE withdrawn_at IS NULL "\n'),),
             prepare=_without_probe,
             targets=('test_the_reader_returns_only_the_harness_lab_rows_whatever_else_is_in_the_table',)),
    Mutation('D69-H5-50', 'the CHECK on the purpose of harness_enrolment is removed',
             ('tests/test_harness_h5b_schema.py',),
             sql_up=('ALTER TABLE harness_enrolment DROP CONSTRAINT harness_enrolment_purpose_check',),
             sql_down=("ALTER TABLE harness_enrolment ADD CONSTRAINT harness_enrolment_purpose_check CHECK (purpose IN ('harness_lab'))",),
             prepare=_without_probe,
             targets=('test_an_insert_with_any_purpose_but_harness_lab_is_a_check_violation',)),
    Mutation('D69-H5-51', 'the CLI gives --purpose a default instead of requiring it',
             ('tests/test_harness_h5b_cli.py',),
             edits=(Edit('scripts/manage_harness_enrolment.py', '    reg.add_argument("--purpose", required=True,\n', '    reg.add_argument("--purpose", default="harness_lab",\n'),),
             prepare=_without_probe,
             targets=('test_a_registration_without_purpose_is_an_error_and_writes_nothing',)),
    Mutation('D69-H5-52', 'the reader of the enrolment list does not filter out withdrawn registrations',
             ('tests/test_harness_h5b_enrolment_db.py',),
             edits=(Edit('harness/enrolment_db.py', '    "WHERE withdrawn_at IS NULL AND purpose = \'harness_lab\' "\n', '    "WHERE purpose = \'harness_lab\' "\n'),),
             prepare=_without_probe,
             targets=('test_a_withdrawn_engagement_leaves_the_list_and_can_be_registered_again',)),
    Mutation('D69-H5-53', 'the unique index on the live registrations of an engagement is removed',
             ('tests/test_harness_h5b_cli.py', 'tests/test_harness_h5b_schema.py'),
             sql_up=('DROP INDEX harness_enrolment_live',),
             sql_down=('CREATE UNIQUE INDEX harness_enrolment_live ON harness_enrolment (engagement_id) WHERE withdrawn_at IS NULL',),
             prepare=_without_probe,
             targets=('test_a_second_registration_of_a_live_engagement_is_refused',)),
    Mutation('D69-H5-54', 'a module of the loop imports a write function of the enrolment CLI',
             ('tests/test_harness_h5b_structure.py',),
             edits=(Edit('harness/worker_step.py', 'from harness.ports import WorkResult\n', 'from harness.ports import WorkResult\nfrom scripts.manage_harness_enrolment import register  # noqa: F401\n'),),
             prepare=_without_probe,
             targets=('test_the_loop_modules_and_the_reader_do_not_import_the_scripts_or_the_cli',)),
    Mutation('D69-H5-55', 'the check of the recorded revision in the D68 dry-run test accepts any string',
             ('tests/test_dp15_record_mode.py',),
             edits=(Edit('tests/test_dp15_record_mode.py', '    return revision in seen\n', '    return True\n'),),
             prepare=_without_probe,
             targets=('test_the_check_of_the_recorded_revision_refuses_one_that_is_not_a_revision_or_is_newer',)),
    # -- H5c1: the real adapter of the ports (harness/loop_adapter.py); H5-56 to H5-62 are the implementer's additions --
    Mutation('D69-H5-1', 'the adapter passes the Worker proposal to propose_action as it is: no task attached, a task of another engagement let through',
             ('tests/test_harness_h5c1_pipeline.py',),
             edits=(Edit('harness/loop_adapter.py', """        if proposal.task_id is not None and proposal.task_id != task_id:
            raise ValueError("the proposal names a task other than the one claimed")
        carried = dataclasses.replace(proposal, task_id=task_id)
""", """        carried = proposal
"""),),
             prepare=_without_probe,
             targets=('test_a_proposal_with_no_task_is_proposed_with_the_task_that_was_claimed', 'test_a_proposal_that_names_another_task_is_refused_before_propose_action')),
    Mutation('D69-H5-3', 'the adapter swallows an exception from propose_action and answers with a DENY, so the loop goes on',
             ('tests/test_harness_h5c1_pipeline.py',),
             edits=(Edit('harness/loop_adapter.py', """        return propose_action(
            engagement_id=engagement_id, proposal=carried, reviewer=self._reviewer,
            policy=policy, agent_id=self._worker.agent_id, actor=self._actor,
            sandbox=self._sandbox, idempotency_key=idempotency_key)
""", """        try:
            return propose_action(
                engagement_id=engagement_id, proposal=carried, reviewer=self._reviewer,
                policy=policy, agent_id=self._worker.agent_id, actor=self._actor,
                sandbox=self._sandbox, idempotency_key=idempotency_key)
        except Exception:
            from control_plane.api.function_api import ActionOutcome
            return ActionOutcome(decision="DENY", proposal_id="")
"""),),
             prepare=_without_probe,
             targets=('test_an_exception_in_propose_action_is_not_swallowed_and_the_rows_stay_coherent',)),
    Mutation('D69-H5-5', 'the adapter answers accepts_work from the engagement row alone: a paused or killed engagement is let through',
             ('tests/test_harness_h5c1_pipeline.py',),
             edits=(Edit('harness/loop_adapter.py', '        return state is not None and state.accepts_work\n', '        return state is not None\n'),),
             prepare=_without_probe,
             targets=('test_after_the_kill_switch_is_engaged_the_loop_makes_no_further_propose_action_call', 'test_a_killed_engagement_is_not_planned_for_and_nothing_reaches_propose_action', 'test_a_kill_that_comes_in_while_the_worker_answers_stops_the_proposal')),
    Mutation('D69-H5-16', 'candidates_from_registry returns the registry\'s scope objects without the allowlist filter',
             ('tests/test_harness_h5c1_adapter.py',),
             edits=(Edit('harness/registry_view.py', '    return candidates_from_scope_objects(list_scope_objects(conn))\n', '    return tuple(ScopeCandidate(scope_object_id=s.scope_object_id, type=s.type, value=s.value, allowed_actions=tuple(s.allowed_actions)) for s in list_scope_objects(conn))\n'),),
             prepare=_without_probe,
             targets=('test_take_snapshot_offers_the_real_registrys_candidates_filtered_to_the_allowlist',)),
    Mutation('D69-H5-17', 'live_tasks answers with no task, so a new loop does not see the live task of the engagement',
             ('tests/test_harness_h5c1_startup.py',),
             edits=(Edit('harness/loop_adapter.py', '        return tuple(LiveTask(task_id=row["task_id"], status=row["status"]) for row in rows)\n', '        return ()\n'),),
             prepare=_without_probe,
             targets=('test_a_new_loop_with_a_live_task_on_the_engagement_ends_with_code_10_and_calls_no_one',)),
    Mutation('D69-H5-25', 'the start-up check writes a row: live_tasks claims a task before it reads',
             ('tests/test_harness_h5c1_startup.py',),
             edits=(Edit('harness/loop_adapter.py', """        with engagement_scope(engagement_id) as conn:
            state = query_state(
""", """        with engagement_scope(engagement_id) as conn:
            claim_task(conn, engagement_id=engagement_id, agent_id="startup-check")
            state = query_state(
"""),),
             prepare=_without_probe,
             targets=('test_the_start_up_check_writes_no_row',)),
    Mutation('D69-H5-26', 'the adapter passes propose_action a key the derivation did not produce',
             ('tests/test_harness_h5c1_pipeline.py',),
             edits=(Edit('harness/loop_adapter.py', 'sandbox=self._sandbox, idempotency_key=idempotency_key)\n', 'sandbox=self._sandbox, idempotency_key=f"x:{task_id}")\n'),),
             prepare=_without_probe,
             targets=('test_the_idempotency_key_stored_with_the_proposal_is_h5_task_1',)),
    Mutation('D69-H5-29', 'the loop runs the start-up check after the first claim instead of before it',
             ('tests/test_harness_h5c1_startup.py',),
             edits=(Edit('harness/loop.py', """            self.start_check(engagement_id)
            snapshot = self.ports.take_snapshot(engagement_id)
""", """            snapshot = self.ports.take_snapshot(engagement_id)
"""), Edit('harness/loop.py', """            task_id = self.ports.claim(engagement_id)
            if task_id is None:
                break
""", """            task_id = self.ports.claim(engagement_id)
            self.start_check(engagement_id)
            if task_id is None:
                break
""")),
             prepare=_without_probe,
             targets=('test_the_start_up_check_comes_before_the_first_claim_on_the_real_rows',)),
    Mutation('D69-H5-56', 'live_tasks reads without the status filter, so old completed tasks fill the page [added by the implementer: the 60 + 1 test of plan item 81]',
             ('tests/test_harness_h5c1_startup.py',),
             edits=(Edit('harness/loop_adapter.py', """                conn, engagement_id=engagement_id, task_status=LIVE_STATUSES,
                task_limit=self._live_task_limit + 1, decision_limit=0)
""", """                conn, engagement_id=engagement_id,
                task_limit=self._live_task_limit + 1, decision_limit=0)
"""),),
             prepare=_without_probe,
             targets=('test_sixty_completed_tasks_and_then_one_queued_task_are_refused_with_code_10',)),
    Mutation('D69-H5-57', 'live_tasks returns the first rows when there are more than its limit, instead of refusing [added by the implementer]',
             ('tests/test_harness_h5c1_startup.py',),
             edits=(Edit('harness/loop_adapter.py', """        if len(rows) > self._live_task_limit:
            raise LiveTasksNotReadable(
                f"more than {self._live_task_limit} live tasks in {engagement_id}")
""", """        rows = rows[: self._live_task_limit]
"""),),
             prepare=_without_probe,
             targets=('test_more_live_tasks_than_the_limit_is_refused_and_never_returned_cut_short',)),
    Mutation('D69-H5-58', 'accepts_work opens its connection and does not close it [added by the implementer: the leak]',
             ('tests/test_harness_h5c1_adapter.py',),
             edits=(Edit('harness/loop_adapter.py', """        with engagement_scope(engagement_id) as conn:
            state = get_engagement(conn, engagement_id)
        return state is not None and state.accepts_work
""", """        scope = engagement_scope(engagement_id)
        conn = scope.__enter__()
        self.__dict__.setdefault("_held", []).append(scope)
        state = get_engagement(conn, engagement_id)
        return state is not None and state.accepts_work
"""),),
             prepare=_without_probe,
             targets=('test_no_port_leaves_a_connection_checked_out',)),
    Mutation('D69-H5-59', 'plan reads the registry again instead of using the candidates of its snapshot [added by the implementer]',
             ('tests/test_harness_h5c1_adapter.py',),
             edits=(Edit('harness/loop_adapter.py', 'ACTOR = "harness"\n', 'ACTOR = "harness"\n\n\ndef _candidates_now(engagement_id):\n    with engagement_scope(engagement_id) as conn:\n        return candidates_from_registry(conn)\n'), Edit('harness/loop_adapter.py', 'supervisor=self._supervisor, state=state, candidates=snap.candidates,', 'supervisor=self._supervisor, state=state, candidates=_candidates_now(engagement_id),')),
             prepare=_without_probe,
             targets=('test_plan_uses_the_candidates_of_its_snapshot_and_does_not_read_the_registry_again',)),
    Mutation('D69-H5-60', 'another module of the harness names claim_task: the m2 allowance for the adapter must not let it through [added by the implementer]',
             ('tests/test_harness_task_source.py',),
             edits=(Edit('harness/round_snapshot.py', 'from __future__ import annotations\n', 'from __future__ import annotations\n\nfrom control_plane.api.function_api import claim_task  # noqa: F401\n'),),
             prepare=_without_probe,
             targets=('test_m2_create_task_is_named_only_in_the_task_source_and_nothing_claims_proposes_or_completes',)),
    Mutation('D69-H5-61', 'the residue check reads no live harness registration [added by the implementer]',
             ('tests/test_harness_h5c1_residue.py',),
             edits=(Edit('tests/residue.py', """    with get_engine().connect() as conn:
        return frozenset(r[0] for r in conn.execute(text(
            "SELECT engagement_id FROM harness_enrolment WHERE withdrawn_at IS NULL")))
""", """    return frozenset()
"""),),
             prepare=_without_probe,
             targets=('test_a_registration_made_after_the_snapshot_is_residue_and_one_before_it_is_not',)),
    Mutation('D69-H5-62', 'leftovers() does not carry the harness registrations into what it reports [added by the implementer: the wiring]',
             ('tests/test_harness_h5c1_residue.py',),
             edits=(Edit('tests/residue.py', """        harness_enrollments=sorted(
            live_harness_enrollments() - before.harness_enrollments))""", """        )"""),),
             prepare=_without_probe,
             targets=('test_a_registration_made_after_the_snapshot_is_residue_and_one_before_it_is_not',)),
    # -- H5c2: the real shape of an answer, the lock, the signals, the banner, the residue listing. H5-7 is the one the plan
    #    assigns to c2; H5-63 to H5-66 are the four of the task of H5c2 (A), added by the implementer; H5-7b and H5-67 to H5-79 are [proposal]
    Mutation('D69-H5-7', 'the harness lock key is the scheduler\'s',
             ('tests/test_harness_h5c2_lock.py',),
             edits=(Edit('harness/lock.py', 'KEY = 0x0D69_5C4E_D000_0001\n', 'KEY = 0x0D62_5C4E_D000_0001\n'),),
             prepare=_without_probe,
             targets=('test_the_key_is_the_registered_value_and_is_not_the_schedulers', 'test_a_lock_the_scheduler_holds_does_not_block_the_harness_and_the_reverse')),
    Mutation('D69-H5-7b', 'a second instance that cannot take the lock does not exit [H5-7, its second half]',
             ('tests/test_harness_h5c2_lock.py',),
             edits=(Edit('scripts/run_harness.py', """    if not taken:
        print("refused: another instance holds the harness lock", file=sys.stderr)
        return EXIT_LOCK_HELD
""", """    pass
"""),),
             prepare=_without_probe,
             targets=('test_a_second_run_exits_with_code_2_before_it_reads_anything',)),
    Mutation('D69-H5-63', 'executed_state judges the real shape by run_id alone [added by the implementer]',
             ('tests/test_harness_h5c2_allow.py',),
             edits=(Edit('harness/result_summary.py', """    if has_run and has_evidence:
        return STATE_EXECUTED
    if has_run and failure == FAILURE_DEDUP_HIT:
        return STATE_DEDUPLICATED
    if has_run:
        return STATE_UNKNOWN_OUTCOME
""", """    if has_run:
        return STATE_EXECUTED
"""),),
             prepare=_without_probe,
             targets=('test_a_second_task_for_the_same_work_is_a_dedup_hit_and_not_an_unknown_outcome', 'test_a_sandbox_that_fails_after_the_run_began_is_an_unknown_outcome')),
    Mutation('D69-H5-64', 'executed_state judges the real shape by evidence_id alone [added by the implementer]',
             ('tests/test_harness_h5c2_allow.py',),
             edits=(Edit('harness/result_summary.py', '    has_run = _present(run_id, "run_id")\n', '    has_run = _present(evidence_id, "run_id")\n'),),
             prepare=_without_probe,
             targets=('test_a_second_task_for_the_same_work_is_a_dedup_hit_and_not_an_unknown_outcome', 'test_a_sandbox_that_fails_after_the_run_began_is_an_unknown_outcome')),
    Mutation('D69-H5-65', 'a dedup_hit is taken for an unknown outcome on the real shape (the error b216fcf fixed) [added by the implementer]',
             ('tests/test_harness_h5c2_allow.py',),
             edits=(Edit('harness/result_summary.py', """    if has_run and failure == FAILURE_DEDUP_HIT:
        return STATE_DEDUPLICATED
""", ""),),
             prepare=_without_probe,
             targets=('test_a_second_task_for_the_same_work_is_a_dedup_hit_and_not_an_unknown_outcome',)),
    Mutation('D69-H5-66', 'the summary copies the failure text of a refused proposal [added by the implementer]',
             ('tests/test_harness_h5c2_allow.py',),
             edits=(Edit('harness/result_summary.py', """    token = failure_token(outcome.failure)
    if token is None:
        return decision
    return f"{decision}:{token}"
""", """    if outcome.failure is None:
        return decision
    return f"{decision}:{outcome.failure}"
"""),),
             prepare=_without_probe,
             targets=('test_the_summary_never_holds_the_text_of_a_failure_in_any_of_three_places',)),
    Mutation('D69-H5-67', 'a lost lock is not turned into exit code 6 [proposal]',
             ('tests/test_harness_h5c2_lock.py',),
             edits=(Edit('scripts/run_harness.py', '        code = EXIT_LOCK_LOST if lock.lost.is_set() else EXIT_CODE[result.reason]\n', '        code = EXIT_CODE[result.reason]\n'),),
             prepare=_without_probe,
             targets=('test_run_returns_the_lock_lost_exit_code_and_cleans_nothing_up',)),
    Mutation('D69-H5-68', 'the guard around the ports does not look at the lock [proposal]',
             ('tests/test_harness_h5c2_lock.py',),
             edits=(Edit('harness/lock.py', """        if not self.held():
            raise LockLost("the harness lock is lost")
""", """        return
"""),),
             prepare=_without_probe,
             targets=('test_once_the_lock_is_lost_no_port_is_called_and_the_call_raises', 'test_run_returns_the_lock_lost_exit_code_and_cleans_nothing_up')),
    Mutation('D69-H5-69', 'an error of the lock session counts as the lock still held [proposal]',
             ('tests/test_harness_h5c2_lock.py',),
             edits=(Edit('harness/lock.py', """        except Exception:  # noqa: BLE001 - any failure of the lock session is "lost"
            ok = False
""", """        except Exception:  # noqa: BLE001 - any failure of the lock session is "lost"
            ok = True
"""),),
             prepare=_without_probe,
             targets=('test_a_killed_lock_connection_is_noticed_by_the_watchdog',)),
    Mutation('D69-H5-70', 'the entry script installs no signal handler [proposal]',
             ('tests/test_harness_h5c2_entry.py', 'tests/test_harness_h5c2_signal.py'),
             edits=(Edit('scripts/run_harness.py', '        install(register, flag, (signal.SIGINT, signal.SIGTERM))\n', '        pass\n'),),
             prepare=_without_probe,
             targets=('test_the_handlers_of_sigint_and_sigterm_are_installed_and_set_the_flag', 'test_a_real_sigterm_stops_the_process_cleanly_after_the_task_it_is_on')),
    Mutation('D69-H5-71', 'the signal handler does not set the flag [proposal]',
             ('tests/test_harness_h5c2_entry.py', 'tests/test_harness_h5c2_signal.py'),
             edits=(Edit('harness/signals.py', """    def handler(*_args: Any) -> None:
        flag.set()
""", """    def handler(*_args: Any) -> None:
        pass
"""),),
             prepare=_without_probe,
             targets=('test_the_handlers_of_sigint_and_sigterm_are_installed_and_set_the_flag', 'test_a_real_sigterm_stops_the_process_cleanly_after_the_task_it_is_on')),
    Mutation('D69-H5-72', 'the banner states both switches as off whatever the policy says [proposal]',
             ('tests/test_harness_h5c2_banner.py',),
             edits=(Edit('harness/banner_facts.py', '    return {name: next(iter(seen)) for name, seen in values.items()}\n', '    return {name: False for name in values}\n'),),
             prepare=_without_probe,
             targets=('test_the_switches_are_read_from_the_policy_of_the_enrolled_engagements',)),
    Mutation('D69-H5-73', 'the banner states a migration head that is not the database\'s [proposal]',
             ('tests/test_harness_h5c2_banner.py',),
             edits=(Edit('harness/banner_facts.py', '    return heads[0]\n', '    return "0000"\n'),),
             prepare=_without_probe,
             targets=('test_the_facts_are_the_ones_the_database_and_the_repository_give',)),
    Mutation('D69-H5-74', 'the banner facts carry the database password [proposal]',
             ('tests/test_harness_h5c2_banner.py',),
             edits=(Edit('harness/banner_facts.py', '"name": url.database, "role": url.username}', '"name": url.database, "role": url.username, "password": url.password}'),),
             prepare=_without_probe,
             targets=('test_the_facts_are_the_ones_the_database_and_the_repository_give', 'test_the_banner_prints_every_field_in_order_and_never_the_password')),
    Mutation('D69-H5-75', 'the Worker\'s prompt digest is made from the Supervisor\'s prompt [proposal]',
             ('tests/test_harness_h5c2_banner.py',),
             edits=(Edit('harness/banner_facts.py', '"worker": digest(WORKER_SYSTEM_PROMPT,', '"worker": digest(supervisor.system_prompt,'),),
             prepare=_without_probe,
             targets=('test_the_facts_are_the_ones_the_database_and_the_repository_give',)),
    Mutation('D69-H5-76', 'the residue listing is not made in a read-only transaction [proposal]',
             ('tests/test_harness_h5c2_residue.py',),
             edits=(Edit('harness/residue_listing.py', '            conn.execute(text("SET TRANSACTION READ ONLY"))\n', ''),),
             prepare=_without_probe,
             targets=('test_the_read_is_made_in_a_read_only_transaction',)),
    Mutation('D69-H5-77', 'the residue listing reads tasks of every state, not the three live ones [proposal]',
             ('tests/test_harness_h5c2_residue.py',),
             edits=(Edit('harness/residue_listing.py', '                conn, engagement_id=engagement_id, task_status=LIVE_STATUSES,\n                task_limit=limit, decision_limit=0)', '                conn, engagement_id=engagement_id,\n                task_limit=limit, decision_limit=0)'),),
             prepare=_without_probe,
             targets=('test_the_listing_shows_the_claimed_and_the_queued_task_a_fault_left',)),
    Mutation('D69-H5-78', 'a bound of the entry script gets a default [proposal]',
             ('tests/test_harness_h5c2_entry.py',),
             edits=(Edit('scripts/run_harness.py', 'run.add_argument(f"--{name}", required=True, type=_positive, help="required, no default")', 'run.add_argument(f"--{name}", required=False, default=1, type=_positive, help="x")'),),
             prepare=_without_probe,
             targets=('test_every_bound_is_required_and_has_no_default', 'test_an_argument_that_is_left_out_is_a_usage_error_before_the_lock_is_taken')),
    Mutation('D69-H5-79', 'the banner is not printed [proposal]',
             ('tests/test_harness_h5c2_entry.py',),
             edits=(Edit('scripts/run_harness.py', '        print(format_banner(facts), flush=True)\n', '        format_banner(facts)\n'),),
             prepare=_without_probe,
             targets=('test_a_run_with_once_exits_0_after_one_round_and_prints_the_banner', 'test_the_banner_is_printed_before_the_loop_starts')),
    # -- added by the implementer for the H5c2 repair (the frozen enrolment; plan item 97) ----------
    Mutation('D69-H5-80', 'the frozen reader degenerates to returning the current enrolment [added by the implementer, H5c2 repair]',
             ('tests/test_harness_h5c2_frozen.py',),
             edits=(Edit('harness/frozen_enrolment.py', '        return tuple(engagement_id for engagement_id in self._at_start if engagement_id in now)\n', '        return now\n'),),
             prepare=_without_probe,
             targets=('test_an_engagement_enrolled_after_the_start_is_never_visited_and_is_no_cause_of_code_10', 'test_the_frozen_reader_never_returns_what_was_enrolled_after_the_start', 'test_the_visit_order_is_the_start_up_order_when_the_databases_order_has_changed')),
    Mutation('D69-H5-81', 'the banner takes the first engagement\'s switch value when the engagements disagree, instead of refusing [added by the implementer, H5c2 repair]',
             ('tests/test_harness_h5c2_banner.py',),
             edits=(Edit('harness/banner_facts.py', '    for engagement_id in engagements:\n        policy = load_policy(engagement_id)\n', '    for engagement_id in list(engagements)[:1]:\n        policy = load_policy(engagement_id)\n'),),
             prepare=_without_probe,
             targets=('test_engagements_that_disagree_on_a_switch_give_no_banner',)),
    Mutation('D69-H5-82', 'the banner is printed when no engagement is enrolled, instead of refusing [added by the implementer, H5c2 repair]',
             ('tests/test_harness_h5c2_banner.py', 'tests/test_harness_h5c2_entry.py'),
             edits=(Edit('harness/banner_facts.py', '    if not engagements:\n        raise BannerFactsUnavailable("switches: no engagement is enrolled, so no policy applies")\n', '    if not engagements:\n        return {"task_relation_enforce": False, "goal_fit_enforce": False}\n'),),
             prepare=_without_probe,
             targets=('test_no_enrolled_engagement_gives_no_banner', 'test_no_enrolled_engagement_is_a_refusal_with_code_10_and_no_banner')),
    Mutation('D69-H5-83', 'the entry script treats an unreachable database as a lock that was acquired and goes on [added by the implementer, H5c2 repair]',
             ('tests/test_harness_h5c2_entry.py',),
             edits=(Edit('scripts/run_harness.py', '        return EXIT_DB_LOST\n    if not taken:', '        taken = True\n    if not taken:'),),
             prepare=_without_probe,
             targets=('test_a_database_that_cannot_be_reached_is_exit_4_and_the_driver_text_is_not_printed',)),
    # -- added by the implementer for H7, the laboratory end to end (tests/test_harness_h7_lab.py) --
    Mutation('D69-H7-L1', 'the start-up check never refuses a start (a leftover live task is not looked at) [added by the implementer, H7]',
             ('tests/test_harness_h7_lab.py',),
             edits=(Edit('harness/loop.py', '        if decide_startup(self.ports.live_tasks(engagement_id)) == STARTUP_REFUSE:\n', '        if False and decide_startup(self.ports.live_tasks(engagement_id)) == STARTUP_REFUSE:\n'),),
             prepare=_without_probe,
             targets=('test_s5_the_next_start_is_refused_with_10_and_no_refused_line',)),
    Mutation('D69-H7-L2', 'the banner prints its engagements in another order than the one the loop visits and `list` shows [added by the implementer, H7]',
             ('tests/test_harness_h7_lab.py',),
             edits=(Edit('harness/banner_facts.py', '        "engagements": engagements,\n', '        "engagements": list(reversed(engagements)),\n'),),
             prepare=_without_probe,
             targets=('test_s3_a_run_once_ends_with_0_and_prints_the_banner_the_runbook_describes',)),
    Mutation('D69-H7-L3', 'the recovery snippet of the runbook completes the task with another word than not_run [added by the implementer, H7]',
             ('tests/test_harness_h7_lab.py',),
             edits=(Edit('docs/D69_HARNESS_OPERATOR_RUNBOOK.md', 'result_summary="not_run", actor="<your name>")', 'result_summary="finished", actor="<your name>")'),),
             prepare=_without_probe,
             targets=('test_s6_the_recovery_snippet_completes_the_leftovers_and_the_next_start_passes',)),
    Mutation('D69-H7-L4', 'the residue listing does not list a claimed task [added by the implementer, H7]',
             ('tests/test_harness_h7_lab.py',),
             edits=(Edit('harness/residue_listing.py', 'task_status=LIVE_STATUSES,', 'task_status=("queued",),'),),
             prepare=_without_probe,
             targets=('test_s4_a_fault_in_the_reviewer_ends_with_12_and_leaves_what_the_runbook_says',)),
    # -- D69 H7, ACCEPTANCE 5.28: the three entries of the plan's section 8 (item 8, "Mutation entries") ----
    # (the plan's names H7-1, H7-2, H7-3; where each edit is made is the review layer's decision of 2026-11-19, plan item 109)
    Mutation('D69-H7-1', 'the loop passes no observations to the Worker (H7-1 of the plan, section 8)',
             ('tests/test_harness_h7_528.py',),
             edits=(Edit('harness/loop_adapter.py', '            observations=snap.round.observations_for_task(), task_id=task_id)', '            observations=(), task_id=task_id)'),),
             prepare=_without_probe,
             targets=('test_each_case_ends_with_the_decision_the_plan_states',)),
    Mutation('D69-H7-2', 'the builder puts every IP literal of the content and every name in hosts into observed_identities (H7-2 of the plan, section 8)',
             ('tests/test_harness_h7_528.py',),
             edits=(Edit('harness/observations.py', r'''        observed_identities=observed_identities(row),
''', r'''        observed_identities=observed_identities(row) + tuple(
            __import__("re").findall(r"\d{1,3}(?:\.\d{1,3}){3}", content.replace("\\", ""))
        ) + tuple(str(h) for h in (row.derived_view.get("hosts") or ())),
'''),),
             prepare=_without_probe,
             targets=('test_each_case_ends_with_the_decision_the_plan_states',)),
    Mutation('D69-H7-3', 'take_snapshot reads the evidence window through the engagement it served last (H7-3 of the plan, section 8)',
             ('tests/test_harness_h7_528.py',),
             edits=(Edit('harness/loop_adapter.py', '''        with engagement_scope(engagement_id) as conn:
            round_snapshot = take_round_snapshot(conn, limit=self._window_limit)
            candidates = candidates_from_registry(conn)
''', '''        with engagement_scope(getattr(self, "_h7_last", engagement_id)) as conn:
            round_snapshot = take_round_snapshot(conn, limit=self._window_limit)
        with engagement_scope(engagement_id) as conn:
            candidates = candidates_from_registry(conn)
        self._h7_last = engagement_id
'''),),
             prepare=_without_probe,
             targets=('test_another_engagements_evidence_is_never_shown_to_this_engagements_worker',)),
    # -- added by the implementer for the token-boundary repair (tests/test_provenance_token_boundaries.py) --
    # (new ids, not in the plan's section 8; the repair is plan items 111-113 and ADR_DISCOVERY_SOURCE.md 8.8)
    Mutation('D69-TB-1', 'the text is searched only with its backslashes removed; the readings that separate a line break are dropped [added by the implementer, token-boundary repair]',
             ('tests/test_provenance_token_boundaries.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''    return (
        text.replace("\\", ""),     # backslashes removed: nmap's escaped dots
        text.replace("\\", " "),    # backslashes as separators: a line break's
        _CONTROL_ESCAPE.sub(" ", text).replace("\\", ""),   # both, in that order
    )
''', r'''    return (
        text.replace("\\", ""),     # backslashes removed: nmap's escaped dots
    )
'''),),
             prepare=_without_probe,
             targets=('test_a_lure_is_introduced_at_every_position_in_every_spelling',
                      'test_a_lure_at_the_edge_of_a_line_is_escalated_through_the_loop')),
    Mutation('D69-TB-2', 'the text is searched only in the readings that separate a line break; the two that restore nmap\'s escaped dots are dropped [added by the implementer, token-boundary repair]',
             ('tests/test_provenance_token_boundaries.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''    return (
        text.replace("\\", ""),     # backslashes removed: nmap's escaped dots
        text.replace("\\", " "),    # backslashes as separators: a line break's
        _CONTROL_ESCAPE.sub(" ", text).replace("\\", ""),   # both, in that order
    )
''', r'''    return (
        text.replace("\\", " "),    # backslashes as separators: a line break's
        _CONTROL_ESCAPE.sub(" ", text),
    )
'''),),
             prepare=_without_probe,
             targets=('test_a_lure_is_introduced_at_every_position_in_every_spelling',
                      'test_a_lure_at_the_edge_of_a_line_is_escalated_through_the_loop')),
    Mutation('D69-TB-3', 'an identity counts as named only when every reading of the text finds it (intersection, not union) [added by the implementer, token-boundary repair]',
             ('tests/test_provenance_token_boundaries.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''    return any(re.search(pattern, form.lower()) for form in _text_forms(text))''',
                         r'''    return all(re.search(pattern, form.lower()) for form in _text_forms(text))'''),
                    Edit('agents/llm/worker_base.py', r'''    keys: set[IdentityKey] = set()
    for form in _text_forms(text):
        for token in _TEXT_TOKEN.findall(form):
            for candidate in _token_candidates(token):
                keys |= _canonical_keys(candidate, _UNTYPED_IDENTITY_TYPES)
                keys |= _untyped_repo_keys(candidate)
    return keys
''', r'''    per_form: list[set[IdentityKey]] = []
    for form in _text_forms(text):
        found: set[IdentityKey] = set()
        for token in _TEXT_TOKEN.findall(form):
            for candidate in _token_candidates(token):
                found |= _canonical_keys(candidate, _UNTYPED_IDENTITY_TYPES)
                found |= _untyped_repo_keys(candidate)
        per_form.append(found)
    return set.intersection(*per_form)
'''),),
             prepare=_without_probe,
             targets=('test_a_lure_is_introduced_at_every_position_in_every_spelling',
                      'test_a_lure_at_the_edge_of_a_line_is_escalated_through_the_loop')),
    # -- added by the implementer for the second repair, the glue class (tests/test_provenance_glue.py) --
    # (new ids; the repair is plan items 114-117 and ADR_DISCOVERY_SOURCE.md 8.9)
    Mutation('D69-GL-1', 'the left boundary of an IPv4 literal stops every word character again, as before the second repair [added by the implementer, glue repair]',
             ('tests/test_provenance_glue.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''        return r"(?<![\d.])", r"(?!\d)(?!\.\d)"''', r'''        return r"(?<![\w.\-])", r"(?!\d)(?!\.\d)"'''),),
             prepare=_without_probe,
             targets=('test_a_lure_glued_to_other_characters_is_introduced',
                      'test_a_glued_lure_is_escalated_through_the_loop')),
    Mutation('D69-GL-2', 'the right boundary of an IPv4 literal no longer stops a dot and a digit (10.82.0.77.1 reads as 10.82.0.77) [added by the implementer, glue repair]',
             ('tests/test_provenance_glue.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''        return r"(?<![\d.])", r"(?!\d)(?!\.\d)"''', r'''        return r"(?<![\d.])", r"(?!\d)"'''),),
             prepare=_without_probe,
             targets=('test_a_longer_address_or_a_subdomain_is_still_another_identity',)),
    Mutation('D69-GL-3', 'the left boundary of a name no longer stops a dot (a.dc99.lure.example reads as dc99.lure.example) [added by the implementer, glue repair]',
             ('tests/test_provenance_glue.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''        return r"(?<!\.)", r"(?![_\-])(?!\.\d)"''', r'''        return r"", r"(?![_\-])(?!\.\d)"'''),),
             prepare=_without_probe,
             targets=('test_a_longer_address_or_a_subdomain_is_still_another_identity',
                      'test_the_first_repairs_counter_examples_still_hold_at_every_position')),
    Mutation('D69-GL-4', 'the text is not also searched with its hex-byte escapes read as separators (an addition of the repair beyond the designed boundary rule) [added by the implementer, glue repair]',
             ('tests/test_provenance_glue.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''    readings = (text, _HEX_BYTE_ESCAPE.sub(" ", text))''', r'''    readings = (text,)'''),),
             prepare=_without_probe,
             targets=('test_a_lure_glued_to_other_characters_is_introduced',)),
    # -- added by the implementer for the /32 repair (tests/test_provenance_slash32.py) --
    # (new ids; the repair is plan items 119-120 and ADR_DISCOVERY_SOURCE.md 8.10)
    Mutation('D69-SL-1', 'a /32 target is not also searched for by its bare address [added by the implementer, /32 repair]',
             ('tests/test_provenance_slash32.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''    single = _IPV4_SLASH32.fullmatch(v)''', r'''    single = None'''),),
             prepare=_without_probe,
             targets=('test_a_slash32_target_is_introduced_by_its_glued_address',
                      'test_a_glued_slash32_lure_is_escalated_through_the_loop')),
    # D69-SL-2 is NOT caught as committed (runner: INVALID). The counter-example pre-registered to
    # catch it, target 10.82.0.0/24 against text m10.82.0.0, is decided at step 1 of
    # _discovery_provenance: the unit helper offers 10.82.0.0/24 itself as a scope object, so the
    # target is explicit scope before any content match. The table is not changed after its first
    # run; a counter-example that can catch it needs a new pre-registered table (plan item 120).
    Mutation('D69-SL-2', 'every IPv4 cidr, not only a /32, is also searched for by its network address [added by the implementer, /32 repair; INVALID as committed, see the comment above]',
             ('tests/test_provenance_slash32.py',),
             edits=(Edit('agents/llm/worker_base.py', r'''_IPV4_SLASH32 = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})/32")''', r'''_IPV4_SLASH32 = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}")'''),),
             prepare=_without_probe,
             targets=('test_a_neighbour_of_a_slash32_target_is_not_its_address',)),
]

if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
