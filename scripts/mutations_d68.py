# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations of D68 (ACCEPTANCE 5.116, 5.118), as runnable checks (see ``mutation_check.py``).

``python scripts/mutations_d68.py --list`` names them. S2: the comparison of a proposal with the
task it names (``control_plane/plan_fit/relation.py``) and its place in ``propose_action``. Each
mutation breaks one rule of it, and a named test must be red.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import Edit, Mutation, main  # noqa: E402

RELATION = "control_plane/plan_fit/relation.py"
API = "control_plane/api/function_api.py"
TESTS = ("tests/test_plan_fit_relation.py",)

CATALOGUE = [
    Mutation("D68-S2-a", "any live task matches, whatever its identity",
             TESTS,
             edits=(Edit(RELATION, '    if identity_key == task["identity_key"]:\n', '    if True:\n'),),
             targets=("test_the_comparison_table", "test_a_task_for_another_host_differs")),
    Mutation("D68-S2-b", "a finished task is as good as a live one",
             TESTS,
             edits=(Edit(RELATION, "    if status not in LIVE_STATUSES:\n", "    if False:\n"),),
             targets=("test_the_comparison_table", "test_a_completed_task_is_not_live")),
    Mutation("D68-S2-c", "a proposal that names no task is taken to match",
             TESTS,
             edits=(Edit(RELATION, "        return TaskRelation(NO_TASK, TASK_ID_ABSENT)\n    row = conn.execute(",
                         "        return TaskRelation(MATCHES_TASK)\n    row = conn.execute("),),
             targets=("test_no_task_is_recorded_stored_and_audited_once",)),
    Mutation("D68-S2-d", "a task of another engagement is found (the read is not confined to the engagement)",
             TESTS,
             edits=(Edit(RELATION, "        return TaskRelation(TASK_NOT_LIVE, TASK_NOT_FOUND, task_id)\n",
                         "        return TaskRelation(MATCHES_TASK, None, task_id)\n"),),
             targets=("test_the_comparison_table", "test_another_engagements_task_is_not_found")),
    Mutation("D68-S2-e", "a host inside the task's network is no longer told apart from any other difference",
             TESTS,
             edits=(Edit(RELATION, "    if same_action and _inside(canonical_target, task[\"canonical_target\"]):\n",
                         "    if False:\n"),),
             targets=("test_the_comparison_table",
                      "test_a_task_on_the_network_and_a_proposal_for_one_host_inside_it")),
    Mutation("D68-S2-f", "a host outside the task's network counts as inside it",
             TESTS,
             edits=(Edit(RELATION, "            return ipaddress.ip_address(p_value) in task_net\n",
                         "            return True\n"),),
             targets=("test_the_comparison_table",)),
    Mutation("D68-S2-g", "the assessment is not stored with the decision",
             TESTS,
             edits=(Edit(API, '                    "plan_fit": run.plan_fit.as_hint(),\n', ""),),
             targets=("test_no_task_is_recorded_stored_and_audited_once",
                      "test_a_matching_task_is_matches_task")),
    Mutation("D68-S2-h", "the assessment is stored under another key",
             TESTS,
             edits=(Edit(API, '                    "plan_fit": run.plan_fit.as_hint(),\n',
                         '                    "planfit": run.plan_fit.as_hint(),\n'),),
             targets=("test_no_task_is_recorded_stored_and_audited_once",)),
    Mutation("D68-S2-i", "the assessment is not audited",
             TESTS,
             edits=(Edit(API, 'event_type="plan_fit.assessed",', 'event_type="plan_fit.assessed_never",'),),
             targets=("test_no_task_is_recorded_stored_and_audited_once",
                      "test_a_retried_request_is_one_event_and_one_stored_value")),
    Mutation("D68-S2-j", "the relation is written into the decision's own inputs (it is allowed to change a decision)",
             TESTS,
             edits=(Edit(API, "        possible_sensitive_data_hint=opinion.possible_sensitive_data_hint,\n    )\n    run.decision = decision\n",
                         "        possible_sensitive_data_hint=opinion.possible_sensitive_data_hint\n        or (('no_task',) if run.plan_fit.value == 'no_task' else ()),\n    )\n    run.decision = decision\n"),),
             targets=("test_the_signal_changes_no_decision_whatever_the_relation",)),
    Mutation("D68-S2-k", "a task that cannot be seen is judged as a mismatch instead of as absent",
             TESTS,
             edits=(Edit(RELATION, "        return TaskRelation(TASK_NOT_LIVE, TASK_NOT_FOUND, task_id)\n",
                         "        return TaskRelation(DIFFERS_FROM_TASK, DIFFERENT_TARGET, task_id)\n"),),
             targets=("test_the_comparison_table", "test_another_engagements_task_is_not_found",
                      "test_the_task_read_is_confined_by_row_level_security_and_the_row_does_exist")),
    Mutation("D68-S2-l", "row-level security is switched off on tasks (the proposing engagement can read another's task)",
             TESTS,
             sql_up=("ALTER TABLE tasks DISABLE ROW LEVEL SECURITY",),
             sql_down=("ALTER TABLE tasks ENABLE ROW LEVEL SECURITY", "ALTER TABLE tasks FORCE ROW LEVEL SECURITY"),
             targets=("test_another_engagements_task_is_not_found",
                      "test_the_task_read_is_confined_by_row_level_security_and_the_row_does_exist")),
]

if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
