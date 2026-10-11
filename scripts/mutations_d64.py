# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations of the D64 implementation steps, as runnable checks (see ``mutation_check.py``).

``python scripts/mutations_d64.py --list`` names them. Ids: ``D64-1-*`` for step 1 (ACCEPTANCE 5.74,
the late-result transition), and so on for the steps that follow.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import Edit, Mutation, main  # noqa: E402

DISPATCH = "control_plane/orchestrator/dispatch.py"
LATE = ("tests/test_dispatch_late_result.py",)
M0017 = "db/migrations/versions/0017_approval_stages.py"
M0021 = "db/migrations/versions/0021_decision_past_received.py"
CEILING = ("tests/test_duration_ceiling.py",)
AUTHZ = "control_plane/policy/rego/authz.rego"
RLS_WRITES = ("tests/test_migrations_rls_writes.py", "tests/test_migrations_roundtrip.py")

CATALOGUE = [
    Mutation(
        "D64-1-a", "the stage transition's result is ignored again (the original 5.74)", LATE,
        edits=(Edit(DISPATCH, "    if stages.advance(conn, proposal_id, expected=stages.DISPATCHING, new=stages.RECORDED,\n"
                    "                      detail=detail):\n        return False\n",
                    "    stages.advance(conn, proposal_id, expected=stages.DISPATCHING, new=stages.RECORDED,\n"
                    "                   detail=detail)\n    return False\n"),),
        targets=("test_the_reconciler_first_then_the_result_arrives_late",
                 "test_a_proposal_someone_else_closed_gets_no_result_and_nothing_is_written")),
    Mutation(
        "D64-1-b", "a late result no longer needs the proposal's detail to be unknown_outcome", LATE,
        edits=(Edit(DISPATCH, "              AND stage_detail = :unknown AND dispatch_state = :unknown\n",
                    "              AND dispatch_state = :unknown\n"),),
        targets=("test_which_states_a_result_may_be_recorded_over",)),
    Mutation(
        "D64-1-c", "a late result no longer needs the dispatch state to be unknown_outcome", LATE,
        edits=(Edit(DISPATCH, "              AND stage_detail = :unknown AND dispatch_state = :unknown\n",
                    "              AND stage_detail = :unknown\n"),),
        targets=("test_which_states_a_result_may_be_recorded_over",)),
    Mutation(
        "D64-1-d", "a late result may also overwrite a `closed` proposal", LATE,
        edits=(Edit(DISPATCH, "            WHERE proposal_id = :pid AND pipeline_stage = :recorded\n              AND stage_detail = :unknown",
                    "            WHERE proposal_id = :pid AND pipeline_stage IN (:recorded, 'closed')\n              AND stage_detail = :unknown"),),
        targets=("test_which_states_a_result_may_be_recorded_over",)),
    Mutation(
        "D64-1-e", "the run row is no longer required to be unknown_outcome for a late result", LATE,
        edits=(Edit(DISPATCH, "                only_if_status=UNKNOWN_OUTCOME if late else None,\n",
                    "                only_if_status=None,\n"),),
        targets=("test_a_run_that_stopped_being_unknown_after_the_stage_check_is_still_not_overwritten",)),
    Mutation(
        "D64-1-f", "the late result is not audited", LATE,
        edits=(Edit(DISPATCH, "            if late:\n                record_audit(\n                    engagement_id=engagement_id, actor=actor, event_type=LATE_RESULT_EVENT,",
                    "            if False:\n                record_audit(\n                    engagement_id=engagement_id, actor=actor, event_type=LATE_RESULT_EVENT,"),),
        targets=("test_the_reconciler_first_then_the_result_arrives_late",)),
    Mutation(
        "D64-1-g", "a refusal before start is recorded over a proposal someone else moved", LATE,
        edits=(Edit(DISPATCH, "                stages.take(conn, proposal_id, expected=stages.DISPATCHING,\n"
                    "                            new=stages.CLOSED, detail=exc.reason)\n",
                    "                stages.advance(conn, proposal_id, expected=stages.DISPATCHING,\n"
                    "                               new=stages.CLOSED, detail=exc.reason)\n"),),
        targets=("test_a_refusal_before_start_does_not_overwrite_a_proposal_someone_moved",)),
    Mutation(
        "D64-1-h", "a sandbox failure after the reconciler marked the run is treated as a conflict", LATE,
        edits=(Edit(DISPATCH, "                    if stages.stage_of(conn, proposal_id) != (stages.RECORDED, UNKNOWN_OUTCOME):\n",
                    "                    if True:\n"),),
        targets=("test_a_sandbox_failure_after_the_reconciler_marked_the_run_is_not_a_conflict",)),
    Mutation(
        "D64-1-i", "the record forgets to set the dispatch state (stage and state tell two stories)", LATE,
        edits=(Edit(DISPATCH, "            _set_state(conn, proposal_id, status)\n            record_audit(\n"
                    "                engagement_id=engagement_id, actor=actor,\n                event_type=f\"tool_run.{status}\"",
                    "            record_audit(\n"
                    "                engagement_id=engagement_id, actor=actor,\n                event_type=f\"tool_run.{status}\""),),
        targets=("test_the_reconciler_first_then_the_result_arrives_late",)),
    # ---- step 1, addendum: the late transition carries the run id and checks it (D64 closeout of 5.74)
    Mutation(
        "D64-1-j", "the late transition no longer asks whose run it is (the EXISTS on tool_runs is gone)", LATE,
        edits=(Edit(DISPATCH, "              AND EXISTS (SELECT 1 FROM tool_runs r\n"
                    "                          WHERE r.run_id = :run AND r.proposal_id = :pid\n"
                    "                            AND r.status = :unknown)\n", ""),),
        targets=("test_a_late_result_moves_the_proposal_only_for_the_run_that_is_its_own",
                 "test_a_late_result_for_a_run_that_is_not_itself_unknown_is_refused")),
    Mutation(
        "D64-1-k", "the late transition accepts a run of another proposal", LATE,
        edits=(Edit(DISPATCH, "WHERE r.run_id = :run AND r.proposal_id = :pid\n",
                    "WHERE r.run_id = :run\n"),),
        targets=("test_a_late_result_moves_the_proposal_only_for_the_run_that_is_its_own",)),
    Mutation(
        "D64-1-l", "the late transition accepts a run that is not itself unknown", LATE,
        edits=(Edit(DISPATCH, "                            AND r.status = :unknown)\n",
                    "                            AND r.status IS NOT NULL)\n"),),
        targets=("test_a_late_result_for_a_run_that_is_not_itself_unknown_is_refused",)),
    Mutation(
        "D64-1-m", "finishing a run ignores which proposal it belongs to", LATE,
        edits=(Edit(DISPATCH, "              AND (CAST(:prop AS text) IS NULL OR proposal_id = CAST(:prop AS text))\n", ""),),
        targets=("test_finishing_a_run_can_be_made_conditional_on_its_proposal",)),
    Mutation(
        "D64-1-n", "the late-result audit record no longer names the run", LATE,
        edits=(Edit(DISPATCH, "                    payload={\"proposal_id\": proposal_id, \"run_id\": started.run_id,\n"
                    "                             \"previous\": UNKNOWN_OUTCOME, \"status\": status,\n",
                    "                    payload={\"proposal_id\": proposal_id,\n"
                    "                             \"previous\": UNKNOWN_OUTCOME, \"status\": status,\n"),),
        targets=("test_the_late_result_audit_record_names_the_run_and_the_proposal",)),
    # ---- step 2: ACCEPTANCE 5.75, data statements in migrations under FORCE ROW LEVEL SECURITY
    Mutation(
        "D64-2-a", "0017's downgrade repairs rows as the owner without switching FORCE off", RLS_WRITES,
        edits=(Edit(M0017, "def downgrade() -> None:\n    op.execute(\"ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY;\")\n",
                    "def downgrade() -> None:\n"),),
        targets=("test_0017_backfills_the_right_proposals_and_its_downgrade_works_with_rows",
                 "test_each_data_statement_runs_with_force_off_for_every_table_it_touches"),
        allowed_errors=("CheckViolation", "IntegrityError")),
    Mutation(
        "D64-2-b", "0017's back-fill reads approvals with FORCE still on (a granted approval is re-opened)", RLS_WRITES,
        edits=(Edit(M0017, "    op.execute(\"ALTER TABLE approvals NO FORCE ROW LEVEL SECURITY;\")\n", ""),),
        targets=("test_0017_backfills_the_right_proposals_and_its_downgrade_works_with_rows",
                 "test_each_data_statement_runs_with_force_off_for_every_table_it_touches")),
    Mutation(
        "D64-2-c", "0017's back-fill reads audit_log with FORCE still on (a denied proposal is re-opened)", RLS_WRITES,
        edits=(Edit(M0017, "    op.execute(\"ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY;\")\n", ""),),
        targets=("test_0017_backfills_the_right_proposals_and_its_downgrade_works_with_rows",
                 "test_each_data_statement_runs_with_force_off_for_every_table_it_touches")),
    Mutation(
        "D64-2-d", "0017 switches FORCE off for approvals and never back on", RLS_WRITES,
        edits=(Edit(M0017, "    op.execute(\"ALTER TABLE approvals FORCE ROW LEVEL SECURITY;\")\n", ""),),
        targets=("test_0017_backfills_the_right_proposals_and_its_downgrade_works_with_rows",
                 "test_each_data_statement_runs_with_force_off_for_every_table_it_touches")),
    Mutation(
        "D64-2-e", "a migration gains a data statement nobody listed", RLS_WRITES,
        edits=(Edit(M0021, "def upgrade() -> None:\n", "def upgrade() -> None:\n    op.execute(\"UPDATE action_proposals SET updated_at = updated_at;\")\n"),),
        targets=("test_every_data_statement_in_a_migration_is_known",)),
    # ---- step 3: the duration ceiling (D58-16). The Rego-only mutations were run with `opa test`
    # (scripts cannot target OPA tests): ceiling 1800 -> 86400, `>` -> `>=`, the missing / invalid /
    # exceeds rules neutralised -- each failed 1 to 3 of the 58 policy tests.
    Mutation(
        "D64-3-a", "the Python ceiling drifts from the Rego one", CEILING,
        edits=(Edit("control_plane/policy/ceiling.py", "MAX_DURATION_CEILING_SECONDS = 1800", "MAX_DURATION_CEILING_SECONDS = 3600"),),
        targets=("test_the_python_constant_and_the_rego_ceiling_are_one_number",)),
    Mutation(
        "D64-3-b", "the policy stops denying a duration above the ceiling", CEILING,
        edits=(Edit(AUTHZ, "\trequested_max_duration > max_duration_ceiling_seconds\n", "\trequested_max_duration > 86400000\n"),
               Edit(AUTHZ, "max_duration_ceiling_seconds := 1800", "max_duration_ceiling_seconds := 1800"),),
        targets=("test_a_request_above_the_ceiling_is_denied_and_nothing_is_minted_or_run",)),
    Mutation(
        "D64-3-c", "a default duration in the code goes above the ceiling", CEILING,
        edits=(Edit("control_plane/api/function_api.py", "budget or Budget(max_duration_seconds=120)", "budget or Budget(max_duration_seconds=7200)"),),
        targets=("test_no_budget_the_code_builds_is_one_the_policy_would_refuse",),
        allowed_errors=("AssertionError",)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
