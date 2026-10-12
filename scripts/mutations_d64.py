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
M0022 = "db/migrations/versions/0022_abandoned_stage.py"


def _load_0022():
    """The migration's own constants (names, stage lists, COMMENT texts), so that the SQL that undoes
    a live-database mutation is built from the text the migration wrote, not retyped here."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("m0022", Path(__file__).resolve().parents[1] / M0022)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_M22 = _load_0022()
STAGES_PY = "control_plane/orchestrator/stages.py"
FUNCTION_API = "control_plane/api/function_api.py"
SNAPSHOT_PY = "control_plane/state/schema_snapshot.py"
ROUNDTRIP = ("tests/test_migrations_roundtrip.py",)
VOCAB = ("tests/test_stage_vocabulary.py",)
DECISION_STAGE = ("tests/test_action_proposals_decision_stage.py",)
SNAPSHOT_TESTS = ("tests/test_schema_snapshot.py",)
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
    # ---- step 5: ACCEPTANCE 5.78, the stage `abandoned` (0022), snapshot_schema(), the vocabulary tests
    Mutation(
        "D64-5-a", "0022's upgrade forgets the COMMENT on the widened decision constraint", ROUNDTRIP,
        edits=(Edit(M0022, '    op.execute(f"COMMENT ON CONSTRAINT {DECISION_CHECK} ON action_proposals "\n'
                    '               f"IS {_literal(COMMENT_DECISION_0022)};")\n', ""),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-b", "0022's downgrade restores the constraint but not its 0021 COMMENT", ROUNDTRIP,
        edits=(Edit(M0022, '    op.execute(f"COMMENT ON CONSTRAINT {DECISION_CHECK} ON action_proposals "\n'
                    '               f"IS {_literal(COMMENT_DECISION_0021)};")\n', ""),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-c", "0022's downgrade does not restore the column COMMENT of 0016", ROUNDTRIP,
        edits=(Edit(M0022, '    op.execute(f"COMMENT ON COLUMN action_proposals.pipeline_stage "\n'
                    '               f"IS {_literal(COMMENT_STAGE_0016)};")\n', ""),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-d", "0022's downgrade moves rows without switching FORCE ROW LEVEL SECURITY off", ROUNDTRIP + RLS_WRITES[:1],
        edits=(Edit(M0022, '    op.execute("ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY;")\n', ""),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",
                 "test_each_data_statement_runs_with_force_off_for_every_table_it_touches")),
    Mutation(
        "D64-5-e", "0022's downgrade leaves FORCE ROW LEVEL SECURITY off", ROUNDTRIP + RLS_WRITES[:1],
        edits=(Edit(M0022, '    op.execute("ALTER TABLE action_proposals FORCE ROW LEVEL SECURITY;")\n', ""),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",
                 "test_each_data_statement_runs_with_force_off_for_every_table_it_touches")),
    Mutation(
        "D64-5-f", "0022's downgrade does not move the abandoned rows", ROUNDTRIP,
        edits=(Edit(M0022, "        WHERE pipeline_stage = 'abandoned';", "        WHERE pipeline_stage = 'no_such_stage';"),),
        targets=("test_0022_downgrade_moves_every_abandoned_row_not_only_one",)),
    Mutation(
        "D64-5-g", "the abandoned CHECK no longer says stage_detail IS NOT NULL (5.69)", ROUNDTRIP,
        edits=(Edit(M0022, "                       AND stage_detail IS NOT NULL\n", ""),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-h", "an abandoned proposal may carry a decision (the CHECK drops decision IS NULL)", ROUNDTRIP,
        edits=(Edit(M0022, "                   OR (decision IS NULL\n                       AND stage_detail IS NOT NULL\n",
                    "                   OR (stage_detail IS NOT NULL\n"),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-i", "0022 leaves NULL decision legal at `received` only", ROUNDTRIP,
        edits=(Edit(M0022, "CHECK (decision IS NOT NULL OR pipeline_stage IN ('received', 'abandoned'));",
                    "CHECK (decision IS NOT NULL OR pipeline_stage = 'received');"),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-j", "0022 leaves the open-stage index listing abandoned rows", ROUNDTRIP,
        edits=(Edit(M0022, "            WHERE pipeline_stage NOT IN ('recorded', 'closed', 'abandoned')\n",
                    "            WHERE pipeline_stage NOT IN ('recorded', 'closed')\n"),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-k", "0022 forgets to add `abandoned` to the stage CHECK", ROUNDTRIP,
        edits=(Edit(M0022, 'NEW_STAGES = (*OLD_STAGES, "abandoned")', "NEW_STAGES = OLD_STAGES"),),
        targets=("test_0022_up_and_down_with_a_row_at_every_stage_and_every_comment_restored",)),
    Mutation(
        "D64-5-l", "the outcome of an abandoned proposal is the reasonless DENY again", VOCAB,
        edits=(Edit(FUNCTION_API, "    if stage == stages.ABANDONED:\n        # Never decided", "    if False:\n        # Never decided"),),
        targets=("test_st6_an_abandoned_proposal_is_reported_as_never_decided_not_as_a_reasonless_deny",
                 "test_st6_a_resumed_proposal_in_a_stage_this_call_cannot_drive_is_reported_with_a_reason")),
    Mutation(
        "D64-5-m", "the decision may overwrite an abandoned proposal (the race is lost the wrong way)", VOCAB,
        edits=(Edit(FUNCTION_API, '             "WHERE proposal_id = :p AND pipeline_stage = :expected RETURNING proposal_id"),',
                    '             "WHERE proposal_id = :p AND pipeline_stage IN (:expected, \'abandoned\') "\n'
                    '             "RETURNING proposal_id"),'),),
        targets=("test_a7_abandoned_while_the_decision_stage_is_in_flight_nothing_follows",)),
    Mutation(
        "D64-5-n", "abandon() no longer compares stage_updated_at", VOCAB,
        edits=(Edit(STAGES_PY, "              AND stage_updated_at = :planned\n", ""),),
        targets=("test_st6_only_a_received_proposal_can_be_abandoned_and_only_if_nothing_touched_it",)),
    Mutation(
        "D64-5-o", "abandon() no longer requires the proposal to be at `received`", VOCAB,
        edits=(Edit(STAGES_PY, "            WHERE proposal_id = :pid AND pipeline_stage = :received\n",
                    "            WHERE proposal_id = :pid\n"),),
        targets=("test_st6_only_a_received_proposal_can_be_abandoned_and_only_if_nothing_touched_it",)),
    Mutation(
        "D64-5-p", "`abandoned` is not terminal", VOCAB,
        edits=(Edit(STAGES_PY, "TERMINAL = (RECORDED, CLOSED, ABANDONED)", "TERMINAL = (RECORDED, CLOSED)"),),
        targets=("test_st5_every_stage_has_exactly_one_class_and_stages_py_agrees",
                 "test_st2_the_open_stage_index_leaves_out_exactly_the_terminal_stages")),
    Mutation(
        "D64-5-q", "a second reason is added in code but not in the database", VOCAB,
        edits=(Edit(STAGES_PY, 'ABANDON_REASONS = ("undecided_past_grace",)',
                    'ABANDON_REASONS = ("undecided_past_grace", "operator_closed")'),),
        targets=("test_a5_the_abandon_reasons_are_registered_once_and_the_check_holds_them_equal",)),
    Mutation(
        "D64-5-r", "snapshot_schema() leaves constraint COMMENTs out", SNAPSHOT_TESTS,
        edits=(Edit(SNAPSHOT_PY, "               || ' comment=' || coalesce(obj_description(c.oid, 'pg_constraint'), '')\n", ""),),
        targets=("test_the_snapshot_notices",)),
    Mutation(
        "D64-5-s", "snapshot_schema() leaves FORCE ROW LEVEL SECURITY out", SNAPSHOT_TESTS,
        edits=(Edit(SNAPSHOT_PY, " || ' force=' || c.relforcerowsecurity", ""),),
        targets=("test_the_snapshot_notices",)),
    # ---- the same properties as the live database states them (the tests that read pg_constraint)
    Mutation(
        "D64-5-t", "the live stage CHECK does not list `abandoned`", DECISION_STAGE + VOCAB,
        sql_up=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.STAGE_CHECK}",
                f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.STAGE_CHECK} CHECK "
                f"(pipeline_stage IN ({_M22._stage_list(_M22.OLD_STAGES)})) NOT VALID"),
        sql_down=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.STAGE_CHECK}",
                  f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.STAGE_CHECK} CHECK "
                  f"(pipeline_stage IN ({_M22._stage_list(_M22.NEW_STAGES)}))"),
        targets=("test_st2_the_stage_check_lists_exactly_the_stages",
                 "test_a_stage_accepts_a_missing_decision_only_if_it_is_received_or_abandoned")),
    Mutation(
        "D64-5-u", "the live decision CHECK allows NULL at `received` only", DECISION_STAGE + VOCAB,
        sql_up=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.DECISION_CHECK}",
                f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.DECISION_CHECK} CHECK "
                "(decision IS NOT NULL OR pipeline_stage = 'received') NOT VALID"),
        sql_down=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.DECISION_CHECK}",
                  f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.DECISION_CHECK} CHECK "
                  "(decision IS NOT NULL OR pipeline_stage IN ('received', 'abandoned'))",
                  f"COMMENT ON CONSTRAINT {_M22.DECISION_CHECK} ON action_proposals "
                  f"IS {_M22._literal(_M22.COMMENT_DECISION_0022)}"),
        targets=("test_st2_the_decision_check_names_exactly_the_undecided_stages",
                 "test_a_stage_accepts_a_missing_decision_only_if_it_is_received_or_abandoned")),
    Mutation(
        "D64-5-v", "the live abandoned CHECK does not exclude a NULL detail (5.69)", DECISION_STAGE + VOCAB,
        sql_up=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.ABANDONED_CHECK}",
                f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.ABANDONED_CHECK} CHECK "
                "(pipeline_stage <> 'abandoned' OR (decision IS NULL "
                "AND stage_detail = 'undecided_past_grace'))"),
        sql_down=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.ABANDONED_CHECK}",
                  f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.ABANDONED_CHECK} CHECK "
                  "(pipeline_stage <> 'abandoned' OR (decision IS NULL "
                  "AND stage_detail IS NOT NULL AND stage_detail = 'undecided_past_grace'))",
                  f"COMMENT ON CONSTRAINT {_M22.ABANDONED_CHECK} ON action_proposals "
                  f"IS {_M22._literal(_M22.COMMENT_ABANDONED)}"),
        targets=("test_an_abandoned_proposal_needs_exactly_its_one_reason_and_null_is_refused",
                 "test_a5_the_abandon_reasons_are_registered_once_and_the_check_holds_them_equal")),
    Mutation(
        "D64-5-w", "the live abandoned CHECK lets an abandoned proposal carry a decision", DECISION_STAGE,
        sql_up=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.ABANDONED_CHECK}",
                f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.ABANDONED_CHECK} CHECK "
                "(pipeline_stage <> 'abandoned' OR (stage_detail IS NOT NULL "
                "AND stage_detail = 'undecided_past_grace'))"),
        sql_down=(f"ALTER TABLE action_proposals DROP CONSTRAINT {_M22.ABANDONED_CHECK}",
                  f"ALTER TABLE action_proposals ADD CONSTRAINT {_M22.ABANDONED_CHECK} CHECK "
                  "(pipeline_stage <> 'abandoned' OR (decision IS NULL "
                  "AND stage_detail IS NOT NULL AND stage_detail = 'undecided_past_grace'))",
                  f"COMMENT ON CONSTRAINT {_M22.ABANDONED_CHECK} ON action_proposals "
                  f"IS {_M22._literal(_M22.COMMENT_ABANDONED)}"),
        targets=("test_an_abandoned_proposal_cannot_carry_a_decision",)),
    Mutation(
        "D64-5-x", "the live open-stage index still lists abandoned rows as open", VOCAB,
        sql_up=("DROP INDEX action_proposals_open_stage",
                "CREATE INDEX action_proposals_open_stage ON action_proposals "
                "(engagement_id, pipeline_stage, stage_updated_at) "
                "WHERE pipeline_stage NOT IN ('recorded', 'closed') OR provenance_complete IS FALSE"),
        sql_down=("DROP INDEX action_proposals_open_stage",
                  "CREATE INDEX action_proposals_open_stage ON action_proposals "
                  "(engagement_id, pipeline_stage, stage_updated_at) WHERE pipeline_stage NOT IN "
                  "('recorded', 'closed', 'abandoned') OR provenance_complete IS FALSE"),
        targets=("test_st2_the_open_stage_index_leaves_out_exactly_the_terminal_stages",)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
