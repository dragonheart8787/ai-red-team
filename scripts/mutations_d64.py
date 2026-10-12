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
M0023 = "db/migrations/versions/0023_reconciler_reader.py"


def _load_0023():
    """Migration 0023's own function texts, so a live-database mutation changes one line of the real
    definition and the SQL that undoes it is the real definition, not a retyped copy."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("m0023", Path(__file__).resolve().parents[1] / M0023)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_M23 = _load_0023()
READER_TESTS = ("tests/test_reconciler_reader.py",)
_OR_REPLACE = ("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION")


def _as_function_owner(*statements: str) -> tuple[str, ...]:
    """Run ``statements`` as ``reconciler_fn_owner``. migration_owner is a member WITH INHERIT FALSE
    (db/roles.sql: otherwise the policies written TO the owner would widen what the table owner
    sees), so it may SET ROLE but does not hold the function owner's privileges. Replacing a
    function needs CREATE on the schema; it is granted for the length of the statement."""
    return ("GRANT CREATE ON SCHEMA public TO reconciler_fn_owner",
            "SET LOCAL ROLE reconciler_fn_owner", *statements, "RESET ROLE",
            "REVOKE CREATE ON SCHEMA public FROM reconciler_fn_owner")


def _stuck_sql(*changes: tuple[str, str]) -> str:
    """The stuck-proposals function as a CREATE OR REPLACE, with each (old, new) applied once."""
    text = _M23._stuck_function("public").replace(*_OR_REPLACE, 1)
    for old, new in changes:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


def _superuser_prepare(sql: str):
    """A ``prepare`` hook that runs one superuser statement (the mutation's undo is ``cleanup_sql``)."""
    def prepare() -> dict[str, str]:
        from mutation_check import _superuser_sql
        _superuser_sql(sql)
        return {}
    return prepare


_STAGE_FILTER = f"WHERE p.pipeline_stage IN ({_M23._stages()})"
_GUARDED_CAST = """CASE WHEN jsonb_typeof(c.budget -> 'max_duration_seconds') = 'number'
                         AND (c.budget ->> 'max_duration_seconds') ~ '^[1-9][0-9]{0,8}$'
                        THEN (c.budget ->> 'max_duration_seconds')::integer END"""
_SIGNATURES = ("public.reconciler_stuck_proposals()", "public.reconciler_run_states(text[])")
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

CATALOGUE += [
    # ---- step 6a (ACCEPTANCE 5.80): the four mistakes of a SECURITY DEFINER read function (E20)
    Mutation(
        "D64-6a-a", "S2: the function has no stage filter of its own (a GUC then widens the owner)",
        READER_TESTS,
        sql_up=_as_function_owner(_stuck_sql((_STAGE_FILTER, "WHERE true"))),
        sql_down=_as_function_owner(_stuck_sql()),
        targets=("test_s2_the_stage_filter_is_in_the_function_body",
                 "test_s2_a_guc_set_by_the_caller_does_not_widen_the_result")),
    Mutation(
        "D64-6a-b", "S3: EXECUTE on both functions is left with PUBLIC", READER_TESTS,
        sql_up=_as_function_owner(*(f"GRANT EXECUTE ON FUNCTION {sig} TO PUBLIC" for sig in _SIGNATURES))[1:-1],
        sql_down=_as_function_owner(*(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC" for sig in _SIGNATURES))[1:-1],
        targets=("test_s3_execute_is_granted_to_the_reader_and_the_owner_alone",
                 "test_s3_an_unrelated_role_is_refused")),
    Mutation(
        "D64-6a-c", "S4: the search_path pin is taken off the stuck-proposals function", READER_TESTS,
        sql_up=_as_function_owner("ALTER FUNCTION public.reconciler_stuck_proposals() RESET search_path")[1:-1],
        sql_down=_as_function_owner("ALTER FUNCTION public.reconciler_stuck_proposals() "
                                    "SET search_path = pg_catalog, public, pg_temp")[1:-1],
        targets=("test_s4_the_search_path_is_pinned_in_the_definition",)),
    Mutation(
        "D64-6a-d", "S4: a relation in the stuck-proposals function is no longer schema-qualified",
        READER_TESTS,
        sql_up=_as_function_owner(_stuck_sql(("FROM public.action_proposals p", "FROM action_proposals p"))),
        sql_down=_as_function_owner(_stuck_sql()),
        targets=("test_s4_every_relation_in_the_body_is_schema_qualified",)),
    Mutation(
        "D64-6a-e", "S5: the budget cast is unguarded (one bad budget blinds the call)", READER_TESTS,
        sql_up=_as_function_owner(_stuck_sql((_GUARDED_CAST, "(c.budget ->> 'max_duration_seconds')::integer"))),
        sql_down=_as_function_owner(_stuck_sql()),
        targets=("test_s5_one_unreadable_budget_neither_blinds_the_call_nor_is_echoed",)),
    Mutation(
        "D64-6a-f", "S5: the cast accepts a JSON string as well as a number", READER_TESTS,
        sql_up=_as_function_owner(_stuck_sql(("jsonb_typeof(c.budget -> 'max_duration_seconds') = 'number'\n"
                                              "                         AND ", ""))),
        sql_down=_as_function_owner(_stuck_sql()),
        targets=("test_s5_one_unreadable_budget_neither_blinds_the_call_nor_is_echoed",)),
    Mutation(
        "D64-6a-g", "the reader is given SELECT on action_proposals", READER_TESTS,
        sql_up=("GRANT SELECT ON action_proposals TO reconciler_reader",),
        sql_down=("REVOKE SELECT ON action_proposals FROM reconciler_reader",),
        targets=("test_the_reader_has_no_privilege_on_any_table_view_or_sequence",
                 "test_a_direct_select_as_the_reader_is_permission_denied")),
    Mutation(
        "D64-6a-h", "the owner is given table-wide SELECT on capabilities (its budget document)",
        READER_TESTS,
        sql_up=("GRANT SELECT ON capabilities TO reconciler_fn_owner",),
        sql_down=("REVOKE SELECT ON capabilities FROM reconciler_fn_owner",
                  "GRANT SELECT (" + ", ".join(_M23.OWNER_COLUMNS["capabilities"])
                  + ") ON capabilities TO reconciler_fn_owner"),
        targets=("test_the_owner_has_column_select_on_exactly_the_listed_columns_and_nothing_else",)),
    Mutation(
        "D64-6a-i", "the owner's stuck-stage policy on action_proposals admits every stage",
        READER_TESTS,
        sql_up=(f"ALTER POLICY {_M23.POLICY} ON action_proposals USING (true)",),
        sql_down=(f"ALTER POLICY {_M23.POLICY} ON action_proposals "
                  f"USING (pipeline_stage IN ({_M23._stages()}))",),
        targets=("test_the_owner_sees_no_recorded_proposal_without_a_guc_and_no_row_of_a_table_"
                 "that_is_not_listed",)),
    Mutation(
        "D64-6a-j", "migration_owner inherits the function owner's privileges (the default GRANT)",
        READER_TESTS,
        prepare=_superuser_prepare("GRANT reconciler_fn_owner TO migration_owner WITH INHERIT TRUE"),
        cleanup_sql=("GRANT reconciler_fn_owner TO migration_owner WITH INHERIT FALSE, SET TRUE",),
        targets=("test_only_the_migration_role_is_a_member_of_the_owner_without_inheriting_it",
                 "test_the_table_owner_and_the_schedulers_view_are_not_widened_by_the_owner_s_policies")),
]

PLAN_PY = "control_plane/reconciler/plan.py"
CONFIG_PY = "control_plane/reconciler/config.py"
OBSERVE_PY = "control_plane/reconciler/observe.py"
PLAN_TESTS = ("tests/test_reconciler_plan.py",)
CONFIG_TESTS = ("tests/test_reconciler_config.py",)
OBSERVE_TESTS = ("tests/test_reconciler_observe.py",)
STRUCT_TESTS = ("tests/test_reconciler_structure.py",)

CATALOGUE += [
    # ---- step 6b: the plan, class by class (tables), the configuration, the observation
    Mutation(
        "D64-6b-a", "R6: a received proposal is abandoned only strictly after the grace",
        PLAN_TESTS,
        edits=(Edit(PLAN_PY, "        if now - row.stage_updated_us >= th.stage_grace_s * US:\n"
                    "            return _move(row, vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)",
                    "        if now - row.stage_updated_us > th.stage_grace_s * US:\n"
                    "            return _move(row, vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)"),),
        targets=("test_r6_received_and_decided_are_acted_on_at_the_grace_and_not_before",)),
    Mutation(
        "D64-6b-b", "R6: a decided proposal is judged by a typed-in hour, not the configured grace",
        PLAN_TESTS + STRUCT_TESTS,
        edits=(Edit(PLAN_PY, "        if now - row.stage_updated_us >= th.stage_grace_s * US:\n"
                    "            return _move(row, vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)",
                    "        if now - row.stage_updated_us >= 3600 * US:\n"
                    "            return _move(row, vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)"),),
        targets=("test_r6_the_grace_is_the_configured_one",
                 "test_plan_py_has_no_numeric_literal_but_zero_and_one")),
    Mutation(
        "D64-6b-c", "R3: the lease grace is ignored", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "        if now >= row.lease_expires_us + th.lease_grace_s * US:",
                    "        if now >= row.lease_expires_us:"),),
        targets=("test_r3_a_lapsed_lease_is_closed_after_the_grace_and_not_before",)),
    Mutation(
        "D64-6b-d", "R4: an approved proposal of an enrolled engagement is closed too", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if row.enrolled:\n        return None\n    if row.approval_id is None:",
                    "    if row.approval_id is None:"),),
        targets=("test_r4_r5_approved_rows",)),
    Mutation(
        "D64-6b-e", "R5: a killed engagement is no longer recognised", PLAN_TESTS,
        edits=(Edit(PLAN_PY, '    if row.kill_switch_engaged is True or row.engagement_status == "killed":',
                    "    if False:"),),
        targets=("test_r4_r5_approved_rows",)),
    Mutation(
        "D64-6b-f", "R1: the budget is not capped in the unknown-outcome bound", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "th.unknown_after_s(row.max_duration_s) * US",
                    "(row.max_duration_s + th.p_proxy_s + th.q_proxy_s) * US"),),
        targets=("test_r1_a_dispatch_is_unknown_at_budget_plus_p_plus_q_capped",
                 "test_r1_a_budget_above_the_cap_is_judged_by_the_cap")),
    Mutation(
        "D64-6b-g", "R2: the budget is not capped in the kill bound", PLAN_TESTS + CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        return min(max_duration_s, self.b_cap_s)",
                    "        return max_duration_s"),),
        targets=("test_r2_the_margin_and_the_cap_are_the_configured_ones",
                 "test_the_derived_bounds_are_functions_of_the_configured_terms_only")),
    Mutation(
        "D64-6b-h", "R2: a container with no owner label is judged like any other", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if c.owner is None:\n        return Report(\"container\", c.container_id, vocab.NO_OWNER_LABEL)\n",
                    ""),),
        targets=("test_a_container_that_is_not_ours_to_judge_is_reported_and_never_touched",)),
    Mutation(
        "D64-6b-i", "R2: a running container of a run the database does not know is killed",
        PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if run_status is None:\n        return Report(\"container\", c.container_id, vocab.RUN_UNKNOWN, c.owner)\n"
                    "    if c.started_us is None:",
                    "    if c.started_us is None:"),),
        targets=("test_r2_nothing_is_killed_on_a_budget_that_cannot_be_read_or_a_run_nobody_knows",)),
    Mutation(
        "D64-6b-j", "R2: a container at rest is removed while its run may still be recording",
        PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    return None        # the run may still be recording: the proposal's own bound decides",
                    "    return _docker_action(c, vocab.REMOVE_CONTAINER, vocab.RUN_FINISHED)"),),
        targets=("test_r2_a_container_at_rest_whose_run_may_still_be_recording_is_kept",)),
    Mutation(
        "D64-6b-k", "R2: the retention window is not applied", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if obs.host_now_us - since < th.retention_s * US:\n        return None\n", ""),),
        targets=("test_r2_a_container_at_rest_is_removed_after_the_retention_and_not_before",)),
    Mutation(
        "D64-6b-l", "R8: a network with a container attached is removed", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if n.attached:\n        return False\n", ""),),
        targets=("test_r8_a_container_of_any_state_attached_keeps_the_network",)),
    Mutation(
        "D64-6b-m", "R8: the name prefix alone makes a network ours", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if not (n.name.startswith(NETWORK_PREFIX) and n.has_allowlist_label):",
                    "    if not n.name.startswith(NETWORK_PREFIX):"),),
        targets=("test_r8_a_network_that_is_not_ours_is_never_touched",)),
    Mutation(
        "D64-6b-n", "R9: a file a live container mounts is removed", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if f.mounted_by_live_container:\n        return None\n", ""),),
        targets=("test_r9_neither_condition_alone_is_enough",)),
    Mutation(
        "D64-6b-o", "R9: the age of a file is not checked", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if obs.host_now_us - f.mtime_us < th.file_age_s() * US:\n        return None\n", ""),),
        targets=("test_r9_neither_condition_alone_is_enough",
                 "test_r9_a_file_is_removed_when_unmounted_and_older_than_cap_plus_p_plus_q")),
    Mutation(
        "D64-6b-p", "R9: a symlink is treated as a regular file", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if not f.is_regular:", "    if False:"),),
        targets=("test_r9_what_is_not_a_regular_file_of_ours_with_its_name_is_reported_not_removed",)),
    Mutation(
        "D64-6b-q", "R9: a file of another owner is removed", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    if f.uid != obs.expected_uid:", "    if False:"),),
        targets=("test_r9_what_is_not_a_regular_file_of_ours_with_its_name_is_reported_not_removed",)),
    Mutation(
        "D64-6b-r", "R9: a name with a trailing newline matches the pattern", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "if CRED_NAME.fullmatch(f.name):", "if CRED_NAME.match(f.name):"),),
        targets=("test_r9_what_is_not_a_regular_file_of_ours_with_its_name_is_reported_not_removed",)),
    Mutation(
        "D64-6b-s", "plan: the actions are not put in execution order", PLAN_TESTS,
        edits=(Edit(PLAN_PY, "    actions.sort(key=lambda a: (EXECUTION_ORDER.index(a.kind), a.subject_id, a.reason_code))\n",
                    ""),),
        targets=("test_the_plan_is_in_the_execution_order_kills_first_files_last",)),
    Mutation(
        "D64-6b-t", "config: a missing key falls back to a default", CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        raw = env.get(key)\n", "        raw = env.get(key, \"60\")\n"),),
        targets=("test_a_missing_key_is_refused_and_named",
                 "test_with_nothing_set_every_key_is_listed_not_just_the_first")),
    Mutation(
        "D64-6b-u", "config: the least-the-code-implies check is gone", CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        if number < floors.get(f.name, 1):", "        if False:"),),
        targets=("test_a_value_below_what_the_code_implies_is_refused_and_the_least_is_accepted",)),
    Mutation(
        "D64-6b-v", "config: a number is accepted with a sign or a unit", CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        if not text.isascii() or not text.isdigit():", "        if False:"),),
        targets=("test_an_unusable_value_is_refused_and_named",)),
    Mutation(
        "D64-6b-w", "observe: a stage the function should never return is accepted", OBSERVE_TESTS,
        edits=(Edit(OBSERVE_PY, '    if values["pipeline_stage"] not in vocab.STUCK_STAGES:', "    if False:"),),
        targets=("test_a_value_the_contract_does_not_allow_is_refused",)),
    Mutation(
        "D64-6b-x", "observe: a changed column list is not noticed", OBSERVE_TESTS,
        edits=(Edit(OBSERVE_PY, "    if columns != STUCK_COLUMNS:", "    if False:"),),
        targets=("test_a_function_that_returns_other_columns_is_refused",)),
    Mutation(
        "D64-6b-y", "observe: a symlink is followed when the file is stat'ed", OBSERVE_TESTS,
        edits=(Edit(OBSERVE_PY, "os.lstat(name, dir_fd=fd)", "os.stat(name, dir_fd=fd)"),),
        targets=("test_files_are_listed_with_lstat_and_a_symlink_is_not_followed",)),
    Mutation(
        "D64-6b-z", "plan.py reads the clock", STRUCT_TESTS,
        edits=(Edit(PLAN_PY, "import re\n\nfrom control_plane.reconciler import vocab",
                    "import re\nimport time\n\nfrom control_plane.reconciler import vocab"),),
        targets=("test_the_pure_modules_import_nothing_that_does_io_or_tells_the_time",)),
    Mutation(
        "D64-6b-za", "observe.py gains a verb that deletes a file", STRUCT_TESTS,
        edits=(Edit(OBSERVE_PY, "def list_files(directory: str, mounted",
                    "def _oops(path):\n    os.unlink(path)\n\n\ndef list_files(directory: str, mounted"),),
        targets=("test_observe_calls_no_verb_that_changes_anything",)),
    Mutation(
        "D64-6b-zb", "observe.py gains a write to the database", STRUCT_TESTS,
        edits=(Edit(OBSERVE_PY, "def read_run_states(conn: Any, run_ids: Iterable[str])",
                    "def _oops(conn):\n    conn.execute(text(\"DELETE FROM tool_runs\"))\n\n\n"
                    "def read_run_states(conn: Any, run_ids: Iterable[str])"),),
        targets=("test_observe_opens_nothing_for_writing_and_its_only_sql_is_the_two_reads",)),
    Mutation(
        "D64-6b-zc", "a threshold is configured and the plan never uses it", STRUCT_TESTS,
        edits=(Edit(PLAN_PY, "th.retention_s * US", "86400 * US"),),
        targets=("test_every_threshold_is_used_by_the_plan_or_named_as_used_elsewhere",)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
