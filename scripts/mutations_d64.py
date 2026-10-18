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
M0026 = "db/migrations/versions/0026_reconciler_has_decision.py"


def _load_0026():
    """Migration 0026, whose ``_with_has_decision`` turns 0023's / 0024's function texts into the
    ones the database has now (the mutations below change one line of those)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("m0026", Path(__file__).resolve().parents[1] / M0026)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_M26 = _load_0026()
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
    text = _M26._with_has_decision(_M23._stuck_function("public")).replace(*_OR_REPLACE, 1)
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
        targets=("test_observe_opens_nothing_for_writing_and_its_only_sql_is_the_four_reads",)),
    Mutation(
        "D64-6b-zc", "a threshold is configured and the plan never uses it", STRUCT_TESTS,
        edits=(Edit(PLAN_PY, "th.retention_s * US", "86400 * US"),),
        targets=("test_every_threshold_is_used_by_the_plan_or_named_as_used_elsewhere",)),
]

ACT_PY = "control_plane/reconciler/act.py"
DOCKER_PY = "control_plane/reconciler/act_docker.py"
FILES_PY = "control_plane/reconciler/act_files.py"
ACT_TESTS = ("tests/test_reconciler_act.py",)
FLAG_TESTS = ("tests/test_reconciler_flags.py",)
ACT_STRUCT = ("tests/test_reconciler_structure.py",)
_CAS = "WHERE proposal_id = :pid AND pipeline_stage = :expected AND stage_updated_at = :planned"

CATALOGUE += [
    # ---- step 6c: the act half -- state changes by compare-and-set, deletions behind a flag
    Mutation(
        "D64-6c-a", "CLOSE no longer compares the stage_updated_at the plan observed", ACT_TESTS,
        edits=(Edit(ACT_PY, _CAS + "\n    RETURNING proposal_id\n\"\"\"\nMARK_UNKNOWN_SQL",
                    "WHERE proposal_id = :pid AND pipeline_stage = :expected\n"
                    "    RETURNING proposal_id\n\"\"\"\nMARK_UNKNOWN_SQL"),),
        targets=("test_every_transition_is_a_compare_and_set_on_the_observed_timestamp",)),
    Mutation(
        "D64-6c-b", "MARK_UNKNOWN no longer requires the stage the plan observed", ACT_TESTS,
        edits=(Edit(ACT_PY, _CAS + "\n    RETURNING proposal_id\n\"\"\"\nRUNS_SQL",
                    "WHERE proposal_id = :pid AND stage_updated_at = :planned\n"
                    "    RETURNING proposal_id\n\"\"\"\nRUNS_SQL"),),
        targets=("test_every_transition_needs_the_stage_the_plan_saw",)),
    Mutation(
        "D64-6c-c", "a dispatch declared unknown leaves its runs in flight", ACT_TESTS,
        edits=(Edit(ACT_PY, "    if moved:                       # the runs of a proposal declared unknown are unknown too\n"
                    "        conn.execute(text(RUNS_SQL), {\"pid\": pid})\n", ""),),
        targets=("test_a_dispatch_declared_unknown_takes_its_runs_with_it",)),
    Mutation(
        "D64-6c-d", "the stage is not read back after the update", ACT_TESTS,
        edits=(Edit(ACT_PY, "            if stages.stage_of(conn, action.subject_id) != (new, detail):",
                    "            if False:"),),
        targets=("test_an_update_that_does_not_stick_is_failed_not_done",)),
    Mutation(
        "D64-6c-e", "the timestamp is compared to the millisecond only", ACT_TESTS,
        edits=(Edit(ACT_PY, "    return _EPOCH + timedelta(microseconds=microseconds)",
                    "    return _EPOCH + timedelta(microseconds=microseconds // 1000 * 1000)"),),
        targets=("test_the_compare_and_set_matches_the_timestamp_to_the_last_microsecond",)),
    Mutation(
        "D64-6c-f", "state-only defaults to having the kill switch on", ACT_TESTS + ACT_STRUCT,
        edits=(Edit(ACT_PY, "    enabled: frozenset[str] = frozenset()", "    enabled: frozenset[str] = frozenset({\"kill\"})"),),
        targets=("test_the_flag_defaults_to_off_and_a_dry_run_cannot_carry_it",
                 "test_every_switch_is_off_by_default_and_nothing_in_the_product_turns_one_on")),
    Mutation(
        "D64-6c-g", "state-only mode carries out deletions", ACT_TESTS,
        edits=(Edit(ACT_PY, "    if flags.CATEGORY_OF[action.kind] not in settings.enabled:\n        return Result(action, SKIPPED_OFF)",
                    "    if False:\n        return Result(action, SKIPPED_OFF)"),),
        targets=("test_state_only_skips_every_deletion_and_never_touches_docker_or_the_filesystem",)),
    Mutation(
        "D64-6c-h", "a dry run acts", ACT_TESTS,
        edits=(Edit(ACT_PY, "    if settings.mode is Mode.DRY_RUN:\n        return Result(action, DRY_RUN)",
                    "    if False:\n        return Result(action, DRY_RUN)"),),
        targets=("test_a_dry_run_opens_no_connection_makes_no_call_and_says_what_it_would_do",)),
    Mutation(
        "D64-6c-i", "a container may be addressed by a short id or a name", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    if client is None or not FULL_ID.fullmatch(action.subject_id):",
                    "    if client is None:"),),
        targets=("test_real_only_a_full_id_is_a_handle",)),
    Mutation(
        "D64-6c-j", "the labels are not checked again before acting", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    if (labels.get(RUN_LABEL) != action.run_id or labels.get(OWNER_LABEL) != action.expected_owner\n"
                    "            or (PROXY_LABEL in labels) != wants_proxy):\n"
                    "        return Result(action, CHANGED, LABELS_CHANGED)\n", ""),),
        targets=("test_real_labels_that_are_not_what_the_plan_saw_stop_the_action",
                 "test_real_a_proxy_label_is_part_of_what_the_plan_saw")),
    Mutation(
        "D64-6c-k", "a running tool container is removed by force", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    if not proxy and _state(container) in LIVE_STATES:\n"
                    "        return Result(action, CHANGED, NOT_AT_REST)        # it started since the plan looked\n", ""),
                Edit(DOCKER_PY, "        container.remove(force=proxy)      # a tool container is removed only if it is at rest",
                     "        container.remove(force=True)"),),
        targets=("test_real_a_container_at_rest_is_removed_and_seen_gone_a_running_one_is_not",)),
    Mutation(
        "D64-6c-l", "a network is removed with a container attached", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    if client.containers.list(all=True, filters={\"network\": network.name}, ignore_removed=True):\n"
                    "        return Result(action, CHANGED, IN_USE)\n", ""),),
        targets=("test_real_a_network_with_a_container_of_any_state_is_kept",)),
    Mutation(
        "D64-6c-m", "a kill is not verified", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    if _wait_until(stopped, th, sleep, clock):\n        return Result(action, DONE)\n"
                    "    return Result(action, FAILED, STILL_RUNNING_AFTER_KILL)",
                    "    return Result(action, DONE)"),),
        targets=("test_a_kill_that_does_nothing_is_failed_after_the_wait_and_never_reaches_the_hook",)),
    Mutation(
        "D64-6c-n", "a removal is verified by get alone, not by the listing", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "        return not client.containers.list(all=True, filters={\"id\": action.subject_id},\n"
                    "                                          ignore_removed=True)",
                    "        return True"),),
        targets=("test_a_container_listed_after_get_says_not_found_is_still_not_gone",)),
    Mutation(
        "D64-6c-o", "a network removal is not verified", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    if _wait_until(gone, th, sleep, clock):\n        return Result(action, DONE)\n"
                    "    return Result(action, FAILED, NOT_GONE_AFTER_REMOVAL)\n\n\ndef live_mount_sources",
                    "    return Result(action, DONE)\n\n\ndef live_mount_sources"),),
        targets=("test_a_network_removal_that_does_nothing_is_failed_not_done",)),
    Mutation(
        "D64-6c-p", "the verification wait ignores the configured time", ACT_TESTS,
        edits=(Edit(DOCKER_PY, "    deadline = clock() + th.verify_wait_s", "    deadline = clock() + 1"),),
        targets=("test_the_verification_waits_the_configured_time_and_not_more",)),
    Mutation(
        "D64-6c-q", "a symlink is unlinked like a file", ACT_TESTS,
        edits=(Edit(FILES_PY, "    if not stat.S_ISREG(info.st_mode):", "    if False:"),),
        targets=("test_a_symlink_is_not_unlinked_and_its_target_is_untouched",)),
    Mutation(
        "D64-6c-r", "a file is unlinked whatever its age", ACT_TESTS,
        edits=(Edit(FILES_PY, "    if wall_clock_us() - info.st_mtime_ns // 1000 < th.file_age_s() * US:\n"
                    "        return Result(action, CHANGED, TOO_YOUNG)\n", ""),),
        targets=("test_a_file_is_judged_again_on_the_spot",)),
    Mutation(
        "D64-6c-s", "a file a container mounts is unlinked", ACT_TESTS,
        edits=(Edit(FILES_PY, "    if os.path.join(directory, name) in act_docker.live_mount_sources(client):\n"
                    "        return Result(action, CHANGED, MOUNTED)\n", ""),),
        targets=("test_a_file_is_judged_again_on_the_spot",)),
    Mutation(
        "D64-6c-t", "a file of another owner is unlinked", ACT_TESTS,
        edits=(Edit(FILES_PY, "    if info.st_uid != expected_uid:\n        return Result(action, CHANGED, FOREIGN_OWNER)\n", ""),),
        targets=("test_a_file_is_judged_again_on_the_spot",)),
    Mutation(
        "D64-6c-u", "an unlink is not verified", ACT_TESTS,
        edits=(Edit(FILES_PY, "        return Result(action, GONE)\n    try:\n        os.lstat(name, dir_fd=fd)\n"
                    "    except FileNotFoundError:\n        return Result(action, DONE)\n"
                    "    return Result(action, FAILED, NOT_GONE_AFTER_REMOVAL)",
                    "        return Result(action, GONE)\n    return Result(action, DONE)"),),
        targets=("test_an_unlink_that_leaves_the_file_is_failed_not_done",)),
    Mutation(
        "D64-6c-v", "the audit hook runs for results that were not verified", ACT_TESTS,
        edits=(Edit(ACT_PY, "        if result.outcome == DONE and on_verified is not None:",
                    "        if on_verified is not None:"),),
        targets=("test_a_proposal_touched_since_the_plan_is_lost_race_and_left_alone",)),
    Mutation(
        "D64-6c-w", "the act half gains a DELETE statement", ACT_STRUCT,
        edits=(Edit(ACT_PY, "_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)",
                    "PURGE_SQL = \"DELETE FROM capabilities WHERE revoked\"\n_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)"),),
        targets=("test_the_act_half_has_exactly_four_sql_statements_each_of_a_known_shape",)),
    Mutation(
        "D64-6c-x", "the act half imports the plan", ACT_STRUCT,
        edits=(Edit(ACT_PY, "from control_plane.reconciler import act_docker, act_files, evidence, flags, vocab",
                    "from control_plane.reconciler import act_docker, act_files, evidence, flags, plan, vocab"),),
        targets=("test_the_act_half_imports_the_one_scope_and_the_stage_helpers_and_nothing_of_the_plan",)),
    Mutation(
        "D64-6c-y", "the act half can dispatch", ACT_STRUCT,
        edits=(Edit(ACT_PY, "from control_plane.orchestrator import stages\n",
                    "from control_plane.orchestrator import stages\n"
                    "from control_plane.orchestrator.dispatch import dispatch_collection\n"),),
        targets=("test_the_act_half_imports_the_one_scope_and_the_stage_helpers_and_nothing_of_the_plan",
                 "test_the_act_half_never_names_what_would_run_something_again_or_open_another_door")),
    Mutation(
        "D64-6c-z", "act_docker gains a way to start a container", ACT_STRUCT,
        edits=(Edit(DOCKER_PY, "def _state(container: Any) -> str:",
                    "def _oops(client):\n    return client.containers.run(\"x\")\n\n\ndef _state(container: Any) -> str:"),),
        targets=("test_nothing_in_the_package_creates_runs_starts_stops_or_prunes",)),
    Mutation(
        "D64-6c-za", "an operator's mode name switches the kill switch on", ACT_TESTS + FLAG_TESTS,
        edits=(Edit(ACT_PY, "    return Settings(mode, enabled=chosen, evidence_dir=evidence_dir)",
                    "    return Settings(mode, enabled=chosen | ({flags.KILL} if mode is Mode.STATE_ONLY else set()), evidence_dir=evidence_dir)"),),
        targets=("test_the_operator_can_choose_two_modes_and_neither_allows_deletions",
                 "test_nothing_is_enabled_by_default_and_an_operator_with_no_words_enables_nothing")),
]

LOCK_PY = "control_plane/reconciler/lock.py"
SERVICE_PY = "control_plane/reconciler/service.py"
EMIT_PY = "control_plane/reconciler/emit.py"
RUN_PY = "scripts/run_reconciler.py"
LOCK_TESTS = ("tests/test_reconciler_lock.py",)
EMIT_TESTS = ("tests/test_reconciler_emit.py",)
SERVICE_TESTS = ("tests/test_reconciler_service.py",)

CATALOGUE += [
    # ---- step 6d: the process -- lock, audit vocabulary, stopping, the command line
    Mutation(
        "D64-6d-a", "the reconciler's lock key is the scheduler's", LOCK_TESTS,
        edits=(Edit(LOCK_PY, "LOCK_KEY = 0x0D64_5EC0_0000_0001", "LOCK_KEY = 0x0D62_5C4E_D000_0001"),),
        targets=("test_the_two_keys_differ_and_neither_is_a_negative_bigint",
                 "test_the_reconciler_and_the_scheduler_can_both_be_held_and_each_excludes_its_own_copy")),
    Mutation(
        "D64-6d-b", "a lost lock is never noticed", LOCK_TESTS + SERVICE_TESTS,
        edits=(Edit(LOCK_PY, "        if not ok:\n            self.lost.set()\n        return ok",
                    "        return True"),),
        targets=("test_a_session_that_is_terminated_has_lost_the_lock_and_says_so",
                 "test_a_lost_lock_stops_the_service_before_it_acts_exit_6")),
    Mutation(
        "D64-6d-c", "a dry run contends for the lock", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "        if not self.audits:                         # a dry run: no lock, no audit, no state",
                    "        if False:"),),
        targets=("test_a_dry_run_takes_no_lock_moves_nothing_and_writes_no_audit_record",)),
    Mutation(
        "D64-6d-d", "an unverified result becomes an event", EMIT_TESTS,
        edits=(Edit(EMIT_PY, "    if result.outcome != DONE:\n        raise ValueError(\"only a verified result becomes an event\")\n", ""),),
        targets=("test_a_result_that_was_not_verified_has_no_event",)),
    Mutation(
        "D64-6d-e", "a failed action is reported on every pass", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "                if key in self._reported:\n                    continue\n", ""),),
        targets=("test_a_failed_action_is_reported_once_per_object_and_counted_in_a_periodic_summary",)),
    Mutation(
        "D64-6d-f", "the failure summary ignores its period", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "        if now - self._window_started < self.th.summary_period_s:\n            return\n", ""),),
        targets=("test_a_failed_action_is_reported_once_per_object_and_counted_in_a_periodic_summary",)),
    Mutation(
        "D64-6d-g", "an audit failure inside the hook is ignored", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "        if self._audit_failed:                      # the hook failed inside act.carry_out\n            raise StopService(emit.STOP_AUDIT_FAILED)\n", ""),),
        targets=("test_a_transition_whose_record_cannot_be_written_is_not_made_and_the_service_stops",)),
    Mutation(
        "D64-6d-h", "the lock is not checked before a pass", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "            if self.audits:\n                self._assert_lock()\n            plan = make_plan(",
                    "            plan = make_plan("),),
        targets=("test_a_lost_lock_stops_the_service_before_it_acts_exit_6",)),
    Mutation(
        "D64-6d-i", "a network is judged idle from its creation, not from when this process saw it",
        SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "        self._idle_seen = {nid: self._idle_seen.get(nid, obs.host_now_us) for nid in idle_now}",
                    "        self._idle_seen = {nid: 0 for nid in idle_now}"),),
        targets=("test_a_network_is_not_planned_for_removal_in_the_first_idle_period_of_a_new_process",)),
    Mutation(
        "D64-6d-j", "an event payload may carry an extra key", EMIT_TESTS,
        edits=(Edit(EMIT_PY, "    if set(payload) != set(schema):", "    if False:"),),
        targets=("test_an_event_refuses_an_extra_key_a_missing_key_and_a_nested_value",)),
    Mutation(
        "D64-6d-k", "an id may be any string", EMIT_TESTS,
        edits=(Edit(EMIT_PY, "    if not isinstance(value, str) or not _ID.fullmatch(value):\n        raise PayloadRejected(f\"not an id",
                    "    if not isinstance(value, str):\n        raise PayloadRejected(f\"not an id"),),
        targets=("test_an_id_is_an_id_and_not_text_a_path_or_a_cidr",)),
    Mutation(
        "D64-6d-l", "a boolean is a count", EMIT_TESTS,
        edits=(Edit(EMIT_PY, "    if isinstance(value, bool) or not isinstance(value, int) or value < 0:",
                    "    if not isinstance(value, int) or value < 0:"),),
        targets=("test_a_count_is_a_non_negative_integer_and_not_a_boolean",)),
    Mutation(
        "D64-6d-m", "a pass limited to engagements is not limited", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "        if self.only_engagements is None:\n            return obs\n", "        return obs\n"),),
        targets=("test_a_pass_limited_to_an_engagement_leaves_every_other_engagements_rows_alone",)),
    Mutation(
        "D64-6d-n", "the service writes the audit trail itself", ACT_STRUCT,
        edits=(Edit(SERVICE_PY, "from control_plane.audit.logger import AuditWriteError",
                    "from control_plane.audit.logger import AuditWriteError, record_audit"),),
        targets=("test_the_service_is_the_one_module_that_joins_the_halves",)),
    Mutation(
        "D64-6d-o", "the lock-held exit code is another one", SERVICE_TESTS,
        edits=(Edit(SERVICE_PY, "EXIT_LOCK_HELD = 2", "EXIT_LOCK_HELD = 9"),),
        targets=("test_a_second_reconciler_is_refused_with_exit_2_and_says_so",
                 "test_the_exit_codes_are_distinct_and_the_scheduler_s_where_they_overlap")),
    Mutation(
        "D64-6d-p", "a refused configuration exits 0", SERVICE_TESTS,
        edits=(Edit(RUN_PY, "        _audit_refusal(args.mode)\n        return EXIT_CONFIG_REFUSED", "        _audit_refusal(args.mode)\n        return 0"),),
        targets=("test_a_refused_configuration_is_exit_8_naming_the_keys_and_nothing_else",)),
    Mutation(
        "D64-6d-q", "the command line has a default mode", SERVICE_TESTS,
        edits=(Edit(RUN_PY, "    parser.add_argument(\"--mode\", required=True, choices=sorted(act.MODE_NAMES))",
                    "    parser.add_argument(\"--mode\", default=\"state-only\", choices=sorted(act.MODE_NAMES))"),),
        targets=("test_there_is_no_default_mode_and_no_third_one",)),
    Mutation(
        "D64-6d-r", "the command line accepts a deletion option", SERVICE_TESTS,
        edits=(Edit(RUN_PY, "    parser.add_argument(\"--once\", action=\"store_true\", help=\"run one pass and exit\")",
                    "    parser.add_argument(\"--once\", action=\"store_true\", help=\"run one pass and exit\")\n"
                    "    parser.add_argument(\"--allow-deletions\", action=\"store_true\")"),),
        targets=("test_there_is_no_default_mode_and_no_third_one",)),
    Mutation(
        "D64-6d-s", "a network event names the whole container-network name", EMIT_TESTS,
        edits=(Edit(EMIT_PY, "        network = (action.name or \"\").rsplit(\"-\", 1)[-1]\n        return None, \"sandbox_network\", network",
                    "        network = (action.name or \"\")\n        return None, \"sandbox_network\", network"),),
        targets=("test_a_verified_result_becomes_exactly_its_event_and_validates",)),
]


AUTHORITY_TESTS = ("tests/test_database_authority.py",)
ROLES_SQL = "db/roles.sql"

CATALOGUE += [
    # ---- pre-deletion item 1 (ACCEPTANCE 5.84): the whole database's memberships and definer objects
    Mutation(
        "D64-P1-a", "a login role is made a member of another role (an unlisted membership)",
        AUTHORITY_TESTS,
        prepare=_superuser_prepare("GRANT cyberorch_app TO ui_reader WITH INHERIT FALSE, SET FALSE"),
        cleanup_sql=("REVOKE cyberorch_app FROM ui_reader",),
        targets=("test_the_complete_list_of_role_memberships_is_the_pinned_one",)),
    Mutation(
        "D64-P1-b", "the listed membership is granted with the default INHERIT (in roles.sql)",
        AUTHORITY_TESTS,
        edits=(Edit(ROLES_SQL, "GRANT reconciler_fn_owner TO migration_owner WITH INHERIT FALSE, SET TRUE;",
                    "GRANT reconciler_fn_owner TO migration_owner WITH SET TRUE;"),),
        targets=("test_a_membership_statement_without_inherit_false_is_refused",)),
    Mutation(
        "D64-P1-c", "the listed membership is changed to INHERIT TRUE in the live database",
        AUTHORITY_TESTS,
        prepare=_superuser_prepare("GRANT reconciler_fn_owner TO migration_owner WITH INHERIT TRUE"),
        cleanup_sql=("GRANT reconciler_fn_owner TO migration_owner WITH INHERIT FALSE, SET TRUE",),
        targets=("test_the_complete_list_of_role_memberships_is_the_pinned_one",)),
    Mutation(
        "D64-P1-d", "a role becomes a member of a built-in role", AUTHORITY_TESTS,
        prepare=_superuser_prepare("GRANT pg_read_all_data TO ui_reader"),
        cleanup_sql=("REVOKE pg_read_all_data FROM ui_reader",),
        targets=("test_no_role_of_the_repository_is_a_member_of_a_built_in_role",)),
    Mutation(
        "D64-P1-e", "a new SECURITY DEFINER function nobody listed (default ACL: PUBLIC may call it)",
        AUTHORITY_TESTS,
        sql_up=("CREATE FUNCTION public.authority_probe() RETURNS int LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS 'SELECT 1'",),
        sql_down=("DROP FUNCTION public.authority_probe()",),
        targets=("test_the_complete_list_of_security_definer_functions_is_the_pinned_one",)),
    Mutation(
        "D64-P1-f", "a definer function's search_path pin is taken off", AUTHORITY_TESTS,
        sql_up=("ALTER FUNCTION public.policy_freeze_point() RESET search_path",),
        sql_down=("ALTER FUNCTION public.policy_freeze_point() SET search_path = public, pg_temp",),
        targets=("test_each_definer_function_has_its_pinned_owner_search_path_and_callers",)),
    Mutation(
        "D64-P1-g", "pg_temp comes first on a definer function's search_path", AUTHORITY_TESTS,
        sql_up=("ALTER FUNCTION public.policy_freeze_point() SET search_path = pg_temp, public",),
        sql_down=("ALTER FUNCTION public.policy_freeze_point() SET search_path = public, pg_temp",),
        targets=("test_each_definer_function_has_its_pinned_owner_search_path_and_callers",)),
    Mutation(
        "D64-P1-h", "EXECUTE on a callable definer function is left with PUBLIC", AUTHORITY_TESTS,
        sql_up=("GRANT EXECUTE ON FUNCTION public.policy_freeze_point() TO PUBLIC",),
        sql_down=("REVOKE EXECUTE ON FUNCTION public.policy_freeze_point() FROM PUBLIC",),
        targets=("test_each_definer_function_has_its_pinned_owner_search_path_and_callers",)),
    Mutation(
        "D64-P1-i", "the scheduler's view is readable by PUBLIC", AUTHORITY_TESTS,
        sql_up=("GRANT SELECT ON scheduler_proposals TO PUBLIC",),
        sql_down=("REVOKE SELECT ON scheduler_proposals FROM PUBLIC",),
        targets=("test_the_complete_list_of_views_is_the_pinned_one_with_its_owner_and_grantees",)),
    Mutation(
        "D64-P1-j", "a role is given BYPASSRLS", AUTHORITY_TESTS,
        prepare=_superuser_prepare("ALTER ROLE ui_reader BYPASSRLS"),
        cleanup_sql=("ALTER ROLE ui_reader NOBYPASSRLS",),
        targets=("test_no_role_but_the_bootstrap_superuser_has_a_powerful_attribute",)),
    Mutation(
        "D64-P1-k", "a default privilege is set for future objects", AUTHORITY_TESTS,
        sql_up=("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ui_reader",),
        sql_down=("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM ui_reader",),
        targets=("test_the_catalog_has_no_object_that_changes_authority_behind_a_grant",)),
    Mutation(
        "D64-P1-l", "PUBLIC may create objects in schema public again", AUTHORITY_TESTS,
        prepare=_superuser_prepare("GRANT CREATE ON SCHEMA public TO PUBLIC"),
        cleanup_sql=("REVOKE CREATE ON SCHEMA public FROM PUBLIC",),
        targets=("test_search_path_schemas_cannot_be_written_by_public",)),
    Mutation(
        "D64-P1-m", "a migration adds a SECURITY DEFINER function without being listed",
        AUTHORITY_TESTS,
        edits=(Edit("db/migrations/versions/0021_decision_past_received.py",
                    '"""A proposal past ``received`` has a decision (D63).',
                    '"""A proposal past ``received`` has a decision (D63). SECURITY DEFINER'),),
        targets=("test_only_the_migrations_that_were_reviewed_contain_a_security_definer_function",)),
]


ORDER_TESTS = ("tests/test_reconciler_order.py", "tests/test_reconciler_structure.py",
               "tests/test_reconciler_service.py", "tests/test_reconciler_emit.py")
ACT_DOCKER_PY = "control_plane/reconciler/act_docker.py"
ACT_FILES_PY = "control_plane/reconciler/act_files.py"
EMIT_PY = "control_plane/reconciler/emit.py"
LOGGER_PY = "control_plane/audit/logger.py"
QUERY_PY = "control_plane/audit/query.py"
SERVICE_PY2 = "control_plane/reconciler/service.py"

CATALOGUE += [
    # ---- pre-deletion item 4 (ACCEPTANCE 5.86): the order of change and record
    Mutation(
        "D64-P4-a", "the transition's record is written after the commit, in a second transaction",
        ORDER_TESTS,
        edits=(Edit(ACT_PY, "            if moved and record is not None:\n                try:\n                    record(conn, action)          # the change's own record: same transaction\n                except Exception as exc:          # noqa: BLE001\n                    log.error(\"reconciler: audit record failed (%s) before %s\",\n                              type(exc).__name__, action.kind)\n                    raise _RecordFailed from exc\n",
                    "            pass\n"),
               Edit(ACT_PY, "        if not moved:\n            return Result(action, LOST_RACE)\n        # After the commit",
                    "        if not moved:\n            return Result(action, LOST_RACE)\n        if record is not None:\n            with engagement_scope(action.engagement_id) as conn2:\n                record(conn2, action)\n        # After the commit")),
        targets=("test_the_record_is_written_inside_the_transition_and_is_visible_only_with_it",
                 "test_a_kill_9_leaves_the_change_and_its_record_together_or_neither",
                 "test_the_transitions_record_is_written_inside_its_transaction_block")),
    Mutation(
        "D64-P4-b", "a record that fails is ignored: the transition commits without it", ORDER_TESTS,
        edits=(Edit(ACT_PY, "                    raise _RecordFailed from exc\n", "                    pass\n"),),
        targets=("test_a_record_that_raises_rolls_the_transition_back",)),
    Mutation(
        "D64-P4-c", "the in-transaction writer returns instead of raising when the insert fails",
        ORDER_TESTS,
        edits=(Edit(LOGGER_PY, "        raise AuditWriteError(\n            f\"could not write audit record {event_type!r} for \"\n            f\"{subject_type}:{subject_id}: {exc}\"\n        ) from exc\n",
                    "        return -1\n", count=2),),
        targets=("test_a_record_the_database_itself_refuses_rolls_the_transition_back",)),
    Mutation(
        "D64-P4-d", "a kill is made without its intent", ORDER_TESTS,
        edits=(Edit(ACT_DOCKER_PY, "def _kill(action: Action, container: Any, th: Thresholds, sleep, clock, intend=None) -> Result:\n    if _state(container) not in LIVE_STATES:\n        return Result(action, CHANGED, NOT_RUNNING)\n    if (blocked := declared(action, intend)) is not None:",
                    "def _kill(action: Action, container: Any, th: Thresholds, sleep, clock, intend=None) -> Result:\n    if _state(container) not in LIVE_STATES:\n        return Result(action, CHANGED, NOT_RUNNING)\n    if (blocked := declared(action, None)) is not None:"),),
        targets=("test_real_every_kind_of_irreversible_action_calls_intend_once_right_before_its_call",
                 "test_real_an_intent_that_cannot_be_written_means_no_call_is_made")),
    Mutation(
        "D64-P4-e", "the intent of a removal is written before the check that can decline it",
        ORDER_TESTS,
        edits=(Edit(ACT_DOCKER_PY, "    proxy = action.kind == vocab.REMOVE_PROXY\n    if not proxy and _state(container) in LIVE_STATES:\n        return Result(action, CHANGED, NOT_AT_REST)        # it started since the plan looked\n    kept = None\n",
                    "    proxy = action.kind == vocab.REMOVE_PROXY\n    if (blocked := declared(action, intend)) is not None:\n        return blocked\n    if not proxy and _state(container) in LIVE_STATES:\n        return Result(action, CHANGED, NOT_AT_REST)        # it started since the plan looked\n    kept = None\n"),),
        targets=("test_real_an_action_that_is_declined_writes_no_intent",
                 "test_every_irreversible_call_comes_after_the_intent_in_the_same_function")),
    Mutation(
        "D64-P4-f", "an intent that cannot be written is ignored: the call is made anyway",
        ORDER_TESTS,
        edits=(Edit(ACT_DOCKER_PY, "        return Result(action, FAILED, AUDIT_FAILED)\n    return None\n", "        return None\n    return None\n"),),
        targets=("test_real_an_intent_that_cannot_be_written_means_no_call_is_made",
                 "test_an_intent_that_cannot_be_written_means_no_unlink")),
    Mutation(
        "D64-P4-g", "a file is unlinked without its intent", ORDER_TESTS,
        edits=(Edit(ACT_FILES_PY, "    if (blocked := act_docker.declared(action, intend)) is not None:", "    if (blocked := act_docker.declared(action, None)) is not None:"),),
        targets=("test_a_file_is_announced_before_it_is_unlinked_and_not_when_it_is_declined",
                 "test_an_intent_that_cannot_be_written_means_no_unlink")),
    Mutation(
        "D64-P4-h", "the unresolved-intents query accepts any later reconciler event as the result",
        ORDER_TESTS,
        edits=(Edit(QUERY_PY, "                AND (r.event_type = CASE i.payload ->> 'kind' {cases} END", "                AND (r.event_type <> 'reconciler.action_intended'"),),
        targets=("test_an_intent_alone_is_unresolved_and_a_result_or_a_failure_after_it_closes_it",)),
    Mutation(
        "D64-P4-i", "a failed object is attempted again at once (the hold-back is off)", ORDER_TESTS,
        edits=(Edit(SERVICE_PY2, "            if failed is not None and now - failed < self.th.retry_after_failure_s:", "            if failed is not None and False:"),),
        targets=("test_a_failed_irreversible_action_is_not_attempted_again_until_the_wait_has_passed",)),
    Mutation(
        "D64-P4-j", "the service writes a proposal's event a second time, and the writer would take it",
        ORDER_TESTS,
        edits=(Edit(SERVICE_PY2, "        if result.audited:\n            return\n        try:\n            event_type, payload, engagement_id, subject_type, subject_id = emit.for_result(result)",
                    "        try:\n            event_type, payload, engagement_id, subject_type, subject_id = emit.for_result(result)"),
               Edit(EMIT_PY, "    if event_type in TRANSACTIONAL_EVENTS:\n        raise PayloadRejected(f\"{event_type!r:.40} is written in the transaction of its change\")\n    clean = validate(event_type, payload)\n    scope, _ = SCHEMAS[event_type]",
                    "    clean = validate(event_type, payload)\n    scope, _ = SCHEMAS[event_type]")),
        targets=("test_a_state_only_pass_moves_the_rows_audits_each_and_a_second_pass_does_nothing",)),
    Mutation(
        "D64-P4-k", "emit() writes a proposal event on its own connection again", ORDER_TESTS,
        edits=(Edit(EMIT_PY, "    if event_type in TRANSACTIONAL_EVENTS:\n        raise PayloadRejected(f\"{event_type!r:.40} is written in the transaction of its change\")\n    clean = validate(event_type, payload)\n    scope, _ = SCHEMAS[event_type]",
                    "    clean = validate(event_type, payload)\n    scope, _ = SCHEMAS[event_type]"),),
        targets=("test_a_proposal_event_is_never_written_on_the_audit_paths_own_connection",)),
    Mutation(
        "D64-P4-l", "emit_in_transaction takes any event", ORDER_TESTS,
        edits=(Edit(EMIT_PY, "    if event_type not in TRANSACTIONAL_EVENTS:\n        raise PayloadRejected(f\"{event_type!r:.40} is not written inside a transaction\")\n", ""),),
        targets=("test_the_in_transaction_writer_takes_proposal_events_only_and_needs_an_engagement",)),
    Mutation(
        "D64-P4-m", "another reconciler module imports the in-transaction audit writer", ORDER_TESTS,
        edits=(Edit("control_plane/reconciler/lock.py", "from __future__ import annotations\n",
                    "from __future__ import annotations\n\nfrom control_plane.audit.logger import record_audit_in_transaction  # noqa: F401\n"),),
        targets=("test_the_in_transaction_audit_writer_is_used_by_the_reconcilers_emit_alone",)),
]


UNKNOWN_TESTS = ("tests/test_unknown_outcome_events.py",)

CATALOGUE += [
    # ---- pre-deletion item 5 (ACCEPTANCE 5.87): the two unknown-outcome event names and their readers
    Mutation(
        "D64-P5-a", "the unknown-outcome query asks for the older name only", UNKNOWN_TESTS,
        edits=(Edit(QUERY_PY, 'UNKNOWN_OUTCOME_EVENTS = ("dispatch.unknown_outcome", "reconciler.dispatch_unknown_outcome")',
                    'UNKNOWN_OUTCOME_EVENTS = ("dispatch.unknown_outcome", "dispatch.unknown_outcome")'),),
        targets=("test_the_query_module_exposes_the_pair_in_one_place",
                 "test_the_query_returns_both_writers_events_oldest_first")),
    Mutation(
        "D64-P5-b", "the reconciler's event drops out of the proposal's chain (stage 'other')",
        UNKNOWN_TESTS,
        edits=(Edit(QUERY_PY, '    "reconciler.dispatch_unknown_outcome": "execution",\n', ''),),
        targets=("test_both_names_are_in_the_execution_stage_of_a_proposals_chain",)),
    Mutation(
        "D64-P5-c", "the older event's sentence is built from the proposal", UNKNOWN_TESTS,
        edits=(Edit("control_plane/orchestrator/dispatch.py", '"note": "not retried: the action may already have executed"},',
                    '"note": f"not retried: the action {proposal_id} may already have executed"},'),),
        targets=("test_the_older_events_payload_is_the_same_whatever_the_proposal_was",
                 "test_the_sentence_is_one_string_literal_in_the_writer_and_nothing_is_interpolated")),
    Mutation(
        "D64-P5-d", "a reader outside the query module hard-codes the older name", UNKNOWN_TESTS,
        edits=(Edit("control_plane/reconciler/lock.py", "from __future__ import annotations\n",
                    "from __future__ import annotations\n\n_SEEN = \"dispatch.unknown_outcome\"\n"),),
        targets=("test_no_module_names_either_event_by_its_literal_except_the_writers_and_the_one_reader",)),
]


M0024 = "db/migrations/versions/0024_reconciler_paging.py"


def _load_0024():
    import importlib.util
    spec = importlib.util.spec_from_file_location("m0024", Path(__file__).resolve().parents[1] / M0024)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_M24 = _load_0024()
CONC_TESTS = ("tests/test_reconciler_concurrency.py",)
NEGATIVE_TESTS = ("tests/test_reconciler_negative.py",)
PAGING_TESTS = ("tests/test_reconciler_paging.py", "tests/test_reconciler_reader.py",
                "tests/test_reconciler_structure.py")
OBSERVE_PY2 = "control_plane/reconciler/observe.py"
_AFTER_SIG = "public.reconciler_stuck_proposals_after(bigint, text)"


def _after_sql(*changes: tuple[str, str]) -> str:
    """The next-page function as a CREATE OR REPLACE, with each (old, new) applied once."""
    text = _M26._with_has_decision(_M24._function("public")).replace(*_OR_REPLACE, 1)
    for old, new in changes:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


_GUARD = "              AND p_after_us IS NOT NULL AND p_after_id IS NOT NULL\n"

CATALOGUE += [
    # ---- pre-deletion item 6 (ACCEPTANCE 5.88): more than 5,000 stuck rows
    Mutation(
        "D64-P6-a", "the next page returns rows for a cursor with a missing half", PAGING_TESTS,
        sql_up=_as_function_owner(_after_sql((_GUARD, ""))),
        sql_down=_as_function_owner(_after_sql()),
        targets=("test_a_cursor_with_a_missing_half_returns_nothing",)),
    Mutation(
        "D64-P6-b", "the next page starts at the cursor row instead of after it", PAGING_TESTS,
        sql_up=_as_function_owner(_after_sql(("                  > ROW(timestamptz", "                  >= ROW(timestamptz"))),
        sql_down=_as_function_owner(_after_sql()),
        targets=("test_the_cursor_is_strictly_after_the_row_it_names_and_before_the_next",
                 "test_rows_with_the_same_timestamp_are_ordered_by_id_and_the_cursor_splits_them")),
    Mutation(
        "D64-P6-c", "the next page has no stage filter of its own", PAGING_TESTS,
        sql_up=_as_function_owner(_after_sql((f"WHERE p.pipeline_stage IN ({_M23._stages()})", "WHERE true"))),
        sql_down=_as_function_owner(_after_sql()),
        targets=("test_the_next_page_has_the_same_stage_filter_order_and_limit_as_the_first",
                 "test_s2_the_caller_s_guc_does_not_widen_the_next_page_either")),
    Mutation(
        "D64-P6-d", "a page that does not move past the one before is not an error", PAGING_TESTS,
        edits=(Edit(OBSERVE_PY2, "        if cursor is not None and moved <= cursor:", "        if False:"),),
        targets=("test_a_page_that_does_not_move_past_the_one_before_is_an_error_not_a_loop",)),
    Mutation(
        "D64-P6-e", "a proposal seen on two pages is counted twice", PAGING_TESTS,
        edits=(Edit(OBSERVE_PY2, "            seen[row.proposal_id] = row", "            seen[(row.proposal_id, row.stage_updated_us)] = row"),),
        targets=("test_a_row_seen_on_two_pages_counts_once_and_the_later_reading_wins",)),
    Mutation(
        "D64-P6-f", "a read that stopped at max_pages never says it was truncated", PAGING_TESTS,
        edits=(Edit(OBSERVE_PY2, "    return tuple(seen.values()), True\n", "    return tuple(seen.values()), False\n"),),
        targets=("test_reading_stops_after_max_pages_and_says_truncated",)),
    Mutation(
        "D64-P6-g", "max_pages is ignored: only the first page is ever read", PAGING_TESTS,
        edits=(Edit(OBSERVE_PY2, "    for _ in range(max(1, max_pages)):", "    for _ in range(1):"),),
        targets=("test_e23_five_thousand_rows_the_reconciler_leaves_alone_hide_one_it_must_close",
                 "test_reading_stops_after_max_pages_and_says_truncated")),
    Mutation(
        "D64-P6-h", "a pass carries out every planned action, whatever the cap", PAGING_TESTS,
        edits=(Edit(SERVICE_PY2, "            actions = actions[:self.th.max_actions_per_pass]\n", ""),),
        targets=("test_a_pass_carries_out_at_most_the_configured_actions_and_the_next_does_the_rest",
                 "test_the_service_hands_observe_the_configured_page_count_and_the_act_half_the_configured_cap")),
    Mutation(
        "D64-P6-i", "the back-off has no ceiling", PAGING_TESTS,
        edits=(Edit(SERVICE_PY2, "            return min(interval * 2 ** self._backoff_steps, max(interval, self.th.backoff_max_s))\n",
                    "            return interval * 2 ** self._backoff_steps\n"),),
        targets=("test_the_wait_doubles_after_a_backlog_that_got_nothing_done_up_to_the_cap",)),
    Mutation(
        "D64-P6-j", "a pass that got something done is also made to wait longer", PAGING_TESTS,
        edits=(Edit(SERVICE_PY2, "        if backlog and report.outcomes.get(DONE, 0) == 0:", "        if backlog:"),),
        targets=("test_a_pass_that_did_something_never_slows_down_and_resets_the_wait",)),
    Mutation(
        "D64-P6-k", "the service reads one page whatever RECONCILER_MAX_PAGES says", PAGING_TESTS,
        edits=(Edit(SERVICE_PY2, "max_pages=self.th.max_pages,", "max_pages=1,"),),
        targets=("test_the_service_hands_observe_the_configured_page_count_and_the_act_half_the_configured_cap",
                 "test_a_truncated_read_is_reported_by_the_pass")),
    Mutation(
        "D64-P7-a", "an unlisted Docker verb (container.logs) is added to observe", STRUCT_TESTS,
        edits=(Edit(OBSERVE_PY, "            seen[container.id] = container\n",
                    "            seen[container.id] = container\n            container.logs()\n"),),
        targets=("test_every_method_called_on_a_docker_handle_is_on_the_modules_allow_list",)),
    Mutation(
        "D64-P7-b", "act_docker calls an unlisted verb through an alias of the container", STRUCT_TESTS,
        edits=(Edit(DOCKER_PY, "        container.kill()\n    except APIError:",
                    "        alias = container\n        alias.pause()\n        container.kill()\n    except APIError:"),),
        targets=("test_every_method_called_on_a_docker_handle_is_on_the_modules_allow_list",)),
    Mutation(
        "D64-P7-c", "stages.advance accepts abandoned as a destination", VOCAB,
        edits=(Edit(STAGES_PY, "    if new == ABANDONED:\n        raise ValueError(", "    if False:\n        raise ValueError("),),
        targets=("test_st4_the_generic_helpers_refuse_to_write_abandoned_whatever_the_caller_computes",)),
    Mutation(
        "D64-P7-d", "dispatch imports stages.abandon under another name", VOCAB,
        edits=(Edit(DISPATCH, "from control_plane.audit.logger import record_audit\n",
                    "from control_plane.audit.logger import record_audit\nfrom control_plane.orchestrator.stages import abandon as _quietly\n"),),
        targets=("test_st4_abandoned_is_written_by_stages_abandon_and_nothing_else",)),
    Mutation(
        "D64-P7-e", "the reconciler's close does not compare the stage or the timestamp", CONC_TESTS,
        edits=(Edit(ACT_PY, "    WHERE proposal_id = :pid AND pipeline_stage = :expected AND stage_updated_at = :planned\n    RETURNING proposal_id\n\"\"\"\nMARK_UNKNOWN_SQL",
                    "    WHERE proposal_id = :pid\n    RETURNING proposal_id\n\"\"\"\nMARK_UNKNOWN_SQL"),),
        targets=("test_rt3_the_dispatch_takes_the_stage_first_and_the_reconciler_moves_nothing",
                 "test_rt3_genuinely_concurrent_the_reconciler_waits_on_the_dispatchs_row_lock")),
    Mutation(
        "D64-P7-f", "a container removed by someone else while we removed it is a failure", CONC_TESTS,
        edits=(Edit(DOCKER_PY, "        try:\n            container.reload()\n        except NotFound:\n            return Result(action, GONE)\n        if not proxy",
                    "        container.reload()\n        if not proxy"),),
        targets=("test_rt8_scripted_a_refusal_followed_by_not_found_is_gone",)),
    Mutation(
        "D64-P7-g", "Docker's 409 (removal in progress) on a removal is a failure", CONC_TESTS,
        edits=(Edit(DOCKER_PY, "        if exc.status_code == 409 and _wait_until(gone, th, sleep, clock):", "        if False:"),),
        targets=("test_rt8_scripted_a_409_that_resolves_within_the_wait_is_gone",
                 "test_rt8_both_at_once_never_ends_in_a_failure")),
    Mutation(
        "D64-P7-h", "a start refused for a network that is gone is not typed as not started", CONC_TESTS,
        edits=(Edit("tool_gateway/sandbox.py", "            if not never_ran:\n                raise\n", "            if True:\n                raise\n"),),
        targets=("test_rt9_a_network_removed_between_ensure_and_create_is_a_not_started_and_the_retry_works",)),
    Mutation(
        "D64-P7-i", "the observation lists every container that wears an owner label", NEGATIVE_TESTS,
        edits=(Edit(OBSERVE_PY, "    for label in (RUN_LABEL, PROXY_LABEL):", "    for label in (RUN_LABEL, PROXY_LABEL, OWNER_LABEL):"),),
        targets=("test_e24_a_whole_host_pass_removes_the_forgers_container_and_touches_nothing_else",)),
]


# ---------------------------------------------------------------------------------------------
# completion round 2 (D64-N1: tool_runs.refusal_code, the network-conflict read and plan; the
# session's own rows; someone-else-first races) -- ACCEPTANCE 5.90
# ---------------------------------------------------------------------------------------------

M0025 = "db/migrations/versions/0025_tool_run_refusal_code.py"


def _load_0025():
    import importlib.util
    spec = importlib.util.spec_from_file_location("m0025", Path(__file__).resolve().parents[1] / M0025)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_M25 = _load_0025()
REFUSAL_TESTS = ("tests/test_refusal_code.py",)
CONFLICT_READ_TESTS = ("tests/test_network_conflicts_read.py",)
PLAN_CONFLICT_TESTS = ("tests/test_reconciler_plan_conflicts.py",)
CONFLICT_OBSERVE_TESTS = ("tests/test_reconciler_conflict_observe.py",)
RESIDUE_TESTS = ("tests/test_residue_check.py",)
RACE_TESTS = ("tests/test_reconciler_races.py",)
PLAN_PY2 = "control_plane/reconciler/plan.py"
FILES_PY = "control_plane/reconciler/act_files.py"
RESIDUE_PY = "tests/residue.py"
HELPERS_PY = "tests/helpers.py"
_UNDO_CODES = ("UPDATE tool_runs SET refusal_code = NULL WHERE refusal_code IS NOT NULL AND "
               f"(refusal_code NOT IN ({_M25._codes()}) OR status <> 'failed' OR exit_code IS NOT NULL)",)


def _conflicts_sql(*changes: tuple[str, str, int]) -> tuple[str, ...]:
    """The conflicts function as a CREATE OR REPLACE with each (old, new, occurrences) applied."""
    text = _M25._function("public").replace(*_OR_REPLACE, 1)
    for old, new, count in changes:
        assert text.count(old) == count, (old, text.count(old))
        text = text.replace(old, new)
    return _as_function_owner(text)


_CONFLICTS_ORIGINAL = _as_function_owner(_M25._function("public").replace(*_OR_REPLACE, 1))


def _function_mutation(id_, summary, targets, *changes, tests=CONFLICT_READ_TESTS):
    return Mutation(id_, summary, tests, sql_up=_conflicts_sql(*changes),
                    sql_down=_CONFLICTS_ORIGINAL, targets=targets)


def _check_mutation(id_, summary, constraint, definition, targets):
    return Mutation(
        id_, summary, REFUSAL_TESTS,
        sql_up=(f"ALTER TABLE tool_runs DROP CONSTRAINT {constraint}",),
        sql_down=_UNDO_CODES + (f"ALTER TABLE tool_runs ADD CONSTRAINT {constraint} CHECK ({definition})",),
        cleanup_sql=_UNDO_CODES, targets=targets)


CATALOGUE += [
    Mutation(
        "D64-C2-a", "a refused run's code is not written", REFUSAL_TESTS,
        edits=(Edit(DISPATCH, "_finish_run(conn, run_id, FAILED, exit_code=None, refusal_code=refusal_code_of(exc))",
                    "_finish_run(conn, run_id, FAILED, exit_code=None)"),),
        targets=("test_a_real_refusal_writes_the_exceptions_code_in_the_runs_own_row",
                 "test_the_network_conflict_refusal_is_the_code_the_trigger_reads")),
    Mutation(
        "D64-C2-b", "a reason outside the vocabulary is written as it is and the refusal is lost", REFUSAL_TESTS,
        edits=(Edit(DISPATCH, "    return exc.reason if exc.reason in REFUSAL_CODES else SANDBOX_NOT_STARTED",
                    "    return exc.reason"),),
        targets=("test_a_reason_nobody_added_still_records_the_refusal_with_the_general_code",
                 "test_an_unknown_reason_is_recorded_as_sandbox_not_started_so_the_refusal_is_not_lost")),
    _check_mutation(
        "D64-C2-c", "the database's never-ran rule is dropped", _M25.NULL_RULE_CHECK,
        "refusal_code IS NULL OR (status = 'failed' AND exit_code IS NULL)",
        ("test_the_database_enforces_the_vocabulary_and_the_never_ran_rule",
         "test_a_late_rewrite_of_a_refused_runs_status_cannot_leave_the_code_behind")),
    _check_mutation(
        "D64-C2-d", "the database's vocabulary check is dropped", _M25.VOCAB_CHECK,
        f"refusal_code IS NULL OR refusal_code IN ({_M25._codes()})",
        ("test_the_database_enforces_the_vocabulary_and_the_never_ran_rule",
         "test_the_check_in_the_database_lists_exactly_that_vocabulary")),
    _function_mutation(
        "D64-C2-e", "a refused range counts as history, so it can block",
        ("test_a_refused_range_never_ran_so_it_cannot_block_another_refusal",),
        ("WHERE t.refusal_code IS NULL AND cardinality(t.network_allowlist) > 0",
         "WHERE cardinality(t.network_allowlist) > 0", 1)),
    _function_mutation(
        "D64-C2-f", "the window is ignored", ("test_a_refusal_outside_the_window_does_not_count",),
        ("AND t.finished_at >= now() - make_interval(secs => p_window_s)", "AND true", 2)),
    _function_mutation(
        "D64-C2-g", "every run on a blocker counts as unfinished",
        ("test_runs_that_are_not_over_are_counted_apart_from_those_that_are",),
        ("count(*) FILTER (WHERE t.status IN ('queued', 'dispatching', 'running'))",
         "count(*) FILTER (WHERE true)", 1)),
    _function_mutation(
        "D64-C2-h", "the allowlist is hashed in the order it was stored, not sorted",
        ("test_an_allowlist_equal_to_the_refused_one_is_not_its_own_blocker",),
        ("string_agg(e, '|' ORDER BY e COLLATE \"C\")", "string_agg(e, '|')", 2)),
    _function_mutation(
        "D64-C2-i", "the aggregate runs even when no refusal is in the window",
        ("test_the_aggregate_sits_behind_a_gate_and_an_index_serves_it",),
        ("IF NOT EXISTS (SELECT 1 FROM public.tool_runs t", "IF false AND NOT EXISTS (SELECT 1 FROM public.tool_runs t", 1)),
    _function_mutation(
        "D64-C2-j", "a malformed allowlist element is cast without a check",
        ("test_a_malformed_element_in_the_history_is_skipped_not_raised_on",),
        ("WHERE pg_input_is_valid(a, 'inet') AND pg_input_is_valid(b, 'inet')\n                      AND a::inet && b::inet)",
         "WHERE a::inet && b::inet)", 1),
        # only this test: without the guard one malformed row blinds every other test of the
        # function too (that is the defect), and those would read as the mutation's own errors
        tests=("tests/test_network_conflicts_read.py::test_a_malformed_element_in_the_history_is_skipped_not_raised_on",)),
    _function_mutation(
        "D64-C2-k", "refusals with no blocker are not counted",
        ("test_a_refusal_with_no_blocker_among_the_allowlists_run_here_is_counted_apart",),
        ("FROM unblocked u\n", "FROM unblocked u WHERE false\n", 1)),
    Mutation(
        "D64-C2-l", "plan: a conflict older than the last use still removes the network", PLAN_CONFLICT_TESTS,
        edits=(Edit(PLAN_PY2, "    if c.conflicts_n < 1 or c.last_conflict_us <= c.last_used_us:", "    if c.conflicts_n < 1:"),),
        targets=("test_2_only_a_refusal_after_the_last_use_counts",)),
    Mutation(
        "D64-C2-m", "plan: a run still in flight does not block the removal", PLAN_CONFLICT_TESTS,
        edits=(Edit(PLAN_PY2, "    if c.live_runs_n or c.db_now_us - c.last_used_us < th.network_conflict_min_idle_s * US:",
                    "    if c.db_now_us - c.last_used_us < th.network_conflict_min_idle_s * US:"),),
        targets=("test_3_a_run_on_the_allowlist_that_is_not_over_blocks_it_however_old_the_last_one_is",)),
    Mutation(
        "D64-C2-n", "plan: the idle time is judged on the host's clock, not the database's", PLAN_CONFLICT_TESTS,
        edits=(Edit(PLAN_PY2, "    if c.live_runs_n or c.db_now_us - c.last_used_us < th.network_conflict_min_idle_s * US:",
                    "    if c.live_runs_n or obs.host_now_us - c.last_used_us < th.network_conflict_min_idle_s * US:"),),
        targets=("test_3_the_idle_time_is_the_configured_one_and_the_database_clock_is_the_one_used",)),
    Mutation(
        "D64-C2-o", "plan: a container attached to the blocking network does not keep it", PLAN_CONFLICT_TESTS,
        edits=(Edit(PLAN_PY2, "    if n.attached:\n        return unresolved\n", ""),),
        targets=("test_4_a_container_of_any_state_attached_keeps_the_network",)),
    Mutation(
        "D64-C2-p", "plan: the daily cap is not applied", PLAN_CONFLICT_TESTS,
        edits=(Edit(PLAN_PY2, "    if obs.conflict_removals_24h.get(c.blocking_hash_n, 0) >= th.network_conflict_daily_cap:\n        return unresolved\n", ""),),
        targets=("test_5_a_blocking_network_is_removed_at_most_the_daily_cap_of_times",)),
    Mutation(
        "D64-C2-q", "plan: foreign refusals are not reported", PLAN_CONFLICT_TESTS,
        edits=(Edit(PLAN_PY2, "    if any(c.blocking_hash_n == NO_BLOCKER and c.conflicts_n >= 1 for c in obs.conflicts):", "    if False:"),),
        targets=("test_refusals_no_network_of_ours_explains_are_reported_as_foreign_and_nothing_is_removed",)),
    Mutation(
        "D64-C2-r", "observe: a boolean passes for an integer", CONFLICT_OBSERVE_TESTS,
        edits=(Edit(OBSERVE_PY, "            if type(value) is not int:\n                raise ObservationError(f\"{name} is not an integer\")",
                    "            if not isinstance(value, int):\n                raise ObservationError(f\"{name} is not an integer\")"),),
        targets=("test_a_value_outside_the_contract_stops_the_pass",)),
    Mutation(
        "D64-C2-s", "observe: a hash wider than 48 bits is accepted", CONFLICT_OBSERVE_TESTS,
        edits=(Edit(OBSERVE_PY, "< 1 << 48)", "< 1 << 60)"),),
        targets=("test_a_value_outside_the_contract_stops_the_pass",)),
    Mutation(
        "D64-C2-t", "service: a failed removal counts against the cap", CONFLICT_OBSERVE_TESTS,
        edits=(Edit(SERVICE_PY2, "                if (result.outcome == DONE and result.action.kind == vocab.REMOVE_NETWORK",
                    "                if (result.action.kind == vocab.REMOVE_NETWORK"),),
        targets=("test_only_a_verified_removal_for_a_range_conflict_by_a_name_that_is_a_number_counts",)),
    Mutation(
        "D64-C2-u", "service: a removal is never forgotten", CONFLICT_OBSERVE_TESTS,
        edits=(Edit(SERVICE_PY2, "[t for t in times if t > horizon]", "[t for t in times]"),),
        targets=("test_a_removal_is_forgotten_after_twenty_four_hours_and_not_before",)),
    Mutation(
        "D64-C2-v", "config: the minimum idle time may be below B_cap + P + Q", CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        if values[\"network_conflict_min_idle_s\"] < least_idle:", "        if False:"),),
        targets=("test_the_minimum_idle_time_is_never_below_b_cap_plus_p_plus_q",)),
    Mutation(
        "D64-C2-w", "config: the conflict window may exceed what the function accepts", CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        if window > MAX_CONFLICT_WINDOW_S:", "        if False:"),),
        targets=("test_the_conflict_window_is_at_most_what_the_database_function_accepts",)),
    Mutation(
        "D64-C2-x", "a file that vanishes before the unlink is a failure", RACE_TESTS,
        edits=(Edit(FILES_PY, "    except FileNotFoundError:             # whoever made it unlinked it between the look and now",
                    "    except FileExistsError:             # (never raised by unlink)"),),
        targets=("test_file_scripted_the_name_vanishes_between_the_look_and_the_unlink",)),
    Mutation(
        "D64-C2-y", "a network whose removal was refused while someone else removed it is 'in use'", RACE_TESTS,
        edits=(Edit(DOCKER_PY, "        if gone():\n            return Result(action, GONE)\n        return Result(action, FAILED, IN_USE)",
                    "        return Result(action, FAILED, IN_USE)"),),
        targets=("test_network_scripted_a_refusal_while_someone_else_removes_it_is_gone_not_in_use",)),
    Mutation(
        "D64-C2-z", "a real refusal to remove a network is no longer reported", RACE_TESTS,
        edits=(Edit(DOCKER_PY, "        if gone():\n            return Result(action, GONE)\n        return Result(action, FAILED, IN_USE)",
                    "        return Result(action, GONE)"),),
        targets=("test_network_scripted_a_refusal_that_is_real_is_still_in_use",)),
    Mutation(
        "D64-C2-za", "residue: in-flight runs of the session's engagements are left as they were", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "    WHERE status = ANY(:in_flight)\"\"\"", "    WHERE false AND status = ANY(:in_flight)\"\"\""),),
        targets=("test_a_registered_engagements_stuck_rows_and_in_flight_runs_are_closed",)),
    Mutation(
        "D64-C2-zb", "residue: a stuck row in an engagement nobody registered is not looked for", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "                         and r.engagement_id not in CREATED]", "                         and False]"),),
        targets=("test_an_engagement_nobody_registered_is_left_alone_and_its_new_stuck_row_is_found",)),
    Mutation(
        "D64-C2-zc", "residue: an engagement made by make_engagement is not registered", RESIDUE_TESTS,
        edits=(Edit(HELPERS_PY, "    residue.register(engagement_id)", "    pass"),),
        targets=("test_a_registered_engagements_stuck_rows_and_in_flight_runs_are_closed",)),
]


# ---- completion 3: the five switches (ACCEPTANCE 5.92), the hold-back of failed transitions, the
# per-file cap of the session-end cleanup (5.71)
CLOCK_TESTS = ("tests/test_reconciler_clocks.py",)
FLAGS_PY = "control_plane/reconciler/flags.py"
FLAG_UNITS = "tests/test_reconciler_flags.py"
CATALOGUE += [
    Mutation(
        "D64-C3-a", "an operator may enable network and file", (FLAG_UNITS,),
        edits=(Edit(FLAGS_PY, "OPERATOR_MAY_ENABLE = (KILL, CONTAINER, PROXY)", "OPERATOR_MAY_ENABLE = CATEGORIES"),),
        targets=("test_network_and_file_are_refused_whatever_else_is_asked",
                 "test_the_two_unavailable_categories_have_no_other_door")),
    Mutation(
        "D64-C3-b", "'all' means every category an operator may enable", (FLAG_UNITS,),
        edits=(Edit(FLAGS_PY, "    for name in names:\n        if name not in CATEGORIES:",
                    "    for name in names:\n        if name == \"all\":\n            chosen.update(OPERATOR_MAY_ENABLE)\n            continue\n        if name not in CATEGORIES:"),),
        targets=("test_any_word_that_is_not_exactly_a_category_is_refused",)),
    Mutation(
        "D64-C3-c", "the kill and container categories cover each other's kind", (FLAG_UNITS,),
        edits=(Edit(FLAGS_PY, "    KILL: (vocab.KILL_CONTAINER,),\n    CONTAINER: (vocab.REMOVE_CONTAINER,),",
                    "    KILL: (vocab.REMOVE_CONTAINER,),\n    CONTAINER: (vocab.KILL_CONTAINER,),"),),
        targets=("test_each_category_covers_the_kind_its_name_says",
                 "test_with_one_category_on_exactly_its_kinds_reach_the_act_half")),
    Mutation(
        "D64-C3-d", "any enabled category enables every kind", (FLAG_UNITS,),
        edits=(Edit(ACT_PY, "    if flags.CATEGORY_OF[action.kind] not in settings.enabled:", "    if not settings.enabled:"),),
        targets=("test_with_one_category_on_exactly_its_kinds_reach_the_act_half",)),
    Mutation(
        "D64-C3-e", "the command line drops the words it was given", (FLAG_UNITS,),
        edits=(Edit(RUN_PY, "        settings = act.settings_for(args.mode, args.enable or (), args.evidence_dir)", "        settings = act.settings_for(args.mode, (), args.evidence_dir)"),),
        targets=("test_the_right_phrase_at_a_terminal_starts_and_the_record_says_what_was_enabled",
                 "test_a_wrong_phrase_at_a_terminal_is_exit_7_and_nothing_is_started")),
    Mutation(
        "D64-C3-f", "any answer confirms", (FLAG_UNITS,),
        edits=(Edit(RUN_PY, "    return answer.rstrip(\"\\r\\n\") == flags.phrase(categories)", "    return True"),),
        targets=("test_any_other_answer_does_not_confirm",
                 "test_a_wrong_phrase_at_a_terminal_is_exit_7_and_nothing_is_started")),
    Mutation(
        "D64-C3-g", "a pipe may confirm", (FLAG_UNITS,),
        edits=(Edit(RUN_PY, "    if not (_is_terminal(stdin) and _is_terminal(stdout)):", "    if False:"),),
        targets=("test_a_pipe_cannot_confirm_even_with_the_right_phrase",)),
    Mutation(
        "D64-C3-h", "the phrase is not the sorted names", (FLAG_UNITS,),
        edits=(Edit(FLAGS_PY, "    return \"enable \" + \" \".join(sorted(categories))", "    return \"enable \" + \" \".join(reversed(sorted(categories)))"),),
        targets=("test_the_phrase_is_enable_and_the_sorted_categories",)),
    Mutation(
        "D64-C3-i", "reconciler.started does not say what was enabled", (FLAG_UNITS,),
        edits=(Edit(SERVICE_PY, "                                     \"enabled\": sorted(self.settings.enabled)},", "                                     \"enabled\": []},"),),
        targets=("test_the_started_payload_is_what_the_service_writes",
                 "test_the_right_phrase_at_a_terminal_starts_and_the_record_says_what_was_enabled")),
    Mutation(
        "D64-C3-j", "the started event takes an unsorted list", (FLAG_UNITS,),
        edits=(Edit(EMIT_PY, "or list(value) != sorted(set(value))", "or False"),),
        targets=("test_the_started_event_accepts_a_sorted_list_of_known_categories_and_nothing_else",)),
    Mutation(
        "D64-C3-k", "Settings takes a word that is not a category", (FLAG_UNITS,),
        edits=(Edit(ACT_PY, "        if not self.enabled <= flags.EVERYTHING:", "        if False:"),),
        targets=("test_settings_refuses_a_word_that_is_not_a_category_even_from_the_tests",)),
    Mutation(
        "D64-C3-l", "a dry run may carry a switch", (FLAG_UNITS,),
        edits=(Edit(ACT_PY, "        if self.enabled and self.mode is Mode.DRY_RUN:", "        if False:"),),
        targets=("test_a_dry_run_changes_nothing_so_it_cannot_carry_a_switch",)),
    Mutation(
        "D64-C3-m", "a failed proposal transition is retried in every pass", ("tests/test_reconciler_service.py",),
        edits=(Edit(SERVICE_PY, "            if failed is not None and now - failed < self.th.retry_after_failure_s:",
                    "            if (action.kind in emit.IRREVERSIBLE_KINDS and failed is not None\n                    and now - failed < self.th.retry_after_failure_s):"),),
        targets=("test_a_transition_the_database_refuses_is_tried_once_per_period_and_does_not_hold_up_the_rest",)),
    Mutation(
        "D64-C3-n", "the memory of failures is never forgotten", ("tests/test_reconciler_service.py",),
        edits=(Edit(SERVICE_PY, "                           if now - t < self.th.retry_after_failure_s}", "                           if True}"),),
        targets=("test_the_memory_of_failures_is_bounded_by_the_period",)),
    Mutation(
        "D64-C3-o", "residue: no file is ever over its cap", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "                if p + r > self.caps.get(f, 0)}", "                if False}"),),
        targets=("test_a_file_that_left_more_than_its_cap_fails_the_session_naming_it",)),
    Mutation(
        "D64-C3-p", "residue: every file's rows are counted under one name", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "                file = FILE_OF.get(eid, NOT_IN_A_TEST)", "                file = NOT_IN_A_TEST"),),
        targets=("test_the_rows_a_file_left_are_counted_per_file",)),
    Mutation(
        "D64-C3-q", "residue: an engagement does not remember the file that made it", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "    FILE_OF.setdefault(engagement_id, current_file())", "    FILE_OF.setdefault(engagement_id, NOT_IN_A_TEST)"),),
        targets=("test_an_engagement_remembers_the_test_file_that_made_it",)),
    Mutation(
        "D64-C3-r", "the plan does not look at the skew", CLOCK_TESTS,
        edits=(Edit(PLAN_PY, "    if clock is not None:", "    if False:"),),
        targets=("test_a_skew_beyond_the_bound_asks_for_nothing_on_Docker_and_says_so",
                 "test_real_a_host_clock_a_day_ahead_would_kill_a_container_and_the_guard_stops_it")),
    Mutation(
        "D64-C3-s", "a skew exactly at the bound is refused (the bound is exclusive)", CLOCK_TESTS,
        edits=(Edit(PLAN_PY, "    if abs(obs.docker_skew_us) > th.max_clock_skew_s * US:",
                    "    if abs(obs.docker_skew_us) >= th.max_clock_skew_s * US:"),),
        targets=("test_a_skew_up_to_the_bound_changes_nothing",)),
    Mutation(
        "D64-C3-t", "only a skew ahead of the daemon counts", CLOCK_TESTS,
        edits=(Edit(PLAN_PY, "    if abs(obs.docker_skew_us) > th.max_clock_skew_s * US:",
                    "    if obs.docker_skew_us > th.max_clock_skew_s * US:"),),
        targets=("test_a_skew_beyond_the_bound_asks_for_nothing_on_Docker_and_says_so",)),
    Mutation(
        "D64-C3-u", "a skew nobody could measure is zero", CLOCK_TESTS,
        edits=(Edit(OBSERVE_PY, "    except Exception:                                           # noqa: BLE001 - unknown, not zero\n        return None",
                    "    except Exception:                                           # noqa: BLE001\n        return 0"),),
        targets=("test_a_clock_the_daemon_does_not_give_is_unknown_not_zero",)),
    Mutation(
        "D64-C3-v", "an unknown skew is not reported", CLOCK_TESTS,
        edits=(Edit(PLAN_PY, "        return Report(\"result\", \"docker_clock\", vocab.DOCKER_CLOCK_UNKNOWN)", "        return None"),),
        targets=("test_a_skew_nobody_could_measure_is_treated_as_too_large",)),
    Mutation(
        "D64-C3-w", "only the kill is withheld when the clocks disagree", CLOCK_TESTS,
        edits=(Edit(PLAN_PY, "        actions = [a for a in actions if a.kind not in vocab.DOCKER_ACTIONS]",
                    "        actions = [a for a in actions if a.kind != vocab.KILL_CONTAINER]"),),
        targets=("test_every_kind_of_docker_action_is_withheld_not_only_the_kill",)),
    Mutation(
        "D64-C3-x", "the daemon's zone is ignored", CLOCK_TESTS,
        edits=(Edit(OBSERVE_PY, "    elif len(moment) > 6 and moment[-6] in \"+-\" and moment[-3] == \":\":", "    elif False:"),),
        targets=("test_the_daemons_time_is_read_in_any_zone_it_reports_in",
                 "test_a_daemon_zone_ten_hours_east_is_the_same_instant")),
    Mutation(
        "D64-C3-y", "the skew is the host's time before the call, not its middle", CLOCK_TESTS,
        edits=(Edit(OBSERVE_PY, "        return (before + after) // 2 - parse_rfc3339_us(info[\"SystemTime\"])",
                    "        return before - parse_rfc3339_us(info[\"SystemTime\"])"),),
        targets=("test_the_reading_is_taken_at_the_middle_of_the_round_trip",)),
    Mutation(
        "D64-C3-z", "the bound may be as large as the whole margin", CLOCK_TESTS + CONFIG_TESTS,
        edits=(Edit(CONFIG_PY, "        if values[\"max_clock_skew_s\"] * SKEW_FRACTION_OF_MARGIN > values[\"kill_margin_s\"]:", "        if False:"),),
        targets=("test_it_is_at_most_a_quarter_of_the_kill_margin",)),
]


EVIDENCE_PY = "control_plane/reconciler/evidence.py"
EVIDENCE_TESTS = ("tests/test_reconciler_evidence.py",)
_ORDER = "test_the_order_is_archive_then_intent_then_evidence_record_then_removal"
_FAIL_CLOSED = "test_no_evidence_no_intent_no_removal"
_PRIVATE = "test_a_directory_that_is_not_private_and_ours_is_refused"
_DOOR = ("test_container_cannot_be_enabled_without_a_private_directory",)
_SERVICE_TRAIL = "test_service_the_trail_has_intent_evidence_and_removal_in_that_order_with_hashes_only"
CATALOGUE += [
    Mutation(
        "D64-C4-a", "the evidence is not kept before the removal", EVIDENCE_TESTS,
        edits=(Edit(DOCKER_PY, "            kept = evidence.save(container, evidence_dir, action.expected_owner)", "            kept = None"),),
        targets=(_ORDER, _FAIL_CLOSED, _SERVICE_TRAIL, "test_real_a_container_with_output_is_kept_and_then_removed")),
    Mutation(
        "D64-C4-b", "a failure to keep the evidence is ignored and the container is removed", EVIDENCE_TESTS,
        edits=(Edit(DOCKER_PY, "            return Result(action, FAILED, EVIDENCE_NOT_SAVED)", "            kept = None"),),
        targets=(_FAIL_CLOSED, "test_real_a_container_that_cannot_be_archived_is_still_there_after",
                 "test_service_when_the_evidence_cannot_be_kept_the_container_stays_and_it_is_said_once")),
    Mutation(
        "D64-C4-c", "the hashes are never given to the audit trail", EVIDENCE_TESTS,
        edits=(Edit(DOCKER_PY, "            saved(action, kept)", "            pass"),),
        targets=(_ORDER, _SERVICE_TRAIL, "test_real_a_container_with_output_is_kept_and_then_removed")),
    Mutation(
        "D64-C4-d", "a hash record that cannot be written does not stop the removal", EVIDENCE_TESTS,
        edits=(Edit(DOCKER_PY, "            saved(action, kept)", "            try:\n                saved(action, kept)\n            except Exception:  # noqa: BLE001\n                pass"),),
        targets=("test_an_evidence_record_that_cannot_be_written_stops_the_removal",)),
    Mutation(
        "D64-C4-e", "a directory other people can use is accepted", EVIDENCE_TESTS + (FLAG_UNITS,),
        edits=(Edit(EVIDENCE_PY, "    if info.st_mode & 0o077:", "    if False:"),),
        targets=(_PRIVATE, *_DOOR)),
    Mutation(
        "D64-C4-f", "a directory that belongs to somebody else is accepted", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "    if info.st_uid != os.getuid():", "    if False:"),),
        targets=(_PRIVATE,)),
    Mutation(
        "D64-C4-g", "a link to a directory is followed", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "        info = os.lstat(directory)", "        info = os.stat(directory)"),),
        targets=(_PRIVATE,)),
    Mutation(
        "D64-C4-h", "a file that is already there is replaced", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "            os.link(temporary, final)             # fails if the name is taken: nothing is replaced", "            os.replace(temporary, final)"),),
        targets=("test_a_different_file_already_there_is_never_replaced_and_is_a_refusal",)),
    Mutation(
        "D64-C4-i", "the hash is of what was meant to be written, not of the file in place", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "        return _sha256_of(final)", "        return written"),),
        targets=("test_the_hash_is_that_of_the_file_in_place_not_of_what_was_meant_to_be_written",)),
    Mutation(
        "D64-C4-j", "a log of any size is kept", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "                if limit is not None and size > limit:", "                if False:"),),
        targets=("test_a_log_too_large_to_keep_is_refused_not_cut",)),
    Mutation(
        "D64-C4-k", "the file is not synced before it is trusted", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "            handle.flush()\n            os.fsync(handle.fileno())\n        written = _sha256_of(temporary)", "            handle.flush()\n            pass\n        written = _sha256_of(temporary)"),),
        targets=("test_a_file_or_directory_that_cannot_be_synced_is_not_evidence",)),
    Mutation(
        "D64-C4-l", "an unknown-outcome container is removed as soon as its run is over, retention or not", (*EVIDENCE_TESTS, "tests/test_reconciler_plan.py"),
        edits=(Edit(PLAN_PY, "    if obs.host_now_us - since < th.retention_s * US:\n        return None\n    if run_status is None:", "    if run_status != \"unknown_outcome\" and obs.host_now_us - since < th.retention_s * US:\n        return None\n    if run_status is None:"),),
        targets=("test_retention_binds_an_unknown_outcome_container_to_the_microsecond",
                 "test_r2_a_container_at_rest_is_removed_after_the_retention_and_not_before")),
    Mutation(
        "D64-C4-m", "an unknown-outcome container is removed like a finished one", (*EVIDENCE_TESTS, "tests/test_reconciler_plan.py"),
        edits=(Edit(PLAN_PY, "    if run_status == \"unknown_outcome\":     # nobody knows how it ended: keep what it left first", "    if False:"),),
        targets=("test_only_a_run_of_unknown_outcome_carries_that_reason",
                 "test_r2_a_container_at_rest_is_removed_after_the_retention_and_not_before")),
    Mutation(
        "D64-C4-n", "the evidence event takes any text for a hash", EVIDENCE_TESTS,
        edits=(Edit(EMIT_PY, "    if not isinstance(value, str) or not _SHA256.fullmatch(value):", "    if not isinstance(value, str):"),),
        targets=("test_the_evidence_event_refuses_anything_else",)),
    Mutation(
        "D64-C4-o", "the service never gives the act half a place to record the hashes", EVIDENCE_TESTS,
        edits=(Edit(SERVICE_PY, "                saved=self._evidence_saved if self.audits else None,", "                saved=None,"),),
        targets=(_SERVICE_TRAIL,)),
    Mutation(
        "D64-C4-p", "container can be enabled without somewhere to keep the evidence", EVIDENCE_TESTS + (FLAG_UNITS,),
        edits=(Edit(ACT_PY, "    if flags.CONTAINER in chosen:", "    if False:"),),
        targets=(*_DOOR, "test_container_without_a_private_evidence_directory_is_exit_7_before_anything")),
    Mutation(
        "D64-C4-q", "the command line drops the evidence directory", EVIDENCE_TESTS + (FLAG_UNITS,),
        edits=(Edit(RUN_PY, "        settings = act.settings_for(args.mode, args.enable or (), args.evidence_dir)", "        settings = act.settings_for(args.mode, args.enable or ())"),),
        targets=("test_the_right_phrase_at_a_terminal_starts_and_the_record_says_what_was_enabled",)),
    Mutation(
        "D64-C4-r", "every container removal keeps evidence, even of a run that finished normally", EVIDENCE_TESTS,
        edits=(Edit(DOCKER_PY, "    if action.reason_code == vocab.RUN_UNKNOWN_OUTCOME and not proxy:", "    if not proxy:"),),
        targets=("test_a_finished_run_needs_no_evidence_and_leaves_none",)),
]


PLAN_TESTS26 = ("tests/test_reconciler_plan.py", "tests/test_reconciler_observe.py")
SERVICE_TESTS26 = ("tests/test_reconciler_service.py",)
_HD = "test_has_decision_is_a_boolean_that_says_whether_never_what"
CATALOGUE += [
    Mutation(
        "D64-C4-s", "the plan does not look at has_decision", PLAN_TESTS26 + SERVICE_TESTS26,
        edits=(Edit(PLAN_PY, "        if row.has_decision:\n", "        if False:\n"),),
        targets=("test_r6_a_received_proposal_with_a_decision_is_reported_never_abandoned",
                 "test_a_received_proposal_with_a_decision_is_reported_not_acted_on_and_counted_in_the_summary")),
    Mutation(
        "D64-C4-t", "a received proposal with a decision is reported only past the grace", PLAN_TESTS26,
        edits=(Edit(PLAN_PY, "        if row.has_decision:\n", "        if row.has_decision and now - row.stage_updated_us >= th.stage_grace_s * US:\n"),),
        targets=("test_r6_a_received_proposal_with_a_decision_is_reported_never_abandoned",)),
    Mutation(
        "D64-C4-u", "a decided proposal is judged by has_decision too", PLAN_TESTS26,
        edits=(Edit(PLAN_PY, "    if stage == vocab.STAGE_DECIDED:\n", "    if stage == vocab.STAGE_DECIDED and not row.has_decision:\n"),),
        targets=("test_a_decision_is_what_every_later_stage_has_so_has_decision_changes_nothing_there",)),
    Mutation(
        "D64-C4-v", "a NULL has_decision is accepted", PLAN_TESTS26,
        edits=(Edit(OBSERVE_PY, "             \"enrolled\", \"has_decision\"}", "             \"enrolled\"}"),),
        targets=("test_a_value_the_contract_does_not_allow_is_refused",)),
    Mutation(
        "D64-C4-w", "has_decision may be an integer", PLAN_TESTS26,
        edits=(Edit(OBSERVE_PY, "\"run_status\": _TEXT, \"has_decision\": _BOOL,", "\"run_status\": _TEXT, \"has_decision\": _INT + _BOOL,"),),
        targets=("test_a_value_the_contract_does_not_allow_is_refused",)),
    Mutation(
        "D64-C4-x", "the summary counts passes, not objects", SERVICE_TESTS26,
        edits=(Edit(SERVICE_PY, "f\"{report.subject}:{report.reason_code}\", set()).add(report.subject_id)", "f\"{report.subject}:{report.reason_code}\", set()).add(self._window_passes)"),),
        targets=("test_what_is_reported_is_counted_as_objects_not_as_passes_and_the_window_starts_again",)),
    Mutation(
        "D64-C4-y", "a window with reports and no failure writes no summary", SERVICE_TESTS26,
        edits=(Edit(SERVICE_PY, "        if self._window or self._window_reported:", "        if self._window:"),),
        targets=("test_a_received_proposal_with_a_decision_is_reported_not_acted_on_and_counted_in_the_summary",
                 "test_what_is_reported_is_counted_as_objects_not_as_passes_and_the_window_starts_again")),
    Mutation(
        "D64-C4-z", "what was reported is carried into the next window", SERVICE_TESTS26,
        edits=(Edit(SERVICE_PY, "        self._window_reported.clear()\n", ""),),
        targets=("test_what_is_reported_is_counted_as_objects_not_as_passes_and_the_window_starts_again",)),
    Mutation(
        "D64-C4-aa", "the pass hands the plan's reports to nobody", SERVICE_TESTS26,
        edits=(Edit(SERVICE_PY, "                self._after(results, plan.reports)\n", "                self._after(results)\n"),),
        targets=("test_a_received_proposal_with_a_decision_is_reported_not_acted_on_and_counted_in_the_summary",)),
    Mutation(
        "D64-C4-ab", "the first function says the opposite of the truth", READER_TESTS,
        sql_up=_as_function_owner(_stuck_sql(("p.decision IS NOT NULL", "p.decision IS NULL"))),
        sql_down=_as_function_owner(_stuck_sql()),
        targets=(_HD,)),
    Mutation(
        "D64-C4-ac", "the next page says the opposite of the truth", READER_TESTS,
        sql_up=_as_function_owner(_after_sql(("p.decision IS NOT NULL", "p.decision IS NULL"))),
        sql_down=_as_function_owner(_after_sql()),
        targets=(_HD,)),
    Mutation(
        "D64-C4-ad", "the functions' owner can read another column of the proposals", READER_TESTS,
        sql_up=("GRANT SELECT (stage_detail) ON action_proposals TO reconciler_fn_owner",),
        sql_down=("REVOKE SELECT (stage_detail) ON action_proposals FROM reconciler_fn_owner",),
        targets=("test_the_owner_has_column_select_on_exactly_the_listed_columns_and_nothing_else",)),
    Mutation(
        "D64-C4-ae", "the reader is given the decision column", READER_TESTS,
        sql_up=("GRANT SELECT (decision) ON action_proposals TO reconciler_reader",),
        sql_down=("REVOKE SELECT (decision) ON action_proposals FROM reconciler_reader",),
        targets=("test_the_functions_owner_reads_the_decision_column_and_the_reader_cannot",)),
]


CONFTEST_PY = "tests/conftest.py"
CATALOGUE += [
    Mutation(
        "D64-C4-af", "the end of a test closes nothing", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "    closed = close_rows(made)\n", "    closed = close_rows(set())\n"),),
        targets=("test_finishing_a_test_closes_what_its_engagements_left_and_says_which_file",
                 "test_ends_one_and_by_the_next_test_it_has_been_closed")),
    Mutation(
        "D64-C4-ag", "the end of a test closes the module's engagements too", RESIDUE_TESTS,
        edits=(Edit(CONFTEST_PY, "    made = residue.CREATED - before\n", "    made = set(residue.CREATED)\n"),),
        targets=("test_module_two_and_the_first_test_did_not_close_it_early",)),
    Mutation(
        "D64-C4-ah", "the end of a test is never reached", RESIDUE_TESTS,
        edits=(Edit(CONFTEST_PY, "    if made:\n        residue.finish_test(made)", "    if False:\n        residue.finish_test(made)"),),
        targets=("test_ends_one_and_by_the_next_test_it_has_been_closed",)),
    Mutation(
        "D64-C4-ai", "a file is given an allowance", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "FILE_CAP: dict[str, int] = {}", "FILE_CAP: dict[str, int] = {\"tests/test_residue_check.py\": 1}"),),
        targets=("test_a_cap_is_never_above_the_ceiling",)),
    Mutation(
        "D64-C4-aj", "the rows are closed and the in-flight runs are not", RESIDUE_TESTS,
        edits=(Edit(RESIDUE_PY, "                runs = conn.execute(text(CLOSE_RUNS), {\"in_flight\": list(IN_FLIGHT)}).rowcount\n", "                runs = 0\n"),),
        targets=("test_a_registered_engagements_stuck_rows_and_in_flight_runs_are_closed",)),
]


NUMBERING_TESTS = ("tests/test_acceptance_numbering.py",)
ACCEPTANCE_MD = "docs/ACCEPTANCE_MVP1_AGENTS.md"
CATALOGUE += [
    Mutation(
        "D64-C4-ak", "an ACCEPTANCE number is used twice", NUMBERING_TESTS,
        edits=(Edit(ACCEPTANCE_MD, "| **5.95** |", "| **5.94** |"),),
        targets=("test_the_rows_of_the_table_are_consecutive_each_number_once_and_in_order",)),
    Mutation(
        "D64-C4-al", "an ACCEPTANCE row is lost from the table", NUMBERING_TESTS,
        edits=(Edit(ACCEPTANCE_MD, "| **5.93** |", "| **5.93x** |"),),
        targets=("test_the_rows_of_the_table_are_consecutive_each_number_once_and_in_order",)),
    Mutation(
        "D64-C4-am", "a status in none of the document's words", NUMBERING_TESTS,
        edits=(Edit(ACCEPTANCE_MD, "**Closed at completion 4, item 2.**", "**Done at completion 4, item 2.**"),),
        targets=("test_every_row_from_5_58_on_starts_its_status_with_one_of_the_documents_words",)),
    Mutation(
        "D64-C4-an", "a file points at an ACCEPTANCE row that does not exist", NUMBERING_TESTS,
        edits=(Edit("tests/residue.py", "(ACCEPTANCE 5.71, 5.96).", "(ACCEPTANCE 5.71, 5.196)."),),
        targets=("test_every_acceptance_pointer_in_the_repository_names_an_item_that_exists",)),
    Mutation(
        "D64-C4-ao", "a row says it was revised by a row that does not exist", NUMBERING_TESTS,
        edits=(Edit(ACCEPTANCE_MD, "*Revised by 5.97: `--enable container` needs", "*Revised by 5.197: `--enable container` needs"),),
        targets=("test_every_revised_by_names_a_row_that_exists_and_comes_after_the_row_it_revises",)),
    Mutation(
        "D64-C4-ap", "the Makefile starts the reconciler with a switch", ("tests/test_reconciler_flags.py",),
        edits=(Edit("Makefile", "lint:\n\t.venv/bin/ruff check .", "lint:\n\t.venv/bin/ruff check .\n\tpython scripts/run_reconciler.py --mode state-only --enable kill"),),
        targets=("test_nothing_that_ships_starts_the_reconciler_with_a_switch",)),
]


CATALOGUE += [
    Mutation(
        "D64-C4-aq", "a raised ceiling is not noticed", RESIDUE_TESTS,
        edits=(Edit("tests/test_residue_check.py", "            if ceiling > main.get(file, 0)]", "            if False]"),),
        targets=("test_the_comparison_with_the_main_line_says_which_ceiling_is_raised",)),
]


CATALOGUE += [
    Mutation(
        "D64-C5-a", "an engagement's evidence subdirectory may be open to others", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "or info.st_uid != os.getuid() or info.st_mode & 0o077:", "or info.st_uid != os.getuid():"),),
        targets=("test_an_engagement_subdirectory_that_is_not_private_and_ours_is_refused",)),
    Mutation(
        "D64-C5-b", "an engagement name is not checked, so it can be a path", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "not _ENGAGEMENT_NAME.fullmatch(engagement_id):", "not engagement_id:"),),
        targets=("test_an_engagement_name_that_is_a_path_is_refused_and_nothing_is_made",)),
    Mutation(
        "D64-C5-c", "every engagement's evidence goes into the same directory", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "    path = os.path.join(directory, engagement_id)\n", "    path = directory\n"),),
        targets=("test_each_engagement_has_its_own_private_subdirectory_and_the_files_are_in_it",)),
    Mutation(
        "D64-C5-d", "the start-up probe checks nothing", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "    directory = check_directory(directory)\n    name = os.path.join(directory, f\".probe.{os.getpid()}\")", "    return\n    name = os.path.join(directory, f\".probe.{os.getpid()}\")"),),
        targets=("test_the_start_up_probe_refuses_a_directory_that_cannot_take_a_file",)),
    Mutation(
        "D64-C5-e", "the service does not run the start-up probe", EVIDENCE_TESTS,
        edits=(Edit(SERVICE_PY, "                evidence.probe(self.settings.evidence_dir)", "                pass"),),
        targets=("test_a_reconciler_with_container_enabled_and_a_bad_evidence_directory_refuses_to_start",)),
    Mutation(
        "D64-C5-f", "the service probes the evidence directory even where container is off", EVIDENCE_TESTS,
        edits=(Edit(SERVICE_PY, "        if flags.CONTAINER in self.settings.enabled:\n            try:", "        if True:\n            try:"),),
        targets=("test_a_reconciler_without_container_enabled_does_not_look_at_the_evidence_directory",)),
    Mutation(
        "D64-C5-g", "the start-up probe leaves its file behind", EVIDENCE_TESTS,
        edits=(Edit(EVIDENCE_PY, "            os.unlink(name)\n", "            pass\n"),),
        targets=("test_the_start_up_probe_writes_syncs_and_removes_a_file_and_leaves_nothing",)),
]

# --- completion 5, part 2: a stopped or killed mutation sweep puts back what it changed ------------

MUTCHECK_PY = "scripts/mutation_check.py"
HYGIENE_PY = "tests/db_hygiene.py"
RESIDUE_PY = "tests/residue.py"
MUTATION_SAFETY_TESTS = ("tests/test_mutation_safety.py",)

CATALOGUE += [
    Mutation(
        "D64-C5-h", "snapshot_schema() leaves the database's ACL out of the fact", SNAPSHOT_TESTS,
        edits=(Edit(SNAPSHOT_PY, " || ' acl=' || coalesce(datacl::text, '')", ""),),
        targets=("test_the_snapshot_notices_the_database_acl_and_names_it",)),
    Mutation(
        "D64-C5-i", "the 0023 downgrade does not give TEMPORARY back (the round trip sees the database)",
        ("tests/test_migrations_roundtrip.py::test_0023_adds_exactly_the_reader_s_objects_and_the_downgrade_removes_them_all",),
        edits=(Edit("db/migrations/versions/0023_reconciler_reader.py",
                    "            EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO PUBLIC', current_database());",
                    "            NULL;"),),
        targets=("test_0023_adds_exactly_the_reader_s_objects_and_the_downgrade_removes_them_all",)),
    Mutation(
        "D64-C5-j", "a scratch schema left by a round trip is not a problem", MUTATION_SAFETY_TESTS,
        edits=(Edit(HYGIENE_PY, "    found = [f\"a scratch schema of a round-trip test was left: {name}\"\n             for name in scratch_schemas(conn)]",
                    "    found = []"),),
        targets=("test_a_scratch_schema_of_a_round_trip_is_a_problem",
                 "test_the_session_end_check_fails_the_run_on_either")),
    Mutation(
        "D64-C5-k", "TEMPORARY held by PUBLIC is not a problem", MUTATION_SAFETY_TESTS,
        edits=(Edit(HYGIENE_PY, "number >= REVOKES_TEMPORARY_FROM and public_holds_temporary(conn):",
                    "number >= REVOKES_TEMPORARY_FROM and False:"),),
        targets=("test_temporary_held_by_public_is_a_problem_once_0023_is_applied",
                 "test_the_session_end_check_fails_the_run_on_either")),
    Mutation(
        "D64-C5-l", "the session-end check does not look at the database", MUTATION_SAFETY_TESTS,
        edits=(Edit(RESIDUE_PY, "database=db_hygiene.current_problems(),", "database=[],"),),
        targets=("test_the_session_end_check_fails_the_run_on_either",)),
    Mutation(
        "D64-C5-m", "the runner does not drop a scratch schema a killed test left", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "                conn.execute(text(f'DROP SCHEMA \"{name}\" CASCADE'))", "                pass"),),
        targets=("test_the_runner_drops_the_schema_and_revokes_the_grant_and_says_so",
                 "test_a_mutation_that_leaves_a_scratch_schema_behind_is_not_valid_and_is_cleaned")),
    Mutation(
        "D64-C5-n", "the runner does not revoke the TEMPORARY grant a killed test left", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, '            _superuser_sql("REVOKE TEMPORARY ON DATABASE cyberorch FROM PUBLIC")', "            pass"),),
        targets=("test_the_runner_drops_the_schema_and_revokes_the_grant_and_says_so",)),
    Mutation(
        "D64-C5-o", "the runner does not say what it cleaned", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, '    return [f"CLEANED: {line}" for line in found] + [f"STILL WRONG: {line}" for line in still]',
                    '    return [f"STILL WRONG: {line}" for line in still]'),),
        targets=("test_the_runner_drops_the_schema_and_revokes_the_grant_and_says_so",
                 "test_a_mutation_that_leaves_a_scratch_schema_behind_is_not_valid_and_is_cleaned")),
    Mutation(
        "D64-C5-p", "recover() does not put the files back", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "            path.write_bytes(original)\n            said.append", "            said.append"),),
        targets=("test_a_killed_run_s_files_are_put_back_at_the_next_start",
                 "test_a_run_killed_while_the_tests_run_is_put_back_from_the_journal_alone")),
    Mutation(
        "D64-C5-q", "recover() does not undo the database change", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "            _owner_sql(*payload[\"sql_down\"])", "            pass"),),
        targets=("test_the_database_change_of_a_killed_run_is_undone_once",)),
    Mutation(
        "D64-C5-r", "recover() undoes a database change that was never made", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "\"sql_down\": list(sql_down) if applied_sql else []", "\"sql_down\": list(sql_down)"),),
        targets=("test_a_change_that_was_never_applied_is_not_undone",)),
    Mutation(
        "D64-C5-s", "recover() forgets the journal even when the database could not be put back", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "        return said                                   # the journal stays: nothing is lost",
                    "        _journal_clear()\n        return said"),),
        targets=("test_when_the_database_cannot_be_put_back_the_journal_stays_and_it_is_said",)),
    Mutation(
        "D64-C5-t", "recover() keeps the journal after it has put everything back", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "    _journal_clear()\n    return said\n\n\ndef hygiene", "    return said\n\n\ndef hygiene"),),
        targets=("test_a_killed_run_s_files_are_put_back_at_the_next_start",)),
    Mutation(
        "D64-C5-u", "the journal is written after the files are changed, not before", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "    _journal_write(originals, sql_down, mutation.cleanup_sql,\n                   bool(mutation.sql_up or mutation.build_sql))\n    try:\n",
                    "    try:\n"),
               Edit(MUTCHECK_PY, "        for path in originals:\n            why = _compiles(path)",
                    "        _journal_write(originals, sql_down, mutation.cleanup_sql,\n                       bool(mutation.sql_up or mutation.build_sql))\n        for path in originals:\n            why = _compiles(path)")),
        targets=("test_the_journal_is_on_disk_before_the_first_byte_of_a_file_is_changed",)),
    Mutation(
        "D64-C5-v", "run() clears the journal even when a restore failed", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "        if not any(p.startswith((\"RESTORE FAILED\", \"RECOVERY\")) or \"was not restored\" in p\n                   for p in result.problems):\n            _journal_clear()",
                    "        _journal_clear()"),),
        targets=("test_a_restore_that_fails_keeps_the_journal_and_makes_the_mutation_invalid",)),
    Mutation(
        "D64-C5-w", "run() does not clean up after a test run that left the database dirty", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "        for line in hygiene():\n            result.problems.append(line)              # a test left it: the mutation is not valid",
                    "        pass"),),
        targets=("test_a_mutation_that_leaves_a_scratch_schema_behind_is_not_valid_and_is_cleaned",)),
    Mutation(
        "D64-C5-x", "an interrupted test run is killed at once, its fixtures never run", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "            os.killpg(proc.pid, signal.SIGINT)\n", "            pass\n"),),
        targets=("test_an_interrupted_test_run_is_asked_to_stop_so_its_fixtures_run",)),
    Mutation(
        "D64-C5-y", "an interrupted test run that does not stop is never killed", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "                os.killpg(proc.pid, signal.SIGKILL)\n            except ProcessLookupError:\n                pass\n            proc.wait()",
                    "                pass\n            except ProcessLookupError:\n                pass\n            proc.wait(timeout=5)"),),
        targets=("test_one_that_does_not_stop_is_killed_after_the_wait_and_the_interrupt_still_propagates",)),
    Mutation(
        "D64-C5-z", "an interrupt is swallowed instead of raised again", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "            proc.wait()\n        raise\n    return subprocess.CompletedProcess", "            proc.wait()\n        return subprocess.CompletedProcess(cmd, -2, \"\", \"\")\n    return subprocess.CompletedProcess"),),
        targets=("test_an_interrupted_test_run_is_asked_to_stop_so_its_fixtures_run",)),
    Mutation(
        "D64-C5-za", "the test run is not in a process group of its own", MUTATION_SAFETY_TESTS,
        edits=(Edit(MUTCHECK_PY, "text=True, env={**os.environ, **(env or {})}, start_new_session=True)", "text=True, env={**os.environ, **(env or {})})"),),
        targets=("test_the_children_of_the_test_run_are_in_the_group_that_is_stopped",)),
]

# --- F1 (ACCEPTANCE 5.107): an object that is gone between two calls is gone; a lost daemon is lost -----

VANISH_TESTS = ("tests/test_reconciler_vanishing.py",)
SANDBOX_PY2 = "tool_gateway/sandbox.py"

CATALOGUE += [
    Mutation(
        "D64-F1-a", "a container removed while the reconciler lists is a failure again", VANISH_TESTS,
        edits=(Edit(OBSERVE_PY2, '        for container in client.containers.list(all=True, filters={"label": label},\n                                                ignore_removed=True):', '        for container in client.containers.list(all=True, filters={"label": label}):'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_container_removed_between_the_list_and_the_inspect_is_not_listed_40_times",)),
    Mutation(
        "D64-F1-b", "a network removed between the list and its inspect is a failure again", VANISH_TESTS,
        edits=(Edit(OBSERVE_PY2, '        try:\n            network.reload()\n        except NotFound:                  # removed between the list and the inspect: not there\n            continue', '        network.reload()'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_network_removed_between_the_list_and_its_inspect_is_not_listed_40_times",)),
    Mutation(
        "D64-F1-c", "a container on a network removed while its members are read is a failure again", VANISH_TESTS,
        edits=(Edit(OBSERVE_PY2, '                    client.containers.list(all=True, filters={"network": network.name},\n                                           ignore_removed=True))', '                    client.containers.list(all=True, filters={"network": network.name}))'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_container_attached_to_a_network_that_vanishes_while_its_members_are_read_40_times",)),
    Mutation(
        "D64-F1-d", "a container removed while mount sources are read (observe) is a failure again", VANISH_TESTS,
        edits=(Edit(OBSERVE_PY2, '    for container in client.containers.list(all=True, ignore_removed=True):\n        if container.attrs.get("State", {}).get("Status") in LIVE_STATES:', '    for container in client.containers.list(all=True):\n        if container.attrs.get("State", {}).get("Status") in LIVE_STATES:'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_container_removed_while_mount_sources_are_read_is_not_a_mount_40_times[observe]",)),
    Mutation(
        "D64-F1-e", "a container removed while mount sources are read (act) is a failure again", VANISH_TESTS,
        edits=(Edit(DOCKER_PY, '    for container in client.containers.list(all=True, ignore_removed=True):\n        status = container.attrs.get("State", {}).get("Status")', '    for container in client.containers.list(all=True):\n        status = container.attrs.get("State", {}).get("Status")'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_container_removed_while_mount_sources_are_read_is_not_a_mount_40_times[act_docker]",)),
    Mutation(
        "D64-F1-f", "a container on a network removed while the network is removed is a failure again", VANISH_TESTS,
        edits=(Edit(DOCKER_PY, '    if client.containers.list(all=True, filters={"network": network.name}, ignore_removed=True):', '    if client.containers.list(all=True, filters={"network": network.name}):'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_container_on_a_network_that_vanishes_while_the_network_is_removed_40_times",)),
    Mutation(
        "D64-F1-g", "the sandbox's exclusivity check fails on a container that vanished", VANISH_TESTS,
        edits=(Edit(SANDBOX_PY2, '                try:\n                    other.reload()\n                except NotFound:         # removed since it was listed: it is not on the network\n                    continue', '                other.reload()'),),
        allowed_errors=("NotFound",),
        targets=("test_gone_a_container_that_vanishes_while_the_sandbox_checks_exclusivity_40_times",)),
    Mutation(
        "D64-F1-h", "a NotFound that reaches the top is a lost daemon again", VANISH_TESTS,
        edits=(Edit("control_plane/docker_health.py", "    if isinstance(exc, NotFound):\n        return GONE\n", "    if isinstance(exc, NotFound):\n        return LOST\n"),),
        targets=("test_the_classification_rule", "test_a_notfound_is_a_defect_if_it_reaches_the_top_never_a_lost_daemon")),
    Mutation(
        "D64-F1-i", "a server error of the daemon is no longer a lost daemon", VANISH_TESTS,
        edits=(Edit("control_plane/docker_health.py", "return LOST if status is None or status >= 500 else ANSWERED", "return LOST if status is None else ANSWERED"),),
        targets=("test_the_classification_rule",)),
    Mutation(
        "D64-F1-j", "a conflict the daemon answered is a lost daemon", VANISH_TESTS,
        edits=(Edit("control_plane/docker_health.py", "return LOST if status is None or status >= 500 else ANSWERED", "return LOST if status is None or status >= 400 else ANSWERED"),),
        targets=("test_the_classification_rule",)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
