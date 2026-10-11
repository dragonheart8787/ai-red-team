# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations reported for the scheduler (D62) and the closeouts (D63), as runnable checks.

``python scripts/mutations_d62_d63.py --list`` names them; see ``scripts/mutation_check.py`` for what
"valid" means. The ids are the ones the reports use (``M1`` ... ``M15`` in the D62 report; ``D63-*``
in the D63 audit and in ACCEPTANCE 5.60-5.69).

The older mutation claims in ACCEPTANCE 5.56 and 5.58 (D61, D58-7) are not in this catalogue.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_check import Edit, Mutation, _owner_scalar, main  # noqa: E402

SCHEDULER = (
    "tests/test_scheduler_actions.py", "tests/test_scheduler_allowlist.py",
    "tests/test_scheduler_cli.py", "tests/test_scheduler_e2e.py",
    "tests/test_scheduler_policy_change.py", "tests/test_scheduler_roles.py",
    "tests/test_scheduler_service.py", "tests/test_scheduler_skips.py",
    "tests/test_scheduler_structure.py",
)
ROLES = ("tests/test_scheduler_roles.py",)
ROUNDTRIP = ("tests/test_migrations_roundtrip.py",)
M0020 = "db/migrations/versions/0020_scheduler_state_narrow.py"
M0021 = "db/migrations/versions/0021_decision_past_received.py"
SVC = "control_plane/scheduler/service.py"
DEC = "control_plane/scheduler/decide.py"
ALLOW = "control_plane/scheduler/allowlist.py"


def _grant(sql_up: str, sql_down: str, summary: str, mid: str) -> Mutation:
    return Mutation(mid, summary, ROLES, sql_up=(sql_up,), sql_down=(sql_down,))


def _check1(change) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Replace ``scheduler_state_check1`` by a changed copy of the live definition."""
    live = _owner_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                         "WHERE conname = 'scheduler_state_check1' "
                         "AND conrelid = 'scheduler_state'::regclass")
    changed = change(live)
    assert changed != live, "the change did not change the constraint"
    swap = "ALTER TABLE scheduler_state DROP CONSTRAINT scheduler_state_check1"
    return ((swap, f"ALTER TABLE scheduler_state ADD CONSTRAINT scheduler_state_check1 {changed}"),
            (swap, f"ALTER TABLE scheduler_state ADD CONSTRAINT scheduler_state_check1 {live}"))


def _no_not_null(live: str) -> str:
    return live.replace("AND (reason_code IS NOT NULL) ", "")


def _one_more_skip_code(live: str) -> str:
    return live.replace("'ipv6_not_supported_v0'::text]",
                        "'ipv6_not_supported_v0'::text, 'because_i_said_so'::text]")


CATALOGUE = [
    Mutation(
        "M1", "no lock: acquire always succeeds and held() is always true", SCHEDULER,
        edits=(Edit("control_plane/scheduler/lock.py",
                    '        got = bool(self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"),\n'
                    '                                      {"k": LOCK_KEY}).scalar_one())',
                    "        got = True\n        self.held = lambda: True"),),
        targets=("test_a_second_instance_is_refused_before_it_reads_anything",
                 "test_a_killed_lock_connection_stops_dispatching",
                 "test_run_returns_the_lock_lost_exit_code")),
    Mutation(
        "M2", "the enrollment read ignores withdrawal (the withdrawn_at IS NULL filter removed)",
        SCHEDULER,
        edits=(Edit(DEC, '"SELECT engagement_id FROM scheduler_enrollment WHERE withdrawn_at IS NULL "',
                    '"SELECT engagement_id FROM scheduler_enrollment "'),),
        targets=("test_withdrawing_an_enrollment_takes_effect_on_the_next_tick",)),
    _grant("GRANT SELECT (reason) ON action_proposals TO scheduler_reader",
           "REVOKE SELECT (reason) ON action_proposals FROM scheduler_reader",
           "grant the reader SELECT (reason) on action_proposals", "M3a"),
    _grant("GRANT SELECT ON audit_log TO scheduler_reader",
           "REVOKE SELECT ON audit_log FROM scheduler_reader",
           "grant the reader SELECT on audit_log", "M3b"),
    _grant("GRANT UPDATE (status) ON engagements TO scheduler_state_writer",
           "REVOKE UPDATE (status) ON engagements FROM scheduler_state_writer",
           "grant the state writer UPDATE (status) on engagements", "M3c"),
    Mutation(
        "M4", "the audit payload whitelist is relaxed (any payload accepted)", SCHEDULER,
        edits=(Edit("control_plane/scheduler/emit.py",
                    '    if set(payload) != set(schema):\n'
                    '        raise PayloadRejected(\n'
                    '            f"{event_type}: payload keys {sorted(payload)} != allowed {sorted(schema)}")\n'
                    '    return {key: schema[key](payload[key]) for key in schema}',
                    '    return dict(payload)'),)),
    Mutation(
        "M5", "a skip raises the exit-7 stop", SCHEDULER, allowed_errors=("StopService",),
        edits=(Edit(SVC, "                continue                      # a skip is not a dispatch: "
                    "nothing below applies",
                    "                raise StopService(vocab.STOP_NOT_ADVANCED)"),)),
    Mutation(
        "M7", "a skip is recorded every tick", SCHEDULER,
        edits=(Edit(SVC, "        if known.get(proposal_id) == reason:\n            return False",
                    "        if False:\n            return False"),),
        targets=("test_a_skipped_proposal_over_many_ticks_does_not_stop_the_service_and_is_recorded_once",)),
    Mutation(
        "M8", "dispatch before the decision is recorded", SCHEDULER,
        edits=(Edit(
            SVC,
            '        emit.emit(vocab.DISPATCHED, {"proposal_id": pid, "reason_code": '
            'vocab.APPROVED_AND_IDLE},\n'
            '                  engagement_id=eid, subject_type="action_proposal", subject_id=pid)\n'
            '        state.record_proposal(eid, pid, vocab.DISPATCH_DECIDED, vocab.APPROVED_AND_IDLE)\n'
            '        execute.dispatch(eid, pid, prepared, sandbox=self.sandbox)',
            '        execute.dispatch(eid, pid, prepared, sandbox=self.sandbox)\n'
            '        emit.emit(vocab.DISPATCHED, {"proposal_id": pid, "reason_code": '
            'vocab.APPROVED_AND_IDLE},\n'
            '                  engagement_id=eid, subject_type="action_proposal", subject_id=pid)\n'
            '        state.record_proposal(eid, pid, vocab.DISPATCH_DECIDED, '
            'vocab.APPROVED_AND_IDLE)'),)),
    Mutation(
        "M9", "deferred is recorded every tick", SCHEDULER,
        edits=(Edit(DEC, "        if obs.waiting and not (\n"
                    "            obs.disposition == vocab.DEFERRED_STATE and obs.deferred_reason == "
                    "obs.defer_reason\n        ):",
                    "        if obs.waiting:"),)),
    Mutation(
        "M10", "the reserved-address check is removed", SCHEDULER,
        edits=(Edit(ALLOW, "        if _reserved(target, block):\n"
                    "            return Derived(skip=vocab.TARGET_RESERVED)",
                    "        pass"),)),
    Mutation(
        "M11", "no Docker reachability check before a dispatch", SCHEDULER,
        edits=(Edit(SVC, "            if not execute.docker_reachable():\n"
                    "                raise StopService(vocab.STOP_DOCKER_LOST)",
                    "            pass"),)),
    Mutation(
        "M12", "tick does not check that the lock is still held", SCHEDULER,
        edits=(Edit(SVC, "    def _assert_lock(self) -> None:\n"
                    "        if not self.lock.held():\n"
                    "            raise StopService(vocab.STOP_LOCK_LOST)",
                    "    def _assert_lock(self) -> None:\n        return None"),)),
    Mutation(
        "M13", "scheduler_state_check1 without 'reason_code IS NOT NULL' in each branch", ROLES,
        build_sql=lambda: _check1(_no_not_null),
        cleanup_sql=("DELETE FROM scheduler_state",)),
    Mutation(
        "M14", "one more skip code in scheduler_state_check1 than the vocabulary has", ROLES,
        build_sql=lambda: _check1(_one_more_skip_code),
        cleanup_sql=("DELETE FROM scheduler_state",)),
    Mutation(
        "M15", "an ip-type scope is widened to a /28 again", SCHEDULER,
        edits=(Edit(ALLOW, "        return Derived(skip=vocab.SCOPE_TOO_NARROW)\n"
                    "    if scope_type != \"cidr\":",
                    "        return Derived(allowlist=(str(ipaddress.ip_network("
                    "scope_value + \"/28\", strict=False)),))\n    if scope_type != \"cidr\":"),)),

    # --- D63 --------------------------------------------------------------------------------
    Mutation(
        "D63-a", "0020: the downgrade does nothing", ROUNDTRIP,
        edits=(Edit(M0020, "def downgrade() -> None:\n    _replace_constraints(OLD_SKIP)",
                    "def downgrade() -> None:\n    pass"),),
        targets=("test_0020_rewrites_the_retired_code_up_refuses_it_after_and_accepts_it_again_down",)),
    Mutation(
        "D63-b", "0020: the upgrade does not rewrite the retired code", ROUNDTRIP,
        edits=(Edit(M0020,
                    '    op.execute("UPDATE scheduler_state SET reason_code = '
                    "'scope_narrower_than_sandbox_minimum' \"\n"
                    "               \"WHERE reason_code = 'no_usable_block_for_address';\")\n", ""),),
        targets=("test_0020_rewrites_the_retired_code_up_refuses_it_after_and_accepts_it_again_down",)),
    Mutation(
        "D63-c", "0020: FORCE ROW LEVEL SECURITY is never turned back on", ROUNDTRIP,
        edits=(Edit(M0020, '    op.execute("ALTER TABLE scheduler_state FORCE ROW LEVEL SECURITY;")\n',
                    ""),),
        targets=("test_the_schedulers_tables_keep_force_row_security_after_every_step_up_and_down",
                 "test_0020_switches_force_row_security_off_and_on_inside_one_transaction")),
    Mutation(
        "D63-d", "0020: NO FORCE inside an autocommit block", ROUNDTRIP,
        edits=(Edit(M0020, '    op.execute("ALTER TABLE scheduler_state NO FORCE ROW LEVEL SECURITY;")\n',
                    "    with op.get_context().autocommit_block():\n"
                    '        op.execute("ALTER TABLE scheduler_state NO FORCE ROW LEVEL SECURITY;")\n'),),
        targets=("test_0020_switches_force_row_security_off_and_on_inside_one_transaction",)),
    Mutation(
        "D63-e", "0020: an END between the rewrite and FORCE (invisible to the source check)",
        ROUNDTRIP,
        edits=(Edit(M0020, "               \"WHERE reason_code = 'no_usable_block_for_address';\")\n",
                    "               \"WHERE reason_code = 'no_usable_block_for_address';\")\n"
                    '    op.execute("END;")\n'),),
        targets=("test_0020_switches_force_row_security_off_and_on_inside_one_transaction",)),
    Mutation(
        "D63-f", "code.secrets is dropped from SUPPORTED_ACTIONS", SCHEDULER,
        edits=(Edit("control_plane/scheduler/vocab.py",
                    'SUPPORTED_ACTIONS = ("network.scan", "network.recon", "code.scan", "code.secrets")',
                    'SUPPORTED_ACTIONS = ("network.scan", "network.recon", "code.scan")'),)),
    Mutation(
        "D63-g", "a CHECK on a nullable column is not listed with its reason (entry deleted)",
        ("tests/test_check_constraints_null_rule.py",),
        edits=(Edit("tests/test_check_constraints_null_rule.py",
                    '    ("findings", "findings_verifier_state_check"):\n'
                    '        "NULL = not verified yet; the verifier states are the closed set once '
                    'it has run.",\n', ""),)),
    Mutation(
        "D63-h", "the graph queries use UNION ALL (the formulation D42-2 rejected)",
        ("tests/test_graph_queries_structure.py",),
        # (anchored on the lines that follow the UNION, so this file never quotes the whole query:
        # test_only_queries_module_defines_recursive_security_graph_queries reads every file.)
        edits=(Edit("control_plane/graph/queries.py",
                    "    UNION\n    SELECT e.dst_node_id, bfs.depth + 1\n    FROM bfs\n"
                    "    JOIN security_graph_edges e ON e.src_node_id = bfs.node_id\n"
                    "    WHERE bfs.depth < :max_depth\n)\nSELECT MIN(depth) AS shortest_hops",
                    "    UNION ALL\n    SELECT e.dst_node_id, bfs.depth + 1\n    FROM bfs\n"
                    "    JOIN security_graph_edges e ON e.src_node_id = bfs.node_id\n"
                    "    WHERE bfs.depth < :max_depth\n)\nSELECT MIN(depth) AS shortest_hops"),
               Edit("control_plane/graph/queries.py",
                    "    UNION\n    SELECT e.dst_node_id, bfs.depth + 1\n    FROM bfs\n"
                    "    JOIN security_graph_edges e ON e.src_node_id = bfs.node_id\n"
                    "    WHERE bfs.depth < :max_depth\n)\nSELECT node_id, MIN(depth) AS depth",
                    "    UNION ALL\n    SELECT e.dst_node_id, bfs.depth + 1\n    FROM bfs\n"
                    "    JOIN security_graph_edges e ON e.src_node_id = bfs.node_id\n"
                    "    WHERE bfs.depth < :max_depth\n)\nSELECT node_id, MIN(depth) AS depth")),
        allowed_errors=("QueryCanceled",),
        targets=("test_graph_queries_module_uses_union_not_union_all",)),
    Mutation(
        "D63-i", "the graph edge indexes are dropped (the plan test must see it)",
        ("tests/test_graph_queries_structure.py",),
        sql_up=("DROP INDEX security_graph_edges_src", "DROP INDEX security_graph_edges_src_only"),
        sql_down=("CREATE INDEX security_graph_edges_src ON security_graph_edges "
                  "(engagement_id, src_node_id)",
                  "CREATE INDEX security_graph_edges_src_only ON security_graph_edges "
                  "(src_node_id)"),
        allowed_errors=("QueryCanceled",),
        targets=("test_graph_queries_stay_fast_on_a_hub_shaped_fixture",)),
    Mutation(
        "D63-j", "0021 (live database): NULL decision allowed at 'recorded' as well",
        ("tests/test_action_proposals_decision_stage.py",),
        sql_up=("ALTER TABLE action_proposals DROP CONSTRAINT action_proposals_decision_past_received",
                "ALTER TABLE action_proposals ADD CONSTRAINT action_proposals_decision_past_received "
                "CHECK (decision IS NOT NULL OR pipeline_stage IN ('received', 'recorded'))"),
        sql_down=("ALTER TABLE action_proposals DROP CONSTRAINT action_proposals_decision_past_received",
                  "ALTER TABLE action_proposals ADD CONSTRAINT action_proposals_decision_past_received "
                  "CHECK (decision IS NOT NULL OR pipeline_stage = 'received')",
                  "COMMENT ON CONSTRAINT action_proposals_decision_past_received ON action_proposals "
                  "IS 'NULL decision is the state of a proposal that has been received and not "
                  "decided. Every later stage has a decision (D63, ACCEPTANCE 5.69).'"),
        targets=("test_a_stage_accepts_a_missing_decision_only_if_it_is_received[recorded]",)),
    Mutation(
        "D63-k", "0021 (migration): the constraint allows NULL at 'recorded' as well", ROUNDTRIP,
        edits=(Edit(M0021, "CHECK (decision IS NOT NULL OR pipeline_stage = 'received');",
                    "CHECK (decision IS NOT NULL OR pipeline_stage IN ('received', 'recorded'));"),),
        targets=("test_0021_blocks_on_an_undecided_proposal_past_received_and_leaves_nothing_behind",)),
    Mutation(
        "D63-l", "the decision stage moves the stage without writing the decision",
        ("tests/test_pipeline_stages.py",),
        edits=(Edit("control_plane/api/function_api.py",
                    '        text("UPDATE action_proposals SET decision = :d, decision_reasons = :r, "',
                    '        text("UPDATE action_proposals SET decision_reasons = :r, "'),),
        allowed_errors=("IntegrityError", "CheckViolation")),
    Mutation(
        "D63-m", "the residue check ignores containers", ("tests/test_residue_check.py",),
        edits=(Edit("tests/residue.py",
                    '    found.containers = [f"{c.name} ({c.short_id}) {c.status}"\n'
                    '                        for c in client.containers.list(all=True) '
                    'if c.id not in before.containers]\n', "    found.containers = []\n"),),
        targets=("test_a_container_is_residue_even_if_it_never_started",)),
    Mutation(
        "D63-n", "the residue check ignores global policy layers", ("tests/test_residue_check.py",),
        edits=(Edit("tests/residue.py",
                    "    found = Leftovers(layers=[\n"
                    "        row for row in _active_unbound_layers() if row[0] not in before.layers])\n",
                    "    found = Leftovers(layers=[])\n"),),
        targets=("test_an_active_global_layer_is_residue_and_is_not_cleaned_up",)),
    Mutation(
        "D63-o", "the session does not fail on residue (conftest)",
        ("tests/test_residue_wiring.py",),
        edits=(Edit("tests/conftest.py",
                    '        pytest.fail("the test session left state behind:\\n  " + '
                    '"\\n  ".join(found.failures()),\n'
                    "                    pytrace=False)\n", "        pass\n"),),
        targets=("test_a_session_that_leaves_a_global_layer_behind_fails",)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
