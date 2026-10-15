# ruff: noqa: E501  -- the edits quote source lines verbatim; they must match exactly
"""The mutations reported for the scheduler (D62) and the closeouts (D63), as runnable checks.

``python scripts/mutations_d62_d63.py --list`` names them; see ``scripts/mutation_check.py`` for what
"valid" means. The ids are the ones the reports use (``M1`` ... ``M15`` in the D62 report; ``D63-*``
in the D63 audit and in ACCEPTANCE 5.60-5.69).

Added at D63 closeout 4 (the older ones, re-verified with the same rule): ``D60-*`` (the six of the
D60 report §5), ``D61-r*`` (the six re-derivation mutations of 5.56 / the D61 report), ``D58-7-*``
(the four of the D58-7 report and the three of its follow-up). Not in the catalogue: the five
"issue" mutations of 5.56 (D61 report §4.4) and everything before D58.
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
STAGES_PY = "control_plane/orchestrator/stages.py"
# (`return moved is not None` is also the last line of `stages.abandon`; the line before it, in
# `advance`, is what tells them apart)
ANCHOR_ADVANCE = ('        {"pid": proposal_id, "new": new, "detail": detail, "expected": stages},\n'
                  '    ).scalar_one_or_none()\n    return moved is not None')
FAPI = "control_plane/api/function_api.py"
DISPATCH = "control_plane/orchestrator/dispatch.py"
APPROVED = "control_plane/api/approved_dispatch.py"
SANDBOX = "tool_gateway/sandbox.py"
PIPELINE = ("tests/test_pipeline_stages.py", "tests/test_decision_boundaries.py")
APPROVED_TESTS = ("tests/test_approved_dispatch.py",)
NOT_STARTED = ("tests/test_sandbox_not_started.py", "tests/test_network_isolation.py",
               "tests/test_dispatch.py")


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
                "CHECK (decision IS NOT NULL OR "
                "pipeline_stage IN ('received', 'abandoned', 'recorded'))"),
        # (since 0022 the constraint also allows 'abandoned'; the entry said 'received' alone and so
        # could not run against a database that holds an abandoned proposal -- found at completion 5)
        sql_down=("ALTER TABLE action_proposals DROP CONSTRAINT action_proposals_decision_past_received",
                  "ALTER TABLE action_proposals ADD CONSTRAINT action_proposals_decision_past_received "
                  "CHECK (decision IS NOT NULL OR pipeline_stage IN ('received', 'abandoned'))",
                  "COMMENT ON CONSTRAINT action_proposals_decision_past_received ON action_proposals "
                  "IS 'NULL decision is legal at `received` (not decided yet) and at `abandoned` "
                  "(never decided, past the grace period) and at no other stage (D63 5.69, D64 0022).'"),
        targets=("test_a_stage_accepts_a_missing_decision_only_if_it_is_received_or_abandoned[recorded]",)),
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
                    "        row for row in _active_unbound_layers() if row[0] not in before.layers],\n"
                    "        database=db_hygiene.current_problems())\n",
                    "    found = Leftovers(layers=[], database=db_hygiene.current_problems())\n"),),
        targets=("test_an_active_global_layer_is_residue_and_is_not_cleaned_up",)),
    Mutation(
        "D63-o", "the session does not fail on residue (conftest)",
        ("tests/test_residue_wiring.py",),
        edits=(Edit("tests/conftest.py",
                    '    if found.failures() or rows.failures():\n'
                    '        pytest.fail("the test session left state behind:\\n  "\n'
                    '                    + "\\n  ".join(found.failures() + rows.failures()), '
                    'pytrace=False)\n', "    if found.failures() or rows.failures():\n        pass\n"),),
        targets=("test_a_session_that_leaves_a_global_layer_behind_fails",)),

    # --- the decision stage's boundaries (D63 closeout 4) ----------------------------------
    Mutation(
        "D63-p", "the decision statement moves the stage but does not write the decision",
        ("tests/test_decision_boundaries.py",),
        edits=(Edit(FAPI, '        text("UPDATE action_proposals SET decision = :d, decision_reasons = :r, "',
                    '        text("UPDATE action_proposals SET decision_reasons = :r, "'),),
        targets=("test_a_fault_at_each_boundary_of_the_decision_stage_never_leaves_received_undecided",)),

    Mutation(
        "D63-q", "the decision statement no longer requires the proposal to be at 'received'",
        PIPELINE,
        edits=(Edit(FAPI, '             "WHERE proposal_id = :p AND pipeline_stage = :expected RETURNING proposal_id"),',
                    '             "WHERE proposal_id = :p RETURNING proposal_id"),'),),
        targets=("test_two_callers_racing_for_the_decision_leave_one_decision_and_no_undecided_row",)),

    # --- the image-literal guard (A3) -------------------------------------------------------
    Mutation(
        "D63-r", "CI no longer builds the web-target image (the workflow step is dropped)",
        ("tests/test_image_literals.py",),
        edits=(Edit(".github/workflows/test.yml", "        run: ./tool_gateway/images/build_web_target_image.sh",
                    "        run: echo skipped"),),
        targets=("test_every_image_a_test_names_is_one_ci_builds_or_pulls",)),
    Mutation(
        "D63-s", "a test names busybox:latest, which CI does not have",
        ("tests/test_image_literals.py",),
        edits=(Edit("tests/test_residue_check.py", 'BASE_IMAGE = "python:3.12-slim"',
                    'BASE_IMAGE = "busybox:latest"'),),
        targets=("test_every_image_a_test_names_is_one_ci_builds_or_pulls",)),

    # --- D60 (report section 5): the six guards of "a stage runs once" ----------------------
    Mutation(
        "D60-1", "the stage transition always wins (advance returns True)", PIPELINE,
        edits=(Edit(STAGES_PY, ANCHOR_ADVANCE, ANCHOR_ADVANCE.replace("moved is not None", "True")),)),
    Mutation(
        "D60-2", "...and the driver also ignores the committed stage (retry = run everything)",
        PIPELINE,
        edits=(Edit(STAGES_PY, ANCHOR_ADVANCE, ANCHOR_ADVANCE.replace("moved is not None", "True")),
               Edit(FAPI, "        stage, _detail = _stage_of(run.engagement_id, proposal_id)\n",
                    "        stage, _detail = _stage_of(run.engagement_id, proposal_id)\n"
                    "        if _ == 0:\n            stage = stages.RECEIVED\n"))),
    Mutation(
        "D60-3", "ON CONFLICT ... DO NOTHING removed (a retry no longer finds its proposal)",
        PIPELINE, allowed_errors=("UniqueViolation",),
        edits=(Edit(FAPI, "            ON CONFLICT (engagement_id, request_idempotency_key) DO NOTHING\n"
                    "            RETURNING proposal_id", "            RETURNING proposal_id"),)),
    Mutation(
        "D60-4", "dispatch does not take the dispatching stage", PIPELINE,
        edits=(Edit(DISPATCH, "    stages.take(conn, proposal_id, expected=stages.BEFORE_DISPATCH, "
                    "new=stages.DISPATCHING)\n", "    pass\n", count=3),)),
    Mutation(
        "D60-5", "a provenance failure is not isolated (it propagates)", PIPELINE,
        edits=(Edit(FAPI, "    except SQLAlchemyError as exc:\n        logger.error(\n"
                    "            \"provenance for %s was not recorded",
                    "    except ZeroDivisionError as exc:\n        logger.error(\n"
                    "            \"provenance for %s was not recorded"),),
        allowed_errors=("OperationalError",)),
    Mutation(
        "D60-6", "dispatch trusts the capability it was handed instead of re-reading it", PIPELINE,
        edits=(Edit(DISPATCH, "    fresh = get_capability(conn, capability.capability_id)\n"
                    "    if fresh is None or fresh.revoked or not fresh.is_live():",
                    "    fresh = capability\n    if False:"),)),

    # --- D61 re-derivation (5.56 / D61 report): the six guards ------------------------------
    Mutation(
        "D61-r1", "no re-derivation at all", APPROVED_TESTS,
        edits=(Edit(APPROVED, "    reasons: list[str] = []\n    try:\n        target = normalize_target("
                    "dict(proposal[\"target\"]))", "    return ()\n    reasons: list[str] = []\n    try:\n"
                    "        target = normalize_target(dict(proposal[\"target\"]))"),)),
    Mutation(
        "D61-r2", "the classification is not compared", APPROVED_TESTS,
        edits=(Edit(APPROVED, "    if now[\"classification\"] != approved[\"classification\"]:\n"
                    "        reasons.append(CLASSIFICATION_CHANGED)", "    pass"),)),
    Mutation(
        "D61-r3", "the approval/proposal binding is not checked", APPROVED_TESTS,
        edits=(Edit(APPROVED, "    if approval is None or approval[\"proposal_id\"] != proposal[\"proposal_id\"]:\n"
                    "        return (APPROVAL_NOT_FOR_PROPOSAL,)\n"
                    "    if approval[\"action_class\"] != proposal[\"action\"]:\n"
                    "        return (APPROVAL_NOT_FOR_PROPOSAL,)",
                    "    if approval is None:\n        return (APPROVAL_NOT_FOR_PROPOSAL,)"),)),
    Mutation(
        "D61-r4", "the OPA verdict is ignored", APPROVED_TESTS,
        edits=(Edit(APPROVED, "    if decision.decision == fa.DENY:\n        reasons.append(POLICY_NOW_DENIES)\n"
                    "    elif decision.decision == fa.HUMAN_APPROVAL:",
                    "    if False:\n        reasons.append(POLICY_NOW_DENIES)\n    elif False:"),)),
    Mutation(
        "D61-r5", "there is no ceiling on the constraints (the proposal may ask for more)",
        APPROVED_TESTS,
        edits=(Edit(APPROVED, "    if derived != approved_constraints(approval):", "    if False:"),)),
    Mutation(
        "D61-r6", "the approvals immutability trigger is disabled", APPROVED_TESTS,
        sql_up=("ALTER TABLE approvals DISABLE TRIGGER approvals_guard_update",),
        sql_down=("ALTER TABLE approvals ENABLE TRIGGER approvals_guard_update",)),

    # --- D58-7 (report): the four, and the three of the follow-up ---------------------------
    Mutation(
        "D58-7-1", "dispatch handles only the network family of refusals (the pre-fix behaviour)",
        NOT_STARTED,
        edits=(Edit(DISPATCH, "    except NotStarted as exc:\n        try:\n"
                    "            with engagement_scope(engagement_id) as conn:\n",
                    "    except NetworkNotAvailable as exc:\n        try:\n"
                    "            with engagement_scope(engagement_id) as conn:\n"),)),
    Mutation(
        "D58-7-2", "daemon errors are not translated into DaemonUnreachable", NOT_STARTED,
        edits=(Edit(SANDBOX, "    except (DockerException, _RequestsConnectionError) as exc:\n"
                    "        raise DaemonUnreachable(f\"docker is not reachable: {exc}\") from exc\n\n\n"
                    "def _is_only_the_helpers_refusal",
                    "    except ZeroDivisionError as exc:\n"
                    "        raise DaemonUnreachable(f\"docker is not reachable: {exc}\") from exc\n\n\n"
                    "def _is_only_the_helpers_refusal"),),
        allowed_errors=("DockerException", "APIError", "ConnectionError")),
    Mutation(
        "D58-7-3", "client() raises an untyped error when the daemon is unreachable", NOT_STARTED,
        edits=(Edit(SANDBOX, "            self._client = None\n"
                    "            raise DaemonUnreachable(f\"docker is not reachable: {exc}\") from exc",
                    "            self._client = None\n"
                    "            raise RuntimeError(f\"docker is not reachable: {exc}\") from exc"),),
        allowed_errors=("RuntimeError",)),
    Mutation(
        "D58-7-4", "every SandboxUnavailable is treated as not started", NOT_STARTED,
        edits=(Edit(DISPATCH, "    except NotStarted as exc:\n        try:\n"
                    "            with engagement_scope(engagement_id) as conn:\n",
                    "    except SandboxUnavailable as exc:\n        try:\n"
                    "            with engagement_scope(engagement_id) as conn:\n"),),
        allowed_errors=("AttributeError",)),
    Mutation(
        "D58-7-5", "(follow-up) start() is untyped again", NOT_STARTED,
        edits=(Edit(SANDBOX, "            container.start()\n        except APIError as exc:",
                    "            container.start()\n        except ZeroDivisionError as exc:"),),
        allowed_errors=("APIError",)),
    Mutation(
        "D58-7-6", "(follow-up) the proof that the container never ran is dropped", NOT_STARTED,
        edits=(Edit(SANDBOX, "            if not never_ran:\n                raise", "            if False:\n                raise"),)),
    Mutation(
        "D58-7-7", "(follow-up) a failed inspection is typed as not started", NOT_STARTED,
        edits=(Edit(SANDBOX, "            except (DockerException, _RequestsConnectionError):\n"
                    "                raise exc from None",
                    "            except (DockerException, _RequestsConnectionError):\n"
                    "                state = {\"Status\": \"created\", \"Running\": False, \"Pid\": 0,\n"
                    "                         \"StartedAt\": \"0001-01-01T00:00:00Z\"}"),)),
]


if __name__ == "__main__":
    main({m.id: m for m in CATALOGUE})
