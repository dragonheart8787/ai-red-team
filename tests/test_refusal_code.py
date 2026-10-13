"""``tool_runs.refusal_code``: why the sandbox declined to start a run, as state (D64-N1; 5.90).

The fact the network-conflict trigger needs -- *this run was refused because its range overlaps a
network Docker already has* -- used to be a log line. It is now a column, written by the statement
that fails the run, in the transaction that decides the run's fate; a closed vocabulary; NULL for
every run that ran. What is shown here, each from both sides:

* the vocabulary is **one list in three places** (the migration's CHECK, ``dispatch``, the sandbox's
  own exception classes and the helper's codes) and a test fails if they differ;
* the database refuses a code outside it, and refuses a code on a run that did not *never run*
  (not failed, or with an exit code -- a timeout has one, even -1), and a late rewrite of a run's
  status cannot leave a stale code behind;
* a real refusal through ``propose_action`` writes the exception's code; a success, a timeout and
  an unknown outcome write none; a reason nobody added to the vocabulary is recorded as
  ``sandbox_not_started`` rather than losing the refusal;
* **same transaction**: when the stage was already moved (the reconciler got there first) the
  refusal is rolled back whole -- the run keeps no code that its proposal's state does not back.
"""

from __future__ import annotations

import importlib.util
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from control_plane.orchestrator import dispatch, stages
from control_plane.reconciler import act
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.model import Action
from control_plane.state.db import engagement_scope
from tests.reconciler_support import _proposal, _run
from tests.test_pipeline_stages import CIDR, FakeSandbox, assert_coherent, go, only, snapshot
from tests.test_timeout_vs_not_started import (
    REFUSALS,
    TimedOut,
    _helper_codes,
    _not_started_classes,
)
from tool_gateway.sandbox import NotStarted, SandboxUnavailable

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "m0025", REPO / "db" / "migrations" / "versions" / "0025_tool_run_refusal_code.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def codes_of(eid: str) -> list[tuple]:
    with engagement_scope(eid) as conn:
        return conn.execute(text(
            "SELECT status, exit_code, refusal_code FROM tool_runs ORDER BY created_at")).all()


# ---------------------------------------------------------------------------------------------
# the vocabulary: one list
# ---------------------------------------------------------------------------------------------

def test_the_vocabulary_is_the_same_in_the_migration_the_dispatcher_and_the_sandbox():
    in_the_sandbox = {c.reason for c in _not_started_classes()} | _helper_codes()
    assert len(in_the_sandbox) >= 15, in_the_sandbox
    assert set(M.REFUSAL_CODES) == set(dispatch.REFUSAL_CODES) == in_the_sandbox
    assert len(set(M.REFUSAL_CODES)) == len(M.REFUSAL_CODES)
    assert dispatch.TIMED_OUT not in M.REFUSAL_CODES
    assert M.CONFLICT_CODE == "network_range_conflicts_with_another_network"
    assert M.CONFLICT_CODE in M.REFUSAL_CODES


def test_the_check_in_the_database_lists_exactly_that_vocabulary(db_available):
    with engagement_scope("ENG-NONE") as conn:
        definition = conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = :n AND conrelid = 'tool_runs'::regclass"),
            {"n": M.VOCAB_CHECK}).scalar_one_or_none()
    assert definition is not None, "the vocabulary check does not exist"
    assert set(re.findall(r"'([a-z_]+)'::text", definition)) == set(M.REFUSAL_CODES)


def test_an_unknown_reason_is_recorded_as_sandbox_not_started_so_the_refusal_is_not_lost():
    class Brand(NotStarted):
        reason = "a_reason_nobody_added"

    assert dispatch.refusal_code_of(Brand("x")) == dispatch.SANDBOX_NOT_STARTED
    for exc in REFUSALS:
        assert dispatch.refusal_code_of(exc) == exc.reason
    assert dispatch.refusal_code_of(NotStarted("x")) == "sandbox_not_started"


# ---------------------------------------------------------------------------------------------
# the database's two rules
# ---------------------------------------------------------------------------------------------

def attempt(eid: str, pid: str, cid: str | None, *, status: str, exit_code, code):
    """Make a run and try to give it the code; returns the name of the constraint that refused, or
    None."""
    rid = _run(eid, pid, cid, "running")
    try:
        with engagement_scope(eid) as conn:
            conn.execute(text("UPDATE tool_runs SET status = :s, exit_code = :x, "
                              "refusal_code = :c WHERE run_id = :r"),
                         {"s": status, "x": exit_code, "c": code, "r": rid})
    except IntegrityError as exc:
        return exc.orig.diag.constraint_name
    return None


@pytest.mark.parametrize("code, status, exit_code, refused_by", [
    ("network_range_conflicts_with_another_network", "failed", None, None),
    ("docker_unreachable", "failed", None, None),
    (None, "succeeded", 0, None),                                   # NULL is always allowed
    (None, "failed", -1, None),
    ("not_in_the_vocabulary", "failed", None, M.VOCAB_CHECK),
    ("", "failed", None, M.VOCAB_CHECK),
    ("tool_run_timed_out", "failed", None, M.VOCAB_CHECK),          # the other code, never this one
    ("docker_unreachable", "succeeded", None, M.NULL_RULE_CHECK),
    ("docker_unreachable", "unknown_outcome", None, M.NULL_RULE_CHECK),
    ("docker_unreachable", "running", None, M.NULL_RULE_CHECK),
    ("docker_unreachable", "failed", 0, M.NULL_RULE_CHECK),         # it ran and exited
    ("docker_unreachable", "failed", -1, M.NULL_RULE_CHECK),        # a timeout has an exit code
])
def test_the_database_enforces_the_vocabulary_and_the_never_ran_rule(
        engagement_id, code, status, exit_code, refused_by):
    pid = _proposal(engagement_id, "dispatching")
    assert attempt(engagement_id, pid, None, status=status, exit_code=exit_code,
                   code=code) == refused_by


def test_a_late_rewrite_of_a_refused_runs_status_cannot_leave_the_code_behind(engagement_id):
    pid = _proposal(engagement_id, "dispatching")
    rid = _run(engagement_id, pid, None, "running")
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE tool_runs SET status = 'failed', refusal_code = "
                          "'container_start_refused' WHERE run_id = :r"), {"r": rid})
    with pytest.raises(IntegrityError) as caught:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text("UPDATE tool_runs SET status = 'succeeded' WHERE run_id = :r"),
                         {"r": rid})
    assert caught.value.orig.diag.constraint_name == M.NULL_RULE_CHECK
    with pytest.raises(IntegrityError):                          # nor can the exit code appear
        with engagement_scope(engagement_id) as conn:
            conn.execute(text("UPDATE tool_runs SET exit_code = 0 WHERE run_id = :r"), {"r": rid})


# ---------------------------------------------------------------------------------------------
# written by a real refusal, and by nothing else
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("refusal", REFUSALS, ids=lambda e: e.reason)
def test_a_real_refusal_writes_the_exceptions_code_in_the_runs_own_row(world, refusal):
    eid = world["engagement_id"]
    outcome = go(world, sandbox=FakeSandbox(error=refusal))
    assert outcome.failure == refusal.reason
    assert codes_of(eid) == [("failed", None, refusal.reason)]
    assert_coherent(snapshot(eid))


def test_the_network_conflict_refusal_is_the_code_the_trigger_reads(world):
    from tool_gateway.sandbox import NetworkRangeConflict
    go(world, sandbox=FakeSandbox(error=NetworkRangeConflict("overlaps")))
    assert codes_of(world["engagement_id"]) == [("failed", None, M.CONFLICT_CODE)]


def test_a_reason_nobody_added_still_records_the_refusal_with_the_general_code(world):
    class Brand(NotStarted):
        reason = "a_reason_nobody_added"

    raised, outcome = None, None
    try:
        outcome = go(world, sandbox=FakeSandbox(error=Brand("new kind of refusal")))
    except Exception as exc:                                  # noqa: BLE001
        raised = type(exc).__name__
    assert raised is None, f"the refusal could not be recorded: {raised}"
    assert outcome.failure == "a_reason_nobody_added"
    assert codes_of(world["engagement_id"]) == [("failed", None, "sandbox_not_started")]


def test_runs_that_ran_carry_no_code_whatever_became_of_them(world):
    eid = world["engagement_id"]
    go(world, key="k-ok", target="10.82.0.5")
    go(world, sandbox=TimedOut(), key="k-timeout", target="10.82.0.6")
    go(world, sandbox=FakeSandbox(error=SandboxUnavailable("daemon went away")),
       key="k-unknown", target="10.82.0.7")
    runs = codes_of(eid)
    assert sorted(r[0] for r in runs) == ["failed", "succeeded", "unknown_outcome"]
    assert all(r[2] is None for r in runs), runs


# ---------------------------------------------------------------------------------------------
# the same transaction as the stage take
# ---------------------------------------------------------------------------------------------

def test_a_refusal_that_lost_the_stage_race_leaves_no_code_on_the_run(world):
    """The reconciler marked the dispatch unknown while the sandbox was refusing it: the stage take
    fails, the refusal's transaction rolls back whole, and the run -- already marked by the
    reconciler -- carries no code its proposal's state does not back."""
    eid = world["engagement_id"]

    def reconciler_gets_there_first(_kwargs):
        with engagement_scope(eid) as conn:
            pid, us = conn.execute(text(
                "SELECT proposal_id, (extract(epoch FROM stage_updated_at) * 1000000)::bigint "
                "FROM action_proposals WHERE pipeline_stage = 'dispatching'")).one()
        action = Action(kind="mark_unknown_outcome", reason_code="unknown_outcome", subject_id=pid,
                        engagement_id=eid, expected_stage="dispatching",
                        planned_stage_updated_us=us)
        assert act.carry_out([action], Settings(Mode.STATE_ONLY))[0].outcome == "done"

    refusal = REFUSALS[0]
    go(world, sandbox=FakeSandbox(during=reconciler_gets_there_first, error=refusal))
    snap = snapshot(eid)
    assert (only(snap)["stage"], only(snap)["detail"]) == (stages.RECORDED, "unknown_outcome")
    (run,) = codes_of(eid)
    assert run == ("unknown_outcome", None, None), run
