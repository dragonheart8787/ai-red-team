"""A dispatch records its result only if the proposal is where it left it (ACCEPTANCE 5.74).

Found by experiment at D64 (E17): while a container was "running", the reconciler's function marked
the proposal ``recorded / unknown_outcome``; the dispatch then finished and recorded its success
*beside* that -- stage, dispatch state, run status, evidence and audit contradicting each other --
because the dispatch ignored that its own stage transition had matched no row.

Now the record transaction takes the stage as its first statement, and there is exactly one state
in which a result that finds the stage moved is still wanted: the reconciler's ``recorded /
unknown_outcome`` (proposal and run both ``unknown_outcome``). It replaces "unknown" in the same
transaction and is audited as ``run.late_result``. Anything else rolls the whole record back and the
outcome says ``stage_moved_before_record``.

Both orders of the race are here, with the container held open by a hook so that neither depends on
timing, plus one genuinely concurrent test (the reconciler's function blocked on the row lock while
the record transaction is open).
"""

from __future__ import annotations

import logging
import threading
import uuid

import pytest
from sqlalchemy import text

from control_plane.orchestrator import dispatch, stages
from control_plane.state.db import engagement_scope
from tests.test_pipeline_stages import (
    CIDR,
    FakeSandbox,
    assert_coherent,
    go,
    only,
    snapshot,
)
from tool_gateway.sandbox import ImageNotPresent, SandboxUnavailable


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def _reconcile(eid: str) -> list[str]:
    with engagement_scope(eid) as conn:
        return dispatch.reconcile_stale_dispatches(
            conn, engagement_id=eid, older_than_seconds=0, actor="test-reconciler")


def _set(eid: str, sql: str, **params) -> None:
    with engagement_scope(eid) as conn:
        conn.execute(text(sql), params)


def _rows(eid: str) -> dict:
    with engagement_scope(eid) as conn:
        run = conn.execute(text("SELECT status, exit_code FROM tool_runs")).all()
        evidence = conn.execute(text("SELECT count(*) FROM evidence")).scalar_one()
    snap = snapshot(eid)
    return {"runs": [tuple(r) for r in run], "evidence": evidence, "audit": snap["audit"],
            "proposal": only(snap)}


# ---------------------------------------------------------------------------
# the two orders
# ---------------------------------------------------------------------------

def test_the_reconciler_first_then_the_result_arrives_late(world):
    """E17 as a test. The result replaces ``unknown_outcome``; every story agrees afterwards."""
    eid = world["engagement_id"]
    seen: dict = {}

    def during(_kwargs):
        seen["marked"] = _reconcile(eid)
        seen["between"] = _rows(eid)["proposal"]

    outcome = go(world, sandbox=FakeSandbox(during=during))

    assert len(seen["marked"]) == 1
    assert (seen["between"]["stage"], seen["between"]["detail"]) == (
        stages.RECORDED, "unknown_outcome")
    assert outcome.decision == "ALLOW" and outcome.run_id and outcome.failure is None

    final = _rows(eid)
    p = final["proposal"]
    assert (p["stage"], p["detail"], p["dispatch_state"]) == (
        stages.RECORDED, "succeeded", "succeeded")
    assert final["runs"] == [("succeeded", 0)] and final["evidence"] == 1
    assert final["audit"].get("dispatch.unknown_outcome") == 1       # what the reconciler said
    assert final["audit"].get("run.late_result") == 1                # and that it was superseded
    assert final["audit"].get("tool_run.succeeded") == 1
    assert_coherent(snapshot(eid))


def test_the_result_first_then_the_reconciler_finds_nothing(world):
    eid = world["engagement_id"]
    go(world)
    before = _rows(eid)
    assert _reconcile(eid) == []
    after = _rows(eid)
    assert after == before
    assert "run.late_result" not in after["audit"]
    assert "dispatch.unknown_outcome" not in after["audit"]
    assert_coherent(snapshot(eid))


def test_the_reconciler_blocked_on_the_row_lock_while_the_result_is_being_recorded(
    world, monkeypatch,
):
    """Genuinely concurrent: the record transaction is open (evidence being written), the
    reconciler's UPDATE waits on the row lock, and after the commit it finds the proposal no longer
    in flight."""
    eid = world["engagement_id"]
    in_record, release = threading.Event(), threading.Event()
    real = dispatch.record_evidence

    def slow_evidence(*a, **k):
        in_record.set()
        assert release.wait(30)
        return real(*a, **k)

    monkeypatch.setattr(dispatch, "record_evidence", slow_evidence)
    box: dict = {}
    worker = threading.Thread(target=lambda: box.update(outcome=go(world)))
    worker.start()
    assert in_record.wait(30)
    reconciler = threading.Thread(target=lambda: box.update(marked=_reconcile(eid)))
    reconciler.start()
    reconciler.join(timeout=1.5)
    assert reconciler.is_alive(), "the reconciler should be waiting on the row lock"
    release.set()
    worker.join(30)
    reconciler.join(30)

    assert box["marked"] == []
    p = _rows(eid)["proposal"]
    assert (p["stage"], p["detail"], p["dispatch_state"]) == (
        stages.RECORDED, "succeeded", "succeeded")
    assert "run.late_result" not in _rows(eid)["audit"]
    assert_coherent(snapshot(eid))


# ---------------------------------------------------------------------------
# what is NOT a late result
# ---------------------------------------------------------------------------

def test_a_proposal_someone_else_closed_gets_no_result_and_nothing_is_written(world, caplog):
    eid = world["engagement_id"]

    def during(_kwargs):
        _set(eid, "UPDATE action_proposals SET pipeline_stage = 'closed', stage_detail = 'manual'")

    with caplog.at_level(logging.CRITICAL, logger="cyberorch.dispatch"):
        outcome = go(world, sandbox=FakeSandbox(during=during))

    assert outcome.failure == dispatch.STAGE_MOVED and outcome.run_id
    final = _rows(eid)
    assert (final["proposal"]["stage"], final["proposal"]["detail"]) == (stages.CLOSED, "manual")
    assert final["evidence"] == 0 and final["runs"] == [("running", None)]
    assert "tool_run.succeeded" not in final["audit"] and "run.late_result" not in final["audit"]
    assert any("NOT recorded" in r.getMessage() and "sha256" in r.getMessage()
               for r in caplog.records)


def test_a_late_result_needs_the_run_to_be_unknown_too(world):
    """The reconciler marks the proposal and the run together. A proposal at ``recorded /
    unknown_outcome`` whose run is still ``running`` is a state this code did not make: the whole
    record, the stage included, is rolled back."""
    eid = world["engagement_id"]

    def during(_kwargs):
        _set(eid, "UPDATE action_proposals SET pipeline_stage = 'recorded', "
                  "stage_detail = 'unknown_outcome', dispatch_state = 'unknown_outcome'")

    outcome = go(world, sandbox=FakeSandbox(during=during))

    assert outcome.failure == dispatch.STAGE_MOVED
    final = _rows(eid)
    assert (final["proposal"]["stage"], final["proposal"]["detail"]) == (
        stages.RECORDED, "unknown_outcome")
    assert final["runs"] == [("running", None)] and final["evidence"] == 0
    assert "run.late_result" not in final["audit"]


LATE_CASES = [
    # (stage, detail, dispatch_state) -> is the result still wanted?
    (stages.DISPATCHING, None, "running", "normal"),
    (stages.RECORDED, "unknown_outcome", "unknown_outcome", "late"),
    (stages.RECORDED, "succeeded", "succeeded", "refused"),          # already recorded: no second
    (stages.RECORDED, "failed", "failed", "refused"),
    (stages.RECORDED, "succeeded", "unknown_outcome", "refused"),    # the two stories disagree
    (stages.RECORDED, "unknown_outcome", "failed", "refused"),       # ... the other way round
    (stages.RECORDED, "unknown_outcome", "running", "refused"),
    # `closed` is not the reconciler's state
    (stages.CLOSED, "unknown_outcome", "unknown_outcome", "refused"),
    (stages.CLOSED, "manual", "running", "refused"),
    (stages.CAPABILITY_ISSUED, None, "queued", "refused"),
]


@pytest.mark.parametrize("stage,detail,state,expected", LATE_CASES,
                         ids=[f"{c[0]}/{c[1]}/{c[2]}" for c in LATE_CASES])
def test_which_states_a_result_may_be_recorded_over(world, stage, detail, state, expected):
    eid = world["engagement_id"]
    go(world)                                       # a proposal that has been through everything
    _set(eid, "UPDATE action_proposals SET pipeline_stage = :s, stage_detail = :d, "
              "dispatch_state = :ds", s=stage, d=detail, ds=state)
    # The run is unknown in every case, so that what decides is the proposal's own state: a run
    # that is not unknown is refused whatever the proposal says (tested below), which would hide
    # whether the stage conditions are doing their part.
    _set(eid, "UPDATE tool_runs SET status = 'unknown_outcome', exit_code = NULL")
    with engagement_scope(eid) as conn:
        pid = only(snapshot(eid))["proposal_id"]
        run_id = conn.execute(text("SELECT run_id FROM tool_runs")).scalar_one()
        if expected == "refused":
            with pytest.raises(stages.StageConflict):
                dispatch._take_result_stage(conn, pid, run_id, detail="succeeded")
            return
        late = dispatch._take_result_stage(conn, pid, run_id, detail="succeeded")
        assert late is (expected == "late")
        assert stages.stage_of(conn, pid) == (stages.RECORDED, "succeeded")


# ---------------------------------------------------------------------------
# whose result it is: the late transition carries the run id and checks it
# ---------------------------------------------------------------------------

def _two_unknown_proposals(world):
    """Two proposals of one engagement, each with its own run, both declared unknown by the
    reconciler (stage, dispatch state and run)."""
    eid = world["engagement_id"]
    go(world, key="key-a", target="10.82.0.5")
    go(world, key="key-b", target="10.82.0.6")
    _set(eid, "UPDATE action_proposals SET pipeline_stage = 'recorded', "
              "stage_detail = 'unknown_outcome', dispatch_state = 'unknown_outcome'")
    _set(eid, "UPDATE tool_runs SET status = 'unknown_outcome', exit_code = NULL")
    with engagement_scope(eid) as conn:
        rows = conn.execute(text(
            "SELECT proposal_id, run_id FROM tool_runs ORDER BY created_at")).all()
    assert len(rows) == 2 and rows[0][0] != rows[1][0]
    return rows[0], rows[1]


def test_a_late_result_moves_the_proposal_only_for_the_run_that_is_its_own(world):
    (pid_a, run_a), (pid_b, run_b) = _two_unknown_proposals(world)
    eid = world["engagement_id"]
    with engagement_scope(eid) as conn:
        # another proposal's run, although that run is unknown too: not this proposal's result
        with pytest.raises(stages.StageConflict) as caught:
            dispatch._take_result_stage(conn, pid_a, run_b, detail="succeeded")
        assert run_b in str(caught.value)
        # a run id that exists nowhere
        with pytest.raises(stages.StageConflict):
            dispatch._take_result_stage(conn, pid_a, "RUN-NO-SUCH-RUN", detail="succeeded")
    with engagement_scope(eid) as conn:
        assert stages.stage_of(conn, pid_a) == (stages.RECORDED, "unknown_outcome")
        assert stages.stage_of(conn, pid_b) == (stages.RECORDED, "unknown_outcome")
        # the run that is its own
        assert dispatch._take_result_stage(conn, pid_a, run_a, detail="succeeded") is True
        assert stages.stage_of(conn, pid_a) == (stages.RECORDED, "succeeded")
        assert stages.stage_of(conn, pid_b) == (stages.RECORDED, "unknown_outcome")


def test_a_late_result_for_a_run_that_is_not_itself_unknown_is_refused(world):
    (pid_a, run_a), _ = _two_unknown_proposals(world)
    eid = world["engagement_id"]
    _set(eid, "UPDATE tool_runs SET status = 'running' WHERE run_id = :r", r=run_a)
    with engagement_scope(eid) as conn:
        with pytest.raises(stages.StageConflict):
            dispatch._take_result_stage(conn, pid_a, run_a, detail="succeeded")
        assert stages.stage_of(conn, pid_a) == (stages.RECORDED, "unknown_outcome")


def test_finishing_a_run_can_be_made_conditional_on_its_proposal(world):
    """The second line of the same defence: even holding the right stage, a run row of another
    proposal is not rewritten."""
    (pid_a, run_a), (_, run_b) = _two_unknown_proposals(world)
    eid = world["engagement_id"]
    with engagement_scope(eid) as conn:
        assert dispatch._finish_run(
            conn, run_b, "succeeded", exit_code=0, only_if_status="unknown_outcome",
            of_proposal=pid_a) is False
        assert conn.execute(text("SELECT status FROM tool_runs WHERE run_id = :r"),
                            {"r": run_b}).scalar_one() == "unknown_outcome"
        assert dispatch._finish_run(
            conn, run_a, "succeeded", exit_code=0, only_if_status="unknown_outcome",
            of_proposal=pid_a) is True


def test_a_run_that_stopped_being_unknown_after_the_stage_check_is_still_not_overwritten(
    world, monkeypatch,
):
    """The stage move and the run update are two statements. The first now checks the run itself,
    but the second keeps its own condition, for the window between them: here the first is
    stubbed to say yes about a run that is in fact still ``running``."""
    eid = world["engagement_id"]

    def during(_kwargs):
        _set(eid, "UPDATE action_proposals SET pipeline_stage = 'recorded', "
                  "stage_detail = 'unknown_outcome', dispatch_state = 'unknown_outcome'")

    monkeypatch.setattr(dispatch, "_take_result_stage",
                        lambda conn, proposal_id, run_id, *, detail: True)
    outcome = go(world, sandbox=FakeSandbox(during=during))
    assert outcome.failure == dispatch.STAGE_MOVED
    final = _rows(eid)
    assert final["runs"] == [("running", None)] and final["evidence"] == 0
    assert "run.late_result" not in final["audit"] and "tool_run.succeeded" not in final["audit"]


def test_the_late_result_audit_record_names_the_run_and_the_proposal(world):
    eid = world["engagement_id"]
    outcome = go(world, sandbox=FakeSandbox(during=lambda _k: _reconcile(eid)))
    with engagement_scope(eid) as conn:
        rows = conn.execute(text(
            "SELECT subject_id, payload FROM audit_log WHERE event_type = 'run.late_result'"
        )).all()
        proposal_id = conn.execute(text("SELECT proposal_id FROM action_proposals")).scalar_one()
    assert len(rows) == 1
    subject, payload = rows[0]
    assert subject == outcome.run_id
    assert payload.get("run_id") == outcome.run_id and payload.get("proposal_id") == proposal_id
    assert payload["previous"] == "unknown_outcome" and payload["status"] == "succeeded"


# ---------------------------------------------------------------------------
# the other two record sites
# ---------------------------------------------------------------------------

def test_a_refusal_before_start_does_not_overwrite_a_proposal_someone_moved(world):
    eid = world["engagement_id"]

    def during(_kwargs):
        _set(eid, "UPDATE action_proposals SET pipeline_stage = 'closed', stage_detail = 'manual'")

    outcome = go(world, sandbox=FakeSandbox(during=during, error=ImageNotPresent("no such image")))
    assert outcome.failure == dispatch.STAGE_MOVED and not outcome.run_id
    final = _rows(eid)
    assert (final["proposal"]["stage"], final["proposal"]["detail"]) == (stages.CLOSED, "manual")
    assert final["runs"] == [("running", None)]
    assert "tool_run.refused" not in final["audit"]


def test_a_sandbox_failure_after_the_reconciler_marked_the_run_is_not_a_conflict(world):
    eid = world["engagement_id"]
    outcome = go(world, sandbox=FakeSandbox(
        during=lambda _k: _reconcile(eid), error=SandboxUnavailable("the daemon went away")))
    assert outcome.failure != dispatch.STAGE_MOVED
    final = _rows(eid)
    p = final["proposal"]
    assert (p["stage"], p["detail"], p["dispatch_state"]) == (
        stages.RECORDED, "unknown_outcome", "unknown_outcome")
    assert final["runs"] == [("unknown_outcome", None)]
    assert "run.late_result" not in final["audit"]
    assert_coherent(snapshot(eid))
