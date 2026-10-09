"""The scheduler, end to end (D62): an approved proposal is dispatched by a *tick*, nobody calls
``dispatch_approved`` by hand.

The story is the one D61 closed from the other side: ``create_engagement`` -> register scope ->
enroll -> propose -> HUMAN_APPROVAL -> a real ``grant_approval`` -> **tick** -> a real container
runs the tool -> evidence is written -> the audit trail is complete, from ``scheduler.dispatched``
to ``evidence.stored``. Everything after the approval is done by ``Scheduler.tick``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from control_plane.audit.query import reconstruct_decision
from control_plane.orchestrator import stages
from control_plane.scheduler import vocab
from control_plane.state.db import scheduler_reader_scope
from tests import scheduler_support as sup
from tests.helpers import committing_scope
from tests.test_pipeline_stages import FakeSandbox, assert_coherent, snapshot

CIDR = "10.96.62.0/24"
HOST = "10.96.62.9"


@pytest.fixture
def world(engagement_id, registry):
    """An engagement with a scope, a policy that lets a human decide, enrolled in the scheduler."""
    sup.publish_engagement_policy(engagement_id)
    scope_id = sup.register_scope(registry, type="cidr", value=CIDR)
    sup.enroll(engagement_id)
    yield {"engagement_id": engagement_id, "scope_id": scope_id}
    sup.withdraw(engagement_id)


def stage(eid, pid):
    with committing_scope(eid) as conn:
        return stages.stage_of(conn, pid)


def test_a_tick_dispatches_an_approved_proposal_and_a_real_container_runs_the_tool(world, capfd):
    eid = world["engagement_id"]
    proposal_id = sup.escalate(eid, sup.proposal_for(world["scope_id"], host=HOST))
    assert stage(eid, proposal_id) == (stages.AWAITING_APPROVAL, None)

    # waiting for a human: a tick has nothing to do, and says nothing about it
    with sup.running() as sched:
        quiet = sched.tick()
        assert (quiet.dispatched, quiet.skipped, quiet.deferred) == ([], [], [])
        assert sup.audit(eid, "scheduler.dispatched") == []

        approval = sup.approve(eid, proposal_id)
        assert approval.stage == stages.APPROVED

        report = sched.tick()          # the scheduler's real sandbox: DockerSandbox, nmap image

    assert report.dispatched == [proposal_id]
    assert stage(eid, proposal_id) == (stages.RECORDED, "succeeded")

    # the tool really ran: a run row, an exit code, an evidence row
    (run,) = sup.rows(eid, "SELECT run_id, status, exit_code, capability_id FROM tool_runs")
    assert (run["status"], run["exit_code"]) == ("succeeded", 0)
    (evidence,) = sup.rows(eid, "SELECT evidence_id, run_id FROM evidence")
    assert evidence["run_id"] == run["run_id"]
    (cap,) = sup.rows(eid, "SELECT capability_id, approval_id FROM capabilities")
    assert cap["capability_id"] == run["capability_id"]
    assert cap["approval_id"] == approval.approval_id

    # the scheduler's own record: one decision, before the pipeline's first event of the dispatch
    (decided,) = sup.audit(eid, "scheduler.dispatched")
    assert decided["actor"] == "scheduler" and decided["subject_id"] == proposal_id
    assert decided["payload"] == {"proposal_id": proposal_id,
                                  "reason_code": vocab.APPROVED_AND_IDLE}
    issued = sup.audit(eid, "capability.issued")
    assert issued and decided["audit_id"] < issued[0]["audit_id"]

    # the pipeline's events are all there, in order, and reconstruct_decision sees the whole story
    with committing_scope(eid) as conn:
        chain = reconstruct_decision(conn, proposal_id=proposal_id)
    kinds = [e.event_type for e in chain.events]
    for earlier, later in [
        ("proposal.submitted", "policy.decided"),
        ("policy.decided", "approval.granted"),
        ("approval.granted", "scheduler.dispatched"),
        ("scheduler.dispatched", "capability.issued"),
        ("capability.issued", "tool_run.started"),
    ]:
        assert earlier in kinds and later in kinds, kinds
        assert kinds.index(earlier) < kinds.index(later), kinds
    assert chain.executed and chain.decision == "HUMAN_APPROVAL", chain
    assert {"decision", "capability", "execution"} <= set(chain.reached_stages)
    assert chain.capability_ids and chain.run_ids and chain.evidence_ids
    assert kinds.count("scheduler.dispatched") == 1
    assert "evidence.recorded" in kinds and "tool_run.succeeded" in kinds, kinds
    assert_coherent(snapshot(eid))

    # a further tick finds nothing left to do and does not run the tool again
    with sup.running() as sched:
        again = sched.tick()
    assert again.dispatched == []
    assert len(sup.rows(eid, "SELECT 1 FROM tool_runs")) == 1


def test_an_engagement_that_is_not_enrolled_is_never_touched(engagement_id, registry):
    """Same approved proposal, no enrollment: nothing happens, however many ticks pass."""
    sup.publish_engagement_policy(engagement_id)
    scope_id = sup.register_scope(registry, type="cidr", value=CIDR)
    proposal_id = sup.approved_proposal(engagement_id, scope_id, host=HOST)
    sandbox = FakeSandbox()

    with sup.running(sandbox) as sched:
        for _ in range(3):
            report = sched.tick()
            assert (report.dispatched, report.skipped, report.deferred) == ([], [], [])

    assert sandbox.calls == 0
    assert stage(engagement_id, proposal_id)[0] == stages.APPROVED
    assert sup.audit(engagement_id, "scheduler.dispatched", "scheduler.skipped",
                     "scheduler.deferred") == []
    assert sup.rows(engagement_id, "SELECT 1 FROM capabilities") == []


def test_withdrawing_an_enrollment_takes_effect_on_the_next_tick(world):
    eid = world["engagement_id"]
    pid = sup.approved_proposal(eid, world["scope_id"], host=HOST)
    sandbox = FakeSandbox()
    with sup.running(sandbox) as sched:
        sup.withdraw(eid)
        assert sched.tick().dispatched == []
    assert sandbox.calls == 0 and stage(eid, pid)[0] == stages.APPROVED


# ---------------------------------------------------------------------------------------------
# pause / kill: deferred once, resumed once -- edges, not a per-tick stream
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("stop,reason", [
    (sup.pause, "engagement_paused"),
    (sup.kill, "engagement_killed"),
])
def test_a_paused_or_killed_engagement_is_deferred_once_not_per_tick(world, stop, reason):
    eid = world["engagement_id"]
    pid = sup.approved_proposal(eid, world["scope_id"], host=HOST)
    sandbox = FakeSandbox()
    stop(eid)

    with sup.running(sandbox) as sched:
        reports = [sched.tick() for _ in range(5)]

    assert [r.deferred for r in reports] == [[eid], [], [], [], []]
    assert all(r.dispatched == [] for r in reports)
    assert sandbox.calls == 0
    assert stage(eid, pid)[0] == stages.APPROVED          # deferred, not refused: still waiting
    (event,) = sup.audit(eid, "scheduler.deferred")
    assert event["payload"] == {"reason_code": reason, "waiting_count": 1}
    assert sup.rows(eid, "SELECT 1 FROM tool_runs") == []


def test_a_resumed_engagement_is_dispatched_and_the_resumption_is_recorded_once(world):
    eid = world["engagement_id"]
    pid = sup.approved_proposal(eid, world["scope_id"], host=HOST)
    sup.pause(eid)
    sandbox = FakeSandbox()

    with sup.running(sandbox) as sched:
        assert sched.tick().deferred == [eid]
        sup.resume(eid)
        report = sched.tick()
        assert (report.resumed, report.dispatched) == ([eid], [pid])
        assert sched.tick().resumed == []

    assert sandbox.calls == 1
    (resumed,) = sup.audit(eid, "scheduler.resumed")
    assert resumed["payload"]["waiting_count"] == 1
    with scheduler_reader_scope(eid) as conn:
        (state,) = conn.execute(text(
            "SELECT disposition, reason_code FROM scheduler_state "
            "WHERE proposal_id IS NULL")).all()
    assert tuple(state) == (vocab.SERVED, None)
