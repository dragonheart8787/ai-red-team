"""Just-in-time capability issuance for approved proposals (D58-8, D61).

The gap this closes: ``grant_approval`` wrote an ``approvals`` row and issued a 60-second
capability, then returned -- and nothing in ``control_plane/`` or ``agents/`` ever dispatched it.
A capability's lease is anchored to the transaction that issues it (D58), so a capability issued at
grant time had spent its lease on the human's latency before anything could use it. One cause for
both: it was issued when the decision was made, not when it was used.

What these tests establish:

* **The gap is closed end to end.** A proposal triggers HUMAN_APPROVAL, a human approves it, and
  afterwards a tool really executes, its evidence is written and the audit trail is complete --
  driven through the real entry points, the tool run by a real container in one test.
* **The capability is not born expired.** The D58 scenario (3 s TTL, 4 s of waiting) is reproduced
  on the approval path, and the capability is shown to be issued *after* the wait, with its lease
  anchored there.
* **Everything is checked at the moment of use**, not at the grant: kill switch, engagement
  status, approval validity, scope object, and the policy version the decision was made under.
* **The "approved, awaiting dispatch" state is committed state**, queryable, and carries what a
  reconciler (D58-9) needs to recognise an approved proposal that has waited too long.
* **One stage-commit logic.** The post-approval path takes the same stage transitions through the
  same functions as an ALLOW; it has no transaction handling of its own.
* **ad.collect**: the credential path's incompatibility with HUMAN_APPROVAL is *unchanged* by JIT
  (D58 report §5) -- pinned here so that a later change to it is a deliberate one.

Each guard has a mutation test at the bottom that puts it back the old way and requires the suite to
go red.
"""

from __future__ import annotations

import inspect
import threading
import time
import uuid

import pytest
from sqlalchemy import text

import control_plane.orchestrator.dispatch as dispatch_module
from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api import approved_dispatch, function_api
from control_plane.api.approvals import (
    ApprovalError,
    deny_approval,
    grant_approval,
    list_pending_approvals,
)
from control_plane.api.approved_dispatch import dispatch_approved, list_approved_awaiting_dispatch
from control_plane.api.function_api import propose_action
from control_plane.capability.broker import (
    APPROVAL_EXPIRED,
    ENGAGEMENT_NOT_ACTIVE,
    KILL_SWITCH,
    POLICY_CHANGED,
    SCOPE_OBJECT_DEACTIVATED,
)
from control_plane.orchestrator import stages
from control_plane.orchestrator.engagement import engage_kill_switch, pause_engagement
from control_plane.policy.layers import publish_policy_layer
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.registry.scope_registry import deactivate_scope_object
from control_plane.state.db import registry_admin_scope
from tests.helpers import committing_scope as engagement_scope
from tests.test_pipeline_stages import FakeSandbox, assert_coherent, snapshot

CIDR = "10.61.0.0/24"
HOST = "10.61.0.5"


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII", "customer_database"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id}


def _proposal(world, *, ports="443", scan_type="version", ttl=60, host=HOST):
    return ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": host},
                "ports": ports, "scan_type": scan_type},
        authorization={"source": "engagement_scope", "scope_object_id": world["scope_id"]},
        discovery={"source": "explicit_scope"},
        requested_capability_ttl_seconds=ttl,
    )


def escalate(world, *, proposal=None, key=None):
    """A proposal OPA sends to a human (a reviewer that names sensitive data, D11 Case D)."""
    outcome = propose_action(
        engagement_id=world["engagement_id"], proposal=proposal or _proposal(world),
        reviewer=HonestFakeReviewer(sensitive_hint=("pii",)), policy=_policy(),
        agent_id="worker-1", idempotency_key=key,
    )
    assert outcome.decision == "HUMAN_APPROVAL", outcome
    return outcome.proposal_id


def approve(world, proposal_id, *, approver="alice", scope="this_proposal_only", seconds=3600):
    with engagement_scope(world["engagement_id"]) as conn:
        return grant_approval(
            conn, engagement_id=world["engagement_id"], proposal_id=proposal_id,
            approver=approver, approved_scope=scope, valid_for_seconds=seconds,
        )


def dispatch(world, proposal_id, sandbox=None, **kwargs):
    return dispatch_approved(
        engagement_id=world["engagement_id"], proposal_id=proposal_id,
        sandbox=sandbox if sandbox is not None else FakeSandbox(), network_allowlist=[CIDR],
        **kwargs,
    )


def stage(world, proposal_id):
    with engagement_scope(world["engagement_id"]) as conn:
        return stages.stage_of(conn, proposal_id)


def rows(world, sql, **params):
    with engagement_scope(world["engagement_id"]) as conn:
        return [dict(r) for r in conn.execute(text(sql), params).mappings()]


# ---------------------------------------------------------------------------
# 1. The gap, closed end to end
# ---------------------------------------------------------------------------

def _audit_kinds(world, *subject_ids):
    out = []
    with engagement_scope(world["engagement_id"]) as conn:
        for row in conn.execute(
            text("SELECT audit_id, event_type, actor, subject_id, payload FROM audit_log "
                 "WHERE subject_id = ANY(:ids) ORDER BY audit_id"),
            {"ids": list(subject_ids)},
        ).mappings():
            out.append(dict(row))
    return out


def test_an_approved_proposal_runs_a_tool_writes_evidence_and_leaves_a_complete_trail(world):
    """The functional gap, as one story: propose -> HUMAN_APPROVAL -> approve -> a tool runs.

    Before D61 the last step did not exist: the only thing that happened after the approval was a
    capability ageing out of its lease.
    """
    eid = world["engagement_id"]
    proposal_id = escalate(world, proposal=_proposal(world, ports="443", scan_type="version"))

    # --- waiting for a human ---------------------------------------------------------------
    assert stage(world, proposal_id) == (stages.AWAITING_APPROVAL, None)
    with engagement_scope(eid) as conn:
        assert [p["proposal_id"] for p in list_pending_approvals(
            conn, engagement_id=eid)] == [proposal_id]
        assert list_approved_awaiting_dispatch(conn, engagement_id=eid) == []

    # --- the human approves: a fact is recorded, nothing is issued -------------------------
    approval = approve(world, proposal_id)
    assert approval.stage == stages.APPROVED
    assert stage(world, proposal_id) == (stages.APPROVED, approval.approval_id)
    assert rows(world, "SELECT count(*) AS n FROM capabilities")[0]["n"] == 0
    with engagement_scope(eid) as conn:
        assert list_pending_approvals(conn, engagement_id=eid) == []
        waiting = list_approved_awaiting_dispatch(conn, engagement_id=eid)
    assert [w["proposal_id"] for w in waiting] == [proposal_id]
    assert waiting[0]["approval_id"] == approval.approval_id
    assert waiting[0]["approved_by"] == "alice" and waiting[0]["approval_live"] is True

    # --- dispatch: the capability is issued now, and the tool runs ------------------------
    sandbox = FakeSandbox()
    out = dispatch(world, proposal_id, sandbox)
    assert out.failure is None, out.failure
    assert out.executed and out.run_id and out.evidence_id and out.capability_id
    assert sandbox.calls == 1
    assert stage(world, proposal_id) == (stages.RECORDED, "succeeded")

    # what ran is what the human was shown: ports and scan type survive the round trip
    (cap,) = rows(world, "SELECT * FROM capabilities")
    assert cap["capability_id"] == out.capability_id
    assert cap["approval_id"] == approval.approval_id
    assert cap["constraints"]["ports"] == "443" and cap["constraints"]["scan_type"] == "version"
    (approval_row,) = rows(world, "SELECT constraints, resource FROM approvals")
    assert {k: v for k, v in cap["constraints"].items() if k != "host"} == \
        approval_row["constraints"]

    # --- evidence ------------------------------------------------------------------------------
    (run,) = rows(world, "SELECT run_id, status, capability_id, exit_code FROM tool_runs")
    assert (run["status"], run["capability_id"], run["exit_code"]) == (
        "succeeded", out.capability_id, 0)
    (evidence,) = rows(world, "SELECT evidence_id, run_id FROM evidence")
    assert evidence["run_id"] == run["run_id"] == out.run_id

    # --- the audit trail, in order, naming the approval ---------------------------------------
    trail = _audit_kinds(world, proposal_id, out.capability_id, out.run_id)
    kinds = [e["event_type"] for e in trail]
    for earlier, later in [
        ("proposal.submitted", "policy.decided"),
        ("policy.decided", "approval.granted"),
        ("approval.granted", "capability.issued"),
        ("capability.issued", "tool_run.started"),
    ]:
        assert earlier in kinds and later in kinds, kinds
        assert kinds.index(earlier) < kinds.index(later), kinds
    assert kinds.count("approval.granted") == 1 and kinds.count("capability.issued") == 1
    granted = next(e for e in trail if e["event_type"] == "approval.granted")
    issued = next(e for e in trail if e["event_type"] == "capability.issued")
    assert granted["actor"] == "alice"
    assert issued["payload"]["approval_id"] == approval.approval_id
    decided = next(e for e in trail if e["event_type"] == "policy.decided")
    assert decided["payload"]["reviewer_opinion"]["possible_sensitive_data_hint"] == ["pii"]

    # --- provenance: the finished proposal's graph is written from committed rows ------------
    (p,) = rows(world, "SELECT provenance_complete FROM action_proposals")
    assert p["provenance_complete"] is True
    edges = {(r["from_type"], r["to_type"], r["relation"]) for r in rows(
        world, "SELECT from_type, to_type, relation FROM provenance_edges")}
    assert {
        ("scope_object", "action_proposal", "authorized"),
        ("action_proposal", "capability", "issued"),
        ("capability", "tool_run", "executed"),
        ("tool_run", "evidence", "produced"),
    } <= edges, edges

    # --- and nothing waits any more -------------------------------------------------------------
    with engagement_scope(eid) as conn:
        assert list_approved_awaiting_dispatch(conn, engagement_id=eid) == []
    assert_coherent(snapshot(eid))


def test_the_same_story_with_a_real_container(engagement_id, registry):
    """The tool is run by a real container, not a stand-in: network.scan under DockerSandbox.

    A host that does not exist answers nothing; nmap still runs and reports it. What is established
    is that the approval path reaches the *real* dispatch -- an image, a network, a run row, an
    evidence row -- not that the scan found anything.
    """
    cidr = "10.96.61.0/24"
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=cidr,
                   allowed_actions=["network.scan"])
    world = {"engagement_id": engagement_id, "scope_id": scope_id}
    proposal_id = escalate(world, proposal=_proposal(
        world, ports="8080", scan_type="connect", host="10.96.61.9"))
    approve(world, proposal_id)

    out = dispatch_approved(engagement_id=engagement_id, proposal_id=proposal_id,
                            sandbox=None, network_allowlist=[cidr])

    assert out.run_id and out.evidence_id, out.failure
    (run,) = rows(world, "SELECT status, exit_code FROM tool_runs")
    assert run["status"] == "succeeded" and run["exit_code"] == 0
    assert stage(world, proposal_id) == (stages.RECORDED, "succeeded")
    (ev,) = rows(world, "SELECT evidence_id FROM evidence")
    assert ev["evidence_id"] == out.evidence_id


# ---------------------------------------------------------------------------
# 2. Not born expired (D58: 3 s TTL + a 4 s wait)
# ---------------------------------------------------------------------------

def test_a_three_second_capability_is_not_born_expired_after_a_four_second_wait(world):
    """The D58 scenario on the approval path.

    A proposal asks for a 3-second capability. The human takes 4 seconds to be done and for
    something to dispatch it. If the capability were issued at the grant, its lease -- anchored to
    that moment -- would end 1 second before the tool could start. Issued at dispatch, the lease
    starts when the tool does.
    """
    proposal_id = escalate(world, proposal=_proposal(world, ttl=3))
    approval = approve(world, proposal_id)
    waited_from = time.monotonic()
    time.sleep(4)
    waited = time.monotonic() - waited_from
    assert waited >= 4

    sandbox = FakeSandbox()
    out = dispatch(world, proposal_id, sandbox)
    assert out.failure is None and sandbox.calls == 1, out.failure

    (row,) = rows(world, """
        SELECT c.issued_at, c.lease_expires_at, r.started_at,
               a.created_at AS approved_at,
               EXTRACT(EPOCH FROM (c.lease_expires_at - c.issued_at)) AS lease_seconds
        FROM capabilities c
        JOIN tool_runs r ON r.capability_id = c.capability_id
        JOIN approvals a ON a.approval_id = c.approval_id
    """)
    # An independent witness: the database's own clock, not the test's.
    assert (row["issued_at"] - row["approved_at"]).total_seconds() >= 3.9, (
        "the capability was issued at the grant, not at dispatch")
    assert row["lease_seconds"] == pytest.approx(3, abs=0.01)
    # The lease started at dispatch time and the run started inside it ...
    assert row["issued_at"] <= row["started_at"] <= row["lease_expires_at"]
    # ... whereas a lease anchored to the grant (what the old path issued) would already be over:
    assert (row["approved_at"].timestamp() + 3) < row["started_at"].timestamp()
    assert approval.approval_id


def test_the_issue_to_dispatch_window_is_close_to_zero(world):
    """W1 (D58): the time between the capability's lease start and the run starting.

    The approval is allowed to wait 3 seconds first, so a window measured from the grant would be
    at least that. Measured from the JIT issue it is the length of one stage hand-off.
    """
    proposal_id = escalate(world)
    approve(world, proposal_id)
    time.sleep(3)
    out = dispatch(world, proposal_id)
    assert out.executed
    (row,) = rows(world, """
        SELECT EXTRACT(EPOCH FROM (r.started_at - c.issued_at)) AS w1,
               EXTRACT(EPOCH FROM (c.issued_at - a.created_at)) AS grant_to_issue
        FROM capabilities c JOIN tool_runs r ON r.capability_id = c.capability_id
        JOIN approvals a ON a.approval_id = c.approval_id
    """)
    assert 0 <= row["w1"] < 1.0, row
    assert row["grant_to_issue"] >= 2.9, row


# ---------------------------------------------------------------------------
# 3. Checked at the moment of use
# ---------------------------------------------------------------------------

def _refused(world, proposal_id, sandbox, out, reason):
    assert out.decision == "DENY" and out.failure == "capability_refused", out
    assert reason in out.deny_reasons, out.deny_reasons
    assert sandbox.calls == 0
    s, detail = stage(world, proposal_id)
    assert s == stages.CLOSED and detail.startswith("capability_refused:") and reason in detail
    snap = snapshot(world["engagement_id"])
    assert snap["capabilities"] == 0 and snap["runs"] == []
    assert_coherent(snap)


def test_a_kill_switch_engaged_after_the_approval_stops_the_dispatch(world):
    proposal_id = escalate(world)
    approve(world, proposal_id)
    with engagement_scope(world["engagement_id"]) as conn:
        engage_kill_switch(conn, engagement_id=world["engagement_id"], actor="operator",
                           reason="d61 test")
    sandbox = FakeSandbox()
    _refused(world, proposal_id, sandbox, dispatch(world, proposal_id, sandbox), KILL_SWITCH)


def test_a_paused_engagement_stops_the_dispatch(world):
    proposal_id = escalate(world)
    approve(world, proposal_id)
    with engagement_scope(world["engagement_id"]) as conn:
        pause_engagement(conn, engagement_id=world["engagement_id"], actor="operator",
                         reason="d61 test")
    sandbox = FakeSandbox()
    _refused(world, proposal_id, sandbox, dispatch(world, proposal_id, sandbox),
             ENGAGEMENT_NOT_ACTIVE)


def test_an_approval_that_expired_while_waiting_does_not_back_the_dispatch(world):
    """§4.7: an approval granted earlier must not back today's action. Nothing issued at grant time
    could have noticed this; the broker, asked at dispatch, does."""
    proposal_id = escalate(world)
    approve(world, proposal_id, seconds=1)
    time.sleep(2)
    with engagement_scope(world["engagement_id"]) as conn:
        (waiting,) = list_approved_awaiting_dispatch(conn, engagement_id=world["engagement_id"])
    assert waiting["approval_live"] is False, "the queue must say the approval has lapsed"
    sandbox = FakeSandbox()
    _refused(world, proposal_id, sandbox, dispatch(world, proposal_id, sandbox),
             APPROVAL_EXPIRED)


def test_a_scope_object_withdrawn_after_the_approval_stops_the_dispatch(world):
    proposal_id = escalate(world)
    approve(world, proposal_id)
    with registry_admin_scope(world["engagement_id"]) as conn:
        deactivate_scope_object(conn, engagement_id=world["engagement_id"],
                                scope_object_id=world["scope_id"], actor="em")
    sandbox = FakeSandbox()
    _refused(world, proposal_id, sandbox, dispatch(world, proposal_id, sandbox),
             SCOPE_OBJECT_DEACTIVATED)


def test_a_policy_published_after_the_decision_invalidates_the_approval(world):
    """I9: a human approved *that* decision, under *that* policy. If the policy moved, the
    operator re-proposes; the old approval does not quietly carry over."""
    proposal_id = escalate(world)
    approve(world, proposal_id)
    with engagement_scope(world["engagement_id"]) as conn:
        publish_policy_layer(
            conn, engagement_id=world["engagement_id"], layer="engagement", version=1,
            document={"actions": {"network.scan": "ALLOW"}}, actor="policy-admin",
            scoped_to_engagement=True,
        )
    sandbox = FakeSandbox()
    _refused(world, proposal_id, sandbox, dispatch(world, proposal_id, sandbox),
             POLICY_CHANGED)


def test_a_policy_in_force_at_the_decision_does_not_block_the_dispatch(world):
    """The control for the test above: the version is *compared*, not required to be zero."""
    with engagement_scope(world["engagement_id"]) as conn:
        publish_policy_layer(
            conn, engagement_id=world["engagement_id"], layer="engagement", version=1,
            document={"actions": {"network.scan": "ALLOW"}}, actor="policy-admin",
            scoped_to_engagement=True,
        )
    proposal_id = escalate(world)
    assert rows(world, "SELECT decided_policy_version FROM action_proposals")[0][
        "decided_policy_version"] is not None
    approve(world, proposal_id)
    out = dispatch(world, proposal_id)
    assert out.executed, out.failure


# ---------------------------------------------------------------------------
# 4. The "approved, awaiting dispatch" state
# ---------------------------------------------------------------------------

def test_a_waiting_proposal_can_be_found_by_how_long_it_has_waited(world):
    """The interface D58-9's reconciler reads: committed state plus an age, and a way to tell an
    approval that is still good from one that has lapsed. Nothing here decides anything."""
    old = escalate(world)
    approve(world, old)
    time.sleep(2)
    young = escalate(world, proposal=_proposal(world, ports="22"))
    approve(world, young)
    eid = world["engagement_id"]
    with engagement_scope(eid) as conn:
        everything = list_approved_awaiting_dispatch(conn, engagement_id=eid)
        stuck = list_approved_awaiting_dispatch(conn, engagement_id=eid, older_than_seconds=1.5)
    assert [r["proposal_id"] for r in everything] == [old, young]
    assert [r["proposal_id"] for r in stuck] == [old]
    assert stuck[0]["waiting_seconds"] >= 1.5 > everything[1]["waiting_seconds"]


def test_only_approved_proposals_are_listed_and_only_those_of_this_engagement(
    world, engagement_factory
):
    pending = escalate(world)                                  # awaiting_approval
    approved = escalate(world, proposal=_proposal(world, ports="22"))
    approve(world, approved)
    denied = escalate(world, proposal=_proposal(world, ports="23"))
    with engagement_scope(world["engagement_id"]) as conn:
        deny_approval(conn, engagement_id=world["engagement_id"], proposal_id=denied,
                      denier="alice", reason="no")
    other_eid, other_registry = engagement_factory()
    other_scope = f"SCOPE-{uuid.uuid4().hex[:8]}"
    other_registry.scope(scope_object_id=other_scope, type="cidr", value=CIDR,
                         allowed_actions=["network.scan"])
    other = {"engagement_id": other_eid, "scope_id": other_scope}
    other_proposal = escalate(other)
    approve(other, other_proposal)

    with engagement_scope(world["engagement_id"]) as conn:
        listed = [r["proposal_id"] for r in list_approved_awaiting_dispatch(
            conn, engagement_id=world["engagement_id"])]
    assert listed == [approved]
    assert pending not in listed and denied not in listed and other_proposal not in listed


def test_an_attempt_that_failed_before_it_committed_leaves_the_proposal_waiting_and_retryable(
    world, monkeypatch
):
    """A dispatch attempt that dies inside the issue stage rolls that stage back: the proposal is
    still ``approved``, still listed, and the next attempt dispatches it. This is the
    "attempt failed" half of what D58-9 must be able to recognise -- it reads as *waiting*."""
    proposal_id = escalate(world)
    approve(world, proposal_id)
    real = function_api.issue_capability

    def broken(*args, **kwargs):
        raise RuntimeError("the database went away mid-issue")

    monkeypatch.setattr(function_api, "issue_capability", broken)
    with pytest.raises(RuntimeError):
        dispatch(world, proposal_id)
    monkeypatch.setattr(function_api, "issue_capability", real)

    assert stage(world, proposal_id)[0] == stages.APPROVED
    snap = snapshot(world["engagement_id"])
    assert snap["capabilities"] == 0 and snap["runs"] == []
    assert_coherent(snap)
    with engagement_scope(world["engagement_id"]) as conn:
        assert [r["proposal_id"] for r in list_approved_awaiting_dispatch(
            conn, engagement_id=world["engagement_id"])] == [proposal_id]

    out = dispatch(world, proposal_id)
    assert out.executed, out.failure
    assert stage(world, proposal_id) == (stages.RECORDED, "succeeded")


def test_a_second_dispatch_reports_the_first_and_runs_nothing(world):
    proposal_id = escalate(world)
    approve(world, proposal_id)
    sandbox = FakeSandbox()
    first = dispatch(world, proposal_id, sandbox)
    second = dispatch(world, proposal_id, sandbox)
    assert sandbox.calls == 1
    assert second.run_id == first.run_id and second.capability_id == first.capability_id
    assert len(rows(world, "SELECT 1 FROM capabilities")) == 1


def test_two_dispatchers_at_once_run_the_tool_once(world):
    """Two workers pick up the same approved proposal. The conditional UPDATE that takes
    ``approved -> capability_issued`` lets exactly one of them issue; the other reloads the
    stage and reports."""
    proposal_id = escalate(world)
    approve(world, proposal_id)
    sandbox = FakeSandbox(during=lambda _k: time.sleep(0.3))
    outcomes: list = []
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()
        outcomes.append(dispatch(world, proposal_id, sandbox))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sandbox.calls == 1, "the tool ran twice"
    assert len(rows(world, "SELECT 1 FROM capabilities")) == 1
    assert len(rows(world, "SELECT 1 FROM tool_runs")) == 1
    assert len(outcomes) == 2
    assert_coherent(snapshot(world["engagement_id"]))


# ---------------------------------------------------------------------------
# 5. What dispatch_approved will not do
# ---------------------------------------------------------------------------

def test_a_proposal_nobody_approved_is_not_dispatched(world):
    proposal_id = escalate(world)
    sandbox = FakeSandbox()
    out = dispatch(world, proposal_id, sandbox)
    assert out.decision == "HUMAN_APPROVAL" and out.failure == "not_approved"
    assert sandbox.calls == 0 and snapshot(world["engagement_id"])["capabilities"] == 0
    assert stage(world, proposal_id) == (stages.AWAITING_APPROVAL, None)


def test_a_denied_proposal_is_not_dispatched_and_is_closed(world):
    proposal_id = escalate(world)
    with engagement_scope(world["engagement_id"]) as conn:
        deny_approval(conn, engagement_id=world["engagement_id"], proposal_id=proposal_id,
                      denier="alice", reason="out of window")
    sandbox = FakeSandbox()
    out = dispatch(world, proposal_id, sandbox)
    assert sandbox.calls == 0 and out.failure == "approval_denied"
    assert stage(world, proposal_id) == (stages.CLOSED, "approval_denied")
    assert snapshot(world["engagement_id"])["capabilities"] == 0


def test_an_unknown_or_foreign_proposal_is_refused(world, engagement_factory):
    other_eid, other_registry = engagement_factory()
    other_scope = f"SCOPE-{uuid.uuid4().hex[:8]}"
    other_registry.scope(scope_object_id=other_scope, type="cidr", value=CIDR,
                         allowed_actions=["network.scan"])
    foreign = escalate({"engagement_id": other_eid, "scope_id": other_scope})
    approve({"engagement_id": other_eid}, foreign)
    sandbox = FakeSandbox()
    for pid in ("PROP-doesnotexist", foreign):
        out = dispatch(world, pid, sandbox)
        assert out.failure == "unknown_proposal" and sandbox.calls == 0
    assert stage({"engagement_id": other_eid}, foreign)[0] == stages.APPROVED


def test_asking_propose_action_again_does_not_dispatch_an_approved_proposal(world):
    """Dispatching an approved proposal is its own explicit call, never a side effect of a retry."""
    proposal_id = escalate(world, key="retry-me")
    approve(world, proposal_id)
    sandbox = FakeSandbox()
    again = propose_action(
        engagement_id=world["engagement_id"], proposal=_proposal(world),
        reviewer=HonestFakeReviewer(sensitive_hint=("pii",)), policy=_policy(),
        agent_id="worker-1", sandbox=sandbox, network_allowlist=[CIDR],
        idempotency_key="retry-me",
    )
    assert again.proposal_id == proposal_id and again.decision == "HUMAN_APPROVAL"
    assert sandbox.calls == 0
    assert stage(world, proposal_id)[0] == stages.APPROVED
    assert snapshot(world["engagement_id"])["capabilities"] == 0


def test_two_approvers_cannot_both_win(world):
    proposal_id = escalate(world)
    approve(world, proposal_id, approver="alice")
    with pytest.raises(ApprovalError):
        approve(world, proposal_id, approver="bob")
    assert len(rows(world, "SELECT 1 FROM approvals")) == 1


# ---------------------------------------------------------------------------
# 6. One stage-commit logic
# ---------------------------------------------------------------------------

def _transitions(monkeypatch):
    seen: list[tuple] = []
    real = stages.advance

    def spy(conn, proposal_id, *, expected, new, detail=None):
        won = real(conn, proposal_id, expected=expected, new=new, detail=detail)
        seen.append((tuple([expected] if isinstance(expected, str) else expected), new, won))
        return won

    monkeypatch.setattr(stages, "advance", spy)
    return seen


def test_the_approval_path_takes_the_same_transitions_through_the_same_functions(
    world, engagement_factory, monkeypatch
):
    """An ALLOW and an approved proposal walk the same stages after the point they diverge, using
    the very same ``_issue``/``_dispatch`` -- checked by recording every conditional UPDATE."""
    transitions = _transitions(monkeypatch)
    # ALLOW
    allowed = propose_action(
        engagement_id=world["engagement_id"], proposal=_proposal(world),
        reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="worker-1",
        sandbox=FakeSandbox(), network_allowlist=[CIDR],
    )
    assert allowed.executed
    allow_run = list(transitions)
    # the approval path (on a second engagement, so the two runs cannot interfere)
    other_eid, other_registry = engagement_factory()
    other_scope = f"SCOPE-{uuid.uuid4().hex[:8]}"
    other_registry.scope(scope_object_id=other_scope, type="cidr", value=CIDR,
                         allowed_actions=["network.scan"])
    other = {"engagement_id": other_eid, "scope_id": other_scope}
    proposal_id = escalate(other)
    approve(other, proposal_id)
    before_dispatch = len(transitions)
    assert dispatch(other, proposal_id).executed
    approval_run = transitions[before_dispatch:]

    def after_the_decision(ts):
        """(from, to) of every transition at and after the capability is issued."""
        i = next(n for n, t in enumerate(ts) if t[1] == stages.CAPABILITY_ISSUED)
        return ts[i], [(new, won) for _exp, new, won in ts[i:]]

    (allow_issue, allow_tail) = after_the_decision(allow_run)
    (approval_issue, approval_tail) = after_the_decision(approval_run)
    # after the decision the two walk the same stages, each transition won by its caller ...
    assert allow_tail == approval_tail == [
        (stages.CAPABILITY_ISSUED, True), (stages.DISPATCHING, True), (stages.RECORDED, True),
    ]
    # ... and the issuing transition differs in exactly one thing: where it comes from
    assert allow_issue[0] == (stages.DECIDED,)
    assert approval_issue[0] == (stages.APPROVED,)
    # a hand-written caller's dispatch boundary (BEFORE_DISPATCH) does not admit an approved
    # proposal: it can reach dispatching only by being issued first
    assert stages.APPROVED not in stages.BEFORE_DISPATCH
    assert stages.AWAITING_APPROVAL not in stages.BEFORE_DISPATCH


def test_dispatch_approved_has_no_transaction_handling_of_its_own():
    """Structure, not behaviour: the post-approval path drives ``function_api._drive``; it writes
    nothing itself, so there is no second commit logic to drift from the first."""
    source = inspect.getsource(approved_dispatch.dispatch_approved)
    assert "fa._drive(" in source
    for forbidden in ("INSERT INTO", "UPDATE action_proposals", "DELETE FROM", "commit(",
                      ".begin(", "stages.take", "stages.advance", "issue_capability",
                      "record_audit"):
        assert forbidden not in source, f"dispatch_approved does {forbidden!r} itself"
    # the module's only SQL is the read-only listing and the read of the proposal row
    module_source = inspect.getsource(approved_dispatch)
    for forbidden in ("INSERT INTO", "DELETE FROM", "UPDATE action_proposals", "commit(",
                      ".begin("):
        assert forbidden not in module_source, forbidden
    # one issuing stage for both entry points
    issue_source = inspect.getsource(function_api._issue)
    assert "stages.APPROVED" in issue_source and "stages.DECIDED" in issue_source
    assert function_api._drive.__module__ == "control_plane.api.function_api"


# ---------------------------------------------------------------------------
# 7. ad.collect: the credential path is unchanged by JIT (D58 report §5)
# ---------------------------------------------------------------------------

def test_ad_collect_after_approval_is_still_refused_because_the_capability_has_no_credential(
    engagement_id, monkeypatch
):
    """JIT moves *when* the capability is issued, not *what* it carries. An approval names no
    credential, so the approved capability has none, and ``dispatch_collection`` refuses an
    ``ad.collect`` without one (D50 F1). The incompatibility D58 found is therefore still there.

    Pinned, with the control beside it (the same proposal through ``propose_action`` *with* a
    credential runs), so that the day D58-15 gives approved proposals a credential this test fails
    for the right reason and is rewritten, not deleted.
    """
    from tests import test_ad_collection_e2e as ad

    ad._RecordingDockerSandbox.instances.clear()
    monkeypatch.setattr(dispatch_module, "DockerSandbox", ad._RecordingDockerSandbox)
    scope_object_id = ad._setup(engagement_id)
    credential_id = ad._store_credential(engagement_id)
    proposal = ad._proposal(scope_object_id, credential_username="svc-account")

    # HUMAN_APPROVAL for an ad.collect, by the same reviewer-hint route as everything else here
    outcome = propose_action(
        engagement_id=engagement_id, proposal=proposal,
        reviewer=HonestFakeReviewer(sensitive_hint=("pii",)), policy=ad._policy(),
        agent_id="test-worker", credential_id=credential_id,
    )
    assert outcome.decision == "HUMAN_APPROVAL", outcome
    # a credential handed to the escalated *call* is not carried to the approval: nothing stores it
    approve({"engagement_id": engagement_id}, outcome.proposal_id)

    out = dispatch_approved(
        engagement_id=engagement_id, proposal_id=outcome.proposal_id,
        network_allowlist=["10.0.0.0/8"],
    )

    assert out.capability_id is not None, "the capability itself is issued"
    assert out.run_id is None and out.failure == dispatch_module.UNBUILDABLE_PLAN
    assert ad._RecordingDockerSandbox.instances == [], "refused before any container exists"
    with ad.engagement_scope(engagement_id) as conn:
        cap = conn.execute(
            text("SELECT credential_id, approval_id FROM capabilities WHERE capability_id = :c"),
            {"c": out.capability_id}).mappings().one()
    assert cap["credential_id"] is None and cap["approval_id"] is not None
