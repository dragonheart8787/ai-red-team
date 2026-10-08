"""propose_action as stages that each commit (D58-5, D60).

Until D60 the whole pipeline was one database transaction. The D58 report reproduced what that
meant -- ``kill -9``, a Postgres restart and a kill switch in the middle of a dispatch each rolled
every state row back and left only the audit trail to say anything had begun -- and D59 had
already paid for the same assumption once (a network conflict recorded as ``unknown_outcome``
because the design knew only "succeeded" and "fully failed").

What these tests establish, and how, because this is the foundation the orchestrator stands on:

* **Each stage commits before the next begins.** Observed from *another connection* while a stage
  is in flight, never from the one doing the work: the container starts with a committed
  ``running`` row and no open transaction anywhere.
* **The stage a proposal reads as is the last one whose work is fully committed.** Faults are
  injected at every boundary, one at a time, and after each the committed rows must satisfy the
  coherence rules in :func:`assert_coherent` -- never a capability without a decision, never a run
  without a capability, never ``dispatching`` without a ``running`` row.
* **The three D58 crash experiments, reproduced** against the real thing: a real subprocess killed
  with SIGKILL mid-dispatch; a kill switch engaged mid-run and between stages; a failure at the
  moment the result is to be recorded.
* **A stage happens once.** Retrying with the same idempotency key resumes from the committed
  stage and repeats nothing. The mutation tests at the bottom put each guard back the old way and
  require these tests to go red.

The Postgres-restart experiment (E2) needs to stop the database server, which CI cannot do; its
deterministic equivalent here is a failure at the moment of recording, and the restart itself is
reported in ``docs/D60_PIPELINE_STAGES_REPORT.md`` as run by hand.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api import function_api
from control_plane.api.function_api import propose_action
from control_plane.orchestrator import dispatch, stages
from control_plane.orchestrator.dispatch import reconcile_stale_dispatches
from control_plane.orchestrator.engagement import engage_kill_switch, pause_engagement
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.provenance import graph
from control_plane.state.db import engagement_scope
from tests.helpers import committing_scope
from tool_gateway.sandbox import SandboxResult

TARGET = "10.82.0.5"
CIDR = "10.82.0.0/24"


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


class CountingReviewer(HonestFakeReviewer):
    """Counts its calls, and can run a hook (an injected fault, a kill switch) inside one."""

    def __init__(self, hook=None):
        super().__init__()
        self.calls = 0
        self.hook = hook

    def review(self, **kwargs):
        self.calls += 1
        if self.hook is not None:
            self.hook()
        return super().review(**kwargs)


class FakeSandbox:
    """Stands in for the container. ``during`` runs while "the container is running"."""

    def __init__(self, *, during=None, error: BaseException | None = None):
        self.calls = 0
        self.during = during
        self.error = error

    def run(self, **kwargs):
        self.calls += 1
        if self.during is not None:
            self.during(kwargs)
        if self.error is not None:
            raise self.error
        return SandboxResult(0, "Nmap done: 1 host up", "", False, 0.5, (CIDR,), "fake")


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def _proposal(world, target=TARGET):
    return ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": target}},
        authorization={"source": "engagement_scope", "scope_object_id": world["scope_id"]},
        discovery={"source": "explicit_scope"},
    )


def go(world, *, reviewer=None, sandbox=None, key="default", target=TARGET, **extra):
    """One propose_action call. ``key="default"`` uses the world's key (a retryable request)."""
    return propose_action(
        engagement_id=world["engagement_id"], proposal=_proposal(world, target),
        reviewer=reviewer or CountingReviewer(), policy=_policy(), agent_id="worker",
        sandbox=sandbox or FakeSandbox(),
        idempotency_key=world["key"] if key == "default" else key, **extra,
    )


# ---------------------------------------------------------------------------
# What the committed rows say, and what they must never say
# ---------------------------------------------------------------------------

def snapshot(engagement_id: str) -> dict:
    with engagement_scope(engagement_id) as conn:
        proposals = [dict(r) for r in conn.execute(text(
            "SELECT proposal_id, pipeline_stage AS stage, stage_detail AS detail, decision, "
            "dispatch_state, provenance_complete FROM action_proposals ORDER BY created_at"
        )).mappings()]
        capabilities = conn.execute(text("SELECT count(*) FROM capabilities")).scalar_one()
        # D61: which proposals a human approved, and which have a capability.
        approved = {r[0] for r in conn.execute(text(
            "SELECT proposal_id FROM approvals WHERE revoked IS FALSE")).all()}
        with_capability = {r[0] for r in conn.execute(text(
            "SELECT proposal_id FROM capabilities")).all()}
        runs = [r[0] for r in conn.execute(text("SELECT status FROM tool_runs")).all()]
        evidence = conn.execute(text("SELECT count(*) FROM evidence")).scalar_one()
        audit: dict[str, int] = {}
        for event, n in conn.execute(text(
                "SELECT event_type, count(*) FROM audit_log GROUP BY 1")).all():
            audit[event] = n
    return {"proposals": proposals, "capabilities": capabilities, "runs": runs,
            "evidence": evidence, "audit": audit, "approved": approved,
            "with_capability": with_capability}


def assert_coherent(snap: dict) -> None:
    """The rules no committed state may break, whatever failed and wherever.

    No stage ever commits something "partly right": a later stage's rows imply an earlier stage's.
    """
    for p in snap["proposals"]:
        stage = p["stage"]
        if stage != stages.RECEIVED:
            assert p["decision"] is not None, f"stage {stage} with no recorded decision: {p}"
        if stage in (stages.CAPABILITY_ISSUED, stages.DISPATCHING, stages.RECORDED):
            # ALLOW, or (D61) a HUMAN_APPROVAL that a human then approved.
            assert p["decision"] == "ALLOW" or (
                p["decision"] == "HUMAN_APPROVAL" and p["proposal_id"] in snap["approved"]), p
        if stage == stages.AWAITING_APPROVAL:
            assert p["decision"] == "HUMAN_APPROVAL", p
            assert p["proposal_id"] not in snap["approved"], "awaiting approval but approved"
            assert p["proposal_id"] not in snap["with_capability"], p
        if stage == stages.APPROVED:
            # The grant's two writes commit together: the stage and the approval row.
            assert p["decision"] == "HUMAN_APPROVAL", p
            assert p["proposal_id"] in snap["approved"], "approved stage with no approval row"
            assert p["detail"] and p["detail"].startswith("APPR-"), p
            assert p["proposal_id"] not in snap["with_capability"], (
                "an approved proposal has a capability before anything dispatched it")
        if stage == stages.DISPATCHING:
            assert p["dispatch_state"] == "running", p
    if snap["capabilities"]:
        assert snap["proposals"], "a capability with no proposal"
        for pid in snap["with_capability"]:
            p = next(p for p in snap["proposals"] if p["proposal_id"] == pid)
            assert p["decision"] == "ALLOW" or pid in snap["approved"], (
                "a capability was issued for a proposal that was neither allowed nor approved")
        assert all(p["stage"] != stages.RECEIVED for p in snap["proposals"]), (
            "a capability exists but its proposal's decision stage never committed")
    if snap["runs"]:
        assert snap["capabilities"], "a tool run with no capability"
        assert all(p["stage"] in (stages.DISPATCHING, stages.RECORDED, stages.CLOSED)
                   for p in snap["proposals"]), snap["proposals"]
    if snap["evidence"]:
        assert snap["runs"], "evidence with no run"
    for p in snap["proposals"]:
        if p["stage"] == stages.DISPATCHING:
            assert "running" in snap["runs"], "dispatching with no running run row"


def only(snap: dict) -> dict:
    assert len(snap["proposals"]) == 1, snap["proposals"]
    return snap["proposals"][0]


# ---------------------------------------------------------------------------
# 1. The stages, observed from outside
# ---------------------------------------------------------------------------

def test_a_proposal_walks_the_stages_and_each_is_visible_from_another_connection(world):
    """The container starts with a *committed* running row and no transaction open anywhere.

    Observed from inside the fake container (so: while stage 3b is in flight) through a
    connection of the test's own -- not the one doing the work.
    """
    seen: dict = {}

    def during(_kwargs):
        seen["snapshot"] = snapshot(world["engagement_id"])
        with committing_scope(world["engagement_id"]) as conn:
            seen["open_transactions"] = conn.execute(text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND usename = current_user AND pid <> pg_backend_pid() "
                "AND state LIKE 'idle in transaction%'")).scalar_one()

    reviewer = CountingReviewer()
    outcome = go(world, reviewer=reviewer, sandbox=FakeSandbox(during=during))
    assert outcome.decision == "ALLOW" and outcome.run_id and outcome.evidence_id

    mid = seen["snapshot"]
    p = only(mid)
    assert p["stage"] == stages.DISPATCHING and p["dispatch_state"] == "running", p
    assert p["decision"] == "ALLOW" and mid["capabilities"] == 1
    assert mid["runs"] == ["running"] and mid["evidence"] == 0
    assert mid["audit"].get("tool_run.started") == 1
    assert seen["open_transactions"] == 0, "a transaction was open while the container ran"
    assert_coherent(mid)

    final = snapshot(world["engagement_id"])
    p = only(final)
    assert (p["stage"], p["detail"], p["provenance_complete"]) == (
        stages.RECORDED, "succeeded", True)
    assert final["runs"] == ["succeeded"] and final["evidence"] == 1
    assert_coherent(final)


def test_a_deny_commits_its_decision_and_closes(world):
    outcome = go(world, target="10.99.9.9")        # outside the scope object
    assert outcome.decision == "DENY"
    snap = snapshot(world["engagement_id"])
    p = only(snap)
    assert (p["stage"], p["detail"], p["decision"]) == (stages.CLOSED, "decision_DENY", "DENY")
    assert snap["capabilities"] == 0 and snap["runs"] == []
    assert p["provenance_complete"] is True
    assert_coherent(snap)


def test_the_broker_is_asked_in_its_own_stage_not_at_the_start(world):
    """Paused while the reviewer is thinking: the decision (made earlier) stands and is committed,
    and the *issue* stage -- which checks the engagement now, not when the proposal arrived --
    refuses. Before D60 the broker's check ran in the same transaction as the decision, in the
    same instant."""
    def pause():
        with engagement_scope(world["engagement_id"]) as conn:
            pause_engagement(conn, engagement_id=world["engagement_id"], actor="operator",
                             reason="d60 test")

    sandbox = FakeSandbox()
    outcome = go(world, reviewer=CountingReviewer(hook=pause), sandbox=sandbox)
    assert outcome.failure == "capability_refused"
    assert "engagement_not_active" in outcome.deny_reasons
    assert sandbox.calls == 0
    snap = snapshot(world["engagement_id"])
    p = only(snap)
    assert p["decision"] == "ALLOW", "the decision itself was committed and survives"
    assert p["stage"] == stages.CLOSED and p["detail"].startswith("capability_refused:")
    assert snap["capabilities"] == 0
    assert_coherent(snap)


# ---------------------------------------------------------------------------
# 2. The kill switch, at the boundaries (D58 experiment E3)
# ---------------------------------------------------------------------------

def test_a_kill_switch_between_the_capability_and_the_dispatch_is_caught_at_the_boundary(
    world, monkeypatch,
):
    """The capability is committed in stage 2, so the kill switch can *see* it -- and revoke it --
    before stage 3 begins. Stage 3 starts by asking again, and does not dispatch.

    On the unfixed pipeline the capability was uncommitted and invisible to the revocation until
    the container had already finished (the D58 report's E3: ``revoked: []``, and the run
    proceeded to produce evidence)."""
    real = function_api._dispatch_for_action
    revoked: list = []

    def killed_just_before_dispatch(**kwargs):
        with engagement_scope(world["engagement_id"]) as conn:
            state = engage_kill_switch(conn, engagement_id=world["engagement_id"],
                                       actor="operator", reason="d60 test")
        revoked.extend(state.revoked_capabilities)
        return real(**kwargs)

    monkeypatch.setattr(function_api, "_dispatch_for_action", killed_just_before_dispatch)
    sandbox = FakeSandbox()
    outcome = go(world, sandbox=sandbox)

    assert len(revoked) == 1, "the kill switch revoked the committed capability"
    assert sandbox.calls == 0, "the container was never started"
    assert outcome.run_id is None and outcome.failure == "capability_not_live"
    snap = snapshot(world["engagement_id"])
    p = only(snap)
    assert (p["stage"], p["detail"]) == (stages.CLOSED, "capability_not_live")
    assert snap["runs"] == []
    assert_coherent(snap)


def test_a_kill_switch_during_the_run_revokes_the_capability_and_the_result_says_so(world):
    """Nothing stops a container that is already running (that is D44-7 / D58-16, not built).
    What changes is that the revocation is no longer a no-op against the run: the capability row
    exists, is revoked, and the recorded result carries the fact."""
    revoked: list = []

    def kill_mid_run(_kwargs):
        with engagement_scope(world["engagement_id"]) as conn:
            state = engage_kill_switch(conn, engagement_id=world["engagement_id"],
                                       actor="operator", reason="d60 test")
        revoked.extend(state.revoked_capabilities)

    outcome = go(world, sandbox=FakeSandbox(during=kill_mid_run))
    assert len(revoked) == 1, "mid-run, the kill switch finds the capability (was: [])"
    assert outcome.run_id and outcome.evidence_id, "the run's result is still recorded"
    with engagement_scope(world["engagement_id"]) as conn:
        revoked_flag = conn.execute(text(
            "SELECT payload -> 'capability_revoked_during_run' FROM audit_log "
            "WHERE event_type = 'tool_run.succeeded'")).scalar_one()
        capability_revoked = conn.execute(text(
            "SELECT revoked FROM capabilities")).scalar_one()
    assert capability_revoked is True
    assert revoked_flag == "kill_switch_engaged"
    assert_coherent(snapshot(world["engagement_id"]))


# ---------------------------------------------------------------------------
# 3. A process killed mid-dispatch (D58 experiment E1) -- a real SIGKILL
# ---------------------------------------------------------------------------

def test_a_killed_process_leaves_a_committed_dispatching_row_the_reconciler_can_find(world):
    child = subprocess.Popen(
        [sys.executable, "-m", "tests.crash_child", world["engagement_id"], world["scope_id"],
         world["key"]],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert child.stdout.readline().strip() == "CONTAINER_STARTED"
        child.kill()
        child.wait(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()

    snap = snapshot(world["engagement_id"])
    p = only(snap)
    # Before D60 every one of these was empty: the audit trail was all that remembered.
    assert p["decision"] == "ALLOW"
    assert (p["stage"], p["dispatch_state"]) == (stages.DISPATCHING, "running")
    assert snap["capabilities"] == 1 and snap["runs"] == ["running"]
    assert snap["audit"].get("tool_run.started") == 1
    assert_coherent(snap)

    # ...so the reconciler that has existed since §8.8 finally has something to reconcile.
    with committing_scope(world["engagement_id"]) as conn:
        found = reconcile_stale_dispatches(
            conn, engagement_id=world["engagement_id"], older_than_seconds=0,
            actor="reconciler")
    assert found == [p["proposal_id"]]
    after = snapshot(world["engagement_id"])
    p = only(after)
    assert (p["dispatch_state"], p["stage"], p["detail"]) == (
        "unknown_outcome", stages.RECORDED, "unknown_outcome")
    assert after["runs"] == ["unknown_outcome"]
    assert_coherent(after)

    # And a restarted caller retrying the same request does not run it again.
    sandbox = FakeSandbox()
    retried = go(world, sandbox=sandbox)
    assert sandbox.calls == 0 and retried.run_id is not None
    assert len(snapshot(world["engagement_id"])["proposals"]) == 1


def test_a_failure_at_the_moment_of_recording_leaves_the_run_running_and_the_output_on_disk(
    world, monkeypatch, caplog,
):
    """The deterministic form of D58's E2 (Postgres unreachable when the result is to be
    written): the run row is already committed ``running``, the result is not, and the log says
    where the output is -- the window between "container exited" and "result recorded" is no
    longer a window in which the result exists nowhere."""
    def database_gone(*_a, **_k):
        raise OperationalError("INSERT INTO evidence", {}, Exception("connection lost"))

    monkeypatch.setattr(dispatch, "record_evidence", database_gone)
    with caplog.at_level("CRITICAL", logger="cyberorch.dispatch"):
        with pytest.raises(OperationalError):
            go(world)

    snap = snapshot(world["engagement_id"])
    p = only(snap)
    assert (p["stage"], p["dispatch_state"]) == (stages.DISPATCHING, "running")
    assert snap["runs"] == ["running"] and snap["evidence"] == 0
    message = " ".join(r.getMessage() for r in caplog.records)
    assert "could not be recorded" in message and "output is on disk at" in message
    path = message.split("output is on disk at ")[1].split(" ")[0]
    with open(path, "rb") as handle:
        assert b"Nmap done" in handle.read()
    assert_coherent(snap)


# ---------------------------------------------------------------------------
# 4. A fault at every boundary: nothing partly right is ever committed
# ---------------------------------------------------------------------------

def _boom(*_a, **_k):
    raise RuntimeError("injected fault")


def _fault_in_reviewer(world, monkeypatch):
    return {"reviewer": CountingReviewer(hook=lambda: _boom())}


def _fault_before_the_decision_commits(world, monkeypatch):
    monkeypatch.setattr(function_api, "_record_decision", _boom)
    return {}


def _fault_after_the_broker_inserted(world, monkeypatch):
    real = function_api.issue_capability

    def issue_then_fail(*a, **k):
        real(*a, **k)
        raise RuntimeError("injected fault")

    monkeypatch.setattr(function_api, "issue_capability", issue_then_fail)
    return {}


def _fault_before_the_run_row_commits(world, monkeypatch):
    real = dispatch.record_audit

    def fail_on_started(**kw):
        if kw.get("event_type") == "tool_run.started":
            raise RuntimeError("injected fault")
        return real(**kw)

    monkeypatch.setattr(dispatch, "record_audit", fail_on_started)
    return {}


def _fault_in_the_container(world, monkeypatch):
    return {"sandbox": FakeSandbox(error=RuntimeError("injected fault"))}


FAULTS = [
    # name, injector, stage the proposal must be left in
    ("the reviewer", _fault_in_reviewer, stages.RECEIVED),
    ("the decision commit", _fault_before_the_decision_commits, stages.RECEIVED),
    ("just after the capability insert", _fault_after_the_broker_inserted, stages.DECIDED),
    ("before the run row commits", _fault_before_the_run_row_commits,
     stages.CAPABILITY_ISSUED),
    ("the container", _fault_in_the_container, stages.DISPATCHING),
]


@pytest.mark.parametrize("name,inject,expected_stage", FAULTS, ids=[f[0] for f in FAULTS])
def test_a_fault_at_any_boundary_leaves_coherent_state_and_a_retry_completes_it_once(
    world, monkeypatch, name, inject, expected_stage,
):
    with monkeypatch.context() as patched:
        extra = inject(world, patched)
        with pytest.raises(RuntimeError, match="injected fault"):
            go(world, **extra)
        left = snapshot(world["engagement_id"])
    p = only(left)
    assert p["stage"] == expected_stage, (name, p)
    assert_coherent(left)

    if expected_stage == stages.DISPATCHING:
        # The container may have run. A retry does not run it again.
        sandbox = FakeSandbox()
        outcome = go(world, sandbox=sandbox)
        assert sandbox.calls == 0
        assert outcome.failure == "dispatch_in_progress_or_unknown_outcome"
        assert only(snapshot(world["engagement_id"]))["stage"] == stages.DISPATCHING
        return

    sandbox = FakeSandbox()
    outcome = go(world, sandbox=sandbox)
    assert outcome.decision == "ALLOW" and outcome.run_id and outcome.evidence_id
    done = snapshot(world["engagement_id"])
    assert_coherent(done)
    assert only(done)["stage"] == stages.RECORDED
    # Once each, however many attempts: one proposal, one capability, one run, one container.
    assert done["capabilities"] == 1 and done["runs"] == ["succeeded"]
    assert sandbox.calls == 1
    assert done["audit"].get("policy.decided", 0) == 1 if name != "the reviewer" else True
    assert done["audit"].get("tool_run.started") == 1


# ---------------------------------------------------------------------------
# 5. Provenance is a step of its own
# ---------------------------------------------------------------------------

def test_a_provenance_failure_cannot_take_a_recorded_result_with_it(world, monkeypatch):
    def edges_fail(*_a, **_k):
        raise OperationalError("INSERT INTO provenance_edges", {}, Exception("lost"))

    with monkeypatch.context() as patched:
        patched.setattr(graph, "record_provenance", edges_fail)
        outcome = go(world)
    # The result is whole: the old pipeline lost all of this to one cheap, late write.
    assert outcome.run_id and outcome.evidence_id and outcome.failure is None
    snap = snapshot(world["engagement_id"])
    p = only(snap)
    assert (p["stage"], p["detail"], p["provenance_complete"]) == (
        stages.RECORDED, "succeeded", False)
    assert snap["runs"] == ["succeeded"] and snap["evidence"] == 1
    assert_coherent(snap)

    def edges_count():
        with engagement_scope(world["engagement_id"]) as conn:
            return conn.execute(text("SELECT count(*) FROM provenance_edges")).scalar_one()

    assert edges_count() == 0
    # ...and it can be written afterwards, any number of times, adding only what is missing.
    counts = []
    for _ in range(3):
        with engagement_scope(world["engagement_id"]) as conn:
            assert graph.record_provenance(
                conn, engagement_id=world["engagement_id"], proposal_id=p["proposal_id"]) is True
        counts.append(edges_count())
    # scope object -> proposal, proposal -> capability, capability -> run, run -> evidence
    assert counts[0] >= 4 and counts == [counts[0]] * 3, counts
    assert only(snapshot(world["engagement_id"]))["provenance_complete"] is True


def test_provenance_is_not_written_for_a_proposal_that_has_not_finished(world):
    with pytest.raises(RuntimeError):
        go(world, sandbox=FakeSandbox(error=RuntimeError("container died")))
    p = only(snapshot(world["engagement_id"]))
    assert p["stage"] == stages.DISPATCHING
    with engagement_scope(world["engagement_id"]) as conn:
        assert graph.record_provenance(
            conn, engagement_id=world["engagement_id"], proposal_id=p["proposal_id"]) is False


# ---------------------------------------------------------------------------
# 6. Idempotency across stages (D4.1, re-verified)
# ---------------------------------------------------------------------------

def test_the_same_request_twice_is_one_proposal_one_decision_one_run(world):
    reviewer, sandbox = CountingReviewer(), FakeSandbox()
    first = go(world, reviewer=reviewer, sandbox=sandbox)
    second = go(world, reviewer=reviewer, sandbox=sandbox)

    assert second.proposal_id == first.proposal_id
    assert second.run_id == first.run_id and second.evidence_id == first.evidence_id
    assert second.capability_id == first.capability_id
    assert (reviewer.calls, sandbox.calls) == (1, 1), "a stage was run a second time"
    snap = snapshot(world["engagement_id"])
    assert len(snap["proposals"]) == 1 and snap["capabilities"] == 1
    assert snap["runs"] == ["succeeded"]
    for event in ("proposal.submitted", "policy_reviewer.opinion", "policy.decided",
                  "capability.issued", "tool_run.started", "tool_run.succeeded",
                  "evidence.recorded"):
        assert snap["audit"].get(event) == 1, (event, snap["audit"])


def test_a_retry_after_the_decision_does_not_decide_again(world, monkeypatch):
    """Stage 1 committed, stage 2 failed. The retry must not repeat stage 1 -- no second
    reviewer call, no second ``policy.decided``."""
    reviewer = CountingReviewer()
    with monkeypatch.context() as patched:
        patched.setattr(function_api, "issue_capability", _boom)
        with pytest.raises(RuntimeError):
            go(world, reviewer=reviewer)
    assert only(snapshot(world["engagement_id"]))["stage"] == stages.DECIDED

    go(world, reviewer=reviewer)
    snap = snapshot(world["engagement_id"])
    assert reviewer.calls == 1
    assert snap["audit"].get("policy.decided") == 1
    assert snap["audit"].get("policy_reviewer.opinion") == 1
    assert only(snap)["stage"] == stages.RECORDED and snap["capabilities"] == 1


def test_a_key_reused_for_a_different_request_is_refused_not_resumed(world):
    go(world)
    other = go(world, target="10.82.0.77")
    assert other.decision == "DENY"
    assert other.deny_reasons == ("idempotency_key_reused_with_a_different_request",)
    assert len(snapshot(world["engagement_id"])["proposals"]) == 1


def test_calls_without_a_key_are_independent_proposals(world):
    go(world, key=None)
    go(world, key=None)
    assert len(snapshot(world["engagement_id"])["proposals"]) == 2


def test_two_callers_with_one_key_leave_one_of_everything(world):
    """The two race: both find no proposal, or one inserts and the other resumes mid-stage.
    Whichever way it falls, one stage-transition wins each stage and the rest repeat nothing."""
    barrier = threading.Barrier(2)
    sandbox = FakeSandbox(during=lambda _k: time.sleep(0.3))
    results: list = []
    errors: list = []

    def caller():
        try:
            barrier.wait()
            results.append(go(world, sandbox=sandbox))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=caller) for _ in range(2)]
    [t.start() for t in threads]
    [t.join(timeout=120) for t in threads]
    assert not errors, errors
    assert len(results) == 2
    snap = snapshot(world["engagement_id"])
    assert_coherent(snap)
    assert len(snap["proposals"]) == 1
    assert snap["audit"].get("policy.decided") == 1
    assert snap["capabilities"] == 1
    assert snap["runs"] == ["succeeded"] and sandbox.calls == 1
    assert snap["audit"].get("tool_run.started") == 1


# ---------------------------------------------------------------------------
# 7. The wiring that keeps it honest
# ---------------------------------------------------------------------------

def test_propose_action_and_the_dispatch_functions_take_no_connection():
    """A caller's transaction is exactly what cannot be allowed to contain the stages: it would
    commit them all at once, at its own exit."""
    import inspect

    for function in (propose_action, dispatch.dispatch_scan, dispatch.dispatch_collection,
                     dispatch.dispatch_code_scan):
        assert "conn" not in inspect.signature(function).parameters, function.__name__


def test_the_stage_vocabulary_matches_the_database_constraint():
    with engagement_scope("ENG-NONE") as conn:
        definition = conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'action_proposals_pipeline_stage_check'")).scalar_one()
    for stage in stages.STAGES:
        assert f"'{stage}'" in definition
