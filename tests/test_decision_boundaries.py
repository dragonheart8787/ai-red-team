"""A proposal does not leave ``received`` without a decision -- every boundary failed (D63).

Migration 0021 makes the database refuse any stage past ``received`` with no decision, and the
decision stage was changed to write the decision in the same statement that moves the stage. That
the rule holds is something the CHECK would report as an ``IntegrityError`` -- which is exactly
what must *not* happen in a correct run. So a fault is injected at **each boundary of the decision
stage** (and at the idempotency paths around it), one at a time, and after each:

* the exception that comes out is the injected one, and nothing in its chain is a database
  ``CheckViolation`` (the code never *tried* to move a proposal on without a decision);
* every committed proposal is either at ``received`` or has a decision (no counter-example),
  and the pipeline's coherence rules hold;
* the same request, retried with the same key, completes -- once: one proposal, one
  ``decision`` recorded, one run.

Boundaries, in the order the stage meets them: the proposal row and its audit record (stage 0); the
two registry reads and the policy-version read; the reviewer; the audit record of its opinion; OPA;
the decision statement itself; the decision's audit record, refused and -- the worst case -- written
and then the transaction fails; provenance after a committed DENY; two callers racing; and an
idempotency key reused for a different request while the first is still at ``received``.
"""

from __future__ import annotations

import threading
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

from control_plane.api import function_api
from control_plane.orchestrator import stages
from control_plane.state.db import engagement_scope
from tests.test_pipeline_stages import (
    CIDR,
    CountingReviewer,
    FakeSandbox,
    assert_coherent,
    go,
    only,
    snapshot,
)

INJECTED = "injected fault"
CONSTRAINT = "action_proposals_decision_past_received"


def _no_decision_violation(exc: IntegrityError) -> None:
    """Fail the test if the database refused a move for want of a decision; any other integrity
    error (a unique index, say) is not this test's business and propagates as it is."""
    if CONSTRAINT in str(exc.orig):
        pytest.fail(f"the decision stage moved a proposal on without a decision: {exc.orig}")
    raise exc


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def _boom(*_a, **_k):
    raise RuntimeError(INJECTED)


def complete(world, **kwargs):
    """``go`` for a call that is expected to get through. If the database refuses it as a
    ``CheckViolation``, the code tried to move a proposal on with no decision -- a failed
    assertion about the code, not an error of the test."""
    try:
        return go(world, **kwargs)
    except IntegrityError as exc:
        _no_decision_violation(exc)


def _undecided_past_received(engagement_id: str) -> list:
    with engagement_scope(engagement_id) as conn:
        return conn.execute(text(
            "SELECT proposal_id, pipeline_stage FROM action_proposals "
            "WHERE decision IS NULL AND pipeline_stage <> 'received'")).all()


def _chain(exc: BaseException) -> list[str]:
    seen, out = set(), []
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        out.append(f"{type(exc).__module__}.{type(exc).__name__}: {exc}")
        exc = exc.__cause__ or exc.__context__
    return out


def _fail_audit(event_type: str, *, after: bool, error=RuntimeError):
    """A ``record_audit`` that fails for one event type -- before writing it, or after (the audit
    connection commits on its own, so 'after' is the record written and the stage's transaction
    then failing)."""
    real = function_api.record_audit

    def wrapper(**kwargs):
        if kwargs.get("event_type") != event_type:
            return real(**kwargs)
        if after:
            real(**kwargs)
        raise error(INJECTED)

    return wrapper


# name -> how to inject; the proposal may or may not exist afterwards
def _in_reviewer(world, patched):
    return {"reviewer": CountingReviewer(hook=lambda: _boom())}


def _in_authorization_read(world, patched):
    patched.setattr(function_api, "resolve_authorization", _boom)
    return {}


def _in_metadata_read(world, patched):
    patched.setattr(function_api, "resolve_metadata", _boom)
    return {}


def _in_policy_version_read(world, patched):
    patched.setattr(function_api, "current_policy_version", _boom)
    return {}


def _in_opinion_audit(world, patched):
    patched.setattr(function_api, "record_audit",
                    _fail_audit("policy_reviewer.opinion", after=False))
    return {}


def _in_opa(world, patched):
    patched.setattr(function_api, "evaluate_policy", _boom)
    return {}


def _in_the_decision_statement(world, patched):
    patched.setattr(function_api, "_record_decision", _boom)
    return {}


def _in_the_decision_audit_refused(world, patched):
    patched.setattr(function_api, "record_audit", _fail_audit("policy.decided", after=False))
    return {}


def _in_the_decision_audit_written_then_fails(world, patched):
    patched.setattr(function_api, "record_audit", _fail_audit("policy.decided", after=True))
    return {}


def _in_the_decision_audit_connection_lost(world, patched):
    patched.setattr(function_api, "record_audit", _fail_audit(
        "policy.decided", after=True,
        error=lambda msg: OperationalError("INSERT", {}, Exception(msg))))
    return {}


def _in_stage_zero_audit(world, patched):
    patched.setattr(function_api, "record_audit", _fail_audit("proposal.submitted", after=False))
    return {}


BOUNDARIES = [
    ("the proposal row's audit record (stage 0)", _in_stage_zero_audit, "no proposal"),
    ("the authorization read", _in_authorization_read, stages.RECEIVED),
    ("the metadata read", _in_metadata_read, stages.RECEIVED),
    ("the policy-version read", _in_policy_version_read, stages.RECEIVED),
    ("the reviewer", _in_reviewer, stages.RECEIVED),
    ("the audit record of the reviewer's opinion", _in_opinion_audit, stages.RECEIVED),
    ("OPA", _in_opa, stages.RECEIVED),
    ("the decision statement", _in_the_decision_statement, stages.RECEIVED),
    ("the decision's audit record, refused", _in_the_decision_audit_refused, stages.RECEIVED),
    ("the decision's audit record, written and then the transaction fails",
     _in_the_decision_audit_written_then_fails, stages.RECEIVED),
    ("the decision's audit record, connection lost",
     _in_the_decision_audit_connection_lost, stages.RECEIVED),
]


@pytest.mark.parametrize("name,inject,expected", BOUNDARIES, ids=[b[0] for b in BOUNDARIES])
def test_a_fault_at_each_boundary_of_the_decision_stage_never_leaves_received_undecided(
    world, monkeypatch, name, inject, expected,
):
    eid = world["engagement_id"]
    with monkeypatch.context() as patched:
        extra = inject(world, patched)
        try:
            with pytest.raises((RuntimeError, OperationalError)) as raised:
                go(world, **extra)
        except IntegrityError as exc:
            _no_decision_violation(exc)
    chain = _chain(raised.value)
    assert INJECTED in chain[0], chain
    assert not [c for c in chain if "CheckViolation" in c or "IntegrityError" in c], (
        f"the code tried to move a proposal on without a decision: {chain}")

    left = snapshot(eid)
    assert _undecided_past_received(eid) == []
    assert_coherent(left)
    if expected == "no proposal":
        assert left["proposals"] == []
    else:
        p = only(left)
        assert p["stage"] == expected and p["decision"] is None, p   # still received, undecided

    # the same request, retried with the same key, completes -- once
    sandbox = FakeSandbox()
    outcome = complete(world, sandbox=sandbox)
    assert outcome.decision == "ALLOW" and outcome.run_id
    done = snapshot(eid)
    assert_coherent(done)
    p = only(done)
    assert p["stage"] == stages.RECORDED and p["decision"] == "ALLOW"
    assert done["capabilities"] == 1 and done["runs"] == ["succeeded"] and sandbox.calls == 1
    assert _undecided_past_received(eid) == []
    # One decision row. The audit trail keeps what an audit connection committed on its own before
    # the stage's transaction failed (D60, ``audit/logger.py``): a record written and then rolled
    # back leaves one extra ``policy.decided`` -- the cost of audit-before-commit, stated.
    extra_record = "written and then" in name or "connection lost" in name
    assert done["audit"].get("policy.decided") == (2 if extra_record else 1), done["audit"]


def test_a_deny_whose_provenance_then_fails_keeps_its_decision(world, monkeypatch):
    """After a DENY the stage is ``closed`` and provenance is a step of its own: when that fails
    the decision stays committed. A DENY is a decision, so closed-with-DENY is not the hole."""
    eid = world["engagement_id"]
    with monkeypatch.context() as patched:
        def lost(*_a, **_k):
            raise OperationalError("INSERT", {}, Exception(INJECTED))

        patched.setattr(function_api.graph, "record_provenance", lost)
        try:
            outcome = complete(world, target="10.99.9.9")    # outside the scope: DENY
        except OperationalError:
            pytest.fail("a provenance failure escaped and took the committed DENY with it")
    assert outcome.decision == "DENY"
    p = only(snapshot(eid))
    assert p["stage"] == stages.CLOSED and p["decision"] == "DENY", p
    assert _undecided_past_received(eid) == []


def test_two_callers_racing_for_the_decision_leave_one_decision_and_no_undecided_row(world):
    eid = world["engagement_id"]
    barrier = threading.Barrier(2)
    results, errors = [], []

    def caller():
        try:
            barrier.wait()
            results.append(complete(world))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=caller) for _ in range(2)]
    [t.start() for t in threads]
    [t.join(timeout=120) for t in threads]
    assert not errors, [_chain(e) for e in errors]
    snap = snapshot(eid)
    assert _undecided_past_received(eid) == []
    assert_coherent(snap)
    assert len(snap["proposals"]) == 1 and snap["audit"].get("policy.decided") == 1


def test_a_key_reused_for_a_different_request_leaves_an_undecided_proposal_as_it_was(
    world, monkeypatch,
):
    """The first request faults before its decision (so it is at ``received``, undecided); the
    same key is then used for a *different* target. The refusal touches nothing: the proposal is
    still ``received`` with no decision, and the original request, retried, still completes."""
    eid = world["engagement_id"]
    with monkeypatch.context() as patched:
        patched.setattr(function_api, "evaluate_policy", _boom)
        with pytest.raises(RuntimeError, match=INJECTED):
            go(world)
    before = only(snapshot(eid))
    assert before["stage"] == stages.RECEIVED and before["decision"] is None

    other = go(world, target="10.82.0.77")
    assert other.decision == "DENY"
    assert other.deny_reasons == ("idempotency_key_reused_with_a_different_request",)
    after = only(snapshot(eid))
    assert after == before                                  # nothing moved, nothing written
    assert _undecided_past_received(eid) == []

    done = complete(world)
    assert done.decision == "ALLOW"
    final = only(snapshot(eid))
    assert final["stage"] == stages.RECORDED and final["decision"] == "ALLOW"


def test_a_key_reused_for_a_different_request_after_the_decision_changes_nothing(world):
    eid = world["engagement_id"]
    complete(world)
    before = only(snapshot(eid))
    assert go(world, target="10.82.0.77").decision == "DENY"
    assert only(snapshot(eid)) == before
    assert _undecided_past_received(eid) == []


def test_a_request_refused_before_any_row_exists_creates_no_proposal(world):
    """The early refusals (a target that cannot be canonicalized) return before stage 0: no row,
    so there is nothing that could be undecided."""
    eid = world["engagement_id"]
    outcome = go(world, target="not a target at all !!")
    assert outcome.decision == "DENY"
    assert snapshot(eid)["proposals"] == []
