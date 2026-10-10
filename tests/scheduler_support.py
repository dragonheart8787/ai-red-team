"""Shared setup for the scheduler tests (D62).

The scheduler is exercised through the same entry points production uses: ``propose_action`` with
the effective policy *loaded from the database*, a real ``grant_approval``, and ``Scheduler.tick``.
Nothing here reaches into the scheduler's modules to make it work.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager

from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.approvals import grant_approval
from control_plane.api.function_api import propose_action
from control_plane.orchestrator.engagement import (
    engage_kill_switch,
    pause_engagement,
    resume_engagement,
)
from control_plane.policy.layers import load_effective_policy, publish_policy_layer
from control_plane.scheduler.lock import SingletonLock
from control_plane.scheduler.service import Scheduler
from control_plane.state.db import scheduler_admin_scope
from tests.helpers import committing_scope


def publish_engagement_policy(engagement_id: str, *, actions=("network.scan",)) -> None:
    """An engagement-scoped layer that allows the given actions and denies PII."""
    with committing_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {a: "ALLOW" for a in actions},
                      "data_deny": ["PII", "customer_database"]},
            actor="policy-admin", scoped_to_engagement=True,
        )


def effective_policy(engagement_id: str):
    with committing_scope(engagement_id) as conn:
        return load_effective_policy(conn, engagement_id)


def register_scope(registry, *, type: str, value: str, actions=("network.scan",)) -> str:
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type=type, value=value,
                   allowed_actions=list(actions))
    return scope_id


def proposal_for(scope_id: str, *, host: str, action="network.scan", target_type="ip",
                 ports="8080", scan_type="connect") -> ProposedAction:
    return ProposedAction(
        action=action,
        target={"logical_identity": {"type": target_type, "value": host},
                "ports": ports, "scan_type": scan_type},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        requested_capability_ttl_seconds=60,
    )


def escalate(engagement_id: str, proposal: ProposedAction) -> str:
    """Propose; the reviewer names sensitive data, so OPA sends it to a human (D11 Case D)."""
    outcome = propose_action(
        engagement_id=engagement_id, proposal=proposal,
        reviewer=HonestFakeReviewer(sensitive_hint=("pii",)),
        policy=effective_policy(engagement_id), agent_id="worker-1",
    )
    assert outcome.decision == "HUMAN_APPROVAL", outcome
    return outcome.proposal_id


def approve(engagement_id: str, proposal_id: str, approver: str = "alice"):
    with committing_scope(engagement_id) as conn:
        return grant_approval(
            conn, engagement_id=engagement_id, proposal_id=proposal_id, approver=approver,
            approved_scope="this_proposal_only", valid_for_seconds=3600,
        )


def approved_proposal(engagement_id: str, scope_id: str, *, host: str, **kwargs) -> str:
    pid = escalate(engagement_id, proposal_for(scope_id, host=host, **kwargs))
    approve(engagement_id, pid)
    return pid


def enroll(engagement_id: str, by: str = "test-operator") -> None:
    with scheduler_admin_scope() as conn:
        conn.execute(text(
            "INSERT INTO scheduler_enrollment (engagement_id, enrolled_by) VALUES (:e, :b)"),
            {"e": engagement_id, "b": by})


def withdraw(engagement_id: str) -> None:
    with scheduler_admin_scope() as conn:
        conn.execute(text(
            "UPDATE scheduler_enrollment SET withdrawn_at = now(), withdrawn_by = 'test-operator' "
            "WHERE engagement_id = :e AND withdrawn_at IS NULL"), {"e": engagement_id})


@contextmanager
def running(sandbox=None, **kwargs):
    """A started scheduler (lock held), stopped and released afterwards."""
    sched = Scheduler(sandbox=sandbox, lock=SingletonLock(), watchdog_interval=0.2, **kwargs)
    sched.start()
    try:
        yield sched
    finally:
        sched.stop("signal")


def audit(engagement_id: str, *event_types: str, subject_id: str | None = None):
    sql = ("SELECT audit_id, event_type, actor, subject_id, payload FROM audit_log "
           "WHERE engagement_id = :e")
    params: dict = {"e": engagement_id}
    if event_types:
        sql += " AND event_type = ANY(:t)"
        params["t"] = list(event_types)
    if subject_id:
        sql += " AND subject_id = :s"
        params["s"] = subject_id
    with committing_scope(engagement_id) as conn:
        return [dict(r) for r in conn.execute(text(sql + " ORDER BY audit_id"), params).mappings()]


def rows(engagement_id: str, sql: str, **params):
    with committing_scope(engagement_id) as conn:
        return [dict(r) for r in conn.execute(text(sql), params).mappings()]


def pause(engagement_id: str) -> None:
    with committing_scope(engagement_id) as conn:
        pause_engagement(conn, engagement_id=engagement_id, actor="op", reason="maintenance")


def resume(engagement_id: str) -> None:
    with committing_scope(engagement_id) as conn:
        resume_engagement(conn, engagement_id=engagement_id, actor="op", reason="done")


def kill(engagement_id: str) -> None:
    with committing_scope(engagement_id) as conn:
        engage_kill_switch(engagement_id=engagement_id, conn=conn, actor="op", reason="stop")
