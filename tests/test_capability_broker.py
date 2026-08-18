"""Capability Broker: lease, heartbeat renewal, revocation (§4.6, I9).

Every test here runs on the ``cyberorch_app`` connection. That is a scope
constraint, not a convenience: the broker's question is "is the decision that
authorized this still in force", which is answered from capabilities,
approvals, credentials, policy_layers and engagements. Whether an action is
authorized *against a target* was settled earlier by the resolvers and OPA. If
the broker ever needed registry_admin, the design would have drifted — so
test_broker_never_touches_the_registries asserts it structurally rather than
leaving it as an intention.

The renewal tests all share one shape, which is the shape I9 describes: issue a
capability while everything is in order, change exactly one thing it depended
on, heartbeat, and require revocation. Each is a bug that only appears in that
sequence — a capability checked at issue time and never again looks perfectly
correct in isolation.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from control_plane.capability.broker import (
    ALREADY_REVOKED,
    APPROVAL_EXPIRED,
    APPROVAL_REVOKED,
    BUDGET_EXHAUSTED,
    CREDENTIAL_REVOKED,
    ENGAGEMENT_NOT_ACTIVE,
    KILL_SWITCH,
    LEASE_EXPIRED,
    POLICY_CHANGED,
    Budget,
    consume_request,
    current_policy_version,
    get_capability,
    issue_capability,
    renew_capability,
    revoke_all_for_engagement,
    revoke_capability,
)
from control_plane.state.db import engagement_scope


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Fixtures — all seeded over cyberorch_app
# ---------------------------------------------------------------------------

@pytest.fixture
def credential(engagement_id):
    cid = _uid("CRED")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("INSERT INTO credentials (credential_id, engagement_id, label) "
                 "VALUES (:cid, :eid, 'test credential')"),
            {"cid": cid, "eid": engagement_id},
        )
    return cid


@pytest.fixture
def approval(engagement_id):
    aid = _uid("APR")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO approvals (approval_id, engagement_id, action_class,
                    resource, valid_until, approved_by, approved_scope)
                VALUES (:aid, :eid, 'network.scan', 'customer_network',
                        now() + interval '1 hour', 'user-X', 'this_proposal_only')
            """),
            {"aid": aid, "eid": engagement_id},
        )
    return aid


def _issue(engagement_id, *, approval_id=None, credential_id=None,
           ttl_seconds=60, budget=None, capability_id=None):
    with engagement_scope(engagement_id) as conn:
        result = issue_capability(
            conn, engagement_id=engagement_id,
            capability_id=capability_id or _uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            constraints={"host": "10.20.0.7"}, budget=budget or Budget(),
            ttl_seconds=ttl_seconds, approval_id=approval_id,
            credential_id=credential_id,
        )
        return result


def _issued(engagement_id, **kwargs):
    """Issue and require success -- the precondition for a renewal test."""
    result = _issue(engagement_id, **kwargs)
    assert result.issued is True, result.reasons
    return result.capability


def _heartbeat(engagement_id, capability_id, ttl_seconds=60):
    with engagement_scope(engagement_id) as conn:
        return renew_capability(
            conn, engagement_id=engagement_id, capability_id=capability_id,
            actor="orchestrator", ttl_seconds=ttl_seconds,
        )


def _publish_emergency_overlay(engagement_id, version):
    """Tighten globally, mid-engagement — the §4.5 emergency channel."""
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO policy_layers (layer, version, document)
                VALUES ('emergency_overlay', :v,
                        '{"actions": {"network.scan": "DENY"}}'::jsonb)
            """),
            {"v": version},
        )


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------

def test_issue_records_budget_lease_and_policy_version(engagement_id, approval,
                                                       credential):
    budget = Budget(max_duration_seconds=600, max_targets=1, max_concurrency=1,
                    tool={"allowed_ports": "1-1024"})
    capability = _issued(engagement_id, approval_id=approval,
                         credential_id=credential, budget=budget)

    assert capability.budget.max_duration_seconds == 600
    assert capability.budget.max_targets == 1
    assert capability.budget.tool == {"allowed_ports": "1-1024"}
    assert capability.lease_expires_at > datetime.now(UTC)
    assert capability.renewal_count == 0
    assert capability.revoked is False
    with engagement_scope(engagement_id) as conn:
        assert capability.policy_version == current_policy_version(
            conn, engagement_id
        )


def test_lease_never_exceeds_the_duration_budget(engagement_id):
    """A 10-minute budget cannot be spent as a one-hour lease."""
    capability = _issued(engagement_id, ttl_seconds=3600,
                         budget=Budget(max_duration_seconds=600))
    granted = capability.lease_expires_at - datetime.now(UTC)
    assert granted <= timedelta(seconds=601)


@pytest.mark.parametrize("mutation,reason", [
    ("UPDATE engagements SET status = 'paused' WHERE engagement_id = :eid",
     ENGAGEMENT_NOT_ACTIVE),
    ("UPDATE engagements SET kill_switch_engaged = TRUE WHERE engagement_id = :eid",
     KILL_SWITCH),
])
def test_issue_is_refused_when_the_engagement_is_not_available(
    engagement_id, mutation, reason
):
    """Issue runs the same checks as renewal — first acquisition, same rule."""
    with engagement_scope(engagement_id) as conn:
        conn.execute(text(mutation), {"eid": engagement_id})
    result = _issue(engagement_id)
    assert result.issued is False
    assert result.capability is None
    assert reason in result.reasons


def test_issue_is_refused_on_an_expired_approval(engagement_id):
    aid = _uid("APR")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO approvals (approval_id, engagement_id, action_class,
                    valid_until, approved_by, approved_scope)
                VALUES (:aid, :eid, 'network.scan', now() - interval '1 minute',
                        'user-X', 'this_proposal_only')
            """),
            {"aid": aid, "eid": engagement_id},
        )
    result = _issue(engagement_id, approval_id=aid)
    assert result.issued is False
    assert APPROVAL_EXPIRED in result.reasons


def test_refusal_is_audited(engagement_id):
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE engagements SET kill_switch_engaged = TRUE "
                 "WHERE engagement_id = :eid"),
            {"eid": engagement_id},
        )
    cid = _uid("CAP")
    assert _issue(engagement_id, capability_id=cid).issued is False
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT event_type, decision, reasons FROM audit_log "
                 "WHERE subject_id = :s"),
            {"s": cid},
        ).mappings().one()
    assert row["event_type"] == "capability.refused"
    assert row["decision"] == "DENY"
    assert KILL_SWITCH in row["reasons"]


# ---------------------------------------------------------------------------
# Renewal — I9 Revocation Safety
# ---------------------------------------------------------------------------

def test_heartbeat_renews_when_nothing_changed(engagement_id, approval, credential):
    """The control case. Without it, a broker that revokes unconditionally
    would pass every other test in this file."""
    capability = _issued(engagement_id, approval_id=approval,
                         credential_id=credential, ttl_seconds=30)
    original_expiry = capability.lease_expires_at

    result = _heartbeat(engagement_id, capability.capability_id, ttl_seconds=120)

    assert result.renewed is True
    assert result.must_terminate is False
    assert result.reasons == ()
    assert result.capability.lease_expires_at > original_expiry
    assert result.capability.renewal_count == 1
    assert result.capability.revoked is False


def test_emergency_tighten_then_heartbeat_revokes(engagement_id, approval, credential):
    """I9's headline case (§4.6).

    The capability was issued under a policy that has since been tightened
    globally. Nothing about the capability changed; what it depended on did.
    A mechanical TTL extension would carry an authorization that no longer
    exists straight past the tightening it was meant to obey.
    """
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    _publish_emergency_overlay(engagement_id, version=int(uuid.uuid4().int % 100000))

    result = _heartbeat(engagement_id, capability.capability_id)

    assert result.renewed is False
    assert result.must_terminate is True
    assert POLICY_CHANGED in result.reasons
    assert result.capability.revoked is True


def test_expired_approval_then_heartbeat_revokes(engagement_id, credential):
    """§4.7: a capability must not outlive the approval that justified it."""
    aid = _uid("APR")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO approvals (approval_id, engagement_id, action_class,
                    valid_until, approved_by, approved_scope)
                VALUES (:aid, :eid, 'network.scan', now() + interval '1 hour',
                        'user-X', 'this_proposal_only')
            """),
            {"aid": aid, "eid": engagement_id},
        )
    capability = _issued(engagement_id, approval_id=aid, credential_id=credential)

    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE approvals SET valid_until = now() - interval '1 second' "
                 "WHERE approval_id = :aid"),
            {"aid": aid},
        )

    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert APPROVAL_EXPIRED in result.reasons
    assert result.capability.revoked is True


def test_revoked_approval_then_heartbeat_revokes(engagement_id, approval, credential):
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE approvals SET revoked = TRUE WHERE approval_id = :aid"),
            {"aid": approval},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert APPROVAL_REVOKED in result.reasons


def test_revoked_credential_then_heartbeat_revokes(engagement_id, approval, credential):
    """§1.3.2: pulling a credential must invalidate outstanding capabilities."""
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE credentials SET revoked = TRUE, revoked_at = now() "
                 "WHERE credential_id = :cid"),
            {"cid": credential},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert CREDENTIAL_REVOKED in result.reasons
    assert result.capability.revoked is True


def test_paused_engagement_then_heartbeat_revokes(engagement_id, approval, credential):
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE engagements SET status = 'paused' WHERE engagement_id = :eid"),
            {"eid": engagement_id},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert ENGAGEMENT_NOT_ACTIVE in result.reasons


def test_kill_switch_then_heartbeat_revokes(engagement_id, approval, credential):
    """§1.2(e): the kill switch stops in-flight work, not just new work."""
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE engagements SET kill_switch_engaged = TRUE "
                 "WHERE engagement_id = :eid"),
            {"eid": engagement_id},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert KILL_SWITCH in result.reasons
    assert result.capability.revoked is True


def test_several_failures_are_all_reported(engagement_id, approval, credential):
    """The audit record should say everything that was wrong."""
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE engagements SET kill_switch_engaged = TRUE, status = 'paused' "
                 "WHERE engagement_id = :eid"),
            {"eid": engagement_id},
        )
        conn.execute(
            text("UPDATE credentials SET revoked = TRUE WHERE credential_id = :cid"),
            {"cid": credential},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert {KILL_SWITCH, ENGAGEMENT_NOT_ACTIVE, CREDENTIAL_REVOKED} <= set(result.reasons)


def test_late_heartbeat_cannot_resurrect_an_expired_lease(engagement_id):
    """§4.6 treats a missing heartbeat as an anomaly worth terminating over."""
    capability = _issued(engagement_id, ttl_seconds=60)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE capabilities SET lease_expires_at = now() - interval '1 second' "
                 "WHERE capability_id = :cid"),
            {"cid": capability.capability_id},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert result.must_terminate is True
    assert LEASE_EXPIRED in result.reasons
    # Refusing to renew is not enough: the capability must end up revoked, or
    # it sits in a state that still looks issuable to anything that reads it.
    assert result.capability.revoked is True
    with engagement_scope(engagement_id) as conn:
        assert get_capability(conn, capability.capability_id).revoked is True


def test_repeated_heartbeats_never_push_the_lease_past_the_budget(engagement_id):
    """Consecutive renewals, checked against the whole-life budget each time.

    The single-renewal test fakes an old issued_at; this one does it the way an
    agent would -- heartbeat after heartbeat, each asking for far more time
    than the budget allows. The invariant is not "each lease is short" but
    "the lease never passes issued_at + max_duration_seconds", which only a
    sequence can check: three renewals that each look reasonable in isolation
    could still walk the deadline forward.

    The sleep is real rather than faked. Rewriting issued_at would test the
    arithmetic while assuming the clock behaves, and the budget is a wall-clock
    bound.
    """
    budget_seconds = 2
    capability = _issued(engagement_id, ttl_seconds=60,
                         budget=Budget(max_duration_seconds=budget_seconds))
    deadline = capability.issued_at + timedelta(seconds=budget_seconds)

    for attempt in range(3):
        result = _heartbeat(engagement_id, capability.capability_id, ttl_seconds=600)
        assert result.renewed is True, (attempt, result.reasons)
        assert result.capability.lease_expires_at <= deadline, (
            f"heartbeat {attempt} pushed the lease past "
            "issued_at + max_duration_seconds"
        )
        assert result.capability.renewal_count == attempt + 1

    # Past the budget now. The next heartbeat must stop, not extend.
    time.sleep(budget_seconds + 0.3)
    final = _heartbeat(engagement_id, capability.capability_id, ttl_seconds=600)

    assert final.renewed is False
    assert final.must_terminate is True
    assert {BUDGET_EXHAUSTED, LEASE_EXPIRED} & set(final.reasons)
    assert final.capability.revoked is True


def test_renewal_cannot_outrun_the_duration_budget(engagement_id):
    """An agent must not heartbeat its way past the budget one window at a time."""
    capability = _issued(engagement_id, ttl_seconds=30,
                         budget=Budget(max_duration_seconds=30))
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE capabilities SET issued_at = now() - interval '31 seconds' "
                 "WHERE capability_id = :cid"),
            {"cid": capability.capability_id},
        )
    result = _heartbeat(engagement_id, capability.capability_id, ttl_seconds=600)
    assert result.renewed is False
    assert BUDGET_EXHAUSTED in result.reasons


def test_renewal_is_audited(engagement_id, approval, credential):
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    _heartbeat(engagement_id, capability.capability_id)
    with engagement_scope(engagement_id) as conn:
        events = conn.execute(
            text("SELECT event_type FROM audit_log WHERE subject_id = :s "
                 "ORDER BY audit_id"),
            {"s": capability.capability_id},
        ).scalars().all()
    assert events == ["capability.issued", "capability.renewed"]


def test_revocation_on_renewal_is_audited(engagement_id, approval, credential):
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE credentials SET revoked = TRUE WHERE credential_id = :cid"),
            {"cid": credential},
        )
    _heartbeat(engagement_id, capability.capability_id)
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT event_type, decision, reasons FROM audit_log "
                 "WHERE subject_id = :s AND decision = 'DENY'"),
            {"s": capability.capability_id},
        ).mappings().one()
    assert row["event_type"] == "capability.revoked_on_renewal"
    assert CREDENTIAL_REVOKED in row["reasons"]


# ---------------------------------------------------------------------------
# Revocation is terminal
# ---------------------------------------------------------------------------

def test_a_revoked_capability_reads_as_revoked_afterwards(engagement_id):
    capability = _issued(engagement_id)
    with engagement_scope(engagement_id) as conn:
        revoke_capability(
            conn, engagement_id=engagement_id,
            capability_id=capability.capability_id,
            reason="operator_action", actor="operator",
        )
        stored = get_capability(conn, capability.capability_id)

    assert stored.revoked is True
    assert stored.revoked_reason == "operator_action"
    assert stored.is_live() is False


def test_revocation_has_no_way_back(engagement_id, approval, credential):
    """I9: renewal is a new authorization, and a revoked capability never
    obtains one — not even when the condition that revoked it is undone."""
    capability = _issued(engagement_id, approval_id=approval, credential_id=credential)
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE credentials SET revoked = TRUE WHERE credential_id = :cid"),
            {"cid": credential},
        )
    assert _heartbeat(engagement_id, capability.capability_id).renewed is False

    # The operator restores the credential. The capability stays dead.
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE credentials SET revoked = FALSE WHERE credential_id = :cid"),
            {"cid": credential},
        )
    again = _heartbeat(engagement_id, capability.capability_id)
    assert again.renewed is False
    assert ALREADY_REVOKED in again.reasons
    assert again.capability.revoked is True


def test_the_first_revocation_reason_is_the_one_kept(engagement_id):
    capability = _issued(engagement_id)
    with engagement_scope(engagement_id) as conn:
        revoke_capability(conn, engagement_id=engagement_id,
                          capability_id=capability.capability_id,
                          reason="first_reason", actor="operator")
        revoke_capability(conn, engagement_id=engagement_id,
                          capability_id=capability.capability_id,
                          reason="second_reason", actor="operator")
        stored = get_capability(conn, capability.capability_id)
    assert stored.revoked_reason == "first_reason"


def test_cascade_revokes_every_live_capability(engagement_id):
    """§1.3.2 revocation cascade: stop now, not at the next heartbeat."""
    ids = [_issued(engagement_id).capability_id for _ in range(3)]
    with engagement_scope(engagement_id) as conn:
        revoked = revoke_all_for_engagement(
            conn, engagement_id=engagement_id, reason=KILL_SWITCH, actor="operator",
        )
        assert set(revoked) == set(ids)
        for capability_id in ids:
            assert get_capability(conn, capability_id).revoked is True


def test_revoked_capability_cannot_consume_budget(engagement_id):
    capability = _issued(engagement_id)
    with engagement_scope(engagement_id) as conn:
        assert consume_request(
            conn, capability_id=capability.capability_id, max_requests=3
        ) is True
        revoke_capability(conn, engagement_id=engagement_id,
                          capability_id=capability.capability_id,
                          reason="operator_action", actor="operator")
        assert consume_request(
            conn, capability_id=capability.capability_id, max_requests=3
        ) is False


def test_budget_is_enforced_by_check_and_increment(engagement_id):
    """§8.5: the predicate and the increment are one statement (I3)."""
    capability = _issued(engagement_id)
    with engagement_scope(engagement_id) as conn:
        results = [
            consume_request(conn, capability_id=capability.capability_id,
                            max_requests=3)
            for _ in range(5)
        ]
        used = get_capability(conn, capability.capability_id).requests_used
    assert results == [True, True, True, False, False]
    assert used == 3


# ---------------------------------------------------------------------------
# Scope constraint
# ---------------------------------------------------------------------------

def test_broker_never_touches_the_registries():
    """The scope constraint, asserted structurally.

    Nothing the broker does requires knowing what a target *is* or whether it
    is in scope — those were settled before a capability was requested. If this
    fails, the design has drifted, and the fix is to move the work back to the
    resolvers rather than to widen the broker's grants.
    """
    from pathlib import Path

    import control_plane.capability.broker as broker_module

    source = Path(broker_module.__file__).read_text()
    for forbidden in ("registry_admin", "scope_registry", "metadata_registry"):
        assert forbidden not in source, (
            f"capability broker references {forbidden!r}; it should need neither "
            "registry nor the role that writes them"
        )


def test_full_lifecycle_runs_on_the_app_role(engagement_id, approval, credential):
    """Issue, heartbeat, consume, revoke — all as cyberorch_app.

    The role that cannot write either registry. If any step needed
    registry_admin this would raise InsufficientPrivilege rather than pass.
    """
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "cyberorch_app"

        issued = issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(max_duration_seconds=600), ttl_seconds=60,
            approval_id=approval, credential_id=credential,
        )
        assert issued.issued is True
        capability = issued.capability
        renewal = renew_capability(
            conn, engagement_id=engagement_id,
            capability_id=capability.capability_id, actor="orchestrator",
        )
        assert renewal.renewed is True

        assert consume_request(
            conn, capability_id=capability.capability_id, max_requests=2
        ) is True

        revoke_capability(
            conn, engagement_id=engagement_id,
            capability_id=capability.capability_id,
            reason="operator_action", actor="operator",
        )
        assert get_capability(conn, capability.capability_id).revoked is True


def test_capabilities_are_engagement_scoped(engagement_id):
    """I4 still applies: another engagement's capability does not exist here."""
    capability = _issued(engagement_id)
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
        assert get_capability(conn, capability.capability_id) is None
        result = renew_capability(
            conn, engagement_id=other, capability_id=capability.capability_id,
            actor="orchestrator",
        )
    assert result.renewed is False
