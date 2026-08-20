"""Capability Broker: lease, heartbeat renewal, revocation (§4.6, I9).

Every test here runs on the ``cyberorch_app`` connection. That is a scope
constraint, not a convenience: the broker's question is "is the decision that
authorized this still in force", which is answered from capabilities,
approvals, credentials, policy_layers and engagements. Whether an action is
authorized *against a target* was settled earlier by the resolvers and OPA, and
is not re-decided here.

The one exception, added after D9's stateful test found the hole it leaves: the
broker reads the single scope_registry row that authorized a capability, to
confirm it is still active and still permits the action. That is a liveness
check on a recorded premise, not an authorization decision, and
test_broker_reads_scope_only_as_a_liveness_check pins the difference
structurally rather than leaving it as an intention.

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
    SCOPE_ACTION_WITHDRAWN,
    SCOPE_OBJECT_DEACTIVATED,
    Budget,
    consume_request,
    current_policy_version,
    get_capability,
    issue_capability,
    renew_capability,
    revoke_all_for_engagement,
    revoke_capability,
)
from control_plane.policy.layers import EMERGENCY_OVERLAY, publish_policy_layer
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
    """Test-only seeding. There is no approval-granting operation to call.

    ``approvals`` is read by check_preconditions -- valid_until and revoked are
    both checked on every issue and renewal -- and written by nothing in the
    control plane. That is deliberate for MVP-Kernel rather than the kill-switch
    pattern repeating: §4.7's Human Approval flow needs an Approval API and a
    reviewer-facing surface, and both are explicitly out of scope for this stage.

    So these rows are seeded directly, and the *checking* of them is what these
    tests cover. Granting and revoking an approval belong to the Phase 1
    Approval API; when it exists, this fixture should call it, and a
    revoke_approval() cascade will need the same treatment revoke_credential()
    got in D9.
    """
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
    """Tighten mid-engagement — the §4.5 emergency channel.

    Goes through publish_policy_layer rather than an INSERT. It used to be a raw
    write, which is how policy_layers ended up being the third state this system
    enforced but could not set: the tests exercised the column and nobody
    noticed there was no operation behind it.

    Scoped to the engagement, not global. A global layer is visible to every
    engagement and outlives the test that published it, so a suite-wide DENY on
    network.scan accumulated in the database and would now change what
    load_effective_policy returns for unrelated tests.
    """
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer=EMERGENCY_OVERLAY,
            version=version, document={"actions": {"network.scan": "DENY"}},
            actor="incident-commander", scoped_to_engagement=True,
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
    # Test-only seeding; see the `approval` fixture for why there is no
    # granting operation to call instead (Phase 1 Approval API).
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
    # Test-only seeding; see the `approval` fixture.
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

def _broker_source() -> str:
    from pathlib import Path

    import control_plane.capability.broker as broker_module

    return Path(broker_module.__file__).read_text()


def _broker_code() -> str:
    """The broker's source with docstrings and comments stripped.

    The prose explains at length what the broker must not do, and naming a
    forbidden construct in order to forbid it would trip a naive substring
    search. These rules are about what the code does, so they read the code.
    """
    import ast

    tree = ast.parse(_broker_source())
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return ast.unparse(tree)


def test_broker_never_touches_the_metadata_registry_or_the_admin_role():
    """The part of the scope constraint that is still absolute.

    What a resource *is* — its data_class, its resource_class — is never the
    broker's business, and neither is the role that writes the registries. If
    this fails the design has drifted, and the fix is to move the work back to
    the resolvers rather than to widen the broker's grants.
    """
    code = _broker_code()
    for forbidden in ("registry_admin", "metadata_registry"):
        assert forbidden not in code, (
            f"capability broker references {forbidden!r}; it needs neither the "
            "metadata registry nor the role that writes the registries"
        )


def test_broker_reads_scope_only_as_a_liveness_check():
    """The narrower rule that replaced "never touches scope_registry".

    D9's stateful test showed the old rule was too strong: renewal has to be
    able to notice that the scope object authorizing a capability was retired,
    and that means reading scope_registry. So the constraint moved rather than
    disappearing — the broker may look one row up by id, and may not decide
    authorization.

    Written structurally because the distinction is easy to erode by degrees.
    "Just also check the target while we're here" is a one-line change that
    would put a second implementation of scope containment in the codebase,
    free to drift from the resolver's. The rule has to be mechanical to survive
    a reader who finds it inconvenient.
    """
    code = _broker_code()

    # 1. No authorization decision. The resolver is upstream and stays there.
    for forbidden in (
        "resolve_authorization", "AuthorizationResolution",
        "canonicalizer", "normalize_target", "CanonicalTarget",
    ):
        assert forbidden not in code, (
            f"capability broker references {forbidden!r}: re-resolving "
            "authorization here duplicates the decision the resolver owns"
        )

    # 2. No target matching, by any route.
    for forbidden in (
        "scope_covers_target", "action_matches", "ip_network", "ip_address",
        "ipaddress", "subnet_of", "logical_identity",
    ):
        assert forbidden not in code, (
            f"capability broker references {forbidden!r}: comparing a target "
            "against a scope object is the resolver's job, and a second "
            "implementation of it is a second thing to get wrong"
        )

    # 3. Exactly one scope_registry statement, selecting only liveness columns.
    import re

    statements = re.findall(r"[Ss][Ee][Ll][Ee][Cc][Tt][^\"']*?scope_registry", code)
    assert len(statements) == 1, (
        f"expected exactly one scope_registry query, found {len(statements)}: "
        f"{statements}"
    )
    assert "active" in statements[0] and "allowed_actions" in statements[0]

    # It is a lookup by id, not a scan: a query that could return more than one
    # scope object would be searching for one that fits.
    assert "WHERE scope_object_id = :sid" in code

    # 4. Read-only. The broker holds SELECT on the registries and nothing more,
    # so a write would fail at runtime — but failing here names the reason.
    for write in ("INSERT INTO scope_registry", "UPDATE scope_registry",
                  "DELETE FROM scope_registry"):
        assert write not in code, f"capability broker attempts {write!r}"


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


# ---------------------------------------------------------------------------
# Scope object liveness (I1, I8) — the gap D9's stateful test found
# ---------------------------------------------------------------------------

@pytest.fixture
def scope_object(engagement_id):
    """A live scope object permitting network.scan."""
    from control_plane.registry.scope_registry import register_scope_object
    from control_plane.state.db import registry_admin_scope

    sid = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid,
            type="cidr", value="10.20.0.0/24",
            allowed_actions=["network.recon", "network.scan"],
            actor="engagement-manager",
        )
    return sid


def _issue_against(engagement_id, scope_object_id, *, action="network.scan"):
    with engagement_scope(engagement_id) as conn:
        result = issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action=action, actor="orchestrator",
            constraints={"host": "10.20.0.7"}, budget=Budget(),
            ttl_seconds=60, scope_object_id=scope_object_id,
        )
    return result


def test_capability_records_the_scope_object_that_authorized_it(
    engagement_id, scope_object
):
    """I8: a capability that cannot name its authorization cannot prove it."""
    capability = _issue_against(engagement_id, scope_object).capability
    assert capability.scope_object_id == scope_object

    with engagement_scope(engagement_id) as conn:
        stored = conn.execute(
            text("SELECT scope_object_id FROM capabilities WHERE capability_id = :c"),
            {"c": capability.capability_id},
        ).scalar_one()
    assert stored == scope_object


def test_renewal_fails_once_the_authorizing_scope_object_is_retired(
    engagement_id, scope_object
):
    """The bug itself (I1, I9).

    Before this, deactivating a scope object revoked nothing and every
    subsequent heartbeat succeeded, so a scan continued against a target that
    was no longer in scope for as long as its budget allowed.
    """
    from control_plane.registry.scope_registry import deactivate_scope_object
    from control_plane.state.db import registry_admin_scope

    capability = _issue_against(engagement_id, scope_object).capability

    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object,
            actor="engagement-manager",
        )

    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert result.must_terminate is True
    assert SCOPE_OBJECT_DEACTIVATED in result.reasons

    # The real reason, not a borrowed one. An investigator reading
    # policy_version_changed here would look for a policy layer that never moved.
    with engagement_scope(engagement_id) as conn:
        stored = get_capability(conn, capability.capability_id)
    assert stored.revoked is True
    assert SCOPE_OBJECT_DEACTIVATED in stored.revoked_reason
    assert POLICY_CHANGED not in (stored.revoked_reason or "")


def test_issue_is_refused_against_a_retired_scope_object(engagement_id, scope_object):
    """Issue and renewal ask the same question, so they get the same answer."""
    from control_plane.registry.scope_registry import deactivate_scope_object
    from control_plane.state.db import registry_admin_scope

    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object,
            actor="engagement-manager",
        )

    result = _issue_against(engagement_id, scope_object)
    assert result.issued is False
    assert SCOPE_OBJECT_DEACTIVATED in result.reasons


def test_renewal_fails_when_the_action_is_withdrawn_from_the_scope_object(
    engagement_id, scope_object
):
    """Narrowing allowed_actions withdraws authorization for exactly that action."""
    from control_plane.registry.scope_registry import register_scope_object
    from control_plane.state.db import registry_admin_scope

    capability = _issue_against(engagement_id, scope_object).capability

    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object,
            type="cidr", value="10.20.0.0/24",
            allowed_actions=["network.recon"],  # network.scan withdrawn
            actor="engagement-manager",
        )

    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert SCOPE_ACTION_WITHDRAWN in result.reasons


def test_retiring_one_scope_object_leaves_capabilities_from_another_alone(
    engagement_id, scope_object
):
    """Precision, and the reason option 2 was rejected.

    Folding scope changes into policy_version would have revoked every
    capability in the engagement on any scope edit. Fail-closed, but a control
    that stops unrelated work is one operators route around.
    """
    from control_plane.registry.scope_registry import (
        deactivate_scope_object,
        register_scope_object,
    )
    from control_plane.state.db import registry_admin_scope

    other = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=other,
            type="cidr", value="10.21.0.0/24", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )

    doomed = _issue_against(engagement_id, scope_object).capability
    bystander = _issue_against(engagement_id, other).capability

    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object,
            actor="engagement-manager",
        )

    assert _heartbeat(engagement_id, doomed.capability_id).renewed is False
    assert _heartbeat(engagement_id, bystander.capability_id).renewed is True

    with engagement_scope(engagement_id) as conn:
        assert get_capability(conn, bystander.capability_id).revoked is False


def test_a_capability_with_no_recorded_scope_object_abstains(
    engagement_id, credential
):
    """NULL is unknown, and unknown is neither a pass nor a veto.

    Capabilities predating the column have no recorded premise to re-check.
    Treating NULL as authorized would be a silent exemption; treating it as
    revoked would strand every capability issued before the migration. It is
    simply not a check that applies, and the other checks still run.
    """
    capability = _issued(engagement_id, credential_id=credential)
    assert capability.scope_object_id is None

    assert _heartbeat(engagement_id, capability.capability_id).renewed is True

    # The other preconditions are unaffected by abstaining here.
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE credentials SET revoked = TRUE WHERE credential_id = :c"),
            {"c": credential},
        )
    result = _heartbeat(engagement_id, capability.capability_id)
    assert result.renewed is False
    assert CREDENTIAL_REVOKED in result.reasons
