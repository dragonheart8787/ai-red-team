"""Human approval — the §4.7 operator surface (D24).

Drives the pipeline into HUMAN_APPROVAL the way a real model did (D11's
escalation-by-narration: a reviewer that names sensitive data), then exercises
the list / approve / deny surface end to end, the fail-closed refusals, and the
lease interaction the brief called out — a proposal legitimately waiting for a
human must not read as a stuck dispatch.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.approvals import (
    APPROVED_SCOPES,
    ApprovalError,
    deny_approval,
    grant_approval,
    list_pending_approvals,
)
from control_plane.api.function_api import propose_action
from control_plane.audit.query import events_for_subject
from control_plane.orchestrator.dispatch import reconcile_stale_dispatches
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.registry.scope_registry import deactivate_scope_object
from control_plane.state.db import engagement_scope, registry_admin_scope

CIDR = "10.79.0.0/24"
HOST = "10.79.0.2"


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global",
                    data_deny=frozenset({"PII", "customer_database"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _escalated_proposal(conn, engagement_id, scope_id):
    """Run one proposal that OPA sends to HUMAN_APPROVAL, the D11 Case-D way.

    A reviewer that names sensitive data trips ``sensitive_data_hint``; the
    action is otherwise allowed and the target authorized, so the only reason
    is the escalation. Returns the outcome (decision HUMAN_APPROVAL, no
    capability).
    """
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": HOST},
                "ports": "8080", "scan_type": "connect"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
    )
    return propose_action(
        conn, engagement_id=engagement_id, proposal=proposal,
        reviewer=HonestFakeReviewer(sensitive_hint=("pii",)),
        policy=_policy(), agent_id="worker-1",
    )


@pytest.fixture
def escalated(engagement_id, registry):
    """An engagement with one HUMAN_APPROVAL proposal waiting."""
    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.recon", "network.scan"])
    with engagement_scope(engagement_id) as conn:
        outcome = _escalated_proposal(conn, engagement_id, scope_id)
    assert outcome.decision == "HUMAN_APPROVAL"
    assert outcome.capability_id is None
    return engagement_id, scope_id, outcome.proposal_id


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

def test_list_shows_only_opa_escalated_proposals(escalated):
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        pending = list_pending_approvals(conn, engagement_id=engagement_id)
    assert [p["proposal_id"] for p in pending] == [proposal_id]
    assert "sensitive_data_hint" in pending[0]["decision_reasons"]


def test_listing_writes_nothing(escalated):
    """Constraint 3: viewing is read-only, like D14. md5 the tables it reads."""
    engagement_id, _, _ = escalated
    tables = ("action_proposals", "approvals", "audit_log", "capabilities")
    with engagement_scope(engagement_id) as conn:
        def snap():
            return [conn.execute(text(
                f"SELECT md5(string_agg(t::text, '' ORDER BY t::text)) FROM {tb} t"
            )).scalar_one() for tb in tables]
        before = snap()
        list_pending_approvals(conn, engagement_id=engagement_id)
        assert snap() == before


# ---------------------------------------------------------------------------
# approve
# ---------------------------------------------------------------------------

def test_approve_writes_a_structured_object_and_issues_a_capability(escalated):
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        outcome = grant_approval(
            conn, engagement_id=engagement_id, proposal_id=proposal_id,
            approver="alice", approved_scope="this_proposal_only",
        )
        assert outcome.issued
        # §4.7 structured object, not a yes/no (constraint 2).
        appr = conn.execute(
            text("SELECT action_class, resource, valid_until, approved_by, "
                 "approved_scope FROM approvals WHERE approval_id = :a"),
            {"a": outcome.approval_id},
        ).mappings().one()
        assert appr["action_class"] == "network.scan"
        assert appr["resource"] == "ip:10.79.0.2"
        assert appr["approved_scope"] == "this_proposal_only"
        assert appr["approved_by"] == "alice"
        assert appr["valid_until"] is not None
        # Constraint 5: a real capability, issued by the broker, citing the approval.
        cap = conn.execute(
            text("SELECT approval_id, revoked FROM capabilities "
                 "WHERE capability_id = :c"),
            {"c": outcome.capability_id},
        ).mappings().one()
        assert cap["approval_id"] == outcome.approval_id
        assert cap["revoked"] is False
    # No longer pending.
    with engagement_scope(engagement_id) as conn:
        assert list_pending_approvals(conn, engagement_id=engagement_id) == []


def test_approve_records_who_when_scope_and_proposal(escalated):
    """Constraint 3: the decision is audited through the existing path."""
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        grant_approval(conn, engagement_id=engagement_id, proposal_id=proposal_id,
                       approver="alice", approved_scope="this_task")
    with engagement_scope(engagement_id) as conn:
        events = events_for_subject(conn, subject_id=proposal_id,
                                    event_types=["approval.granted"])
    assert len(events) == 1
    e = events[0]
    assert e.actor == "alice"
    assert e.payload["approved_scope"] == "this_task"
    assert e.payload["proposal_id"] if "proposal_id" in e.payload else e.subject_id == proposal_id
    assert e.ts is not None


def test_every_approved_scope_is_accepted(escalated):
    """Each §4.7 scope is a real choice — not one button. Fresh proposal each."""
    engagement_id, scope_id, _ = escalated
    for scope in APPROVED_SCOPES:
        with engagement_scope(engagement_id) as conn:
            pid = _escalated_proposal(conn, engagement_id, scope_id).proposal_id
            outcome = grant_approval(
                conn, engagement_id=engagement_id, proposal_id=pid,
                approver="alice", approved_scope=scope)
            assert outcome.approved_scope == scope
            assert outcome.issued


def test_an_unknown_scope_is_refused_and_nothing_is_written(escalated):
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(ApprovalError, match="approved_scope"):
            grant_approval(conn, engagement_id=engagement_id,
                           proposal_id=proposal_id, approver="alice",
                           approved_scope="approve_everything")
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM approvals")).scalar_one() == 0
        assert list_pending_approvals(conn, engagement_id=engagement_id)


def test_only_a_human_approval_proposal_can_be_approved(engagement_id, registry):
    """Constraint 1: this surface never approves something OPA did not escalate.

    The foil is a DENY (an out-of-scope target), which — like HUMAN_APPROVAL —
    returns before the broker, so no dispatch and no sandbox is involved.
    """
    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    with engagement_scope(engagement_id) as conn:
        proposal = ProposedAction(
            action="network.scan",
            target={"logical_identity": {"type": "ip", "value": "203.0.113.9"},
                    "ports": "8080", "scan_type": "connect"},
            authorization={"source": "engagement_scope",
                           "scope_object_id": scope_id},
            discovery={"source": "explicit_scope"})
        denied = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="w")
        assert denied.decision == "DENY"
        with pytest.raises(ApprovalError, match="not awaiting a human"):
            grant_approval(conn, engagement_id=engagement_id,
                           proposal_id=denied.proposal_id, approver="alice",
                           approved_scope="this_proposal_only")


def test_a_proposal_cannot_be_approved_twice(escalated):
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        grant_approval(conn, engagement_id=engagement_id, proposal_id=proposal_id,
                       approver="alice", approved_scope="this_proposal_only")
        with pytest.raises(ApprovalError, match="already has a live approval"):
            grant_approval(conn, engagement_id=engagement_id,
                           proposal_id=proposal_id, approver="bob",
                           approved_scope="this_task")


def test_approval_refused_fail_closed_when_scope_no_longer_authorizes(escalated):
    """Constraint 4: an approval must not resurrect a target the registry
    stopped covering. Retire the scope, then approve, and nothing is written."""
    engagement_id, scope_id, proposal_id = escalated
    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(conn, engagement_id=engagement_id,
                                scope_object_id=scope_id, actor="em")
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(ApprovalError, match="fail-closed"):
            grant_approval(conn, engagement_id=engagement_id,
                           proposal_id=proposal_id, approver="alice",
                           approved_scope="this_proposal_only")
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM approvals")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM capabilities")).scalar_one() == 0


# ---------------------------------------------------------------------------
# deny
# ---------------------------------------------------------------------------

def test_deny_records_the_decision_and_issues_nothing(escalated):
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        deny_approval(conn, engagement_id=engagement_id, proposal_id=proposal_id,
                      denier="alice", reason="outside the approved window")
    with engagement_scope(engagement_id) as conn:
        assert list_pending_approvals(conn, engagement_id=engagement_id) == []
        assert conn.execute(text("SELECT count(*) FROM capabilities")).scalar_one() == 0
        events = events_for_subject(conn, subject_id=proposal_id,
                                    event_types=["approval.denied"])
    assert len(events) == 1 and events[0].actor == "alice"
    assert events[0].payload["reason"] == "outside the approved window"


def test_a_denied_proposal_cannot_then_be_approved(escalated):
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        deny_approval(conn, engagement_id=engagement_id, proposal_id=proposal_id,
                      denier="alice")
        with pytest.raises(ApprovalError, match="already denied"):
            grant_approval(conn, engagement_id=engagement_id,
                           proposal_id=proposal_id, approver="bob",
                           approved_scope="this_proposal_only")


# ---------------------------------------------------------------------------
# lease / pending-approval interaction (brief step 3, constraint 5)
# ---------------------------------------------------------------------------

def test_a_pending_approval_is_not_mistaken_for_a_stuck_dispatch(escalated):
    """A proposal waiting for a human has no capability and its dispatch_state
    is 'queued' — not IN_FLIGHT — so the stale-dispatch sweep leaves it alone,
    however long it waits. "Legitimately waiting" is not "stuck"."""
    engagement_id, _, proposal_id = escalated
    with engagement_scope(engagement_id) as conn:
        # No capability was ever issued for it.
        assert conn.execute(
            text("SELECT count(*) FROM capabilities WHERE proposal_id = :p"),
            {"p": proposal_id}).scalar_one() == 0
        state_before = conn.execute(
            text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id}).scalar_one()
        # Sweep with a zero threshold: everything older than "now" is fair game.
        stale = reconcile_stale_dispatches(
            conn, engagement_id=engagement_id, older_than_seconds=0, actor="sweeper")
        state_after = conn.execute(
            text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id}).scalar_one()
        anomalies = events_for_subject(
            conn, subject_id=proposal_id, event_types=["dispatch.unknown_outcome"])
    assert proposal_id not in stale
    assert state_before == "queued" and state_after == "queued"
    assert anomalies == []  # no spurious anomaly raised
