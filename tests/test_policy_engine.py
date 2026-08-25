"""End-to-end policy evaluation: registries → resolvers → merge → OPA (§5).

The Rego suite tests the policy against hand-written inputs. These tests drive
the same policy through the real path — rows in the registries, the resolvers
reading them, merge.py producing the effective policy — so a mismatch between
what the resolvers emit and what the Rego expects shows up here rather than in
production. Hand-written fixtures cannot catch a shape mismatch, because the
fixture is the shape.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api import function_api
from control_plane.canonicalizer.authorization import resolve_authorization
from control_plane.canonicalizer.metadata import resolve_metadata
from control_plane.canonicalizer.target import normalize_target
from control_plane.capability.broker import Budget
from control_plane.policy.engine import build_policy_input, evaluate
from control_plane.policy.merge import ALLOW, DENY, PolicyLayer, merge_policy
from control_plane.registry.scope_registry import list_scope_objects
from control_plane.state.db import engagement_scope
from tests.scenarios.conftest import RecordingBroker


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _policy(actions, data_deny=("PII", "customer_database")):
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset(data_deny), actions=actions),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _decide(conn, *, target, action, scope_object_id, policy, **kw):
    authorization = resolve_authorization(
        conn, target=target, action=action,
        authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
    )
    metadata = resolve_metadata(conn, target=target)
    # A budget wide enough not to bind, unless a test says otherwise. Since D12
    # the policy denies a proposal with no stated capability request at all
    # (I10), so leaving it out here would make every test in this file pass for
    # a reason it is not about.
    kw.setdefault("capability_request", {"max_targets": 1024,
                                         "max_duration_seconds": 120})
    return evaluate(build_policy_input(
        target=target, action=action, authorization=authorization, metadata=metadata,
        policy=policy, scope_objects=list_scope_objects(conn), **kw,
    ))


@pytest.fixture
def engagement_with_scope(engagement_id, registry):
    """An engagement with a cidr scope object authorizing network.scan.

    Seeded through registry_admin, read back through cyberorch_app -- the same
    split production uses (§5).
    """
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.recon", "network.scan"])
    return engagement_id, sid


def test_authorized_scan_of_a_known_host_is_allowed(engagement_with_scope, registry):
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}})
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="ip", identity_value="10.20.0.7",
        authority="AUTHORITATIVE", source="customer_declared",
        resource_class=["host"], data_class=["network_service"],
    )
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
        )
    assert decision.decision == "ALLOW", decision
    assert decision.engine_error is None


def test_adversarial_reviewer_cannot_talk_a_pii_host_into_allow(
    engagement_with_scope, registry
):
    """I6b through the real path.

    The customer declared PII at AUTHORITATIVE. The reviewer files an LLM_HINT
    saying the host is a harmless static site, reports risk "low", and offers no
    sensitive-data hint. Every honest signal it controls says "go ahead".
    """
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.9"}})
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="ip", identity_value="10.20.0.9",
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["PII"], resource_class=["customer_database"],
    )
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="ip", identity_value="10.20.0.9",
        authority="LLM_HINT", source="adversarial_fake_reviewer",
        data_class=[], resource_class=["static_site"],
    )
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}),
            risk_hint="low", possible_sensitive_data_hint=[],
        )

    assert decision.decision == "DENY", decision
    assert "forbidden_data" in decision.deny_reasons
    # Denied on the classification, not on some incidental malformation.
    assert "target_out_of_scope" not in decision.deny_reasons


def test_fqdn_scope_does_not_authorize_scanning_the_resolved_address(
    engagement_id, registry
):
    """§4.1.5 / I8 end to end."""
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    with engagement_scope(engagement_id) as conn:
        decision = _decide(
            conn,
            target=normalize_target({
                "logical_identity": {"type": "ip", "value": "203.0.113.17"},
                "network_binding": {"ip": "203.0.113.17", "dns_ttl": 300},
            }),
            action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
        )
    assert decision.decision == "DENY"
    assert "target_out_of_scope" in decision.deny_reasons


def test_unregistered_host_may_still_be_scanned(engagement_with_scope):
    """§5: unknown must not block the recon that produces classifications."""
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.55"}})
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
        )
    assert decision.decision == "ALLOW", decision


def test_action_no_layer_mentioned_is_denied(engagement_with_scope):
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}})
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({}), risk_hint="low",
        )
    assert decision.decision == "DENY"
    assert "action_not_in_policy" in decision.deny_reasons


def test_emergency_overlay_deny_reaches_the_decision(engagement_with_scope):
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}})
    policy = merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay", actions={"network.scan": DENY}),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement", actions={"network.scan": ALLOW}),
    )
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=policy, risk_hint="low",
        )
    assert decision.decision == "DENY"
    assert "action_denied_by_policy" in decision.deny_reasons


# ---------------------------------------------------------------------------
# Capability budget (§4.6, I3) — D11-4
# ---------------------------------------------------------------------------

def test_a_range_larger_than_the_budget_is_denied(engagement_with_scope):
    """The D11 counterexample through the real resolvers.

    ``max_targets: 1`` against ``10.20.0.0/24``. The scope object covers the
    whole range and permits the action, so nothing incidental produces the
    DENY — the only thing wrong with this proposal is its size.
    """
    eid, sid = engagement_with_scope
    target = normalize_target(
        {"logical_identity": {"type": "cidr", "value": "10.20.0.0/24"}}
    )
    assert target.address_count == 256

    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
            capability_request={"max_targets": 1, "max_duration_seconds": 120},
        )

    assert decision.decision == "DENY", decision
    assert "target_count_exceeds_budget" in decision.deny_reasons
    assert "target_out_of_scope" not in decision.deny_reasons


def test_the_same_range_is_allowed_once_the_budget_covers_it(engagement_with_scope):
    """The control for the test above.

    Only the budget changes. Without this, a DENY caused by the target being a
    cidr at all — or by anything else about a /24 — would look identical.
    """
    eid, sid = engagement_with_scope
    target = normalize_target(
        {"logical_identity": {"type": "cidr", "value": "10.20.0.0/24"}}
    )
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
            capability_request={"max_targets": 256, "max_duration_seconds": 120},
        )
    assert decision.decision == "ALLOW", decision


def test_a_proposal_with_no_stated_budget_is_denied(engagement_with_scope):
    """I10: silence about a budget is not permission to have none."""
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}})
    with engagement_scope(eid) as conn:
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
            capability_request={},
        )
    assert decision.decision == "DENY", decision
    assert "capability_budget_missing" in decision.deny_reasons


class _ExplodingSandbox:
    """Reaching the Tool Gateway at all is the failure."""

    image = "should-never-run"

    def run(self, **kwargs):  # pragma: no cover - the assertion is the point
        raise AssertionError(f"the sandbox was reached on a DENY: {kwargs}")


def test_the_budget_deny_happens_before_a_capability_exists(
    engagement_with_scope, registry, monkeypatch
):
    """*Where* the DENY happens, not just that one happens.

    This is the part a decision-level test cannot show. "Denied at OPA" and
    "capability issued, then refused by the broker or the gateway" both end in
    no scan, and only the first means the authorization was never granted —
    which is the whole reason D12 put the check in the policy rather than
    downstream.

    So the broker is wrapped and its call count asserted at zero, the same
    technique §10's Scenario B uses for the same reason: the absence of a
    capability row cannot tell "never asked for" from "asked for and refused".
    """
    eid, sid = engagement_with_scope
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="cidr", identity_value="10.20.0.0/24",
        authority="AUTHORITATIVE", source="customer_declared",
        resource_class=["network_host"], data_class=["network_service"],
    )
    broker_spy = RecordingBroker(function_api.issue_capability)
    monkeypatch.setattr(function_api, "issue_capability", broker_spy)

    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "cidr", "value": "10.20.0.0/24"},
                "ports": "8080", "scan_type": "connect"},
        authorization={"source": "engagement_scope", "scope_object_id": sid},
        discovery={"source": "explicit_scope"},
        resources=("network_host",), expected_data=("port_state",),
        reason="scan the range",
    )

    with engagement_scope(eid) as conn:
        outcome = function_api.propose_action(
            conn, engagement_id=eid, proposal=proposal,
            reviewer=HonestFakeReviewer(risk_hint="low"),
            policy=_policy({"network.scan": ALLOW}), agent_id="fake-worker",
            sandbox=_ExplodingSandbox(),
            network_allowlist=["10.20.0.0/24"],
            budget=Budget(max_duration_seconds=120, max_targets=1),
        )

    assert outcome.decision == "DENY", outcome
    assert "target_count_exceeds_budget" in outcome.deny_reasons

    # The distinction this test exists for.
    assert broker_spy.call_count == 0, (
        "a capability was requested; the deny happened downstream of OPA"
    )
    assert outcome.capability_id is None
    assert outcome.failure != "capability_refused"

    # And nothing was written, which the call count alone would not show if
    # some other path had minted one.
    with engagement_scope(eid) as conn:
        assert conn.execute(
            text("SELECT count(*) FROM capabilities WHERE proposal_id = :p"),
            {"p": outcome.proposal_id},
        ).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM tool_runs")).scalar_one() == 0
        events = [
            r[0] for r in conn.execute(
                text("SELECT event_type FROM audit_log WHERE subject_id = :p "
                     "ORDER BY audit_id"),
                {"p": outcome.proposal_id},
            ).all()
        ]
    assert "policy.decided" in events
    assert "capability.issued" not in events


def test_engine_failure_is_denied_not_permitted(engagement_with_scope, tmp_path):
    """I10: a policy engine that cannot answer must not mean 'yes'."""
    from control_plane.policy.engine import evaluate as raw_evaluate

    decision = raw_evaluate({"action": {}}, rego_dir=tmp_path / "no-policy-here")
    assert decision.decision == "DENY"
    assert "policy_engine_unavailable" in decision.deny_reasons
    assert decision.engine_error
