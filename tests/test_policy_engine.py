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

from control_plane.canonicalizer.authorization import resolve_authorization
from control_plane.canonicalizer.metadata import resolve_metadata
from control_plane.canonicalizer.target import normalize_target
from control_plane.policy.engine import build_policy_input, evaluate
from control_plane.policy.merge import ALLOW, DENY, PolicyLayer, merge_policy
from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import list_scope_objects, register_scope_object
from control_plane.state.db import engagement_scope


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
    return evaluate(build_policy_input(
        target=target, action=action, authorization=authorization, metadata=metadata,
        policy=policy, scope_objects=list_scope_objects(conn), **kw,
    ))


@pytest.fixture
def engagement_with_scope(engagement_id):
    """An engagement with a cidr scope object authorizing network.scan."""
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="cidr",
            value="10.20.0.0/24", allowed_actions=["network.recon", "network.scan"],
            actor="engagement-manager",
        )
    return engagement_id, sid


def test_authorized_scan_of_a_known_host_is_allowed(engagement_with_scope):
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}})
    with engagement_scope(eid) as conn:
        register_metadata(
            conn, engagement_id=eid, asset_id=_uid("ASSET"), identity_type="ip",
            identity_value="10.20.0.7", authority="AUTHORITATIVE",
            source="customer_declared", resource_class=["host"],
            data_class=["network_service"], actor="engagement-manager",
        )
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}), risk_hint="low",
        )
    assert decision.decision == "ALLOW", decision
    assert decision.engine_error is None


def test_adversarial_reviewer_cannot_talk_a_pii_host_into_allow(engagement_with_scope):
    """I6b through the real path.

    The customer declared PII at AUTHORITATIVE. The reviewer files an LLM_HINT
    saying the host is a harmless static site, reports risk "low", and offers no
    sensitive-data hint. Every honest signal it controls says "go ahead".
    """
    eid, sid = engagement_with_scope
    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.9"}})
    with engagement_scope(eid) as conn:
        register_metadata(
            conn, engagement_id=eid, asset_id=_uid("ASSET"), identity_type="ip",
            identity_value="10.20.0.9", authority="AUTHORITATIVE",
            source="customer_declared", data_class=["PII"],
            resource_class=["customer_database"], actor="engagement-manager",
        )
        register_metadata(
            conn, engagement_id=eid, asset_id=_uid("ASSET"), identity_type="ip",
            identity_value="10.20.0.9", authority="LLM_HINT",
            source="adversarial_fake_reviewer", data_class=[],
            resource_class=["static_site"], actor="engagement-manager",
        )
        decision = _decide(
            conn, target=target, action="network.scan", scope_object_id=sid,
            policy=_policy({"network.scan": ALLOW}),
            risk_hint="low", possible_sensitive_data_hint=[],
        )

    assert decision.decision == "DENY", decision
    assert "forbidden_data" in decision.deny_reasons
    # Denied on the classification, not on some incidental malformation.
    assert "target_out_of_scope" not in decision.deny_reasons


def test_fqdn_scope_does_not_authorize_scanning_the_resolved_address(engagement_id):
    """§4.1.5 / I8 end to end."""
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="app.customer-a.com", allowed_actions=["web.*"], actor="em",
        )
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


def test_engine_failure_is_denied_not_permitted(engagement_with_scope, tmp_path):
    """I10: a policy engine that cannot answer must not mean 'yes'."""
    from control_plane.policy.engine import evaluate as raw_evaluate

    decision = raw_evaluate({"action": {}}, rego_dir=tmp_path / "no-policy-here")
    assert decision.decision == "DENY"
    assert "policy_engine_unavailable" in decision.deny_reasons
    assert decision.engine_error
