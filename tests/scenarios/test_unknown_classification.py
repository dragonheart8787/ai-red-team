"""An unknown classification escalates a writing action (§5, I10).

Sweep findings #15/#16. ``writes_data`` and ``changes_state`` are read by the
Rego rule ``requires_known_classification``, which is how I10 — fail-closed on
an ambiguous attribute — reaches the policy. The Rego side was well covered:
``policy_tests/authz_test.rego`` proves that given these fields, the rule
decides correctly.

Nothing proved the fields arrive. ``propose_action`` reads them off the proposal
and passes them to ``build_policy_input``, and if that wiring were dropped every
Rego test would still pass, every Python test would still pass, and a writing
action against an unclassified target would proceed unattended. The gap was
between two well-tested halves.

So these tests assert on the input actually handed to the policy engine, and on
the decision that comes back — the two ends of the wiring, rather than either
side of it.
"""

from __future__ import annotations

import pytest

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api import function_api
from control_plane.api.function_api import propose_action
from control_plane.policy.engine import evaluate
from control_plane.state.db import engagement_scope
from tests.scenarios.conftest import ALLOWED_CIDR, uid

UNCLASSIFIED_IP = "10.79.0.31"


@pytest.fixture
def engagement_with_unclassified_target(engagement_id, registry):
    """In scope, and deliberately absent from the Metadata Registry.

    No AUTHORITATIVE row, and no row of any lower tier either — so the resolver
    reports unknown rather than CONFLICT, which is the I10 case these tests are
    about.
    """
    scope_object_id = uid("SCOPE")
    registry.scope(
        scope_object_id=scope_object_id, type="cidr", value=ALLOWED_CIDR,
        allowed_actions=["network.recon", "network.scan", "data.read"],
    )
    return engagement_id, scope_object_id


@pytest.fixture
def captured_policy_input(monkeypatch):
    """Record the input handed to the policy engine, then evaluate for real.

    Wrapping rather than stubbing: a stub would let the test assert on an input
    that OPA never saw, which is the same class of mistake as testing the two
    halves separately.
    """
    captured: list[dict] = []

    def recording_evaluate(policy_input, *args, **kwargs):
        captured.append(policy_input)
        return evaluate(policy_input, *args, **kwargs)

    monkeypatch.setattr(function_api, "evaluate", recording_evaluate)
    return captured


def _propose(engagement, effective_policy, *, writes_data=False,
             changes_state=False, action="network.scan"):
    engagement_id, scope_object_id = engagement
    proposal = ProposedAction(
        action=action,
        target={"logical_identity": {"type": "ip", "value": UNCLASSIFIED_IP},
                "ports": "8080"},
        authorization={"source": "engagement_scope",
                       "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
        reason="sweep #15/#16 coverage",
        writes_data=writes_data,
        changes_state=changes_state,
    )
    with engagement_scope(engagement_id) as conn:
        return propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=effective_policy,
            agent_id="fake-worker", sandbox=None,
            network_allowlist=[ALLOWED_CIDR],
        )


@pytest.mark.parametrize("field", ["writes_data", "changes_state"])
def test_the_flag_reaches_the_policy_input(
    engagement_with_unclassified_target, effective_policy, captured_policy_input,
    field,
):
    """The wiring itself: proposal -> build_policy_input -> OPA."""
    _propose(engagement_with_unclassified_target, effective_policy,
             **{field: True})

    assert len(captured_policy_input) == 1
    action_input = captured_policy_input[0]["action"]
    assert action_input[field] is True, (
        f"{field} was set on the proposal but arrived at the policy as "
        f"{action_input.get(field)!r}"
    )
    # The other flag stays false, so a test asserting on one cannot pass
    # because both were hardcoded true somewhere.
    other = "changes_state" if field == "writes_data" else "writes_data"
    assert action_input[other] is False

    # And the classification really is unknown, which is what makes the rule
    # fire rather than something incidental.
    assert captured_policy_input[0]["resource_metadata"]["known"] is False


@pytest.mark.parametrize("field", ["writes_data", "changes_state"])
def test_a_writing_action_on_an_unclassified_target_needs_a_human(
    engagement_with_unclassified_target, effective_policy, captured_policy_input,
    field,
):
    """I10 end to end: the prerequisite is missing, so it cannot proceed alone.

    The half the Rego tests could not reach. If propose_action stopped passing
    these flags, this is the test that fails.
    """
    outcome = _propose(engagement_with_unclassified_target, effective_policy,
                       **{field: True})

    assert outcome.decision == "HUMAN_APPROVAL"
    assert "unknown_classification_for_action_class" in outcome.approval_reasons
    assert outcome.metadata_authority == "UNKNOWN"
    assert outcome.canonical_data_class == ()

    # Escalated, not denied — and not executed either. HUMAN_APPROVAL stops the
    # pipeline in the same place DENY does.
    assert outcome.deny_reasons == ()
    assert outcome.capability_id is None
    assert outcome.run_id is None


def test_a_read_only_action_on_the_same_target_is_not_escalated(
    engagement_with_unclassified_target, effective_policy, captured_policy_input
):
    """The control that makes the two tests above mean something.

    Same target, same unknown classification, both flags false. If this also
    escalated, the assertions above would be satisfied by an unconditional
    escalation and would prove nothing about the flags.
    """
    outcome = _propose(engagement_with_unclassified_target, effective_policy)

    assert captured_policy_input[0]["action"]["writes_data"] is False
    assert captured_policy_input[0]["action"]["changes_state"] is False
    assert captured_policy_input[0]["resource_metadata"]["known"] is False

    assert "unknown_classification_for_action_class" not in outcome.approval_reasons
    assert outcome.decision == "ALLOW"


def test_both_flags_together_still_escalate_once(
    engagement_with_unclassified_target, effective_policy
):
    """Two reasons to require the prerequisite, one reason recorded.

    ``approval_reasons`` is a set in Rego, so the rule firing along both
    branches yields a single entry rather than a duplicate. Worth pinning: a
    caller that counted reasons would otherwise see the number change with the
    proposal's shape.
    """
    outcome = _propose(engagement_with_unclassified_target, effective_policy,
                       writes_data=True, changes_state=True)

    assert outcome.decision == "HUMAN_APPROVAL"
    assert outcome.approval_reasons.count(
        "unknown_classification_for_action_class"
    ) == 1
