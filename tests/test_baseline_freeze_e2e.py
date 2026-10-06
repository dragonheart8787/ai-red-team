"""The baseline freeze (5.20) and the global role (5.37), through ``propose_action`` (D57).

``tests/test_baseline_freeze.py`` proves the freeze on the policy the engagement *loads*: which
layers merge, and the model of §4.5 over random histories. The D47/D51 lesson applies to it
unchanged -- a layer verified on its own function has not been shown to reach the decision the
system actually makes. ``propose_action`` is the one entry point; this file drives it, with the
policy ``load_effective_policy`` returns for each engagement, and asserts the **decision**.

The actions are random tokens (``freeze.<hex>``): the shared development database may carry any
number of live global baselines, and a real action name could already be allowed or denied by one
of them. A token can only be allowed by a layer this test published.
"""

from __future__ import annotations

import uuid

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.capability.broker import Budget
from control_plane.policy.layers import load_effective_policy
from tests.helpers import EngagementManager, make_engagement

# D60: propose_action opens its own transactions, one per stage, so what a test sets up
# first must be committed -- as it is in production. See tests/helpers.committing_scope.
from tests.helpers import committing_scope as engagement_scope
from tests.test_baseline_freeze import Globals, glob  # noqa: F401 - pytest fixture

CIDR = "10.57.0.0/24"
TARGET_IP = "10.57.0.10"


def _token() -> str:
    return f"freeze.{uuid.uuid4().hex[:10]}"


def _engagement(actions: list[str], customer: str = "CUST-FRZE2E") -> str:
    """A real engagement (``create_engagement``), with a scope that offers every action in
    ``actions``: scope is not what is under test, so it never differs between engagements."""
    eid = f"ENG-FRZE2E-{uuid.uuid4().hex[:10]}"
    make_engagement(eid, customer)
    manager = EngagementManager(eid)
    manager.scope(scope_object_id=f"SCOPE-{eid[-10:]}", type="cidr", value=CIDR,
                  allowed_actions=actions)
    return eid


def _propose(eid: str, action: str):
    """One proposal through the real entry point, under the policy this engagement loads now."""
    proposal = ProposedAction(
        action=action,
        target={"logical_identity": {"type": "ip", "value": TARGET_IP}},
        authorization={"source": "engagement_scope", "scope_object_id": f"SCOPE-{eid[-10:]}"},
        discovery={"source": "explicit_scope"},
        writes_data=False, changes_state=False,
    )
    with engagement_scope(eid) as conn:
        return propose_action(
            engagement_id=eid, proposal=proposal,
            reviewer=HonestFakeReviewer(risk_hint="low"),
            policy=load_effective_policy(conn, eid),
            agent_id="worker-1", network_allowlist=[CIDR], budget=Budget(max_duration_seconds=30),
        )


def test_a_baseline_published_after_the_freeze_does_not_change_the_decision(glob):  # noqa: F811
    """5.20, at the entry point. A widening baseline reaches an engagement created after it and
    does not reach one created before it -- the same proposal, the same moment, two decisions."""
    held, widened = _token(), _token()
    glob.publish("baseline_global", {"actions": {held: "ALLOW"}})
    frozen = _engagement([held, widened])

    assert _propose(frozen, held).decision == "ALLOW", "control: the frozen baseline allows it"
    assert _propose(frozen, widened).decision == "DENY", "not in the baseline it froze"

    glob.publish("baseline_global", {"actions": {widened: "ALLOW"}})
    later = _engagement([held, widened])

    after = _propose(frozen, widened)
    assert after.decision == "DENY", "a baseline published after the freeze reached the engagement"
    assert "action_not_in_policy" in after.deny_reasons
    assert _propose(later, widened).decision == "ALLOW", (
        "the control: an engagement created after the baseline follows it"
    )
    assert _propose(frozen, held).decision == "ALLOW", "and what it froze is still in force"


def test_an_emergency_overlay_reaches_a_frozen_engagement_and_lifting_it_restores_the_decision(
    glob,  # noqa: F811
):
    """5.20/5.37: the one thing that does cross the freeze, written by the global role."""
    action = _token()
    glob.publish("baseline_global", {"actions": {action: "ALLOW"}})
    eid = _engagement([action])
    assert _propose(eid, action).decision == "ALLOW"

    overlay = glob.publish("emergency_overlay", {"actions": {action: "DENY"}})
    denied = _propose(eid, action)
    assert denied.decision == "DENY"
    assert "action_denied_by_policy" in denied.deny_reasons

    glob.retire(overlay)
    assert _propose(eid, action).decision == "ALLOW", "retiring the overlay lifts it"


def test_a_baseline_retired_after_the_freeze_still_governs_the_frozen_engagement(
    glob,  # noqa: F811
):
    """'The baseline as first seen, not as later touched' (5.20 decision 3), as a decision."""
    action = _token()
    baseline = glob.publish("baseline_global", {"actions": {action: "ALLOW"}})
    frozen = _engagement([action])
    glob.retire(baseline)

    assert _propose(frozen, action).decision == "ALLOW"
    after_retirement = _engagement([action])
    assert _propose(after_retirement, action).decision == "DENY", (
        "the control: an engagement created after the retirement does not get it"
    )


def test_a_customer_layer_governs_only_that_customers_engagements_at_the_decision(
    glob,  # noqa: F811
):
    """5.35, at the entry point: a ``customer`` layer that names a customer applies to that
    customer's engagements and to no other's. The same proposal, two customers, two decisions."""
    action = _token()
    customer_a, customer_b = f"CUST-A-{uuid.uuid4().hex[:6]}", f"CUST-B-{uuid.uuid4().hex[:6]}"
    glob.publish("baseline_global", {"actions": {action: "ALLOW"}})
    eng_a = _engagement([action], customer_a)
    eng_b = _engagement([action], customer_b)
    assert _propose(eng_a, action).decision == "ALLOW"
    assert _propose(eng_b, action).decision == "ALLOW"

    glob.publish("customer", {"actions": {action: "DENY"}}, customer_id=customer_a)

    assert _propose(eng_a, action).decision == "DENY", "the customer's own layer did not apply"
    assert _propose(eng_b, action).decision == "ALLOW", (
        "another customer's layer reached this customer's engagement"
    )
