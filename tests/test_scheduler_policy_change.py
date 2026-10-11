"""A waiting approval is voided by a policy publication that applies to it (D63, D58-6).

An approval is a human saying yes to a decision under the policy in force then (I9). The broker
refuses to issue the capability if any policy layer applicable to the engagement has been published
since (``policy_version_changed``, ACCEPTANCE 5.56), and the refusal **closes** the proposal --
nothing re-proposes it. For a one-shot caller that is a re-proposal by hand; for a resident
scheduler that sits on approvals for as long as an engagement is paused, skipped or unenrolled it
is a routine event, and nothing yet owns what follows (the failure ladder, D58-6). These tests pin
what it does today, through a tick, so the gap is a recorded behaviour rather than an assumption:

* a publication that applies to the engagement (its own layer, or a global one) voids the waiting
  approval: the proposal is closed with the reason, nothing runs, the service does **not** stop, and
  later ticks leave it alone;
* a layer published for **another** engagement does not apply and changes nothing.
"""

from __future__ import annotations

import uuid

import pytest

from control_plane.orchestrator import stages
from control_plane.policy.layers import publish_policy_layer
from control_plane.scheduler import vocab
from control_plane.scheduler.service import Scheduler
from tests import scheduler_support as sup
from tests.helpers import committing_scope, deactivate_global_layer, publish_global_layer
from tests.test_scheduler_skips import RecordingSandbox

CIDR, HOST = "10.96.77.0/24", "10.96.77.9"


@pytest.fixture
def waiting(engagement_id, registry):
    """An approved proposal, enrolled, not yet dispatched."""
    sup.publish_engagement_policy(engagement_id)
    scope_id = sup.register_scope(registry, type="cidr", value=CIDR)
    pid = sup.approved_proposal(engagement_id, scope_id, host=HOST)
    sup.enroll(engagement_id)
    yield engagement_id, pid
    sup.withdraw(engagement_id)


def _stage(eid, pid):
    with committing_scope(eid) as conn:
        return stages.stage_of(conn, pid)


def _publish_engagement_layer(eid, version=2):
    with committing_scope(eid) as conn:
        publish_policy_layer(
            conn, engagement_id=eid, layer="engagement", version=version,
            document={"actions": {"network.scan": "ALLOW"}}, actor="policy-admin",
            scoped_to_engagement=True)


def _assert_voided(eid, pid, sandbox, exit_code):
    assert exit_code == vocab.EXIT_OK                   # the service carries on, it does not stop
    assert sandbox.calls == 0
    stage, detail = _stage(eid, pid)
    assert stage == stages.CLOSED
    assert detail.startswith("capability_refused:") and "policy_version_changed" in detail, detail
    assert sup.rows(eid, "SELECT 1 FROM capabilities") == []
    assert sup.rows(eid, "SELECT 1 FROM tool_runs") == []
    assert len(sup.audit(eid, "capability.refused")) == 1
    assert len(sup.audit(eid, "scheduler.dispatched")) == 1      # one attempt; not retried per tick


def test_an_engagement_layer_published_after_the_approval_voids_it_and_the_service_goes_on(waiting):
    eid, pid = waiting
    _publish_engagement_layer(eid)
    sandbox = RecordingSandbox()

    code = Scheduler(sandbox=sandbox, watchdog_interval=0.2).run(interval=0, max_ticks=4)

    _assert_voided(eid, pid, sandbox, code)


def test_a_global_layer_published_after_the_approval_voids_it_too(waiting):
    eid, pid = waiting
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    try:
        sandbox = RecordingSandbox()
        code = Scheduler(sandbox=sandbox, watchdog_interval=0.2).run(interval=0, max_ticks=3)
    finally:
        deactivate_global_layer(layer_id)
    _assert_voided(eid, pid, sandbox, code)


def test_a_layer_published_for_another_engagement_does_not_apply(waiting, engagement_factory):
    eid, pid = waiting
    other, _ = engagement_factory()
    _publish_engagement_layer(other)
    sandbox = RecordingSandbox()

    code = Scheduler(sandbox=sandbox, watchdog_interval=0.2).run(interval=0, max_ticks=2)

    assert code == vocab.EXIT_OK
    assert sandbox.calls == 1
    assert _stage(eid, pid) == (stages.RECORDED, "succeeded")


def test_a_voided_proposal_is_not_picked_up_again_by_later_ticks(waiting):
    eid, pid = waiting
    _publish_engagement_layer(eid)
    sandbox = RecordingSandbox()
    with sup.running(sandbox) as sched:
        first = sched.tick()
        later = [sched.tick() for _ in range(3)]
    assert first.dispatched == [pid]                    # it was handed over, and refused there
    assert all(r.dispatched == [] and r.skipped == [] for r in later)
    assert _stage(eid, pid)[0] == stages.CLOSED
