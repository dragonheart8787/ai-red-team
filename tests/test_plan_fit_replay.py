"""The replay at the approval re-derivation (D68 S3, ACCEPTANCE 5.116): the part of P1 without
which, the day the switch is on, every approval path would be wounded.

``dispatch_approved`` re-derives the decision from the registries and OPA, and refuses if the fresh
decision shows an approval reason the human was not shown (``new_approval_reasons``). It rebuilds
the proposal from its stored row, and that rebuilt proposal has no ``task_id``. So a signal that is
recomputed there reads ``no_task`` for every proposal; and one read from the task's status now reads
``task_not_live`` for any task that finished while the approval waited -- the ordinary case. The
stored signal must be replayed, as the reviewer's hints are, and an absent one must stay absent.

**Why the existing approval tests do not cover this.** They build task-less proposals: decided
``no_task`` and recomputed ``no_task``, the two agree whether or not there is a replay. These tests
use proposals *with* tasks, and rows from before the signal existed.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.approved_dispatch import NEW_APPROVAL_REASONS, dispatch_approved
from control_plane.api.function_api import propose_action
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from tests.helpers import committing_scope as engagement_scope
from tests.task_support import task_for
from tests.test_approved_dispatch import CIDR, _proposal, approve, rows, stage
from tests.test_pipeline_stages import FakeSandbox


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id}


def policy(enforce=True):
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII", "customer_database"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement", task_relation_enforce=enforce),
    )


def propose(world, *, reviewer, task="none", enforce=True, host=None):
    """A proposal under a policy with the switch ``enforce``; ``task``: none | matching | other."""
    proposal = _proposal(world) if host is None else _proposal(world, host=host)
    eid = world["engagement_id"]
    if task == "matching":
        proposal = _with_task(proposal, task_for(eid, proposal))
    elif task == "other":
        other = _proposal(world, host="10.61.0.99")
        proposal = _with_task(proposal, task_for(eid, other))
    return propose_action(
        engagement_id=eid, proposal=proposal, reviewer=reviewer, policy=policy(enforce),
        agent_id="worker-1")


def _with_task(proposal, task_id):
    import dataclasses

    return dataclasses.replace(proposal, task_id=task_id)


def dispatch(world, proposal_id, *, enforce=True):
    sandbox = FakeSandbox()
    return dispatch_approved(
        engagement_id=world["engagement_id"], proposal_id=proposal_id, policy=policy(enforce),
        sandbox=sandbox, network_allowlist=[CIDR])


WORRIED = HonestFakeReviewer(sensitive_hint=("pii",))


def _hints(world, proposal_id):
    return rows(world, "SELECT reviewer_hints FROM action_proposals WHERE proposal_id = :p",
                p=proposal_id)[0]["reviewer_hints"]


def test_a_matching_task_that_finished_while_the_approval_waited_still_dispatches(world):
    """The ordinary case. Decided ``matches_task`` with a reason that is only the reviewer's; the
    task completes; the approval is used. A recompute from the rebuilt proposal says ``no_task``
    (no task_id) or ``task_not_live`` (status) -- a reason the human never saw."""
    out = propose(world, reviewer=WORRIED, task="matching")
    assert out.decision == "HUMAN_APPROVAL" and out.approval_reasons == ("sensitive_data_hint",)
    assert _hints(world, out.proposal_id)["plan_fit"]["task_relation"] == "matches_task"
    approve(world, out.proposal_id)
    with engagement_scope(world["engagement_id"]) as conn:
        conn.execute(text("UPDATE tasks SET status = 'completed'"))
    done = dispatch(world, out.proposal_id)
    assert done.executed, (done.failure, done.deny_reasons)
    assert stage(world, out.proposal_id)[0] == "recorded"


def test_a_proposal_outside_its_task_is_approved_with_the_reason_shown_and_dispatches(world):
    out = propose(world, reviewer=HonestFakeReviewer(), task="other")
    assert out.decision == "HUMAN_APPROVAL"
    assert out.approval_reasons == ("proposal_outside_task",)
    approve(world, out.proposal_id)
    done = dispatch(world, out.proposal_id)
    assert done.executed, (done.failure, done.deny_reasons)


def test_a_proposal_with_no_task_is_approved_with_the_reason_shown_and_dispatches(world):
    out = propose(world, reviewer=HonestFakeReviewer(), task="none")
    assert out.approval_reasons == ("proposal_without_task",)
    approve(world, out.proposal_id)
    assert dispatch(world, out.proposal_id).executed


def test_a_row_from_before_the_signal_existed_adds_nothing_and_dispatches(world):
    """No ``plan_fit`` in the stored hints: absent stays absent. (Recomputed from the rebuilt
    proposal it would read ``no_task`` and refuse every such approval.)"""
    out = propose(world, reviewer=WORRIED, task="matching")
    with engagement_scope(world["engagement_id"]) as conn:
        conn.execute(text(
            "UPDATE action_proposals SET reviewer_hints = reviewer_hints - 'plan_fit'"))
    assert "plan_fit" not in _hints(world, out.proposal_id)
    approve(world, out.proposal_id)
    assert dispatch(world, out.proposal_id).executed


@pytest.mark.parametrize("stored", [
    {"version": "plan_fit_v9", "task_relation": "matches_task", "sub_cause": None},
    {"version": "plan_fit_v1", "task_relation": "probably_fine", "sub_cause": None},
    None,
    "matches_task",
])
def test_a_stored_signal_that_cannot_be_read_refuses_the_dispatch_loudly(world, stored):
    """Fail closed, in the direction that is visible: an unreadable stored value counts as outside
    the plan, which adds a reason the approver was never shown, so the dispatch is refused with
    ``new_approval_reasons`` -- it does not run, and it does not pass quietly."""
    import json

    out = propose(world, reviewer=WORRIED, task="matching")
    with engagement_scope(world["engagement_id"]) as conn:
        conn.execute(
            text("UPDATE action_proposals SET reviewer_hints = jsonb_set(reviewer_hints, "
                 "'{plan_fit}', CAST(:v AS jsonb))"), {"v": json.dumps(stored)})
    approve(world, out.proposal_id)
    done = dispatch(world, out.proposal_id)
    assert not done.executed
    assert NEW_APPROVAL_REASONS in done.deny_reasons, (done.failure, done.deny_reasons)


def test_turning_the_switch_on_after_an_approval_refuses_it_and_the_reason_is_named(world):
    """Approved while the switch was off (stored ``no_task``, no reason shown), dispatched with it
    on: the human never saw ``proposal_without_task``, so the approval does not cover it. The same
    effect as any policy change (``policy_changed``, tested elsewhere); here the in-memory policy
    has the same version, so it is the new reason alone that refuses."""
    out = propose(world, reviewer=WORRIED, task="none", enforce=False)
    assert out.approval_reasons == ("sensitive_data_hint",)
    approve(world, out.proposal_id)
    done = dispatch(world, out.proposal_id, enforce=True)
    assert not done.executed
    assert NEW_APPROVAL_REASONS in done.deny_reasons


def test_with_the_switch_off_at_both_ends_the_signal_changes_nothing(world):
    out = propose(world, reviewer=WORRIED, task="none", enforce=False)
    approve(world, out.proposal_id)
    assert dispatch(world, out.proposal_id, enforce=False).executed
