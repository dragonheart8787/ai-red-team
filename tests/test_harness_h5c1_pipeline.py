"""D69 H5c1: the loop over the real pipeline: plan, claim, work, propose, complete (design tests
1, 5 and 7; plan items 50, 51 and 54).

The roles are scripted, the reviewer is the control plane's fake and the sandbox is a stand-in: the
rows are the test database's. What is measured is what reaches the tables and what reaches
``propose_action``:

* H5-1: every proposal carries the task the loop claimed -- one that names none is given it, one
  that names another task is refused before ``propose_action`` is called;
* H5-26: the idempotency key stored with the proposal is ``h5:<task_id>:1`` (read back from
  ``action_proposals.request_idempotency_key``, not read off the call);
* H5-3: an exception inside ``propose_action`` is not swallowed: the loop ends with code 12, the
  rows are coherent and nothing is cleaned up;
* H5-5: after ``engage_kill_switch`` the loop makes no further ``propose_action`` call.
"""

from __future__ import annotations

import pytest

from control_plane.orchestrator import stages
from harness import loop_adapter
from harness.exit_codes import EXIT_CODE, EXIT_FAULT_OUTSIDE_LIST, StopReason
from harness.result_summary import is_valid_summary
from tests.test_harness_h5c1_support import (
    count_rows,
    drive,
    kill,
    make_rig,
    make_world,
    proposal_rows,
    queued_task,
    task_rows,
)


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _count_propose_action(monkeypatch) -> list:
    calls: list = []
    real = loop_adapter.propose_action

    def spy(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(loop_adapter, "propose_action", spy)
    return calls


# -- the whole path ----------------------------------------------------------------------------


def test_the_whole_path_plans_claims_works_proposes_and_completes_one_task(world, monkeypatch):
    proposed = _count_propose_action(monkeypatch)
    rig = make_rig(world)

    result = drive(rig.adapter)

    assert result.reason is StopReason.CAP_REACHED       # the one round the bounds allow
    assert (rig.supervisor.plan_calls, rig.worker.work_calls, rig.reviewer.calls) == (1, 1, 1)
    assert len(proposed) == 1
    ((task_id, status, owner, _, _, summary),) = task_rows(world.engagement_id)
    assert (status, owner) == ("completed", "scripted-worker")
    assert is_valid_summary(summary), summary
    ((_, proposal_task, stage, decision, _),) = proposal_rows(world.engagement_id)
    assert proposal_task == task_id
    # the decision depends on the policy layers of the database it runs on (the CI baseline is
    # neutral, so it is a DENY there); what is fixed is that one was made and the task says so
    assert decision in ("DENY", "ALLOW", "HUMAN_APPROVAL"), decision
    assert stage != stages.RECEIVED


# -- H5-26: the key --------------------------------------------------------------------------


def test_the_idempotency_key_stored_with_the_proposal_is_h5_task_1(world):
    rig = make_rig(world)

    drive(rig.adapter)

    ((task_id, *_),) = task_rows(world.engagement_id)
    ((_, _, _, _, stored_key),) = proposal_rows(world.engagement_id)
    assert stored_key == f"h5:{task_id}:1"


# -- H5-1: every proposal carries a live task -------------------------------------------------


def test_a_proposal_with_no_task_is_proposed_with_the_task_that_was_claimed(world):
    rig = make_rig(world, make_proposal=lambda task, task_id: world.proposal(task, None))

    drive(rig.adapter)

    ((task_id, *_),) = task_rows(world.engagement_id)
    ((_, stored_task, *_),) = proposal_rows(world.engagement_id)
    assert stored_task == task_id and stored_task is not None


def test_a_proposal_that_names_another_task_is_refused_before_propose_action(
        world, engagement_factory, monkeypatch):
    other_engagement, other_registry = engagement_factory()
    other_world = make_world(other_engagement, other_registry)
    foreign = queued_task(other_world, 7)
    proposed = _count_propose_action(monkeypatch)
    rig = make_rig(world, make_proposal=lambda task, task_id: world.proposal(task, foreign))

    result = drive(rig.adapter)

    assert result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert len(proposed) == 0 and rig.reviewer.calls == 0
    assert proposal_rows(world.engagement_id) == []
    assert proposal_rows(other_engagement) == []
    # nothing was cleaned up: the claimed task is still claimed
    ((_, status, *_),) = task_rows(world.engagement_id)
    assert status == "claimed"


# -- H5-3: an exception inside propose_action ------------------------------------------------


def test_an_exception_in_propose_action_is_not_swallowed_and_the_rows_stay_coherent(world):
    def boom():
        raise RuntimeError("injected into the pipeline")

    rig = make_rig(
        world, reviewer_hook=boom,
        tasks_for_call=lambda call: [world.task(5), world.task(6)])

    result = drive(rig.adapter)

    assert result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert EXIT_CODE[result.reason] == EXIT_FAULT_OUTSIDE_LIST == 12
    assert rig.reviewer.calls == 1                      # the call that raised, and no other
    # coherent: the proposal is where the pipeline left it -- received, never decided --
    # and nothing that follows a decision exists
    ((_, _, stage, decision, _),) = proposal_rows(world.engagement_id)
    assert stage in stages.UNDECIDED_STAGES and decision is None
    assert count_rows(world.engagement_id, "capabilities") == 0
    assert count_rows(world.engagement_id, "tool_runs") == 0
    assert rig.sandbox.calls == 0
    # code 12 cleans nothing up: the task of the fault is still claimed, the other still queued
    statuses = sorted(row[1] for row in task_rows(world.engagement_id))
    assert statuses == ["claimed", "queued"]


# -- H5-5: after the kill switch, no more propose_action calls ---------------------------------


def test_after_the_kill_switch_is_engaged_the_loop_makes_no_further_propose_action_call(
        world, monkeypatch):
    proposed = _count_propose_action(monkeypatch)
    engaged = []

    def kill_during_the_first_review():
        if not engaged:
            engaged.append(True)
            kill(world.engagement_id)

    rig = make_rig(
        world, reviewer_hook=kill_during_the_first_review,
        tasks_for_call=lambda call: [world.task(5), world.task(6), world.task(7)])

    result = drive(rig.adapter)

    assert engaged == [True]
    assert len(proposed) == 1                           # the first; none after the kill
    assert rig.reviewer.calls == 1 and rig.worker.work_calls == 1
    assert len(proposal_rows(world.engagement_id)) == 1
    assert result.reason is StopReason.CAP_REACHED
    # the two tasks that were never claimed are completed as not_run by the stop
    summaries = sorted(row[5] for row in task_rows(world.engagement_id))
    assert summaries.count("not_run") == 2


def test_a_killed_engagement_is_not_planned_for_and_nothing_reaches_propose_action(
        world, monkeypatch):
    proposed = _count_propose_action(monkeypatch)
    kill(world.engagement_id)
    rig = make_rig(world)

    drive(rig.adapter)

    assert len(proposed) == 0 and rig.reviewer.calls == 0
    assert rig.supervisor.plan_calls == 0 and rig.worker.work_calls == 0
    assert task_rows(world.engagement_id) == []


def test_a_kill_that_comes_in_while_the_worker_answers_stops_the_proposal(world, monkeypatch):
    proposed = _count_propose_action(monkeypatch)

    def kill_then_propose(task, task_id):
        kill(world.engagement_id)
        return world.proposal(task, task_id)

    rig = make_rig(world, make_proposal=kill_then_propose)

    drive(rig.adapter)

    assert rig.worker.work_calls == 1
    assert len(proposed) == 0 and rig.reviewer.calls == 0
    ((_, status, _, _, _, summary),) = task_rows(world.engagement_id)
    assert (status, summary) == ("completed", "not_run")
