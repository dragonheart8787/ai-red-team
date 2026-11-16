"""D69 H5a2: the pause and kill check, at each of its three positions (``harness/loop.py``).

The loop asks ``accepts_work`` three times on the way to a proposal: before the Supervisor is
called, before a task is claimed and before the proposal (the last one, after the Worker has
answered). ``propose_action`` itself reads the engagement's state only at its first stage and when
dispatch starts, so a pause or a kill that comes in between is seen by nothing but these checks
(plan items 54 and 76). Each position has its own test, and each counts the calls that must not
happen: ``claim``, ``propose`` and ``complete``.

The stand-in answers a ``propose`` on a closed engagement with ``HUMAN_APPROVAL``, which is what
the pipeline does to a killed one; a test that sees zero ``propose`` calls has therefore shown that
the loop did not ask, not that the answer was harmless.
"""

from __future__ import annotations

import pytest

from harness.exit_codes import StopReason
from tests.harness_fakes import FakeOutcome, FakePorts, drive


def test_position_1_a_closed_engagement_is_not_planned_for_and_nothing_follows():
    ports = FakePorts(("ENG-1",))
    ports.closed.add("ENG-1")

    run = drive(ports, max_rounds=3, no_progress=100)

    assert ports.count("plan") == 0
    assert ports.count("take_snapshot") == 0
    assert ports.count("claim") == 0
    assert ports.count("propose") == 0
    assert ports.count("complete") == 0
    assert run.counters.count("skipped_engagement") == 3        # once in each of the 3 rounds
    assert run.result.reason is StopReason.CAP_REACHED


def test_position_1_a_closed_engagement_does_not_stop_the_others():
    ports = FakePorts(("ENG-1", "ENG-2"))
    ports.closed.add("ENG-1")

    run = drive(ports, max_rounds=1)

    assert [call[1] for call in ports.calls("plan")] == ["ENG-2"]
    assert [call[1] for call in ports.calls("propose")] == ["ENG-2"]
    assert run.counters.count("skipped_engagement") == 1


def test_position_2_an_engagement_closed_after_planning_is_not_claimed_from():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.after("plan", lambda p, engagement_id, snapshot: p.closed.add(engagement_id))

    run = drive(ports, max_rounds=1)

    assert ports.count("plan") == 1
    assert ports.count("claim") == 0
    assert ports.count("work") == 0
    assert ports.count("propose") == 0
    # the two tasks the plan created are completed once, as not_run, by the controlled stop
    assert ports.count("complete") == 2
    assert [summary for _, _, summary in ports.completed] == ["not_run", "not_run"]
    assert run.counters.count("skipped_engagement") == 1
    assert run.counters.count("not_run") == 2
    assert run.result.reason is StopReason.CAP_REACHED


@pytest.mark.parametrize("how, outcome_if_asked", [
    ("killed: HUMAN_APPROVAL if asked", None),
    ("paused: ALLOW if asked", FakeOutcome("ALLOW", None, "RUN-X", "EV-X")),
], ids=["killed: HUMAN_APPROVAL if asked", "paused: ALLOW if asked"])
def test_position_3_an_engagement_closed_after_the_worker_answered_is_not_proposed_to(
        how, outcome_if_asked):
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.after("work", lambda p, engagement_id, task_id, snapshot: p.closed.add(engagement_id))
    if outcome_if_asked is not None:
        ports.outcome_script = [outcome_if_asked]

    run = drive(ports, max_rounds=1)

    task_id = ports.created[0][1]
    assert ports.count("claim") == 1
    assert ports.count("work") == 1
    assert ports.count("propose") == 0, how
    assert ports.count("complete") == 1
    assert ports.completed == [("ENG-1", task_id, "not_run")]
    assert run.counters.count("skipped_engagement") == 1
    assert run.counters.count("not_run") == 1
    assert run.result.reason is StopReason.CAP_REACHED


def test_a_kill_that_comes_in_after_a_proposal_is_not_noticed_until_the_next_check():
    # The first task is proposed; the engagement is killed during its propose. The second task's
    # work is the next thing, and the check before the proposal refuses it.
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.after("propose", lambda p, engagement_id, task_id: p.closed.add(engagement_id))

    run = drive(ports, max_rounds=1)

    first, second = (task for _, task in ports.created)
    assert ports.count("propose") == 1
    # after the kill the claim-time check (position 2) refuses before the second claim
    assert ports.count("claim") == 1
    assert ports.completed == [("ENG-1", first, "executed"), ("ENG-1", second, "not_run")]
    assert run.counters.count("skipped_engagement") == 1
