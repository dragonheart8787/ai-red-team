"""D69 H5a2: the bounds as the loop applies them (``harness/loop.py`` over ``harness/bounds.py``).

``Bounds.record_model_call()`` and ``start_round()`` only count; the cap is kept entirely by the
loop asking ``call_may_be_made()`` before each model call and ``round_may_start()`` before each
round (plan item 73). So the test of a cap is a count of what the stand-ins were actually asked:
with a cap of N model calls the Supervisor, the Worker and the proposal were called N times in
all, not N plus the one that was already under way.

A model call is a ``plan``, a ``work`` or a ``propose`` (the pipeline calls the Reviewer inside it).
"""

from __future__ import annotations

import pytest

from harness.exit_codes import StopReason, exit_code
from harness.ports import PlanResult, WorkResult
from tests.harness_fakes import FakeOutcome, FakePorts, drive


@pytest.mark.parametrize("cap", range(1, 13))
def test_the_cap_of_n_model_calls_gives_exactly_n_calls_to_the_supervisor_worker_and_proposal(cap):
    # Each round is one plan and two tasks: 1 + 2 * (work + propose) = 5 model calls.
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)

    run = drive(ports, max_rounds=50, max_calls=cap, no_progress=100)

    assert ports.model_calls() == cap
    assert ports.count("plan") + ports.count("work") + ports.count("propose") == cap
    assert run.result.reason is StopReason.CAP_REACHED
    assert exit_code(run.result.reason) == 13
    assert not run.bounds.call_may_be_made()


@pytest.mark.parametrize("cap", [1, 2, 3, 4])
def test_with_two_engagements_the_cap_still_gives_exactly_n_calls(cap):
    ports = FakePorts(("ENG-1", "ENG-2"), tasks_per_plan=2)

    run = drive(ports, max_rounds=50, max_calls=cap, no_progress=100)

    assert ports.model_calls() == cap
    assert run.result.reason is StopReason.CAP_REACHED


@pytest.mark.parametrize("rounds", [1, 2, 3, 4])
def test_the_round_cap_of_r_starts_exactly_r_rounds(rounds):
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    run = drive(ports, max_rounds=rounds, no_progress=100)

    assert run.result.rounds == rounds
    assert ports.count("plan") == rounds
    assert run.result.reason is StopReason.CAP_REACHED


def test_the_last_permitted_round_reports_cap_reached_at_its_end_and_not_one_round_later():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    run = drive(ports, max_rounds=2, no_progress=100)

    # plan item 73 (5): completing the last round also reports the cap, so the loop ends there
    assert run.result.rounds == 2
    assert run.result.reason is StopReason.CAP_REACHED
    assert ports.count("complete") == 2


def test_a_proposal_that_reached_propose_is_progress_a_deny_included():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.outcome_script = [FakeOutcome("DENY", "capability_refused") for _ in range(5)]

    run = drive(ports, max_rounds=5, no_progress=2)

    # five proposals, every one denied: never two rounds in a row without progress
    assert ports.count("propose") == 5
    assert run.result.reason is StopReason.CAP_REACHED
    assert [summary for _, _, summary in ports.completed] == ["DENY:capability_refused"] * 5


def test_rounds_that_created_tasks_but_proposed_nothing_are_rounds_without_progress():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.work_script = [WorkResult(None, True) for _ in range(10)]

    run = drive(ports, max_rounds=10, no_progress=3)

    assert run.result.reason is StopReason.NO_PROGRESS
    assert exit_code(run.result.reason) == 14
    assert run.result.rounds == 3
    assert ports.count("plan") == 3 and ports.count("work") == 3
    assert ports.count("propose") == 0


def test_a_round_that_skipped_every_engagement_is_a_round_without_progress():
    ports = FakePorts(("ENG-1", "ENG-2"))
    ports.closed.update({"ENG-1", "ENG-2"})

    run = drive(ports, max_rounds=10, no_progress=2)

    assert run.result.reason is StopReason.NO_PROGRESS
    assert run.result.rounds == 2
    assert run.counters.count("skipped_engagement") == 4        # two engagements, two rounds


def test_a_planning_failure_is_a_round_without_progress():
    ports = FakePorts(("ENG-1",))
    ports.plan_script = [PlanResult((), "plan_refused") for _ in range(5)]

    run = drive(ports, max_rounds=10, no_progress=2)

    assert run.result.reason is StopReason.NO_PROGRESS
    assert ports.count("claim") == 0


def test_an_empty_enrolment_is_a_round_without_progress_and_calls_nothing_else():
    ports = FakePorts(())

    run = drive(ports, max_rounds=10, no_progress=2)

    assert run.result.reason is StopReason.NO_PROGRESS
    assert run.result.rounds == 2
    assert set(ports.order()) == {"enrolled"}


def test_the_enrolment_is_read_once_per_round():
    ports = FakePorts(("ENG-1", "ENG-2"))

    run = drive(ports, max_rounds=3)

    assert ports.count("enrolled") == run.result.rounds == 3


def test_once_runs_exactly_one_round_and_stops_with_code_0():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)

    run = drive(ports, max_rounds=10, no_progress=10, once=True)

    assert run.result.rounds == 1
    assert run.result.reason is StopReason.SIGNAL_OR_ONCE
    assert exit_code(run.result.reason) == 0
    assert ports.count("plan") == 1
    assert ports.count("propose") == 2


def test_the_model_call_count_of_a_run_is_what_the_bounds_recorded():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)

    run = drive(ports, max_rounds=2, max_calls=100, no_progress=100)

    assert ports.model_calls() == 10
    # every call the stand-ins saw was recorded: the next one would be the 11th of a cap of 10
    for _ in range(90):
        run.bounds.record_model_call()
    assert not run.bounds.call_may_be_made()
