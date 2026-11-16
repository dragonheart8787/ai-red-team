"""D69 H5a2: how the loop stops, and what it cleans up (``harness/loop.py``).

Two kinds of stop (plan item 58). A *controlled* stop -- a signal or ``--once``, a refused
start-up check, a cap, no progress -- is a state the loop understands: it completes, as ``not_run``
and in the engagement each belongs to, every task it created and never claimed. A *fault* -- a
foreign task (code 11), a key conflict, any exception, an a2 ``ValueError`` (code 12) -- leaves
everything where it is, the claimed task it happened on included, for a person to look at. Where
the two rules could meet, the fault rule wins: a fault is never cleaned up.
"""

from __future__ import annotations

from collections import Counter

import pytest

from harness.exit_codes import StopReason, exit_code
from harness.ports import LiveTask, PlannedTask, PlanResult
from harness.signals import SignalFlag
from tests.harness_fakes import FakeOutcome, FakePorts, drive

KEY_CONFLICT = "idempotency_key_reused_with_a_different_request"


def leaving_tasks_unclaimed() -> FakePorts:
    """Two engagements whose ``claim`` always answers ``None``: ENG-A gets two tasks a round and
    ENG-B one, and every one of them stays created and unclaimed."""
    ports = FakePorts(("ENG-A", "ENG-B"), tasks_per_plan={"ENG-A": 2, "ENG-B": 1})
    ports.claim_none.update({"ENG-A", "ENG-B"})
    return ports


def enrol_a_residual_engagement_after_the_first_round(ports: FakePorts) -> None:
    def enrol(p, engagement_id):
        if engagement_id == "ENG-B" and "ENG-C" not in p.enrolment.enrolled():
            p.enrolment.add("ENG-C")
            p.live["ENG-C"] = (LiveTask("T-OLD", "claimed"),)

    ports.after("claim", enrol)


def raise_the_stop_flag_at_the_last_claim(ports: FakePorts, flag) -> None:
    ports.after("claim", lambda p, engagement_id: flag.set() if engagement_id == "ENG-B" else None)


@pytest.mark.parametrize("why, expected_reason, expected_code", [
    ("signal", StopReason.SIGNAL_OR_ONCE, 0),
    ("cap", StopReason.CAP_REACHED, 13),
    ("no progress", StopReason.NO_PROGRESS, 14),
    ("start-up check refused", StopReason.STARTUP_REFUSED, 10),
])
def test_a_controlled_stop_completes_the_loops_own_unclaimed_tasks_as_not_run(
        why, expected_reason, expected_code):
    ports = leaving_tasks_unclaimed()
    flag = SignalFlag()
    limits = {"max_rounds": 10, "no_progress": 100, "flag": flag}
    if why == "signal":
        raise_the_stop_flag_at_the_last_claim(ports, flag)
    elif why == "cap":
        limits["max_rounds"] = 1
    elif why == "no progress":
        limits["no_progress"] = 1
    else:
        enrol_a_residual_engagement_after_the_first_round(ports)

    run = drive(ports, **limits)

    assert run.result.reason is expected_reason
    assert exit_code(run.result.reason) == expected_code
    # every task the plans created, in the engagement it was created for, completed once as not_run
    assert ports.created, "the scenario created no task"
    expected = Counter(
        (engagement_id, task_id, "not_run") for engagement_id, task_id in ports.created)
    assert Counter(ports.completed) == expected
    assert set(expected.values()) == {1}
    assert all(task_id.startswith(f"T-{engagement_id}-")
               for engagement_id, task_id, _ in ports.completed)
    assert run.counters.count("not_run") == len(expected)
    assert ports.count("claim") >= 1
    assert ports.count("propose") == 0


def test_a_controlled_stop_that_follows_two_rounds_cleans_up_the_tasks_of_both():
    ports = leaving_tasks_unclaimed()

    run = drive(ports, max_rounds=2, no_progress=100)

    assert run.result.reason is StopReason.CAP_REACHED
    assert len(ports.created) == 6                              # (2 + 1) tasks in each of 2 rounds
    assert Counter(ports.completed) == Counter(
        (engagement_id, task_id, "not_run") for engagement_id, task_id in ports.created)


def test_a_controlled_stop_with_nothing_unclaimed_completes_nothing():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)

    run = drive(ports, max_rounds=1)

    assert run.result.reason is StopReason.CAP_REACHED
    assert [summary for _, _, summary in ports.completed] == ["executed", "executed"]


@pytest.mark.parametrize("foreign", ["FOREIGN-1", "", 5, "T-ENG-1-NOT-CREATED"])
def test_a_claim_that_returns_a_foreign_task_id_stops_with_code_11_and_proposes_nothing(foreign):
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.claim_script = [foreign]

    run = drive(ports, max_rounds=3)

    assert run.result.reason is StopReason.FOREIGN_TASK
    assert exit_code(run.result.reason) == 11
    assert ports.count("claim") == 1
    assert ports.count("work") == 0
    assert ports.count("propose") == 0
    assert ports.count("complete") == 0                         # a fault cleans up nothing


def test_a_task_the_loop_created_but_already_claimed_is_foreign_the_second_time():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    # the first claim hands out the first task; the second claim answers with that same id again
    ports.after("claim", lambda p, engagement_id: (
        p.claim_script.append(p.created[0][1]) if p.count("claim") == 1 else None))

    run = drive(ports, max_rounds=3)

    assert run.result.reason is StopReason.FOREIGN_TASK
    assert ports.count("claim") == 2
    assert ports.count("propose") == 1                          # only the first, own, task


def test_a_key_conflict_is_a_fault_with_code_12_not_a_result():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.outcome_script = [FakeOutcome(
        "DENY", "idempotency key names a different action or target",
        deny_reasons=(KEY_CONFLICT,))]

    run = drive(ports, max_rounds=3)

    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert exit_code(run.result.reason) == 12
    assert ports.count("propose") == 1
    assert ports.count("complete") == 0         # neither the claimed task nor the unclaimed one


def test_an_outcome_the_summary_builder_refuses_stops_with_code_12_and_does_not_clean_up():
    # an evidence id with no run id is not a state the pipeline produces: a ValueError of a2
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.outcome_script = [FakeOutcome("ALLOW", None, None, "EV-1")]

    run = drive(ports, max_rounds=3)

    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert exit_code(run.result.reason) == 12
    assert ports.count("complete") == 0
    assert ports.count("claim") == 1


@pytest.mark.parametrize("method", [
    "enrolled", "accepts_work", "live_tasks", "take_snapshot", "plan", "claim", "work",
    "load_policy", "propose", "complete",
])
def test_an_exception_from_any_port_stops_with_code_12_and_is_not_swallowed(method):
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.raise_on(method, RuntimeError("MODEL-WORDS-7c1f secret"))

    run = drive(ports, max_rounds=3)

    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert exit_code(run.result.reason) == 12
    assert ports.log[-1][0] == method           # the loop did not go on after the exception
    assert ports.count(method) == 1
    assert ports.completed == []                # nothing was cleaned up
    assert "MODEL-WORDS" not in repr(run.result)


def test_an_exception_that_is_not_a_runtime_error_is_a_fault_too():
    ports = FakePorts(("ENG-1",))
    ports.raise_on("plan", KeyError("x"))

    run = drive(ports)

    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST


def test_an_exception_while_cleaning_up_ends_as_a_fault_and_the_clean_up_is_not_retried():
    ports = leaving_tasks_unclaimed()
    ports.raise_on("complete", RuntimeError("write failed"), nth=1)

    run = drive(ports, max_rounds=1)

    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert ports.count("complete") == 1         # the first attempt; the other two are not tried
    assert ports.completed == []


def test_a_fault_leaves_the_tasks_it_did_not_complete_alone():
    ports = FakePorts(("ENG-1",), tasks_per_plan=3)
    ports.raise_on("work", RuntimeError("x"), nth=2)

    run = drive(ports, max_rounds=3)

    first = ports.created[0][1]
    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert ports.completed == [("ENG-1", first, "executed")]    # the one finished before the fault


def test_a_plan_that_names_an_empty_or_a_repeated_task_id_is_a_fault():
    for planned in ((PlannedTask(""),), (PlannedTask("T-1"), PlannedTask("T-1"))):
        ports = FakePorts(("ENG-1",))
        ports.plan_script = [PlanResult(created=planned)]

        run = drive(ports, max_rounds=2)

        assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
        assert ports.completed == []


def test_a_stop_reason_of_a_controlled_stop_is_never_replaced_by_the_cleanup_when_it_works():
    ports = leaving_tasks_unclaimed()

    run = drive(ports, max_rounds=1)

    assert run.result.reason is StopReason.CAP_REACHED
    assert run.result.counters["not_run"] == 3
    assert run.result.counters["skipped_engagement"] == 0
