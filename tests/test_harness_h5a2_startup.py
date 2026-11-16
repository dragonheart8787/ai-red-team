"""D69 H5a2: the start-up check in the loop's order of work (``harness/loop.py``).

The loop keeps the tasks it created in memory only, so an engagement that already has a live task
at the start is one it cannot account for: it refuses (code 10) and does nothing else (plan item
57). The check comes first -- before the snapshot, the planning call, any task creation and any
claim -- and is made once per engagement, on the engagement's first visit, so an engagement enrolled
between two rounds is checked before it is visited.
"""

from __future__ import annotations

import pytest

from harness.exit_codes import StopReason, exit_code
from harness.ports import LiveTask
from tests.harness_fakes import FakePorts, drive


def test_the_start_up_check_comes_before_snapshot_plan_creation_and_claim():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    drive(ports, max_rounds=1)

    order = ports.order()
    assert order[:5] == ["enrolled", "accepts_work", "live_tasks", "take_snapshot", "plan"]
    first = {name: order.index(name) for name in
             ("live_tasks", "take_snapshot", "plan", "claim", "work", "propose")}
    assert first["live_tasks"] < first["take_snapshot"] < first["plan"] < first["claim"]
    assert first["claim"] < first["work"] < first["propose"]

    # and when the check refuses, nothing after it happened: not a snapshot, not a plan, not a claim
    refused = FakePorts(("ENG-1",), tasks_per_plan=1)
    refused.live["ENG-1"] = (LiveTask("T-OLD-1", "queued"),)
    drive(refused, max_rounds=1)
    assert refused.order() == ["enrolled", "accepts_work", "live_tasks"]
    assert refused.count("claim") == 0


@pytest.mark.parametrize("status", ["queued", "claimed", "running"])
def test_a_live_task_on_the_engagement_refuses_the_start_with_code_10_and_nothing_else_is_called(
        status):
    ports = FakePorts(("ENG-1",))
    ports.live["ENG-1"] = (LiveTask("T-OLD-1", status),)

    run = drive(ports, max_rounds=5)

    assert run.result.reason is StopReason.STARTUP_REFUSED
    assert exit_code(run.result.reason) == 10
    assert ports.count("live_tasks") == 1
    for method in ("take_snapshot", "plan", "claim", "work", "load_policy", "propose", "complete"):
        assert ports.count(method) == 0, method
    assert run.result.rounds == 1


def test_one_live_row_is_enough_to_refuse_and_a_page_of_them_is_refused_too():
    ports = FakePorts(("ENG-1",))
    ports.live["ENG-1"] = tuple(LiveTask(f"T-OLD-{n}", "queued") for n in range(50))

    run = drive(ports, max_rounds=2)

    assert run.result.reason is StopReason.STARTUP_REFUSED
    assert ports.count("plan") == 0


def test_the_start_up_check_does_not_refuse_an_engagement_with_no_live_task():
    ports = FakePorts(("ENG-1",))
    ports.live["ENG-1"] = ()

    run = drive(ports, max_rounds=1)

    assert run.result.reason is StopReason.CAP_REACHED
    assert ports.count("plan") == 1


def test_an_engagement_enrolled_between_rounds_is_checked_before_it_is_visited():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    def enrol_after_the_first_plan(p, engagement_id, snapshot):
        if "ENG-2" not in p.enrolment.enrolled():
            p.enrolment.add("ENG-2")
            p.live["ENG-2"] = (LiveTask("T-OLD-2", "running"),)

    ports.after("plan", enrol_after_the_first_plan)

    run = drive(ports, max_rounds=5, no_progress=100)

    assert run.result.reason is StopReason.STARTUP_REFUSED
    assert exit_code(run.result.reason) == 10
    # ENG-1 is checked once, on its first visit; ENG-2 on its first, and it is refused there
    assert ports.calls("live_tasks") == [("live_tasks", "ENG-1"), ("live_tasks", "ENG-2")]
    assert [call[1] for call in ports.calls("plan")] == ["ENG-1", "ENG-1"]
    assert ports.calls("take_snapshot")[-1][1] == "ENG-1"
    assert run.result.rounds == 2


def test_the_start_up_check_is_made_once_per_engagement_and_process():
    ports = FakePorts(("ENG-1", "ENG-2"))

    drive(ports, max_rounds=4)

    assert ports.calls("live_tasks") == [("live_tasks", "ENG-1"), ("live_tasks", "ENG-2")]


def test_a_closed_engagement_is_not_start_checked_until_it_accepts_work():
    ports = FakePorts(("ENG-1",))
    ports.live["ENG-1"] = (LiveTask("T-OLD-1", "queued"),)
    ports.closed.add("ENG-1")

    run = drive(ports, max_rounds=2, no_progress=100)

    assert run.result.reason is StopReason.CAP_REACHED
    assert ports.count("live_tasks") == 0
