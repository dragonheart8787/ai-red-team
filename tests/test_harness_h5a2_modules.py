"""D69 H5a2: the small modules on their own (``startup_check``, ``signals``, ``worker_step``,
``ports``) and the arguments ``run_loop`` refuses.
"""

from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace

import pytest

from harness import ports as ports_module
from harness.action_allowlist import RefusalCounter
from harness.bounds import Bounds, RunCounters
from harness.loop import LoopResult, run_loop
from harness.ports import LiveTask, LoopPorts, PlannedTask, PlanResult, WorkResult
from harness.signals import SignalFlag, StopFlag, handler_for, install
from harness.startup_check import STARTUP_PROCEED, STARTUP_REFUSE, decide_startup, owns
from harness.worker_step import STEP_NOT_RUN, STEP_PROPOSE, decide_after_work
from tests.harness_fakes import FakePorts

# -- startup_check ----------------------------------------------------------------------------


def test_no_live_task_proceeds():
    assert decide_startup(()) == STARTUP_PROCEED == "proceed"
    assert decide_startup([]) == "proceed"


@pytest.mark.parametrize("status", ["queued", "claimed", "running"])
def test_any_live_task_whatever_its_status_refuses_the_start(status):
    assert decide_startup((LiveTask("T-1", status),)) == STARTUP_REFUSE == "refuse"


def test_several_live_tasks_of_mixed_status_refuse_and_so_does_a_row_of_an_unknown_status():
    rows = (LiveTask("T-1", "running"), LiveTask("T-2", "claimed"), LiveTask("T-3", "queued"))
    assert decide_startup(rows) == "refuse"
    assert decide_startup((LiveTask("T-9", "something_else"),)) == "refuse"


@pytest.mark.parametrize("rows", ["T-1", b"T-1", None, 5, {"T-1": 1}.keys()])
def test_rows_that_are_not_a_sequence_are_refused_as_a_value_error(rows):
    with pytest.raises(ValueError):
        decide_startup(rows)


def test_owns_is_true_only_for_a_non_empty_string_in_the_set():
    assert owns("T-1", {"T-1", "T-2"}) is True
    assert owns("T-3", {"T-1", "T-2"}) is False
    assert owns("T-1", set()) is False
    assert owns("", {""}) is False
    assert owns(5, {5}) is False
    assert owns(None, {"T-1"}) is False
    assert owns("T-1", ["T-1"]) is True


# -- signals ----------------------------------------------------------------------------------


def test_a_signal_flag_wraps_an_event_and_starts_unset():
    flag = SignalFlag()
    assert flag.is_set() is False
    flag.set()
    assert flag.is_set() is True
    assert isinstance(flag._event, threading.Event)


def test_the_handler_sets_the_flag_whatever_arguments_a_signal_gives_it():
    flag = SignalFlag()
    handler = handler_for(flag)

    assert handler(15, None) is None
    assert flag.is_set()


def test_install_registers_one_handler_per_signal_number_with_the_function_it_is_given():
    registered: list[tuple[int, object]] = []
    flag = SignalFlag()

    install(lambda number, handler: registered.append((number, handler)), flag, (15, 2))

    assert [number for number, _ in registered] == [15, 2]
    assert flag.is_set() is False                               # registering sets nothing
    for _, handler in registered:
        handler(15, None)
    assert flag.is_set() is True


def test_a_flag_and_an_event_both_serve_as_a_stop_flag():
    assert callable(SignalFlag().is_set)
    assert callable(threading.Event().is_set)
    assert StopFlag is not None


# -- worker_step ------------------------------------------------------------------------------


def test_a_refusal_or_no_proposal_is_not_run_and_the_refusal_counter_stays_empty():
    refusals = RefusalCounter()

    assert decide_after_work(WorkResult(None, True), refusals) == STEP_NOT_RUN
    assert decide_after_work(WorkResult({"action": "network.scan"}, True, "network.scan"),
                             refusals) == STEP_NOT_RUN
    assert decide_after_work(WorkResult(None, False, "network.scan"), refusals) == STEP_NOT_RUN
    assert refusals.total == 0


@pytest.mark.parametrize("action", ["network.scan", "network.recon"])
def test_a_proposal_on_the_allowlist_goes_on_to_the_proposal(action):
    refusals = RefusalCounter()

    assert decide_after_work(WorkResult({"a": 1}, False, action), refusals) == STEP_PROPOSE
    assert refusals.total == 0


@pytest.mark.parametrize("action, reason", [
    ("ad.collect", "action_not_in_allowlist"), ("web.get", "action_not_in_allowlist"),
    (None, "action_missing"), ("", "action_missing"), (5, "action_missing"),
])
def test_a_proposal_outside_the_allowlist_is_not_run_and_the_refusal_is_counted(action, reason):
    refusals = RefusalCounter()

    assert decide_after_work(WorkResult({"a": 1}, False, action), refusals) == STEP_NOT_RUN
    assert refusals.entries() == (("proposal", reason),)


# -- ports ------------------------------------------------------------------------------------


def test_the_interface_has_the_ten_methods_with_the_fixed_names_and_no_others():
    public = {name for name in vars(LoopPorts) if not name.startswith("_")}
    assert public == {
        "accepts_work", "live_tasks", "take_snapshot", "plan", "claim", "work", "load_policy",
        "propose", "complete",
    }
    assert "enrolled" in dir(LoopPorts)                          # the tenth, from EnrolmentReader


def test_the_small_dataclasses_are_frozen_and_have_the_fields_the_loop_reads():
    for cls, fields in (
        (LiveTask, ("task_id", "status")), (PlannedTask, ("task_id",)),
        (PlanResult, ("created", "failure")), (WorkResult, ("proposal", "refusal", "action")),
    ):
        assert [f.name for f in dataclasses.fields(cls)] == list(fields)
        instance = cls(*([None] * len(fields)))
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(instance, fields[0], "x")
    assert PlanResult() == PlanResult(created=(), failure=None)
    assert WorkResult() == WorkResult(proposal=None, refusal=False, action=None)
    assert ports_module.__doc__


def test_the_test_stand_in_has_every_method_of_the_interface():
    interface = {"enrolled", "accepts_work", "live_tasks", "take_snapshot", "plan", "claim",
                 "work", "load_policy", "propose", "complete"}
    assert all(callable(getattr(FakePorts(), name, None)) for name in interface)


# -- run_loop's arguments --------------------------------------------------------------------


def _arguments(**changes):
    arguments = {
        "ports": FakePorts(), "bounds": Bounds(2, 10, 2), "counters": RunCounters(),
        "refusals": RefusalCounter(), "window_limit": 5, "stop_event": SignalFlag(),
    }
    arguments.update(changes)
    return arguments


@pytest.mark.parametrize("changes", [
    {"bounds": SimpleNamespace()}, {"counters": {}}, {"refusals": None},
    {"window_limit": 0}, {"window_limit": -1}, {"window_limit": True}, {"window_limit": "5"},
    {"stop_event": None}, {"stop_event": object()}, {"once": 1}, {"once": None},
])
def test_an_argument_of_the_wrong_kind_is_refused_before_anything_is_called(changes):
    arguments = _arguments(**changes)
    ports = arguments["ports"]

    with pytest.raises(ValueError):
        run_loop(**arguments)

    assert ports.log == []


def test_a_threading_event_serves_as_the_stop_event():
    event = threading.Event()
    event.set()

    result = run_loop(**_arguments(stop_event=event))

    assert isinstance(result, LoopResult)
    assert result.rounds == 0


def test_the_result_carries_the_reason_the_rounds_and_a_snapshot_of_the_counters():
    arguments = _arguments(bounds=Bounds(1, 100, 100))

    result = run_loop(**arguments)

    assert result.rounds == 1
    assert result.counters == arguments["counters"].snapshot()
    assert result.counters is not arguments["counters"].snapshot()
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.rounds = 5
