"""D69 H5a1 (a4): the loop's bounds as a state machine, and the closed run counters
(``harness/bounds.py``).

Every value is given by the caller and none has a default; the module holds no number of its own
(D69-5d: the caps and N are written down before the first run and not tuned from data). The numbers
in these tests are the tests'. No database, no clock.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from harness import bounds as b
from harness.bounds import Bounds, RunCounters
from harness.exit_codes import StopReason

BIG = 1000


def started(n: int, *, max_rounds: int = 3) -> Bounds:
    bounds = Bounds(max_rounds, BIG, BIG)
    for _ in range(n):
        bounds.start_round()
    return bounds


def called(n: int, *, max_calls: int = 5) -> Bounds:
    bounds = Bounds(BIG, max_calls, BIG)
    for _ in range(n):
        bounds.record_model_call()
    return bounds


def run_rounds(bounds: Bounds, progress: list[bool]) -> Bounds:
    for flag in progress:
        bounds.start_round()
        bounds.end_round(flag)
    return bounds


# ---------------------------------------------------------------- the round cap


@pytest.mark.parametrize("n,may", [(0, True), (1, True), (2, True), (3, False), (4, False)])
def test_a_round_may_start_only_while_fewer_than_max_rounds_have_started(n, may):
    assert started(n, max_rounds=3).round_may_start() is may


@pytest.mark.parametrize("n,may", [(0, True), (4, True), (5, False), (6, False), (7, False)])
def test_a_model_call_may_be_made_only_while_fewer_than_the_cap_are_recorded(n, may):
    assert called(n, max_calls=5).call_may_be_made() is may


def test_the_round_cap_is_a_stop_the_call_cap_is_a_stop_and_neither_is_not():
    assert started(2, max_rounds=3).stop_reason() is None
    assert started(3, max_rounds=3).stop_reason() is StopReason.CAP_REACHED
    assert started(4, max_rounds=3).stop_reason() is StopReason.CAP_REACHED
    assert called(4, max_calls=5).stop_reason() is None
    assert called(5, max_calls=5).stop_reason() is StopReason.CAP_REACHED
    assert called(6, max_calls=5).stop_reason() is StopReason.CAP_REACHED


# ---------------------------------------------------------------- no progress


@pytest.mark.parametrize("failures,reason", [
    (0, None), (1, None), (2, None),
    (3, StopReason.NO_PROGRESS), (4, StopReason.NO_PROGRESS), (5, StopReason.NO_PROGRESS)])
def test_the_run_of_rounds_without_progress_stops_at_its_limit(failures, reason):
    bounds = run_rounds(Bounds(BIG, BIG, 3), [False] * failures)
    assert bounds.stop_reason() is reason


@pytest.mark.parametrize("sequence,reason", [
    ([False, False, True], None),
    ([False, False, True, False, False], None),
    ([False, False, True, False, False, False], StopReason.NO_PROGRESS),
    ([True, True, True, True], None),
    ([False, True, False, True, False], None),
])
def test_progress_resets_the_run_of_rounds_without_it(sequence, reason):
    assert run_rounds(Bounds(BIG, BIG, 3), sequence).stop_reason() is reason


def test_a_limit_of_one_stops_after_the_first_round_without_progress():
    assert run_rounds(Bounds(BIG, BIG, 1), [True]).stop_reason() is None
    assert run_rounds(Bounds(BIG, BIG, 1), [True, False]).stop_reason() is StopReason.NO_PROGRESS


# ---------------------------------------------------------------- the priority


def test_when_the_cap_and_no_progress_both_hold_the_cap_is_reported():
    bounds = run_rounds(Bounds(2, BIG, 2), [False, False])
    # two rounds started (the cap) and two in a row without progress (the limit)
    assert bounds.stop_reason() is StopReason.CAP_REACHED
    calls = Bounds(BIG, 1, 1)
    calls.record_model_call()
    calls.start_round()
    calls.end_round(False)
    assert calls.stop_reason() is StopReason.CAP_REACHED


def test_no_progress_is_reported_when_only_it_holds():
    bounds = run_rounds(Bounds(BIG, BIG, 2), [False, False])
    assert bounds.stop_reason() is StopReason.NO_PROGRESS


# ---------------------------------------------------------------- parameters


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("bad", [0, -1, True, False, 1.5, "3", None, [3]])
def test_a_parameter_that_is_not_an_int_of_at_least_one_is_refused(position, bad):
    values = [3, 3, 3]
    values[position] = bad
    with pytest.raises(ValueError):
        Bounds(*values)


def test_end_round_takes_a_bool_and_nothing_else():
    bounds = Bounds(BIG, BIG, 3)
    for bad in (1, 0, None, "yes"):
        with pytest.raises(ValueError):
            bounds.end_round(bad)


def test_every_parameter_is_required_and_none_has_a_default():
    for cls in (Bounds,):
        params = [p for name, p in inspect.signature(cls.__init__).parameters.items()
                  if name != "self"]
        assert [p.name for p in params] == ["max_rounds", "max_model_calls", "no_progress_limit"]
        assert all(p.default is inspect.Parameter.empty for p in params)
    with pytest.raises(TypeError):
        Bounds()
    with pytest.raises(TypeError):
        Bounds(3, 3)


def test_the_module_holds_no_number_of_its_own_beyond_0_and_1():
    tree = ast.parse(Path(b.__file__).read_text())
    numbers = {node.value for node in ast.walk(tree)
               if isinstance(node, ast.Constant) and isinstance(node.value, (int, float))
               and not isinstance(node.value, bool)}
    assert numbers <= {0, 1}, numbers


# ---------------------------------------------------------------- the counters


def test_the_counter_names_are_the_four_and_only_the_four():
    assert b.COUNTER_NAMES == ("skipped_engagement", "not_run", "not_executed", "unknown_outcome")
    assert RunCounters().snapshot() == dict.fromkeys(b.COUNTER_NAMES, 0)


def test_each_counter_counts_by_itself():
    counters = RunCounters()
    for name in b.COUNTER_NAMES:
        assert counters.count(name) == 0
    counters.increment("not_run")
    counters.increment("not_run")
    counters.increment("unknown_outcome")
    assert counters.count("not_run") == 2
    assert counters.count("unknown_outcome") == 1
    assert counters.count("skipped_engagement") == 0
    assert counters.count("not_executed") == 0


def test_the_snapshot_is_a_copy():
    counters = RunCounters()
    counters.increment("not_executed")
    snap = counters.snapshot()
    snap["not_executed"] = 99
    snap["invented"] = 1
    assert counters.snapshot() == {"skipped_engagement": 0, "not_run": 0, "not_executed": 1,
                                   "unknown_outcome": 0}


@pytest.mark.parametrize("name", ["invented", "", "NOT_RUN", "not run", None, 3, "executed"])
def test_a_counter_name_outside_the_closed_vocabulary_is_refused(name):
    counters = RunCounters()
    with pytest.raises(ValueError):
        counters.increment(name)
    with pytest.raises(ValueError):
        counters.count(name)
    assert list(counters.snapshot()) == list(b.COUNTER_NAMES)       # and nothing was added
    assert sum(counters.snapshot().values()) == 0
