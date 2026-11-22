"""D69 shadow runner, stage S3 (plan items 134 and 143): the token cap and the minute cap.

``harness.bounds.Bounds`` takes ``max_tokens`` (against ``tokens_spent()``, a callable) and
``max_minutes`` (from the moment the ``Bounds`` is built, on an injected clock: nothing here
waits), checked by ``round_may_start()`` and by ``call_may_be_made()``. The loop is driven on
``tests.harness_fakes.FakePorts``, whose hooks spend tokens or move the clock in the middle of a
round. ``scripts/run_harness.py`` counts the input and output tokens of the three roles' calls and
not their cache reads; ``scripts/run_shadow.py`` requires both caps. No database, no model, no
file written.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agents.llm.reviewer_base import ReviewCall
from agents.llm.supervisor_base import SupervisorCall
from agents.llm.worker_base import WorkerCall
from harness.action_allowlist import RefusalCounter
from harness.bounds import CAP_MINUTES, CAP_NAMES, CAP_TOKENS, Bounds, RunCounters
from harness.exit_codes import EXIT_CODE, StopReason
from harness.loop import run_loop
from harness.signals import SignalFlag
from scripts import run_harness, run_shadow
from tests.harness_fakes import FakePorts
from tests.test_shadow_runner_guard import (  # noqa: F401 - _subscription_only is a fixture
    _argv,
    _Git,
    _Lock,
    _registration,
    _subscription_only,
)


class Clock:
    """A monotonic clock a test moves by hand."""

    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _bounds(**caps) -> Bounds:
    return Bounds(10, 1000, 1000, **caps)


# -- the token cap ---------------------------------------------------------------------------------


def test_below_the_token_cap_rounds_and_calls_go_on():
    spent = [9]
    bounds = _bounds(max_tokens=10, tokens_spent=lambda: spent[0])
    assert bounds.round_may_start() and bounds.call_may_be_made() and bounds.cap_hit is None
    assert bounds.stop_reason() is None


def test_tokens_equal_to_the_cap_stop_the_next_call_and_the_next_round():
    spent = [10]
    for check in ("call_may_be_made", "round_may_start"):
        bounds = _bounds(max_tokens=10, tokens_spent=lambda: spent[0])
        assert getattr(bounds, check)() is False, check          # at least the cap, not above it
        assert bounds.cap_hit == CAP_TOKENS
        assert bounds.stop_reason() is StopReason.CAP_REACHED
        assert EXIT_CODE[bounds.stop_reason()] == 13


def test_a_token_cap_needs_a_tokens_spent_callable_and_a_positive_int():
    with pytest.raises(ValueError):
        _bounds(max_tokens=10)
    for bad in (0, -1, 1.5, True, "10"):
        with pytest.raises(ValueError):
            _bounds(max_tokens=bad, tokens_spent=lambda: 0)
        with pytest.raises(ValueError):
            _bounds(max_minutes=bad)


def test_without_the_two_caps_the_three_old_caps_behave_as_before():
    bounds = Bounds(1, 2, 1)
    assert bounds.call_may_be_made() and bounds.round_may_start()
    bounds.start_round()
    assert not bounds.round_may_start() and bounds.cap_hit == "rounds"
    other = Bounds(5, 1, 5)
    other.record_model_call()
    assert not other.call_may_be_made() and other.cap_hit == "model_calls"
    assert set(CAP_NAMES) == {"rounds", "model_calls", "tokens", "minutes"}


# -- the minute cap --------------------------------------------------------------------------------


def test_the_minute_cap_is_reached_at_the_next_checkpoint_with_no_waiting():
    clock = Clock(100.0)
    bounds = _bounds(max_minutes=1, clock=clock)
    clock.now = 159.9
    assert bounds.call_may_be_made() and bounds.round_may_start() and bounds.cap_hit is None
    clock.now = 160.0
    assert bounds.call_may_be_made() is False and bounds.cap_hit == CAP_MINUTES
    assert bounds.stop_reason() is StopReason.CAP_REACHED


def test_the_minutes_count_from_when_the_bounds_are_built_not_from_the_first_round():
    clock = Clock(100.0)
    bounds = _bounds(max_minutes=1, clock=clock)
    clock.now = 130.0                                            # half a minute before round 1
    assert bounds.round_may_start()
    bounds.start_round()
    clock.now = 160.0                               # 60 s after the start, 30 s into round 1
    assert bounds.call_may_be_made() is False and bounds.cap_hit == CAP_MINUTES


# -- both checkpoints, in the loop ----------------------------------------------------------------


def _run(ports, bounds):
    result = run_loop(ports, bounds, RunCounters(), RefusalCounter(), window_limit=50,
                      stop_event=SignalFlag(), once=False)
    return result


def test_a_token_cap_reached_by_the_planning_call_stops_before_the_workers_call():
    ports, spent = FakePorts(), [0]
    ports.after("plan", lambda p, *a: spent.__setitem__(0, 50))
    bounds = Bounds(5, 1000, 1000, max_tokens=50, tokens_spent=lambda: spent[0])
    result = _run(ports, bounds)
    assert result.reason is StopReason.CAP_REACHED and bounds.cap_hit == CAP_TOKENS
    assert (ports.count("plan"), ports.count("work"), result.rounds) == (1, 0, 1)
    assert ports.completed and ports.completed[0][2] == "not_run"   # the claimed task


def test_a_token_cap_reached_in_the_last_call_of_a_round_stops_at_the_round_boundary():
    ports, spent = FakePorts(), [0]
    ports.after("propose", lambda p, *a: spent.__setitem__(0, 50))
    bounds = Bounds(5, 1000, 1000, max_tokens=50, tokens_spent=lambda: spent[0])
    result = _run(ports, bounds)
    assert result.reason is StopReason.CAP_REACHED and bounds.cap_hit == CAP_TOKENS
    assert (result.rounds, ports.count("plan"), ports.count("propose")) == (1, 1, 1)


def test_a_minute_cap_reached_in_the_middle_of_a_round_stops_before_the_next_call():
    ports, clock = FakePorts(), Clock(0.0)
    ports.after("plan", lambda p, *a: setattr(clock, "now", 120.0))
    bounds = Bounds(5, 1000, 1000, max_minutes=2, clock=clock)
    result = _run(ports, bounds)
    assert result.reason is StopReason.CAP_REACHED and bounds.cap_hit == CAP_MINUTES
    assert (ports.count("plan"), ports.count("work")) == (1, 0)


def test_a_minute_cap_reached_at_the_end_of_a_round_stops_the_next_round():
    ports, clock = FakePorts(), Clock(0.0)
    ports.after("propose", lambda p, *a: setattr(clock, "now", 120.0))
    bounds = Bounds(5, 1000, 1000, max_minutes=2, clock=clock)
    result = _run(ports, bounds)
    assert result.reason is StopReason.CAP_REACHED and bounds.cap_hit == CAP_MINUTES
    assert (result.rounds, ports.count("plan")) == (1, 1)


# -- what is counted ------------------------------------------------------------------------------


def _roles():
    return SimpleNamespace(
        supervisor=SimpleNamespace(calls=[SupervisorCall(0.0, input_tokens=7, output_tokens=11)]),
        worker=SimpleNamespace(calls=[WorkerCall(0.0, input_tokens=5, output_tokens=3),
                                      WorkerCall(0.0, failed=True, failure="x")]),
        reviewer=SimpleNamespace(calls=[ReviewCall(0.0, 2, 1, cache_read_tokens=1000)]),
        sandbox=object())


def test_the_cap_counts_input_and_output_tokens_and_not_cache_reads():
    roles = _roles()
    assert run_harness.tokens_spent(roles) == 7 + 11 + 5 + 3 + 2 + 1 == 29
    assert run_harness.token_use(roles) == {"input_tokens": 14, "output_tokens": 15,
                                            "cache_read_tokens": 1000}
    bounds = _bounds(max_tokens=30, tokens_spent=lambda: run_harness.tokens_spent(roles))
    assert bounds.call_may_be_made()                       # 29 < 30, the 1000 cache reads aside


# -- run_shadow requires both ----------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["--max-tokens", "--max-minutes"])
def test_run_shadow_without_a_cap_is_a_usage_error_before_any_check(missing, monkeypatch, capsys):
    argv = _argv()
    at = argv.index(missing)
    del argv[at:at + 2]

    def checked(*args, **kwargs):
        raise AssertionError("a check ran")

    monkeypatch.setattr(run_shadow, "registration_problems", checked)
    git, lock = _Git(), _Lock(True)
    with pytest.raises(SystemExit) as stopped:
        run_shadow.main(argv, registration=_registration(), git=git, lock=lock)
    assert stopped.value.code == 2
    assert git.calls == [] and lock.asked == 0
    err = capsys.readouterr().err
    assert missing in err and "refused:" not in err
