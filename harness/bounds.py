"""D69 H5a1 (a4): the loop's bounds as a state machine, and the closed counters of a run.

:class:`Bounds` knows three numbers and nothing else about the loop: how many rounds it may start,
how many model calls it may make, and after how many consecutive rounds without progress it stops
(plan items 47, 48 and 60). **Every parameter is required and none has a default**, and this
module holds no number of its own beyond 0 and 1: the values are written down by a person before
the first run and are not tuned from data (D69-5d), so no value here could be mistaken for one.

* ``round_may_start()`` -- False once ``max_rounds`` rounds have been started;
* ``call_may_be_made()`` -- False once ``max_model_calls`` calls have been recorded;
* ``record_model_call()``, ``start_round()`` -- count;
* ``end_round(progress)`` -- progress means a proposal reached ``propose_action`` (a DENY result
  included, plan item 60); it resets the run of rounds without it, its absence adds one;
* ``stop_reason()`` -- ``None``, or :attr:`StopReason.CAP_REACHED` when either cap is reached, or
  :attr:`StopReason.NO_PROGRESS` when the run without progress has reached its limit. When both
  hold, the cap is reported: it is the one that does not depend on what the models said. It is
  meant to be asked at a round boundary, after ``end_round``.

:class:`RunCounters` counts four things a run must be able to say afterwards, under a closed
list of names; an unknown name is an error, not a new counter.
"""

from __future__ import annotations

from harness.exit_codes import StopReason

COUNTER_SKIPPED_ENGAGEMENT = "skipped_engagement"
COUNTER_NOT_RUN = "not_run"
COUNTER_NOT_EXECUTED = "not_executed"
COUNTER_UNKNOWN_OUTCOME = "unknown_outcome"

COUNTER_NAMES = (
    COUNTER_SKIPPED_ENGAGEMENT, COUNTER_NOT_RUN, COUNTER_NOT_EXECUTED, COUNTER_UNKNOWN_OUTCOME,
)


def _positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} is an int of at least 1, not {value!r}")
    return value


class Bounds:
    """The round cap, the model-call cap and the no-progress limit of one run."""

    def __init__(self, max_rounds: int, max_model_calls: int, no_progress_limit: int) -> None:
        self._max_rounds = _positive_int("max_rounds", max_rounds)
        self._max_model_calls = _positive_int("max_model_calls", max_model_calls)
        self._no_progress_limit = _positive_int("no_progress_limit", no_progress_limit)
        self._rounds_started = 0
        self._model_calls = 0
        self._without_progress = 0

    def round_may_start(self) -> bool:
        return self._rounds_started < self._max_rounds

    def call_may_be_made(self) -> bool:
        return self._model_calls < self._max_model_calls

    def record_model_call(self) -> None:
        self._model_calls += 1

    def start_round(self) -> None:
        self._rounds_started += 1

    def end_round(self, progress: bool) -> None:
        if not isinstance(progress, bool):
            raise ValueError(f"progress is a bool, not {progress!r}")
        if progress:
            self._without_progress = 0
        else:
            self._without_progress += 1

    def stop_reason(self) -> StopReason | None:
        if not self.round_may_start() or not self.call_may_be_made():
            return StopReason.CAP_REACHED
        if self._without_progress >= self._no_progress_limit:
            return StopReason.NO_PROGRESS
        return None


class RunCounters:
    """Counts under the four names of :data:`COUNTER_NAMES`; any other name is a ``ValueError``."""

    def __init__(self) -> None:
        self._counts = {name: 0 for name in COUNTER_NAMES}

    def increment(self, name: str) -> None:
        if name not in COUNTER_NAMES:
            raise ValueError(f"unknown counter {name!r}")
        self._counts[name] = self._counts.get(name, 0) + 1

    def count(self, name: str) -> int:
        if name not in COUNTER_NAMES:
            raise ValueError(f"unknown counter {name!r}")
        return self._counts[name]

    def snapshot(self) -> dict[str, int]:
        return dict(self._counts)
