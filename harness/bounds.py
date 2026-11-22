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

:class:`Bounds` also takes two optional caps (D69 shadow runner S3, plan items 134 and 143), by
keyword: ``max_tokens``, checked against ``tokens_spent()`` -- a callable the caller provides,
returning the tokens used so far -- and ``max_minutes``, counted from the moment the ``Bounds`` is
built (``clock``, ``time.monotonic`` unless a test hands in another). ``None`` means no such cap.
Both are checked by ``round_may_start()`` and by ``call_may_be_made()``, so at every round boundary
and before every model call; a cap is reached when the count is **at least** the cap. Either one
reached is still :attr:`StopReason.CAP_REACHED`; ``cap_hit`` says which cap it was --
``rounds``, ``model_calls``, ``tokens`` or ``minutes`` -- and is ``None`` until one is reached.

:class:`RunCounters` counts five things a run must be able to say afterwards, under a closed
list of names; an unknown name is an error, not a new counter.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import timedelta

from harness.exit_codes import StopReason

COUNTER_SKIPPED_ENGAGEMENT = "skipped_engagement"
COUNTER_NOT_RUN = "not_run"
COUNTER_NOT_EXECUTED = "not_executed"
COUNTER_UNKNOWN_OUTCOME = "unknown_outcome"
COUNTER_DEDUPLICATED = "deduplicated"

COUNTER_NAMES = (
    COUNTER_SKIPPED_ENGAGEMENT, COUNTER_NOT_RUN, COUNTER_NOT_EXECUTED, COUNTER_UNKNOWN_OUTCOME,
    COUNTER_DEDUPLICATED,
)


def _positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} is an int of at least 1, not {value!r}")
    return value


CAP_ROUNDS = "rounds"
CAP_MODEL_CALLS = "model_calls"
CAP_TOKENS = "tokens"
CAP_MINUTES = "minutes"
CAP_NAMES = (CAP_ROUNDS, CAP_MODEL_CALLS, CAP_TOKENS, CAP_MINUTES)


def _optional_positive_int(name: str, value: object) -> int | None:
    return None if value is None else _positive_int(name, value)


class Bounds:
    """The round cap, the model-call cap and the no-progress limit of one run."""

    def __init__(self, max_rounds: int, max_model_calls: int, no_progress_limit: int, *,
                 max_tokens: int | None = None, max_minutes: int | None = None,
                 tokens_spent: Callable[[], int] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._max_rounds = _positive_int("max_rounds", max_rounds)
        self._max_model_calls = _positive_int("max_model_calls", max_model_calls)
        self._no_progress_limit = _positive_int("no_progress_limit", no_progress_limit)
        self._max_tokens = _optional_positive_int("max_tokens", max_tokens)
        self._max_minutes = _optional_positive_int("max_minutes", max_minutes)
        self._max_seconds = (None if self._max_minutes is None
                             else timedelta(minutes=self._max_minutes).total_seconds())
        if self._max_tokens is not None and not callable(tokens_spent):
            raise ValueError("max_tokens needs tokens_spent, a callable returning the tokens used")
        self._tokens_spent = tokens_spent
        self._clock = clock
        self._started_at = clock()
        self._rounds_started = 0
        self._model_calls = 0
        self._without_progress = 0
        #: Which cap was reached first: one of :data:`CAP_NAMES`, or ``None``.
        self.cap_hit: str | None = None

    def _hit(self, cap: str) -> bool:
        if self.cap_hit is None:
            self.cap_hit = cap
        return False

    def _shared_caps_allow(self) -> bool:
        """The token cap and the minute cap, asked at both checkpoints."""
        if self._max_tokens is not None and self._tokens_spent() >= self._max_tokens:
            return self._hit(CAP_TOKENS)
        if (self._max_seconds is not None
                and self._clock() - self._started_at >= self._max_seconds):
            return self._hit(CAP_MINUTES)
        return True

    def round_may_start(self) -> bool:
        if self._rounds_started >= self._max_rounds:
            return self._hit(CAP_ROUNDS)
        return self._shared_caps_allow()

    def call_may_be_made(self) -> bool:
        if self._model_calls >= self._max_model_calls:
            return self._hit(CAP_MODEL_CALLS)
        return self._shared_caps_allow()

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
    """Counts under the five names of :data:`COUNTER_NAMES`; any other name is a ``ValueError``."""

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
