"""D69 H5a2 (a10): the harness loop's control flow, over the ports of :mod:`harness.ports`.

:func:`run_loop` decides what happens and in which order; every effect goes through a port, so
it can be driven by a stand-in that records the calls. It does not exit the process and does not
log: it returns a :class:`LoopResult` whose ``reason`` is a
:class:`~harness.exit_codes.StopReason`, and the caller turns that into an exit status with
:func:`harness.exit_codes.exit_code`.

**A round.** Before it starts: the stop flag, then the round cap (``start_round`` follows). Then,
for each engagement ``enrolled()`` returns (read once per round), in order:

1. the stop flag; the pause and kill check (``accepts_work``) -- a refused engagement is counted
   as ``skipped_engagement`` and passed over;
2. the start-up check, once per engagement and process, on the engagement's first visit: any live
   task refuses the start (exit code 10). It runs before the snapshot, the planning call, any
   task creation and any claim;
3. the snapshot; the call cap; one planning call; the tasks it created are remembered, with their
   engagement, as *created and not claimed*. A planning failure, or a plan with no task, leaves
   the engagement with nothing to claim this round;
4. while the engagement has such a task: the stop flag; the pause and kill check again (a refused
   engagement is counted and the rest is left for the clean-up at a controlled stop); ``claim``
   (``None`` ends the loop without a fault; an id that is not one of the engagement's own created
   and unclaimed tasks is a foreign task, exit code 11, and nothing is proposed or completed);
5. for each claimed task: the call cap, one ``work`` call (never repeated), the decision on its
   answer (:mod:`harness.worker_step`), the pause and kill check a third time (the last one before
   the proposal), the call cap, the policy (read in :func:`_load_policy`, the only place), one
   ``propose`` with the key ``h5:<task_id>:1`` -- and the task is completed once, with the summary
   :func:`~harness.result_summary.build_summary` made. A task that never reaches ``propose`` is
   completed as ``not_run``.

After the last engagement the round ends: ``end_round(progress)``, where progress means a proposal
reached ``propose`` (a DENY result included, plan item 60) and a round that skipped everything made
none; then ``--once``, then ``stop_reason()``.

**What counts as a model call** (the owner's decision): the Supervisor's ``plan``, the Worker's
``work`` and each ``propose`` (inside it the pipeline calls the Reviewer) count once each. The cap
is held entirely here, by asking ``call_may_be_made()`` before each of the three and
``round_may_start()`` before each round; ``record_model_call()`` and ``start_round()`` only count.

**Stopping.** A *controlled stop* is a reason for which
:func:`~harness.exit_codes.cleans_up_unclaimed` is true (a signal or ``--once``, a refused start-up
check, a cap, no progress): the loop completes, as ``not_run`` and in the engagement each belongs
to, every task it created and never claimed, and returns the reason. An exception in that
clean-up ends as a fault and is not retried. A *fault* (a foreign task, a key conflict, any
exception a port or an a2 function raised, ``ValueError`` included) returns its reason
(``FAULT_OUTSIDE_LIST`` for all but the foreign task) and cleans up nothing; the claimed task it
happened on is not completed either: that is left to a person. The text of an exception is never
kept.

**Safe points.** The stop flag is read before a round, between engagements and before a claim, and
nowhere between a task's ``work``, ``propose`` and ``complete``: a flag set in the middle of a task
is seen after that task has been completed.

**The summary** comes from ``build_summary`` and from nothing else, and the one function that
writes it (:func:`_complete`) refuses a string outside the closed set first. The counters are read
off the summary, not off the outcome. ``window_limit`` is validated and not used: ``live_tasks``
has no page size to give it to, and one live row is enough to refuse a start.
"""

from __future__ import annotations

from dataclasses import dataclass

from harness.action_allowlist import RefusalCounter
from harness.bounds import (
    COUNTER_DEDUPLICATED,
    COUNTER_NOT_EXECUTED,
    COUNTER_NOT_RUN,
    COUNTER_SKIPPED_ENGAGEMENT,
    COUNTER_UNKNOWN_OUTCOME,
    Bounds,
    RunCounters,
)
from harness.exit_codes import StopReason, cleans_up_unclaimed
from harness.idempotency import derive_key
from harness.ports import LoopPorts
from harness.result_summary import (
    FAILURE_DEDUP_HIT,
    STATE_NOT_EXECUTED,
    STATE_UNKNOWN_OUTCOME,
    TOKEN_NOT_RUN,
    build_summary,
    is_key_conflict,
    is_valid_summary,
)
from harness.signals import StopFlag
from harness.startup_check import STARTUP_REFUSE, decide_startup, owns
from harness.worker_step import STEP_NOT_RUN, decide_after_work

#: The counter each summary adds to. Read off the summary, which says whether an action ran.
_COUNTER_OF_SUMMARY = {
    STATE_NOT_EXECUTED: COUNTER_NOT_EXECUTED,
    STATE_UNKNOWN_OUTCOME: COUNTER_UNKNOWN_OUTCOME,
    FAILURE_DEDUP_HIT: COUNTER_DEDUPLICATED,
}

#: The attempt in the idempotency key. Nothing retries inside the process (plan item 47).
_ATTEMPT = 1


@dataclass(frozen=True)
class LoopResult:
    """Why the loop stopped, how many rounds it started and what it counted."""

    reason: StopReason
    rounds: int
    counters: dict[str, int]


class _Stop(Exception):
    """The loop's own way out. It carries a reason and no text."""

    def __init__(self, reason: StopReason) -> None:
        super().__init__()
        self.reason = reason


class _ControlledStop(_Stop):
    """A stop that cleans up what the loop left unclaimed."""


class _FaultStop(_Stop):
    """A stop that cleans up nothing."""


def _load_policy(ports: LoopPorts, engagement_id: str) -> object:
    """The one place the policy is read."""
    return ports.load_policy(engagement_id)


def _complete(ports: LoopPorts, engagement_id: str, task_id: str, summary: str) -> None:
    """The one place a task is completed: a summary outside the closed set is refused first."""
    if not is_valid_summary(summary):
        raise ValueError("a result summary outside the closed set")
    ports.complete(engagement_id, task_id, summary)


class _Run:
    """The state of one run: what it created, what it checked, and the objects it counts into."""

    def __init__(
        self,
        ports: LoopPorts,
        bounds: Bounds,
        counters: RunCounters,
        refusals: RefusalCounter,
        stop_event: StopFlag,
    ) -> None:
        self.ports = ports
        self.bounds = bounds
        self.counters = counters
        self.refusals = refusals
        self.stop_event = stop_event
        self.rounds = 0
        self.checked: set[str] = set()
        self.created_ids: set[str] = set()
        self.unclaimed: dict[str, list[str]] = {}

    # -- the rounds ---------------------------------------------------------------------------

    def drive(self, once: bool) -> None:
        """Run rounds until a stop; the only way out is a :class:`_Stop`."""
        while True:
            self.safe_point()
            if not self.bounds.round_may_start():
                raise _ControlledStop(StopReason.CAP_REACHED)
            self.bounds.start_round()
            self.rounds += 1
            progress = self.one_round()
            self.bounds.end_round(progress)
            if once:
                raise _ControlledStop(StopReason.SIGNAL_OR_ONCE)
            stop = self.bounds.stop_reason()
            if stop is not None:
                raise _ControlledStop(stop)

    def safe_point(self) -> None:
        if self.stop_event.is_set():
            raise _ControlledStop(StopReason.SIGNAL_OR_ONCE)

    def one_round(self) -> bool:
        """One round over the enrolled engagements; whether a proposal reached ``propose``."""
        progress = False
        for engagement_id in self.ports.enrolled():
            self.safe_point()
            if not self.ports.accepts_work(engagement_id):
                self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)
                continue
            self.start_check(engagement_id)
            snapshot = self.ports.take_snapshot(engagement_id)
            created = self.plan(engagement_id, snapshot)
            if created and self.claim_loop(engagement_id, snapshot):
                progress = True
            self.safe_point()
        return progress

    def start_check(self, engagement_id: str) -> None:
        """The start-up check, once per engagement, on its first visit."""
        if engagement_id in self.checked:
            return
        if decide_startup(self.ports.live_tasks(engagement_id)) == STARTUP_REFUSE:
            raise _ControlledStop(StopReason.STARTUP_REFUSED)
        self.checked.add(engagement_id)

    # -- the Supervisor -------------------------------------------------------------------------

    def plan(self, engagement_id: str, snapshot: object) -> bool:
        """One planning call. True when it created at least one task and did not fail."""
        if not self.bounds.call_may_be_made():
            raise _ControlledStop(StopReason.CAP_REACHED)
        result = self.ports.plan(engagement_id, snapshot)
        self.bounds.record_model_call()
        for planned in result.created:
            self.remember(engagement_id, planned.task_id)
        return result.failure is None and bool(result.created)

    def remember(self, engagement_id: str, task_id: str) -> None:
        """Record a task this process created, with its engagement, as not yet claimed."""
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("a task id is a non-empty string")
        if task_id in self.created_ids:
            raise ValueError("a task id was created twice")
        self.created_ids.add(task_id)
        self.unclaimed.setdefault(engagement_id, []).append(task_id)

    # -- the Worker and the proposal ----------------------------------------------------------

    def claim_loop(self, engagement_id: str, snapshot: object) -> bool:
        """Claim and run the engagement's tasks; whether any proposal reached ``propose``."""
        progress = False
        while self.unclaimed.get(engagement_id):
            self.safe_point()
            if not self.ports.accepts_work(engagement_id):
                self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)
                break
            task_id = self.ports.claim(engagement_id)
            if task_id is None:
                break
            if not owns(task_id, self.unclaimed[engagement_id]):
                raise _FaultStop(StopReason.FOREIGN_TASK)
            self.unclaimed[engagement_id].remove(task_id)
            if self.run_task(engagement_id, task_id, snapshot):
                progress = True
        return progress

    def run_task(self, engagement_id: str, task_id: str, snapshot: object) -> bool:
        """One claimed task, completed once. True when its proposal reached ``propose``."""
        if not self.bounds.call_may_be_made():
            self.complete_not_run(engagement_id, task_id)
            raise _ControlledStop(StopReason.CAP_REACHED)
        result = self.ports.work(engagement_id, task_id, snapshot)
        self.bounds.record_model_call()
        step = decide_after_work(result, self.refusals)
        if step == STEP_NOT_RUN:
            self.complete_not_run(engagement_id, task_id)
            return False
        if not self.ports.accepts_work(engagement_id):
            self.counters.increment(COUNTER_SKIPPED_ENGAGEMENT)
            self.complete_not_run(engagement_id, task_id)
            return False
        if not self.bounds.call_may_be_made():
            self.complete_not_run(engagement_id, task_id)
            raise _ControlledStop(StopReason.CAP_REACHED)
        policy = _load_policy(self.ports, engagement_id)
        key = derive_key(task_id, _ATTEMPT)
        outcome = self.ports.propose(engagement_id, task_id, result.proposal, policy, key)
        self.bounds.record_model_call()
        if is_key_conflict(outcome):
            raise _FaultStop(StopReason.FAULT_OUTSIDE_LIST)
        summary = build_summary(outcome)
        self.count(summary)
        _complete(self.ports, engagement_id, task_id, summary)
        return True

    def count(self, summary: str) -> None:
        counter = _COUNTER_OF_SUMMARY.get(summary)
        if counter is not None:
            self.counters.increment(counter)

    def complete_not_run(self, engagement_id: str, task_id: str) -> None:
        _complete(self.ports, engagement_id, task_id, TOKEN_NOT_RUN)
        self.counters.increment(COUNTER_NOT_RUN)

    # -- the end ------------------------------------------------------------------------------

    def finish(self, reason: StopReason) -> StopReason:
        """The reason the run ends with, after a controlled stop's clean-up."""
        if not cleans_up_unclaimed(reason):
            return reason
        try:
            for engagement_id, task_ids in list(self.unclaimed.items()):
                for task_id in list(task_ids):
                    self.complete_not_run(engagement_id, task_id)
                    task_ids.remove(task_id)
        except Exception:
            return StopReason.FAULT_OUTSIDE_LIST
        return reason


def _positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} is an int of at least 1")


def run_loop(
    ports: LoopPorts,
    bounds: Bounds,
    counters: RunCounters,
    refusals: RefusalCounter,
    *,
    window_limit: int,
    stop_event: StopFlag,
    once: bool = False,
) -> LoopResult:
    """Run the loop until it stops and say why. Every argument is required except ``once``."""
    if not isinstance(bounds, Bounds):
        raise ValueError("bounds is a Bounds")
    if not isinstance(counters, RunCounters):
        raise ValueError("counters is a RunCounters")
    if not isinstance(refusals, RefusalCounter):
        raise ValueError("refusals is a RefusalCounter")
    _positive_int("window_limit", window_limit)
    if not callable(getattr(stop_event, "is_set", None)):
        raise ValueError("stop_event has an is_set()")
    if not isinstance(once, bool):
        raise ValueError("once is a bool")
    run = _Run(ports, bounds, counters, refusals, stop_event)
    try:
        run.drive(once)
    except _ControlledStop as stop:
        reason = run.finish(stop.reason)
    except _FaultStop as stop:
        reason = stop.reason
    except Exception:
        reason = StopReason.FAULT_OUTSIDE_LIST
    return LoopResult(reason=reason, rounds=run.rounds, counters=counters.snapshot())
