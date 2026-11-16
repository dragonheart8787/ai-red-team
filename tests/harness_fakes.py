"""Stand-ins for the harness loop's ports (D69 H5a2). Not a test file: no ``test_`` in its name.

:class:`FakePorts` implements every method of :class:`harness.ports.LoopPorts` and records each
call in order in ``log`` (a tuple of the method name and its arguments), so a test can count the
calls of one method, ask in which order two happened, and read what was completed. Everything
about its answers can be set from the test:

* ``closed`` -- the engagements the pause and kill check refuses; a ``propose`` on one of them
  would answer ``HUMAN_APPROVAL`` (that is what the pipeline does to a killed engagement), so a
  test that sees zero ``propose`` calls has shown the loop did not ask;
* ``live`` -- the rows ``live_tasks`` returns; ``queue`` -- the ids ``claim`` hands out, in order,
  filled by ``plan`` (``created`` keeps every ``(engagement, task)`` pair ``plan`` made);
  ``claim_script`` -- values ``claim`` returns first (an id, or ``None``);
  ``claim_none`` -- engagements whose ``claim`` always answers ``None``;
* ``plan_script``, ``work_script``, ``outcome_script`` -- answers used first, one per call;
  after them the defaults: a plan that creates ``tasks_per_plan`` tasks, a Worker that proposes
  ``network.scan``, an ALLOW with a run id and an evidence id;
* ``after(method, fn)`` -- calls ``fn(ports, *args)`` after the method has done its work, before
  it returns (to set the stop flag, close an engagement or enrol one in the middle of a round);
* ``raise_on(method, exc, nth=1)`` -- the ``nth`` call of the method raises ``exc``.

:class:`FakeEnrolment` is the in-memory enrolment list. :func:`drive` runs the loop on a
:class:`FakePorts` with finite bounds (so that a mutant that ignores one still ends) and returns
everything a test looks at.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from harness.action_allowlist import RefusalCounter
from harness.bounds import Bounds, RunCounters
from harness.loop import LoopResult, run_loop
from harness.ports import LiveTask, PlannedTask, PlanResult, WorkResult
from harness.signals import SignalFlag


@dataclass(frozen=True)
class FakeOutcome:
    """The five fields :mod:`harness.result_summary` reads of an outcome."""

    decision: str = "ALLOW"
    failure: str | None = None
    run_id: str | None = None
    evidence_id: str | None = None
    deny_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class FakePolicy:
    engagement_id: str
    serial: int


class FakeEnrolment:
    """The enrolment list in memory; ``add`` enrols an engagement."""

    def __init__(self, *engagement_ids: str) -> None:
        self._ids = list(engagement_ids)

    def add(self, engagement_id: str) -> None:
        self._ids.append(engagement_id)

    def enrolled(self) -> tuple[str, ...]:
        return tuple(self._ids)


class FakePorts:
    def __init__(
        self,
        engagements: tuple[str, ...] = ("ENG-1",),
        *,
        tasks_per_plan: int | dict[str, int] = 1,
        enrolment: FakeEnrolment | None = None,
    ) -> None:
        self.enrolment = enrolment if enrolment is not None else FakeEnrolment(*engagements)
        self.tasks_per_plan = tasks_per_plan
        self.closed: set[str] = set()
        self.live: dict[str, tuple[LiveTask, ...]] = {}
        self.queue: dict[str, list[str]] = {}
        self.created: list[tuple[str, str]] = []
        self.claim_none: set[str] = set()
        self.claim_script: list[object] = []
        self.plan_script: list[PlanResult] = []
        self.work_script: list[WorkResult] = []
        self.outcome_script: list[Any] = []
        self.log: list[tuple] = []
        self.completed: list[tuple[str, str, str]] = []
        self.proposed: list[dict[str, Any]] = []
        self.policies: list[FakePolicy] = []
        self.hooks: dict[str, list[Callable[..., None]]] = {}
        self.raises: dict[str, tuple[int, BaseException]] = {}
        self._serial = 0

    # -- what a test sets and reads -----------------------------------------------------------

    def after(self, method: str, fn: Callable[..., None]) -> None:
        self.hooks.setdefault(method, []).append(fn)

    def raise_on(self, method: str, exc: BaseException, nth: int = 1) -> None:
        self.raises[method] = (nth, exc)

    def count(self, method: str) -> int:
        return sum(1 for entry in self.log if entry[0] == method)

    def calls(self, method: str) -> list[tuple]:
        return [entry for entry in self.log if entry[0] == method]

    def order(self) -> list[str]:
        return [entry[0] for entry in self.log]

    def model_calls(self) -> int:
        """The calls the loop counts as model calls: plan, work and propose."""
        return self.count("plan") + self.count("work") + self.count("propose")

    # -- plumbing -----------------------------------------------------------------------------

    def _enter(self, method: str, *args: object) -> None:
        self.log.append((method, *args))
        nth, exc = self.raises.get(method, (0, None))
        if exc is not None and self.count(method) == nth:
            raise exc

    def _leave(self, method: str, *args: object) -> None:
        for hook in self.hooks.get(method, ()):
            hook(self, *args)

    def _next(self) -> int:
        self._serial += 1
        return self._serial

    # -- the ports ----------------------------------------------------------------------------

    def enrolled(self) -> tuple[str, ...]:
        self._enter("enrolled")
        result = self.enrolment.enrolled()
        self._leave("enrolled")
        return result

    def accepts_work(self, engagement_id: str) -> bool:
        self._enter("accepts_work", engagement_id)
        result = engagement_id not in self.closed
        self._leave("accepts_work", engagement_id)
        return result

    def live_tasks(self, engagement_id: str) -> tuple[LiveTask, ...]:
        self._enter("live_tasks", engagement_id)
        rows = self.live.get(engagement_id, ())
        self._leave("live_tasks", engagement_id)
        return rows

    def take_snapshot(self, engagement_id: str) -> object:
        self._enter("take_snapshot", engagement_id)
        snapshot = f"snapshot-{engagement_id}-{self._next()}"
        self._leave("take_snapshot", engagement_id)
        return snapshot

    def plan(self, engagement_id: str, snapshot: object) -> PlanResult:
        self._enter("plan", engagement_id, snapshot)
        if self.plan_script:
            result = self.plan_script.pop(0)
        else:
            how_many = (
                self.tasks_per_plan.get(engagement_id, 1)
                if isinstance(self.tasks_per_plan, dict)
                else self.tasks_per_plan
            )
            result = PlanResult(created=tuple(
                PlannedTask(f"T-{engagement_id}-{self._next()}") for _ in range(how_many)
            ))
        self.queue.setdefault(engagement_id, []).extend(t.task_id for t in result.created)
        self.created.extend((engagement_id, t.task_id) for t in result.created)
        self._leave("plan", engagement_id, snapshot)
        return result

    def claim(self, engagement_id: str) -> str | None:
        self._enter("claim", engagement_id)
        queued = self.queue.get(engagement_id, [])
        if self.claim_script:
            result = self.claim_script.pop(0)
        elif engagement_id in self.claim_none or not queued:
            result = None
        else:
            result = queued.pop(0)
        self._leave("claim", engagement_id)
        return result  # type: ignore[return-value]

    def work(self, engagement_id: str, task_id: str, snapshot: object) -> WorkResult:
        self._enter("work", engagement_id, task_id, snapshot)
        if self.work_script:
            result = self.work_script.pop(0)
        else:
            result = WorkResult(
                proposal={"action": "network.scan", "task": task_id}, action="network.scan"
            )
        self._leave("work", engagement_id, task_id, snapshot)
        return result

    def load_policy(self, engagement_id: str) -> object:
        self._enter("load_policy", engagement_id)
        policy = FakePolicy(engagement_id, self._next())
        self.policies.append(policy)
        self._leave("load_policy", engagement_id)
        return policy

    def propose(
        self,
        engagement_id: str,
        task_id: str,
        proposal: object,
        policy: object,
        idempotency_key: str,
    ) -> Any:
        self._enter("propose", engagement_id, task_id)
        self.proposed.append({
            "engagement_id": engagement_id, "task_id": task_id, "proposal": proposal,
            "policy": policy, "idempotency_key": idempotency_key,
        })
        if self.outcome_script:
            outcome = self.outcome_script.pop(0)
        elif engagement_id in self.closed:
            outcome = FakeOutcome("HUMAN_APPROVAL", "capability_refused")
        else:
            n = self._next()
            outcome = FakeOutcome("ALLOW", None, f"RUN-{n}", f"EV-{n}")
        self._leave("propose", engagement_id, task_id)
        return outcome

    def complete(self, engagement_id: str, task_id: str, summary: str) -> None:
        self._enter("complete", engagement_id, task_id, summary)
        self.completed.append((engagement_id, task_id, summary))
        self._leave("complete", engagement_id, task_id, summary)


@dataclass(frozen=True)
class Driven:
    """A finished run: what ``run_loop`` returned and the objects it counted into."""

    result: LoopResult
    bounds: Bounds
    counters: RunCounters
    refusals: RefusalCounter
    flag: SignalFlag


def drive(
    ports: FakePorts,
    *,
    max_rounds: int = 6,
    max_calls: int = 1000,
    no_progress: int = 1000,
    once: bool = False,
    flag: SignalFlag | None = None,
    window_limit: int = 50,
) -> Driven:
    """Run the loop on ``ports``. The defaults are finite on purpose: a loop that ignores one
    of its bounds must still end, so that a test of it fails instead of hanging."""
    bounds = Bounds(max_rounds, max_calls, no_progress)
    counters = RunCounters()
    refusals = RefusalCounter()
    flag = flag if flag is not None else SignalFlag()
    result = run_loop(
        ports, bounds, counters, refusals,
        window_limit=window_limit, stop_event=flag, once=once,
    )
    return Driven(result, bounds, counters, refusals, flag)
