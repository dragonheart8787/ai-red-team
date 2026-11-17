"""D69 H5c1: the real adapter of the loop's ports, over the test database (``harness/ports.py``).

:class:`LoopAdapter` is the one class that gives the ten methods of
:class:`~harness.ports.LoopPorts` their effect: it reads and writes the control plane through its
function API and runs the two roles it is given. The loop (``harness/loop.py``) decides *when*;
this decides *how*, and is the only module of the harness that names ``claim_task``,
``complete_task`` and ``propose_action`` (``tests/test_harness_task_source.py`` m2 allows exactly
this file to). It has no process entry, no lock and no signal handling: those are H5c2.

* **Every port opens its own connection** (``engagement_scope``: ``cyberorch_app``, bound to the
  one engagement) and closes it before it returns, on every path, including a raised one.
  Nothing is held between two port calls and nothing is shared between two ports. The only
  exception is ``take_snapshot``, which reads the evidence window **and** the registry candidates
  on one connection, so that both describe one moment.
* **The candidates are read once per round**, by ``take_snapshot``
  (:func:`harness.registry_view.candidates_from_registry`, which applies the allowlist filter),
  and held in the snapshot it returns. ``plan`` and ``work`` use the snapshot's candidates; neither
  reads the registry. This module is the first and only caller of that function.
* **``live_tasks`` reads the three live states with a status filter** and asks for one more row
  than its limit. ``query_state`` has no offset, so the limit is not paged through; a read that
  comes back with more than the limit is refused with :class:`LiveTasksNotReadable` and never
  returned cut short. (The filter is in the SQL, before the limit: ``query_state``'s default is
  the first 50 tasks of any state, oldest first, and a page of old completed tasks would hide a
  queued one -- plan item 81.)
* **``propose`` carries the task the loop claimed.** A proposal with no task gets it; one that
  names another task is refused (``ValueError``, so the loop ends with code 12) before
  ``propose_action`` is called. The idempotency key is the loop's, passed through unchanged.
* **The sandbox and the reviewer are required.** ``propose_action`` builds a real
  ``DockerSandbox`` when it is given none, so an adapter without a sandbox is refused when it is
  built. The window size (``window_limit``) is required and has no default.

It writes nothing itself: every write goes through ``create_task`` (inside
:func:`harness.task_source.plan_and_create_tasks`), ``claim_task``, ``propose_action`` and
``complete_task``. It holds no SQL of its own except the reads those functions make.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from agents.base_agent import ProposedAction, ProposedTask
from agents.llm.supervisor_base import BaseSupervisor
from agents.llm.worker_base import BaseWorker, ScopeCandidate
from control_plane.api.function_api import (
    claim_task,
    complete_task,
    propose_action,
    query_state,
)
from control_plane.orchestrator.engagement import get_engagement
from control_plane.policy.layers import load_effective_policy
from control_plane.state.db import engagement_scope
from harness.action_allowlist import RefusalCounter
from harness.enrolment import EnrolmentReader
from harness.ports import LiveTask, PlannedTask, PlanResult, WorkResult
from harness.registry_view import candidates_from_registry
from harness.round_snapshot import RoundSnapshot, build_state_summary, take_round_snapshot
from harness.task_source import RunTaskLedger, plan_and_create_tasks

#: The task states in which a task is still the loop's business: not yet finished.
LIVE_STATUSES = ("queued", "claimed", "running")

#: How many live tasks one engagement may hold before ``live_tasks`` refuses to answer.
LIVE_TASK_LIMIT = 200

#: The ``actor`` of the audit records the adapter's calls write.
ACTOR = "harness"


class LiveTasksNotReadable(RuntimeError):
    """More live tasks than the limit: the list cannot be returned whole, so it is not returned."""


@dataclass(frozen=True)
class LoopSnapshot:
    """What ``take_snapshot`` hands back: one round's evidence and the candidates read with it."""

    engagement_id: str
    round: RoundSnapshot
    candidates: tuple[ScopeCandidate, ...]


def _positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} is a positive integer, not {value!r}")
    return value


class LoopAdapter:
    """The ten ports, over the control plane's function API."""

    def __init__(
        self,
        *,
        enrolment: EnrolmentReader,
        supervisor: BaseSupervisor,
        worker: BaseWorker,
        reviewer: object,
        sandbox: object,
        objective: str,
        window_limit: int,
        live_task_limit: int = LIVE_TASK_LIMIT,
        actor: str = ACTOR,
    ) -> None:
        if sandbox is None:
            raise ValueError("a sandbox is required: propose_action builds a real one when it "
                             "is given none")
        if reviewer is None:
            raise ValueError("a reviewer is required")
        self._enrolment = enrolment
        self._supervisor = supervisor
        self._worker = worker
        self._reviewer = reviewer
        self._sandbox = sandbox
        self._objective = objective
        self._window_limit = _positive_int("window_limit", window_limit)
        self._live_task_limit = _positive_int("live_task_limit", live_task_limit)
        self._actor = actor
        self._ledger = RunTaskLedger()
        self._refusals = RefusalCounter()
        self._tasks: dict[str, ProposedTask] = {}

    @property
    def refusals(self) -> RefusalCounter:
        """What the planning step refused (``harness.action_allowlist``), for the caller."""
        return self._refusals

    # -- 1. enrolled --------------------------------------------------------------------------

    def enrolled(self) -> tuple[str, ...]:
        return tuple(self._enrolment.enrolled())

    # -- 2. accepts_work ----------------------------------------------------------------------

    def accepts_work(self, engagement_id: str) -> bool:
        with engagement_scope(engagement_id) as conn:
            state = get_engagement(conn, engagement_id)
        return state is not None and state.accepts_work

    # -- 3. live_tasks ------------------------------------------------------------------------

    def live_tasks(self, engagement_id: str) -> tuple[LiveTask, ...]:
        with engagement_scope(engagement_id) as conn:
            state = query_state(
                conn, engagement_id=engagement_id, task_status=LIVE_STATUSES,
                task_limit=self._live_task_limit + 1, decision_limit=0)
        rows = state["tasks"]
        if len(rows) > self._live_task_limit:
            raise LiveTasksNotReadable(
                f"more than {self._live_task_limit} live tasks in {engagement_id}")
        return tuple(LiveTask(task_id=row["task_id"], status=row["status"]) for row in rows)

    # -- 4. take_snapshot ---------------------------------------------------------------------

    def take_snapshot(self, engagement_id: str) -> LoopSnapshot:
        with engagement_scope(engagement_id) as conn:
            round_snapshot = take_round_snapshot(conn, limit=self._window_limit)
            candidates = candidates_from_registry(conn)
        return LoopSnapshot(engagement_id=engagement_id, round=round_snapshot,
                            candidates=candidates)

    # -- 5. plan ------------------------------------------------------------------------------

    def plan(self, engagement_id: str, snapshot: object) -> PlanResult:
        snap = self._own_snapshot(engagement_id, snapshot)
        state = build_state_summary(
            snap.round, engagement_id=engagement_id, objective=self._objective)
        outcome = plan_and_create_tasks(
            supervisor=self._supervisor, state=state, candidates=snap.candidates,
            engagement_id=engagement_id, created_by=self._supervisor.agent_id,
            ledger=self._ledger, counter=self._refusals)
        for created in outcome.created:
            self._tasks[created.task_id] = created.task
        return PlanResult(
            created=tuple(PlannedTask(task_id=c.task_id) for c in outcome.created),
            failure=outcome.failure)

    # -- 6. claim -----------------------------------------------------------------------------

    def claim(self, engagement_id: str) -> str | None:
        with engagement_scope(engagement_id) as conn:
            return claim_task(conn, engagement_id=engagement_id, agent_id=self._worker.agent_id)

    # -- 7. work ------------------------------------------------------------------------------

    def work(self, engagement_id: str, task_id: str, snapshot: object) -> WorkResult:
        snap = self._own_snapshot(engagement_id, snapshot)
        task = self._tasks.get(task_id)
        if task is None:
            raise LookupError(f"task {task_id} was not planned by this adapter")
        proposal = self._worker.propose(
            task=task, candidates=snap.candidates,
            observations=snap.round.observations_for_task(), task_id=task_id)
        if proposal is None:
            return WorkResult(refusal=True)
        return WorkResult(proposal=proposal, action=proposal.action)

    # -- 8. load_policy -----------------------------------------------------------------------

    def load_policy(self, engagement_id: str) -> object:
        with engagement_scope(engagement_id) as conn:
            return load_effective_policy(conn, engagement_id)

    # -- 9. propose ---------------------------------------------------------------------------

    def propose(self, engagement_id: str, task_id: str, proposal: object, policy: object,
                idempotency_key: str) -> object:
        if not isinstance(proposal, ProposedAction):
            raise TypeError("a proposal is a ProposedAction")
        if proposal.task_id is not None and proposal.task_id != task_id:
            raise ValueError("the proposal names a task other than the one claimed")
        carried = dataclasses.replace(proposal, task_id=task_id)
        return propose_action(
            engagement_id=engagement_id, proposal=carried, reviewer=self._reviewer,
            policy=policy, agent_id=self._worker.agent_id, actor=self._actor,
            sandbox=self._sandbox, idempotency_key=idempotency_key)

    # -- 10. complete -------------------------------------------------------------------------

    def complete(self, engagement_id: str, task_id: str, summary: str) -> None:
        with engagement_scope(engagement_id) as conn:
            complete_task(conn, engagement_id=engagement_id, task_id=task_id,
                          result_summary=summary, actor=self._actor)

    # -- helpers ------------------------------------------------------------------------------

    @staticmethod
    def _own_snapshot(engagement_id: str, snapshot: object) -> LoopSnapshot:
        if not isinstance(snapshot, LoopSnapshot) or snapshot.engagement_id != engagement_id:
            raise TypeError("the snapshot is not this adapter's snapshot of this engagement")
        return snapshot
