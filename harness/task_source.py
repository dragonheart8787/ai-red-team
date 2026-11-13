"""The harness's task source: plan once, filter, create (D69 H4).

One call, :func:`plan_and_create_tasks`, does the whole of H4 and nothing past it:

1. asks the Supervisor to plan **exactly once**;
2. throws away, counts and never re-asks about every planned task that the harness will not
   run;
3. creates each remaining task, one transaction apiece, and only after that transaction has
   committed writes its id into the in-memory :class:`RunTaskLedger`.

What is in this module and what is deliberately not:

* A planning call that returns ``None`` (which is how the real adapters report a refusal and a
  failure alike) or raises ``SupervisorRefusal`` creates no task and is recorded as one of the
  two closed codes in :data:`PLAN_FAILURE_CODES`. Neither the model's words nor an exception's
  text is copied into the record, and nothing asks the Supervisor a second time. Any other
  exception from ``plan`` is not caught: it is a bug in the caller, not a planning outcome.
* A planned task is refused, before ``create_task``, when its action is not on the allowlist
  (H2's :func:`~harness.action_allowlist.check_task_action`) and then when it is a ``cidr``
  with no prefix length. The second rule exists because the Task Manager reads a prefix-less
  ``cidr`` as a single address: ``10.82.0.0`` becomes ``cidr:10.82.0.0/32``, which is not the
  range the Supervisor meant, so it would be recorded, deduplicated and scanned as something
  else. The order matters only for which reason is counted when both apply; the action comes
  first.
* The exception ``create_task`` raises, and the one an unsuccessful commit raises, are **not**
  caught. They propagate, and a task whose creation did not commit is not in the ledger. Tasks
  created earlier in the same plan stay created and stay in the ledger.
* The ledger knows only the ids this process wrote. It loads nothing from the database, which
  is the point: a task left by an earlier run is not in it. It is not a claim queue and
  nothing here claims, proposes or completes a task.

``created_by`` is the caller's; this module has no opinion about the agent identity. The
candidates handed to the Supervisor are the caller's too -- a caller that offers unfiltered
candidates is still held to the allowlist by the check here, which is what makes it a backstop.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from agents.base_agent import ProposedTask
from agents.llm.supervisor_base import BaseSupervisor, StateSummary, SupervisorRefusal
from agents.llm.worker_base import ScopeCandidate
from control_plane.api.function_api import create_task
from control_plane.canonicalizer.target import CanonicalizationError, normalize_target
from control_plane.state.db import engagement_scope
from harness.action_allowlist import (
    REASON_CIDR_WITHOUT_PREFIX,
    REASON_TARGET_NOT_CANONICAL,
    SIDE_TASK,
    RefusalCounter,
    check_task_action,
)

#: The planning call returned ``None``: the real adapters answer so for a refusal and for a
#: failure alike, so the two are not told apart.
PLAN_RETURNED_NONE = "plan_returned_none"

#: The planning call raised ``SupervisorRefusal``.
PLAN_REFUSED = "plan_refused"

#: The closed vocabulary of planning failures. A record carries one of these, never text.
PLAN_FAILURE_CODES: tuple[str, ...] = (PLAN_RETURNED_NONE, PLAN_REFUSED)


class RunTaskLedger:
    """The ids of the tasks this process created, in memory, and nothing else."""

    def __init__(self) -> None:
        self._ids: set[str] = set()

    def add(self, task_id: str) -> None:
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("a task id is a non-empty string")
        self._ids.add(task_id)

    def __contains__(self, task_id: object) -> bool:
        return task_id in self._ids

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(self._ids)


@dataclass(frozen=True)
class CreatedTask:
    task_id: str
    task: ProposedTask


@dataclass(frozen=True)
class PlanOutcome:
    """What one planning round did: the tasks it created, or the one reason it created none."""

    created: tuple[CreatedTask, ...] = ()
    failure: str | None = None


def _is_cidr_without_prefix(task: ProposedTask) -> bool:
    """A ``cidr`` whose value is not a string with a prefix length (fail closed on the odd)."""
    identity = task.target.get("logical_identity") if isinstance(task.target, Mapping) else None
    if not isinstance(identity, Mapping) or identity.get("type") != "cidr":
        return False
    value = identity.get("value")
    return not (isinstance(value, str) and "/" in value)


def plan_and_create_tasks(
    *,
    supervisor: BaseSupervisor,
    state: StateSummary,
    candidates: tuple[ScopeCandidate, ...],
    engagement_id: str,
    created_by: str,
    ledger: RunTaskLedger,
    counter: RefusalCounter,
) -> PlanOutcome:
    """Ask for one plan, refuse what the harness will not run, create the rest."""
    try:
        planned = supervisor.plan(state=state, candidates=candidates)
    except SupervisorRefusal:
        return PlanOutcome(failure=PLAN_REFUSED)
    if planned is None:
        return PlanOutcome(failure=PLAN_RETURNED_NONE)

    allowed: list[ProposedTask] = []
    for task in planned:
        if not check_task_action(task.action, counter=counter).allowed:
            continue
        if _is_cidr_without_prefix(task):
            counter.record(side=SIDE_TASK, reason=REASON_CIDR_WITHOUT_PREFIX)
            continue
        try:
            normalize_target(dict(task.target))
        except CanonicalizationError:
            counter.record(side=SIDE_TASK, reason=REASON_TARGET_NOT_CANONICAL)
            continue
        allowed.append(task)

    created: list[CreatedTask] = []
    for task in allowed:
        with engagement_scope(engagement_id) as conn:
            task_id = create_task(
                conn, engagement_id=engagement_id, task=task, created_by=created_by,
            )
        ledger.add(task_id)
        created.append(CreatedTask(task_id=task_id, task=task))
    return PlanOutcome(created=tuple(created))
