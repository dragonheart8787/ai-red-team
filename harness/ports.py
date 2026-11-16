"""D69 H5a2 (a7): the small interface between the loop and everything that has a side effect.

The loop (:mod:`harness.loop`) decides *when* things happen; it does not know *how*. Every
read of the database, every model call and every write goes through one of the ten methods of
:class:`LoopPorts`, and a method returns a plain value or one of the small dataclasses below.
That is what lets the loop be tested with a stand-in that records the order of its calls
(``tests/harness_fakes.py``), and what keeps this package free of the control plane: nothing
here imports ``control_plane`` or ``sqlalchemy``, and nothing here names the control plane's
functions. The real adapter, in a later stage, is the only place that does.

The method names are fixed::

    enrolled()                                          the engagements this run works on
    accepts_work(engagement_id)                         the pause and kill check
    live_tasks(engagement_id)                           queued, claimed and running tasks only
    take_snapshot(engagement_id)                        an opaque round snapshot
    plan(engagement_id, snapshot)                       the Supervisor, once
    claim(engagement_id)                                the id of the claimed task, or None
    work(engagement_id, task_id, snapshot)              the Worker, once
    load_policy(engagement_id)                          the policy, read once per proposal
    propose(engagement_id, task_id, proposal, policy, idempotency_key)
    complete(engagement_id, task_id, summary)           writes the task's result_summary

``propose`` returns an outcome with the five fields :mod:`harness.result_summary` reads:
``decision``, ``failure``, ``run_id``, ``evidence_id`` and ``deny_reasons``. ``snapshot``,
``proposal`` and ``policy`` are opaque to the loop: it only hands them on.

A port may raise: ``run_loop`` catches whatever it raises, ends with ``FAULT_OUTSIDE_LIST``
(exit code 12), cleans nothing up and never records the text of the exception (see
:mod:`harness.loop`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from harness.enrolment import EnrolmentReader


@dataclass(frozen=True)
class LiveTask:
    """One row of ``live_tasks``: a task that is queued, claimed or running."""

    task_id: str
    status: str


@dataclass(frozen=True)
class PlannedTask:
    """One task the planning call created. The loop reads only its id."""

    task_id: str


@dataclass(frozen=True)
class PlanResult:
    """What one planning call did: the tasks it created, or the one reason it created none.

    Corresponds to H4's ``PlanOutcome``; the loop uses the ids of ``created`` and whether
    ``failure`` is ``None``, and nothing else.
    """

    created: tuple[PlannedTask, ...] = ()
    failure: str | None = None


@dataclass(frozen=True)
class WorkResult:
    """One call of the Worker.

    ``refusal`` is the model-side failure (the Worker declined or failed); ``proposal`` is
    ``None`` then, or may be ``None`` without it. ``action`` is the action named by the
    proposal, taken out of it by the adapter so that the loop can run the allowlist check
    without knowing the shape of a proposal.
    """

    proposal: Any = None
    refusal: bool = False
    action: str | None = None


class LoopPorts(EnrolmentReader, Protocol):
    """Everything the loop does to the outside world."""

    def accepts_work(self, engagement_id: str) -> bool: ...

    def live_tasks(self, engagement_id: str) -> tuple[LiveTask, ...]: ...

    def take_snapshot(self, engagement_id: str) -> object: ...

    def plan(self, engagement_id: str, snapshot: object) -> PlanResult: ...

    def claim(self, engagement_id: str) -> str | None: ...

    def work(self, engagement_id: str, task_id: str, snapshot: object) -> WorkResult: ...

    def load_policy(self, engagement_id: str) -> object: ...

    def propose(
        self,
        engagement_id: str,
        task_id: str,
        proposal: object,
        policy: object,
        idempotency_key: str,
    ) -> Any: ...

    def complete(self, engagement_id: str, task_id: str, summary: str) -> None: ...
