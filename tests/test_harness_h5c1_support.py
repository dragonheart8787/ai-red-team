"""Helpers the H5c1 tests share (no test is in this file; its name is what the task allows).

The real adapter (``harness/loop_adapter.py``) is driven here with **scripted roles** (a Supervisor
that returns the tasks it is told to, a Worker that returns the proposal it is told to), the
control plane's own fake reviewer and a **fake sandbox**: no model, no container, no network. The
database is the test database, as ``cyberorch_app``.

``drive`` runs ``harness.loop.run_loop`` over an adapter with finite bounds, so a loop that ignores
one of them still ends and the test that sees it fails instead of hanging.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import text

from agents.base_agent import ProposedAction, ProposedTask
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.llm.supervisor_base import BaseSupervisor
from agents.llm.worker_base import BaseWorker
from control_plane.api.function_api import claim_task, complete_task
from control_plane.orchestrator.engagement import engage_kill_switch
from control_plane.state.db import engagement_scope
from harness.bounds import Bounds, RunCounters
from harness.loop import LoopResult, run_loop
from harness.loop_adapter import LoopAdapter
from harness.signals import SignalFlag
from tests.task_support import task_for
from tool_gateway.sandbox import SandboxResult

CIDR = "10.82.0.0/24"
TARGET = "10.82.0.5"
WINDOW = 25            # the evidence window the tests use: an explicit number, never a default


def host(n: int) -> str:
    return f"10.82.0.{n}"


class CountingReviewer(HonestFakeReviewer):
    """Counts its calls, and can run a hook (an injected fault, a kill switch) inside one."""

    def __init__(self, hook=None):
        super().__init__()
        self.calls = 0
        self.hook = hook

    def review(self, **kwargs):
        self.calls += 1
        if self.hook is not None:
            self.hook()
        return super().review(**kwargs)


class FakeSandbox:
    """Stands in for the container; counts its calls."""

    def __init__(self):
        self.calls = 0

    def run(self, **kwargs):
        self.calls += 1
        return SandboxResult(0, "Nmap done: 1 host up", "", False, 0.5, (CIDR,), "fake")


class ScriptedSupervisor(BaseSupervisor):
    """Returns the tasks it is given, once per call, and keeps what it was shown."""

    agent_id = "scripted-supervisor"

    def __init__(self, tasks_for_call):
        super().__init__()
        self._tasks_for_call = tasks_for_call
        self.plan_calls = 0
        self.seen_candidates: list[tuple] = []

    def plan(self, *, state, candidates):
        self.plan_calls += 1
        self.seen_candidates.append(tuple(candidates))
        return self._tasks_for_call(self.plan_calls)


class ScriptedWorker(BaseWorker):
    """Returns ``make(task, task_id)`` (a proposal) for each call, and keeps what it was shown."""

    agent_id = "scripted-worker"

    def __init__(self, make):
        super().__init__()
        self._make = make
        self.work_calls = 0
        self.seen: list[tuple] = []

    def propose(self, *, task, candidates, observations=(), task_id=None):
        self.work_calls += 1
        self.seen.append((task_id, tuple(candidates)))
        return self._make(task, task_id)


@dataclass
class World:
    engagement_id: str
    scope_id: str
    registry: object
    extra: dict = field(default_factory=dict)

    def task(self, n: int = 5, action: str = "network.scan") -> ProposedTask:
        return ProposedTask(
            goal=f"Scan {host(n)} for open ports and the services behind them",
            target={"logical_identity": {"type": "ip", "value": host(n)}},
            action=action, scope_object_id=self.scope_id)

    def proposal(self, task: ProposedTask, task_id: str | None) -> ProposedAction:
        # ``task_id`` is passed on purpose, even when it is None: the tests that need a proposal
        # with no task say so (tests/test_task_less_callers.py reads a missing keyword as a defect)
        return ProposedAction(
            action=task.action, target=dict(task.target),
            authorization={"source": "engagement_scope", "scope_object_id": self.scope_id},
            discovery={"source": "explicit_scope"}, task_id=task_id)


def make_world(engagement_id: str, registry) -> World:
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return World(engagement_id, scope_id, registry)


@dataclass
class Rig:
    """An adapter, the roles and fakes behind it, and the engagement they work on."""

    world: World
    adapter: LoopAdapter
    supervisor: ScriptedSupervisor
    worker: ScriptedWorker
    reviewer: CountingReviewer
    sandbox: FakeSandbox


class OneEngagement:
    """The enrolment of a test: one engagement, no database."""

    def __init__(self, engagement_id: str):
        self._ids = (engagement_id,)

    def enrolled(self) -> tuple[str, ...]:
        return self._ids


def make_rig(world: World, *, tasks_for_call=None, make_proposal=None, reviewer_hook=None,
             live_task_limit: int | None = None) -> Rig:
    supervisor = ScriptedSupervisor(
        tasks_for_call or (lambda call: [world.task(5)]))
    worker = ScriptedWorker(make_proposal or world.proposal)
    reviewer = CountingReviewer(hook=reviewer_hook)
    sandbox = FakeSandbox()
    options = {} if live_task_limit is None else {"live_task_limit": live_task_limit}
    adapter = LoopAdapter(
        enrolment=OneEngagement(world.engagement_id), supervisor=supervisor, worker=worker,
        reviewer=reviewer, sandbox=sandbox, objective="find the open ports of the range",
        window_limit=WINDOW, **options)
    return Rig(world, adapter, supervisor, worker, reviewer, sandbox)


def drive(adapter: LoopAdapter, *, max_rounds: int = 1, max_calls: int = 100,
          no_progress: int = 5) -> LoopResult:
    return run_loop(
        adapter, Bounds(max_rounds, max_calls, no_progress), RunCounters(), adapter.refusals,
        window_limit=WINDOW, stop_event=SignalFlag(), once=False)


# -- the rows, read as ``cyberorch_app`` ---------------------------------------------------------


def task_rows(engagement_id: str) -> list[tuple]:
    with engagement_scope(engagement_id) as conn:
        return [tuple(r) for r in conn.execute(text(
            "SELECT task_id, status, owner_agent_id, lease_expires_at, updated_at, "
            "result_summary FROM tasks ORDER BY created_at, task_id"))]


def proposal_rows(engagement_id: str) -> list[tuple]:
    with engagement_scope(engagement_id) as conn:
        return [tuple(r) for r in conn.execute(text(
            "SELECT proposal_id, task_id, pipeline_stage, decision, request_idempotency_key "
            "FROM action_proposals ORDER BY created_at, proposal_id"))]


def count_rows(engagement_id: str, table: str) -> int:
    assert table in ("capabilities", "tool_runs", "action_proposals", "tasks")
    with engagement_scope(engagement_id) as conn:
        return conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()


# -- tasks made without the loop -----------------------------------------------------------------


def queued_task(world: World, n: int) -> str:
    """A queued task, made as the product makes one (``create_task``), for host ``n``."""
    return task_for(world.engagement_id, world.proposal(world.task(n), None))


def claimed_task(world: World, n: int) -> str:
    task_id = queued_task(world, n)
    with engagement_scope(world.engagement_id) as conn:
        claimed = claim_task(conn, engagement_id=world.engagement_id, agent_id="an-earlier-run")
    assert claimed == task_id
    return task_id


def completed_task(world: World, n: int) -> str:
    task_id = claimed_task(world, n)
    with engagement_scope(world.engagement_id) as conn:
        complete_task(conn, engagement_id=world.engagement_id, task_id=task_id,
                      result_summary="not_run", actor="an-earlier-run")
    return task_id


def kill(engagement_id: str) -> None:
    with engagement_scope(engagement_id) as conn:
        engage_kill_switch(conn, engagement_id=engagement_id, actor="test", reason="test")
