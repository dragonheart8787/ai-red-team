"""Helpers the H5c2 tests share (no test is in this file; its name is what the task allows).

H5c2's tests drive the H5c1 adapter (``harness/loop_adapter.py``) on the test database with the
scripted roles of ``tests/test_harness_h5c1_support.py``, a **fake sandbox** and the control plane's
fake reviewer: no model, no container, no network. What they add is a policy that *allows* the
action, so that a proposal reaches the sandbox and the real pipeline answers with a run and
evidence, and the other shapes of an answer.

The policy is a layer of the test engagement itself (``publish_policy_layer`` on its own
``engagement_scope`` connection, the way ``tests/test_ad_collection_e2e.py`` does it), retired when
the test ends; nothing global is published and no switch is touched.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field

from control_plane.policy.layers import deactivate_policy_layer, publish_policy_layer
from control_plane.state.db import engagement_scope
from harness.bounds import Bounds, RunCounters
from harness.loop import LoopResult, run_loop
from harness.loop_adapter import LoopAdapter
from harness.signals import SignalFlag
from tests.test_harness_h5c1_support import (
    WINDOW,
    CountingReviewer,
    FakeSandbox,
    OneEngagement,
    ScriptedSupervisor,
    ScriptedWorker,
    World,
)
from tool_gateway.sandbox import SandboxResult, SandboxUnavailable


class RaisingSandbox(FakeSandbox):
    """A sandbox whose ``run`` raises what it is given (and counts the call)."""

    def __init__(self, error: BaseException):
        super().__init__()
        self.error = error

    def run(self, **kwargs):
        self.calls += 1
        raise self.error


class RecordingAdapter(LoopAdapter):
    """The real adapter, and a list of every ``ActionOutcome`` ``propose`` returned."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.outcomes: list = []

    def propose(self, engagement_id, task_id, proposal, policy, idempotency_key):
        outcome = super().propose(engagement_id, task_id, proposal, policy, idempotency_key)
        self.outcomes.append(outcome)
        return outcome


@dataclass
class Rig2:
    world: World
    adapter: RecordingAdapter
    supervisor: ScriptedSupervisor
    worker: ScriptedWorker
    reviewer: CountingReviewer
    sandbox: FakeSandbox
    counters: RunCounters = field(default_factory=RunCounters)
    bounds: Bounds | None = None


def make_rig2(world: World, *, sandbox=None, tasks_for_call=None, make_proposal=None,
              reviewer_hook=None) -> Rig2:
    supervisor = ScriptedSupervisor(tasks_for_call or (lambda call: [world.task(5)]))
    worker = ScriptedWorker(make_proposal or world.proposal)
    reviewer = CountingReviewer(hook=reviewer_hook)
    sandbox = sandbox if sandbox is not None else FakeSandbox()
    adapter = RecordingAdapter(
        enrolment=OneEngagement(world.engagement_id), supervisor=supervisor, worker=worker,
        reviewer=reviewer, sandbox=sandbox, objective="find the open ports of the range",
        window_limit=WINDOW)
    return Rig2(world, adapter, supervisor, worker, reviewer, sandbox)


def drive2(rig: Rig2, *, max_rounds: int = 1, max_calls: int = 100,
           no_progress: int = 5) -> LoopResult:
    rig.bounds = Bounds(max_rounds, max_calls, no_progress)
    return run_loop(
        rig.adapter, rig.bounds, rig.counters, rig.adapter.refusals,
        window_limit=WINDOW, stop_event=SignalFlag(), once=False)


@contextlib.contextmanager
def allowed(engagement_id: str, action: str = "network.scan"):
    """An engagement layer that allows ``action``, for the length of the block."""
    with engagement_scope(engagement_id) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {action: "ALLOW"}}, actor="h5c2-test",
            scoped_to_engagement=True)
    try:
        yield layer_id
    finally:
        with engagement_scope(engagement_id) as conn:
            deactivate_policy_layer(conn, engagement_id=engagement_id, layer_id=layer_id,
                                    actor="h5c2-test")


def an_unavailable_sandbox(text: str) -> RaisingSandbox:
    return RaisingSandbox(SandboxUnavailable(text))


__all__ = ["SandboxResult", "allowed", "an_unavailable_sandbox", "drive2", "make_rig2"]


# -- the enrolment of a test, made and ended for real --------------------------------------------

import os  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy import create_engine, text  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import manage_harness_enrolment as cli  # noqa: E402


@contextlib.contextmanager
def enrolled(*engagement_ids: str):
    """Register these engagements for the harness (the CLI's own function, as ``cyberorch_app``)
    and, whatever happens, withdraw them and remove the test's rows (as the owner:
    ``cyberorch_app`` has no DELETE, which is the point of the table)."""
    try:
        for engagement_id in engagement_ids:
            with cli._connect(False) as conn:
                assert cli.register(conn, engagement_id, "harness_lab", "h5c2-test") is None
        yield
    finally:
        for engagement_id in engagement_ids:
            with cli._connect(False) as conn:
                cli.withdraw(conn, engagement_id, "h5c2-test")
        engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
        try:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE harness_enrolment NO FORCE ROW LEVEL SECURITY"))
                conn.execute(text("DELETE FROM harness_enrolment WHERE engagement_id = ANY(:ids)"),
                             {"ids": list(engagement_ids)})
                conn.execute(text("ALTER TABLE harness_enrolment FORCE ROW LEVEL SECURITY"))
        finally:
            engine.dispose()
