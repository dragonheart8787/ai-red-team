"""The scripted roles H5c2's tests hand to ``scripts/run_harness.py`` (``--role-factory``).

No model and no container: a Supervisor that plans ``H5C2_TASKS`` tasks on the test range, a Worker
that proposes ``network.scan`` for the task it is given, the control plane's fake reviewer and a
fake sandbox. ``H5C2_SCOPE_ID`` names the scope object of the test engagement. When ``H5C2_SLOW`` is
set, the Worker's **first** call prints ``WORKER-STARTED`` (flushed) and then waits that many
seconds, which is the moment a test sends a real signal to the process.

``HOOKS`` is for a test that runs the script in its own process: ``HOOKS["work"]``, when set, is
called at the start of every Worker call.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from agents.base_agent import ProposedAction, ProposedTask
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.llm.supervisor_base import BaseSupervisor
from agents.llm.worker_base import BaseWorker

HOOKS: dict = {}


class _Sandbox:
    def run(self, **kwargs):
        raise AssertionError("the sandbox is not reached: the policy denies the action")


class _Supervisor(BaseSupervisor):
    agent_id = "h5c2-supervisor"
    model = "scripted-supervisor"

    def plan(self, *, state, candidates):
        scope_id = os.environ["H5C2_SCOPE_ID"]
        return [
            ProposedTask(
                goal=f"Scan 10.82.0.{5 + n} for open ports and the services behind them",
                target={"logical_identity": {"type": "ip", "value": f"10.82.0.{5 + n}"}},
                action="network.scan", scope_object_id=scope_id)
            for n in range(int(os.environ.get("H5C2_TASKS", "3")))]


class _Worker(BaseWorker):
    agent_id = "h5c2-worker"
    model = "scripted-worker"

    def __init__(self) -> None:
        super().__init__()
        self._calls = 0

    def propose(self, *, task, candidates, observations=(), task_id=None):
        self._calls += 1
        if HOOKS.get("work") is not None:
            HOOKS["work"]()
        slow = float(os.environ.get("H5C2_SLOW", "0"))
        if self._calls == 1 and slow:
            print("WORKER-STARTED", flush=True)
            time.sleep(slow)
        return ProposedAction(
            action=task.action, target=dict(task.target),
            authorization={"source": "engagement_scope",
                           "scope_object_id": os.environ["H5C2_SCOPE_ID"]},
            discovery={"source": "explicit_scope"}, task_id=task_id)


@dataclass
class Roles:
    supervisor: object
    worker: object
    reviewer: object
    sandbox: object


def build() -> Roles:
    return Roles(_Supervisor(), _Worker(), HonestFakeReviewer(), _Sandbox())
