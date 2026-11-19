"""The scripted roles H7's lab tests hand to ``scripts/run_harness.py`` (``--role-factory``).

No model and no container, as in ``tests/harness_h5c2_roles.py``, whose ``Roles`` it reuses. Two
differences, both because H7's tests run the script as a **process** and can only steer it through
the environment:

* the Supervisor plans for the engagement it is asked about (``state.engagement_id``) with that
  engagement's own scope object, from ``H7_SCOPES`` (``ENG-A=SCOPE-A,ENG-B=SCOPE-B``), so a run can
  cover more than one engagement; ``H7_TASKS`` is how many tasks each plan holds (default 3);
* ``H7_FAULT=reviewer`` makes the reviewer raise before it answers: the fault inside
  ``propose_action`` that ends a run with exit code 12 and leaves the proposal at ``received``
  (the state of ``tests/test_harness_h5c1_pipeline.py``, H5-3).

The sandbox is never reached: the neutral baseline of the test database denies the action.
"""

from __future__ import annotations

import os

from agents.base_agent import ProposedAction, ProposedTask
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.llm.supervisor_base import BaseSupervisor
from agents.llm.worker_base import BaseWorker
from tests.harness_h5c2_roles import Roles


class _Sandbox:
    def run(self, **kwargs):
        raise AssertionError("the sandbox is not reached: the policy denies the action")


class _Supervisor(BaseSupervisor):
    agent_id = "h7-supervisor"
    model = "scripted-supervisor"

    def plan(self, *, state, candidates):
        scopes = dict(pair.split("=", 1) for pair in os.environ["H7_SCOPES"].split(","))
        scope_id = scopes[state.engagement_id]
        return [
            ProposedTask(
                goal=f"Scan 10.82.0.{5 + n} for open ports and the services behind them",
                target={"logical_identity": {"type": "ip", "value": f"10.82.0.{5 + n}"}},
                action="network.scan", scope_object_id=scope_id)
            for n in range(int(os.environ.get("H7_TASKS", "3")))]


class _Worker(BaseWorker):
    agent_id = "h7-worker"
    model = "scripted-worker"

    def propose(self, *, task, candidates, observations=(), task_id=None):
        return ProposedAction(
            action=task.action, target=dict(task.target),
            authorization={"source": "engagement_scope", "scope_object_id": task.scope_object_id},
            discovery={"source": "explicit_scope"}, task_id=task_id)


class _Reviewer(HonestFakeReviewer):
    def review(self, **kwargs):
        if os.environ.get("H7_FAULT") == "reviewer":
            raise RuntimeError("injected into the pipeline")
        return super().review(**kwargs)


def build() -> Roles:
    return Roles(_Supervisor(), _Worker(), _Reviewer(), _Sandbox())
