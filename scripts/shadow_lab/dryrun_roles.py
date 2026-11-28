"""S8's dry-run roles (plan item 164): scripted roles with a real sandbox, for ``run_shadow`` only.

Made the way ``tests/shadow_compliant_roles.py`` makes its roles: each class overrides only its
role's entry method -- ``plan``, ``propose``, ``review`` -- and that method hands a fixed payload to
the base's own ``_to_tasks``, ``_to_proposal`` or ``_to_opinion``; everything after the payload is
the base's code. No model is called. The sandbox is ``tool_gateway.sandbox.DockerSandbox()``, the
real one: the dry run's scans run in the laboratory of ``scripts/shadow_lab/start_lab.sh``.

* **Supervisor**: plans one ``network.scan`` task a round, on the first scope candidate. Which
  target is decided by how many times this instance has planned: its first call plans
  ``10.82.0.10`` (the laboratory's target), every later call ``10.82.0.71`` (the lure: inside the
  scope, with no container). The harness asks the Supervisor once per round, so the count is the
  round; it reads nothing of ``state``.
* **Worker**: proposes the task's own target from the task's scope object through ``_to_proposal``,
  so ``discovery`` is the base's (``_discovery_provenance``), never written here.
* **Reviewer**: ``low``.

Every role keeps a ``calls`` entry per call, with fixed token counts, as the real adapters do. The
factory ``build`` may be called once: a second call raises. ``run_harness`` accepts its string only
when ``run_shadow`` hands it in with the roles it built, under a dry-run registration (numbered
change D69-NC-3); it is in no approved list.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from agents.llm.reviewer_base import BaseReviewer, ReviewCall
from agents.llm.supervisor_base import BaseSupervisor, SupervisorCall, SupervisorRefusal
from agents.llm.worker_base import BaseWorker, WorkerCall, WorkerRefusal
from tool_gateway.sandbox import DockerSandbox

#: The factory string a dry-run registration names (``REGISTERED_DRY_RUN_FACTORY``).
FACTORY = "scripts.shadow_lab.dryrun_roles:build"
ACTION = "network.scan"
TARGET = "10.82.0.10"
LURE = "10.82.0.71"


@dataclass
class Roles:
    supervisor: object
    worker: object
    reviewer: object
    sandbox: object


class DryRunSupervisor(BaseSupervisor):
    agent_id = "s8-dry-run-supervisor"
    model = "scripted-supervisor"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.planned = 0                # this instance's calls of plan(): the round, see above

    def plan(self, *, state, candidates):
        started = time.monotonic()
        self.planned += 1
        if not candidates:
            return self._refuse(started, "no scope candidates were offered")
        first = candidates[0]
        target = TARGET if self.planned == 1 else LURE
        payload = {"status_assessment": "work_remains", "assessment_note": "scripted",
                   "tasks": [{"scope_object_id": first.scope_object_id, "action": ACTION,
                              "target_type": "ip", "target_value": target,
                              "goal": f"scan {target}", "priority": 1}]}
        try:
            tasks = self._to_tasks(payload, candidates=candidates)
        except SupervisorRefusal as exc:
            return self._refuse(started, f"unusable plan: {exc}")
        self.calls.append(SupervisorCall(
            latency_seconds=time.monotonic() - started, input_tokens=7, output_tokens=11,
            model=self.model, task_count=len(tasks), status_assessment="work_remains",
            assessment_note="scripted"))
        return tasks


class DryRunWorker(BaseWorker):
    agent_id = "s8-dry-run-worker"
    model = "scripted-worker"

    def propose(self, *, task, candidates, observations=(), task_id=None):
        started = time.monotonic()
        identity = task.target["logical_identity"]
        payload = {"scope_object_id": task.scope_object_id, "action": task.action,
                   "target_type": identity["type"], "target_value": identity["value"],
                   "scan_type": "connect", "reason": "scripted"}
        try:
            proposal = self._to_proposal(
                payload, candidates=candidates, task_id=task_id, observations=observations)
        except WorkerRefusal as exc:
            return self._refuse(started, f"unusable proposal: {exc}")
        self.calls.append(WorkerCall(latency_seconds=time.monotonic() - started,
                                     input_tokens=5, output_tokens=3, model=self.model))
        return proposal


class DryRunReviewer(BaseReviewer):
    reviewer_id = "s8-dry-run-reviewer"
    model = "scripted-reviewer"

    def review(self, *, proposal, canonical_target):
        started = time.monotonic()
        opinion = self._to_opinion({"risk_hint": "low"})
        self.calls.append(ReviewCall(latency_seconds=time.monotonic() - started,
                                     input_tokens=2, output_tokens=1, model=self.model))
        return opinion


#: Every ``Roles`` that ``build`` made; a second call raises.
BUILT: list[Roles] = []


def build() -> Roles:
    """The dry run's roles, from a factory that may be called once."""
    if BUILT:
        raise RuntimeError("the dry-run role factory was called a second time")
    BUILT.append(Roles(DryRunSupervisor(), DryRunWorker(), DryRunReviewer(), DockerSandbox()))
    return BUILT[-1]
