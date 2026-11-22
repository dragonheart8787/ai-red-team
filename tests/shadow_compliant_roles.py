"""Scripted roles that satisfy the shadow runner's role check (plan item 137), for its tests only.

Each overrides only its role's entry method -- ``propose``, ``plan``, ``review`` -- and that method
returns what the base's own ``_to_proposal``, ``_to_tasks`` or ``_to_opinion`` makes of a fixed
payload: the "model" is a constant, everything after it is the base's code. The Reviewer is a
``BaseReviewer`` (``HonestFakeReviewer`` is not). No model, no container. These classes are not in
``scripts/run_shadow.py``'s ``APPROVED_ROLE_CLASSES`` and this module's factories are not in
``scripts/run_harness.py``'s ``APPROVED_ROLE_FACTORIES``; the tests hand both in.

Also here: role classes that break the check one way each, so that each refusal has a subject.
"""

from __future__ import annotations

import time

from agents.llm.reviewer_base import BaseReviewer
from agents.llm.supervisor_base import BaseSupervisor, SupervisorRefusal
from agents.llm.worker_base import BaseWorker, WorkerRefusal
from tests.harness_h5c2_roles import Roles


class ShadowWorker(BaseWorker):
    agent_id = "shadow-scripted-worker"
    model = "scripted-worker"

    def propose(self, *, task, candidates, observations=(), task_id=None):
        identity = task.target["logical_identity"]
        payload = {"scope_object_id": task.scope_object_id, "action": task.action,
                   "target_type": identity["type"], "target_value": identity["value"],
                   "scan_type": "connect", "reason": "scripted"}
        started = time.monotonic()
        try:
            return self._to_proposal(
                payload, candidates=candidates, task_id=task_id, observations=observations)
        except WorkerRefusal as exc:
            return self._refuse(started, f"unusable proposal: {exc}")


class ShadowSupervisor(BaseSupervisor):
    agent_id = "shadow-scripted-supervisor"
    model = "scripted-supervisor"

    def plan(self, *, state, candidates):
        if not candidates:
            return self._refuse(time.monotonic(), "no scope candidates were offered")
        first = candidates[0]
        payload = {"status_assessment": "work_remains", "assessment_note": "scripted",
                   "tasks": [{"scope_object_id": first.scope_object_id,
                              "action": first.allowed_actions[0], "target_type": "ip",
                              "target_value": "10.82.0.5", "goal": "scan 10.82.0.5",
                              "priority": 1}]}
        started = time.monotonic()
        try:
            return self._to_tasks(payload, candidates=candidates)
        except SupervisorRefusal as exc:
            return self._refuse(started, f"unusable plan: {exc}")


class ShadowReviewer(BaseReviewer):
    reviewer_id = "shadow-scripted-reviewer"
    model = "scripted-reviewer"

    def review(self, *, proposal, canonical_target):
        return self._to_opinion({"risk_hint": "low"})


class _Sandbox:
    def run(self, **kwargs):
        raise AssertionError("the shadow runner's tests never reach a sandbox")


def build() -> Roles:
    return Roles(ShadowSupervisor(), ShadowWorker(), ShadowReviewer(), _Sandbox())


#: Every ``Roles`` that ``build_once`` made, in order; a test clears it first.
BUILT: list[Roles] = []


def build_once() -> Roles:
    """The compliant roles, from a factory that may be called once: a second call raises."""
    if BUILT:
        raise AssertionError("the role factory was called a second time")
    BUILT.append(build())
    return BUILT[-1]


# -- one way each of breaking the check ---------------------------------------------------------


class SubclassedWorker(ShadowWorker):
    """A subclass of an approved class: refused, because the check is by exact type."""


class OwnToProposalWorker(ShadowWorker):
    def _to_proposal(self, payload, **kwargs):
        return BaseWorker._to_proposal(self, payload, **kwargs)


class OwnBuildPromptWorker(ShadowWorker):
    def build_prompt(self, **kwargs):
        return BaseWorker.build_prompt(self, **kwargs)


class OwnRefuseWorker(ShadowWorker):
    def _refuse(self, started, reason, *, usage=None):
        return BaseWorker._refuse(self, started, reason, usage=usage)


class OwnToTasksSupervisor(ShadowSupervisor):
    def _to_tasks(self, payload, **kwargs):
        return BaseSupervisor._to_tasks(self, payload, **kwargs)


class OwnToOpinionReviewer(ShadowReviewer):
    def _to_opinion(self, payload):
        return BaseReviewer._to_opinion(self, payload)
