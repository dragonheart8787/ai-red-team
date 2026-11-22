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

import ipaddress
import time

from agents.llm.reviewer_base import BaseReviewer, ReviewCall
from agents.llm.supervisor_base import BaseSupervisor, SupervisorCall, SupervisorRefusal
from agents.llm.worker_base import BaseWorker, WorkerCall, WorkerRefusal
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


class ShadowSandbox:
    """The sandbox the compliant factories return; the tests approve its class by hand-in (S2)."""

    def run(self, **kwargs):
        raise AssertionError("the shadow runner's tests never reach a sandbox")


def build() -> Roles:
    return Roles(ShadowSupervisor(), ShadowWorker(), ShadowReviewer(), ShadowSandbox())


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


class SubclassedSandbox(ShadowSandbox):
    """A subclass of an approved sandbox class: refused, because the check is by exact type."""


# -- roles for the run record (S2): they keep ``calls`` as the real adapters do ------------------

#: Stand-ins for text a model or a target wrote: neither may appear in a run record.
NOTE_MARK = "MODEL-NOTE-7f3a"
FAILURE_MARK = "MODEL-FAILURE-91c2"


class RecordSupervisor(BaseSupervisor):
    """Plans three tasks: the scope's own range (proposed, then denied), one host in it (the
    Worker fails on it) and the range's address with no prefix (refused by the harness)."""

    agent_id = "record-scripted-supervisor"
    model = "scripted-supervisor"

    def plan(self, *, state, candidates):
        started = time.monotonic()
        if not candidates:
            return self._refuse(started, "no scope candidates were offered")
        first = candidates[0]
        network = ipaddress.ip_network(first.value, strict=False)
        targets = (("cidr", first.value), ("ip", str(network[5])),
                   ("cidr", str(network.network_address)))
        payload = {"status_assessment": "work_remains", "assessment_note": NOTE_MARK,
                   "tasks": [{"scope_object_id": first.scope_object_id,
                              "action": first.allowed_actions[0], "target_type": kind,
                              "target_value": value, "goal": f"scan {value}", "priority": 1}
                             for kind, value in targets]}
        try:
            tasks = self._to_tasks(payload, candidates=candidates)
        except SupervisorRefusal as exc:
            return self._refuse(started, f"unusable plan: {exc}")
        self.calls.append(SupervisorCall(
            latency_seconds=time.monotonic() - started, input_tokens=7, output_tokens=11,
            model=self.model, task_count=len(tasks), status_assessment="work_remains",
            assessment_note=NOTE_MARK))
        return tasks


class RecordWorker(BaseWorker):
    """Proposes the range through ``_to_proposal``; fails, with a marked reason, on a host."""

    agent_id = "record-scripted-worker"
    model = "scripted-worker"

    def propose(self, *, task, candidates, observations=(), task_id=None):
        started = time.monotonic()
        identity = task.target["logical_identity"]
        if identity["type"] == "ip":
            return self._refuse(started, f"unusable proposal: {FAILURE_MARK}")
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


class RecordReviewer(BaseReviewer):
    reviewer_id = "record-scripted-reviewer"
    model = "scripted-reviewer"

    def review(self, *, proposal, canonical_target):
        started = time.monotonic()
        opinion = self._to_opinion({"risk_hint": "low"})
        self.calls.append(ReviewCall(latency_seconds=time.monotonic() - started,
                                     input_tokens=2, output_tokens=1, model=self.model))
        return opinion


#: Every ``Roles`` that ``build_recording`` made, in order; a test clears it first.
BUILT_RECORDING: list[Roles] = []


def build_recording() -> Roles:
    BUILT_RECORDING.append(Roles(RecordSupervisor(), RecordWorker(), RecordReviewer(),
                                 ShadowSandbox()))
    return BUILT_RECORDING[-1]
