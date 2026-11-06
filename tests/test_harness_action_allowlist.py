"""D69 H2: the harness offers two actions, and refuses anything else (D69-6, A').

The property under test is not "the allowlist constant has two strings in it" -- that is
one line of it -- but that the two strings are the only actions that reach the control
plane along either path:

* the **candidates** a role is offered carry no other action, so a role that reads its
  candidates cannot name one (tests 1-3);
* a role that names one anyway is **refused in this process**, before ``create_task`` on
  the Supervisor path and before ``propose_action`` on the Worker path (tests 4a, 4b).

Test 1 is the control that makes the rest mean something: the same payload, naming
``ad.collect``, is accepted by ``BaseWorker._to_proposal`` and ``BaseSupervisor._to_tasks``
when the candidates come straight from the registry, and refused when they come through
:func:`harness.action_allowlist.candidates_from_scope_objects`. The base classes already
check an action against the candidate it names; what the filter changes is what the
candidate says. Without the control a green test here could mean the base classes refuse
everything.

No database and no model. The scope objects are real :class:`ScopeObject` values built in
the test, the payloads are written by hand, and the two role subclasses raise if anything
asks them for a model call.
"""

from __future__ import annotations

from typing import Any

import pytest

from agents.llm.supervisor_base import BaseSupervisor, SupervisorRefusal
from agents.llm.worker_base import BaseWorker, ScopeCandidate, WorkerRefusal
from control_plane.registry.scope_registry import ScopeObject
from harness.action_allowlist import (
    ALLOWED_ACTIONS,
    REASON_ACTION_MISSING,
    REASON_ACTION_NOT_ALLOWED,
    REASON_CODES,
    SIDE_PROPOSAL,
    SIDE_TASK,
    RefusalCounter,
    candidates_from_scope_objects,
    check_proposal_action,
    check_task_action,
)

# One scope object the harness can work with, and one it cannot. The range's registry entry
# is deliberately wide -- the registry says what the engagement authorized, not what this
# harness runs -- which is what lets the control in test 1 exist at all: an action the base
# classes accept against the unfiltered candidate and refuse against the filtered one.
SCOPE_OBJECTS = (
    ScopeObject(
        scope_object_id="so-range",
        engagement_id="eng-1",
        type="cidr",
        value="10.10.0.0/24",
        allowed_actions=("network.scan", "ad.collect", "code.secrets", "web.get"),
        version=1,
        active=True,
    ),
    ScopeObject(
        scope_object_id="so-host",
        engagement_id="eng-1",
        type="fqdn",
        value="app.example.test",
        allowed_actions=("ad.collect", "web.get"),
        version=1,
        active=True,
    ),
)


def unfiltered_candidates() -> tuple[ScopeCandidate, ...]:
    """The candidates as the registry has them -- what the harness must *not* offer."""
    return tuple(
        ScopeCandidate(
            scope_object_id=obj.scope_object_id,
            type=obj.type,
            value=obj.value,
            allowed_actions=tuple(obj.allowed_actions),
        )
        for obj in SCOPE_OBJECTS
    )


class StubWorker(BaseWorker):
    """A Worker with no backend: ``propose`` is the model call, and it must not happen."""

    agent_id = "test-harness-worker"

    def propose(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("the test asked the Worker for a model call")


class StubSupervisor(BaseSupervisor):
    """A Supervisor with no backend: ``plan`` is the model call, and it must not happen."""

    agent_id = "test-harness-supervisor"

    def plan(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("the test asked the Supervisor for a model call")


def proposal_payload(action: str) -> dict[str, Any]:
    """What a Worker's reply looks like when it names ``action`` on the range."""
    return {
        "scope_object_id": "so-range",
        "action": action,
        "target_type": "cidr",
        "target_value": "10.10.0.0/24",
        "scan_type": "ping",
        "reason": "the task asks for the live hosts of the range",
    }


def task_payload(action: str) -> dict[str, Any]:
    """What a Supervisor's reply looks like when it plans ``action`` on the range."""
    return {
        "status_assessment": "work_remains",
        "tasks": [
            {
                "goal": "find the live hosts of the range",
                "action": action,
                "scope_object_id": "so-range",
                "target_type": "cidr",
                "target_value": "10.10.0.0/24",
                "priority": 0,
            }
        ],
    }


# -- 1. the control: the filter is what refuses the excluded action ----------------------

def test_a_worker_naming_an_excluded_action_is_refused_only_once_the_candidates_are_filtered():
    worker = StubWorker()
    accepted = worker._to_proposal(
        proposal_payload("ad.collect"), candidates=unfiltered_candidates(), task_id="t-1"
    )
    assert accepted.action == "ad.collect"          # the control: nothing else refuses it

    with pytest.raises(WorkerRefusal) as refusal:
        worker._to_proposal(
            proposal_payload("ad.collect"),
            candidates=candidates_from_scope_objects(SCOPE_OBJECTS),
            task_id="t-1",
        )
    assert "ad.collect" in str(refusal.value)


def test_a_supervisor_planning_an_excluded_action_is_refused_once_the_candidates_are_filtered():
    supervisor = StubSupervisor()
    accepted = supervisor._to_tasks(task_payload("ad.collect"), candidates=unfiltered_candidates())
    assert [t.action for t in accepted] == ["ad.collect"]     # the control

    with pytest.raises(SupervisorRefusal) as refusal:
        supervisor._to_tasks(
            task_payload("ad.collect"),
            candidates=candidates_from_scope_objects(SCOPE_OBJECTS),
        )
    assert "ad.collect" in str(refusal.value)


# -- 2. an allowed action passes ---------------------------------------------------------

def test_an_allowed_action_passes_against_the_filtered_candidates_on_both_paths():
    offered = candidates_from_scope_objects(SCOPE_OBJECTS)

    proposal = StubWorker()._to_proposal(
        proposal_payload("network.scan"), candidates=offered, task_id="t-1"
    )
    assert proposal.action == "network.scan"
    assert proposal.authorization["scope_object_id"] == "so-range"

    tasks = StubSupervisor()._to_tasks(task_payload("network.scan"), candidates=offered)
    assert [t.action for t in tasks] == ["network.scan"]
    assert [t.scope_object_id for t in tasks] == ["so-range"]

    assert check_proposal_action("network.scan").allowed is True
    assert check_task_action("network.recon").allowed is True


# -- 3. a candidate with nothing left is not offered -------------------------------------

def test_a_scope_object_whose_only_actions_are_excluded_is_not_offered_at_all():
    offered = candidates_from_scope_objects(SCOPE_OBJECTS)

    assert [c.scope_object_id for c in offered] == ["so-range"]
    assert [c.allowed_actions for c in offered] == [("network.scan",)]
    assert all(c.allowed_actions for c in offered)


# -- 4a. the Supervisor-side check: refused, counted, not asked again --------------------

def test_a_task_whose_action_is_outside_the_allowlist_is_refused_counted_and_not_re_asked():
    counter = RefusalCounter()
    asked = []

    def ask_the_supervisor() -> dict[str, Any]:
        asked.append("plan")
        return task_payload("code.secrets")

    # The candidates were not filtered, so the base class accepts the plan: this check is
    # what stands between it and create_task.
    planned = StubSupervisor()._to_tasks(ask_the_supervisor(), candidates=unfiltered_candidates())
    created = []
    for task in planned:
        outcome = check_task_action(task.action, counter=counter)
        if not outcome.allowed:
            continue                      # counted by the check; no retry, no second ask
        created.append(task)

    assert created == []
    assert counter.count(side=SIDE_TASK, reason=REASON_ACTION_NOT_ALLOWED) == 1
    assert counter.total == 1
    assert asked == ["plan"]


# -- 4b. the Worker-side check: refused, counted, not asked again ------------------------

def test_a_proposal_whose_action_is_outside_the_allowlist_is_refused_counted_and_not_re_asked():
    counter = RefusalCounter()
    asked = []

    def ask_the_worker() -> dict[str, Any]:
        asked.append("propose")
        return proposal_payload("web.get")

    proposal = StubWorker()._to_proposal(
        ask_the_worker(), candidates=unfiltered_candidates(), task_id="t-1"
    )
    outcome = check_proposal_action(proposal.action, counter=counter)

    assert outcome.allowed is False
    assert outcome.reason == REASON_ACTION_NOT_ALLOWED
    assert counter.count(side=SIDE_PROPOSAL, reason=REASON_ACTION_NOT_ALLOWED) == 1
    assert counter.total == 1
    assert asked == ["propose"]


def test_both_checks_refuse_a_missing_action_and_each_refusal_is_counted_on_its_own_side():
    counter = RefusalCounter()
    for action in (None, "", 7):
        assert check_task_action(action, counter=counter).reason == REASON_ACTION_MISSING
        assert check_proposal_action(action, counter=counter).reason == REASON_ACTION_MISSING

    assert counter.count(side=SIDE_TASK, reason=REASON_ACTION_MISSING) == 3
    assert counter.count(side=SIDE_PROPOSAL, reason=REASON_ACTION_MISSING) == 3
    assert counter.total == 6


def test_a_refusal_record_takes_a_reason_code_and_not_a_string_a_model_produced():
    counter = RefusalCounter()
    with pytest.raises(ValueError):
        counter.record(side=SIDE_TASK, reason="I think ad.collect is in scope here")
    with pytest.raises(ValueError):
        counter.record(side="whatever the model called it", reason=REASON_ACTION_NOT_ALLOWED)

    assert counter.total == 0
    assert all(reason in REASON_CODES for _side, reason in counter.entries())


# -- 6. the list itself ------------------------------------------------------------------

def test_the_allowlist_is_exactly_the_two_network_actions():
    assert ALLOWED_ACTIONS == ("network.scan", "network.recon")
    for excluded in ("ad.collect", "code.scan", "code.secrets",
                     "web.get", "web.post", "web.put", "web.delete", "web.render"):
        assert excluded not in ALLOWED_ACTIONS
        assert check_task_action(excluded).allowed is False
        assert check_proposal_action(excluded).allowed is False
