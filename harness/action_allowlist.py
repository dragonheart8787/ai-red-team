"""The harness's action allowlist (D69-6, option A').

The harness offers the roles two actions and no others::

    network.scan   network.recon

``ad.collect``, ``code.scan``, ``code.secrets`` and the ``web.*`` actions are outside it.
The list is a closed constant, not configuration: the first production harness runs the
two actions whose failure modes D68 measured, and widening it is a decision for a person
to take in a later stage, not a value to read from a file at start-up.

Three things live here, and they are the whole of H2:

* :data:`ALLOWED_ACTIONS`, the list itself;
* :func:`candidates_from_scope_objects`, which turns registry rows into the candidates a
  role is offered, with each row's ``allowed_actions`` filtered to the list. A row left
  with no action is not offered at all -- a candidate whose actions are all outside the
  list is not a choice, and offering it with an empty ``allowed_actions`` would invite a
  role to pick an action nobody offered;
* :func:`check_task_action` and :func:`check_proposal_action`, the two checks a caller
  runs *before* it reaches the control plane -- the first before ``create_task``, the
  second before ``propose_action``. They are checks, not calls: nothing in this module
  creates a task, claims one or proposes an action.

The filter and the checks say the same thing twice on purpose. The filter means a role
is never shown an action the harness will not run; the checks mean that a role which
names one anyway -- a model that ignored its candidates, a payload assembled by hand, a
future backend that validates less -- is refused in this process rather than in the
Authorization Resolver.

A refusal is **counted, not retried**: the caller records it and moves on. It never asks
the role again with the same inputs, because a role that returned an action outside the
list once has no new information that would make the second answer better, and a retry
loop is how a quiet refusal becomes a busy one. What a refusal records is a reason code
from :data:`REASON_CODES` and nothing else: no model-produced string reaches a refusal
record, so none can reach a prompt or a ``result_summary`` through one.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agents.llm.worker_base import ScopeCandidate

#: The closed allowlist. Not configuration, not read from the database, not widened at
#: run time. D69-6 (A').
ALLOWED_ACTIONS: tuple[str, ...] = ("network.scan", "network.recon")

#: Which check refused. The Supervisor side plans tasks; the Worker side proposes actions.
SIDE_TASK = "task"
SIDE_PROPOSAL = "proposal"
SIDES: tuple[str, ...] = (SIDE_TASK, SIDE_PROPOSAL)

#: The closed vocabulary of refusal reasons. A record carries one of these, never text a
#: model wrote.
REASON_ACTION_NOT_ALLOWED = "action_not_in_allowlist"
REASON_ACTION_MISSING = "action_missing"
REASON_CODES: tuple[str, ...] = (REASON_ACTION_NOT_ALLOWED, REASON_ACTION_MISSING)


@dataclass(frozen=True)
class ActionCheck:
    """The answer of one check: allowed, or refused with a reason code."""

    allowed: bool
    reason: str | None = None


class RefusalCounter:
    """Counts refusals, one entry each, by side and reason code.

    Deliberately not a logger and not a store: it holds a count and the pairs it counted,
    so a caller can report "this many refusals, of these kinds" without keeping anything a
    model produced. :meth:`record` refuses a reason outside :data:`REASON_CODES`, which is
    what keeps the vocabulary closed rather than merely conventional.
    """

    def __init__(self) -> None:
        self._entries: list[tuple[str, str]] = []

    def record(self, *, side: str, reason: str) -> None:
        if side not in SIDES:
            raise ValueError(f"unknown side {side!r}; expected one of {list(SIDES)}")
        if reason not in REASON_CODES:
            raise ValueError(
                f"{reason!r} is not one of the closed refusal reasons {list(REASON_CODES)}"
            )
        self._entries.append((side, reason))

    @property
    def total(self) -> int:
        return len(self._entries)

    def count(self, *, side: str | None = None, reason: str | None = None) -> int:
        """How many refusals match ``side`` and ``reason``; either omitted means any."""
        return sum(
            1
            for entry_side, entry_reason in self._entries
            if (side is None or entry_side == side)
            and (reason is None or entry_reason == reason)
        )

    def entries(self) -> tuple[tuple[str, str], ...]:
        """The refusals in the order they happened, as ``(side, reason)`` pairs."""
        return tuple(self._entries)


def _refused(counter: RefusalCounter | None, *, side: str, reason: str) -> ActionCheck:
    if counter is not None:
        counter.record(side=side, reason=reason)
    return ActionCheck(allowed=False, reason=reason)


def candidates_from_scope_objects(scope_objects: Iterable[Any]) -> tuple[ScopeCandidate, ...]:
    """The candidates a role may be offered, from the registry's live scope objects.

    Pure: it reads the rows it is given and returns candidates. No database, no clock, no
    model. Each row keeps only the actions on :data:`ALLOWED_ACTIONS`, in the row's own
    order; a row left with none is left out entirely.
    """
    offered: list[ScopeCandidate] = []
    for scope_object in scope_objects:
        actions = tuple(a for a in tuple(scope_object.allowed_actions) if a in ALLOWED_ACTIONS)
        if not actions:
            continue
        offered.append(ScopeCandidate(
            scope_object_id=scope_object.scope_object_id,
            type=scope_object.type,
            value=scope_object.value,
            allowed_actions=actions,
        ))
    return tuple(offered)


def check_task_action(action: Any, *, counter: RefusalCounter | None = None) -> ActionCheck:
    """Refuse a Supervisor-planned task whose action is outside the allowlist.

    Run before ``create_task``, on the action of each task the Supervisor returned. A
    refusal is counted and the task is not created; the Supervisor is not asked again.
    """
    if not isinstance(action, str) or not action:
        return _refused(counter, side=SIDE_TASK, reason=REASON_ACTION_MISSING)
    if action not in ALLOWED_ACTIONS:
        return _refused(counter, side=SIDE_TASK, reason=REASON_ACTION_NOT_ALLOWED)
    return ActionCheck(allowed=True, reason=None)


def check_proposal_action(action: Any, *, counter: RefusalCounter | None = None) -> ActionCheck:
    """Refuse a Worker proposal whose action is outside the allowlist.

    Run before ``propose_action``, on the action of the proposal the Worker returned. A
    refusal is counted and nothing is proposed; the Worker is not asked again.
    """
    if not isinstance(action, str) or not action:
        return _refused(counter, side=SIDE_PROPOSAL, reason=REASON_ACTION_MISSING)
    if action not in ALLOWED_ACTIONS:
        return _refused(counter, side=SIDE_PROPOSAL, reason=REASON_ACTION_NOT_ALLOWED)
    return ActionCheck(allowed=True, reason=None)
