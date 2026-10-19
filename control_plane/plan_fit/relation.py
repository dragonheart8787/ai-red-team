"""P1: the relation between a proposal and the task it names (D68, ACCEPTANCE 5.116).

Until D68 nothing compared the two: ``task_id`` was stored on the proposal and written to the audit,
and a Worker could name task X and propose Y, or name no task at all. Authorization still applied to
Y, so this was never a scope bypass -- what went unasked was whether the proposal belongs to the
plan. This answers it, with a closed vocabulary and no model.

**This stage records and decides nothing.** The value is computed, stored with the decision and
audited; no policy input reads it yet (D68 S3 adds that, behind a switch that is off). Everything
here is a pure function of rows and strings, so it can be judged before it is allowed to escalate
anything.

The relation:

====================  =======================================================================
``matches_task``      the task is live and its ``identity_key`` equals the proposal's
``differs_from_task`` the task is live and its identity is not the proposal's
``task_not_live``     the task is not visible to this engagement, or is completed/failed/cancelled
``no_task``           the proposal names no task
====================  =======================================================================

Identity is the task layer's own (``ADR_TASK_IDENTITY.md`` Option 1): the action and the canonical
target at host/network granularity, from the same canonicalizer. It is passed in by the caller, who
computed it with the function ``create_task`` uses, so the two cannot come from different rules.

``differs_from_task`` carries a sub-cause, because the first thing to learn from the shadow is how
much of it is a legitimate decomposition (a task on a ``/24``, a proposal for one host inside it).
That case is *recorded as its own sub-cause and judged as nothing*: it is still
``differs_from_task`` (DP-13 -- a vocabulary value is added only with numbers in hand).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

#: The version of the whole signal object stored with a decision. Additive evolution only.
VERSION = "plan_fit_v1"

MATCHES_TASK = "matches_task"
DIFFERS_FROM_TASK = "differs_from_task"
TASK_NOT_LIVE = "task_not_live"
NO_TASK = "no_task"
RELATIONS = (MATCHES_TASK, DIFFERS_FROM_TASK, TASK_NOT_LIVE, NO_TASK)

#: A task is live when it is queued or being worked. Kept equal to
#: ``function_api._LIVE_TASK_STATUSES`` (the set an overlap warning uses) by a test, so "live" has
#: one meaning.
LIVE_STATUSES = ("queued", "claimed", "running")

# sub-causes -- closed, per relation
TASK_ID_ABSENT = "task_id_absent"
TASK_NOT_FOUND = "task_not_found"
TASK_STATUS_NOT_LIVE = "task_status_not_live"
DIFFERENT_ACTION = "different_action"
DIFFERENT_TARGET = "different_target"
DIFFERENT_ACTION_AND_TARGET = "different_action_and_target"
INSIDE_TASK_TARGET = "same_action_target_inside_task_target"
TASK_TARGET_NOT_CANONICAL = "task_target_not_canonical"
PROPOSAL_TARGET_NOT_CANONICAL = "proposal_target_not_canonical"
SUB_CAUSES = {
    MATCHES_TASK: (None,),
    NO_TASK: (TASK_ID_ABSENT,),
    TASK_NOT_LIVE: (TASK_NOT_FOUND, TASK_STATUS_NOT_LIVE),
    DIFFERS_FROM_TASK: (DIFFERENT_ACTION, DIFFERENT_TARGET, DIFFERENT_ACTION_AND_TARGET,
                        INSIDE_TASK_TARGET, TASK_TARGET_NOT_CANONICAL,
                        PROPOSAL_TARGET_NOT_CANONICAL),
}


@dataclass(frozen=True)
class TaskRelation:
    value: str
    sub_cause: str | None = None
    task_id: str | None = None
    task_status: str | None = None

    def __post_init__(self) -> None:
        # A value or sub-cause outside the vocabulary is a bug here, not data: refuse to build it.
        if self.value not in RELATIONS or self.sub_cause not in SUB_CAUSES[self.value]:
            raise ValueError(
                f"not in the task_relation vocabulary: {self.value!r}/{self.sub_cause!r}")

    def as_hint(self) -> dict[str, Any]:
        """What is stored with the decision (``reviewer_hints['plan_fit']``) and replayed."""
        return {"version": VERSION, "task_relation": self.value, "sub_cause": self.sub_cause}

    def audit_payload(self) -> dict[str, Any]:
        return {**self.as_hint(), "task_id": self.task_id, "task_status": self.task_status}


def _inside(proposal_target: str | None, task_target: str | None) -> bool:
    """True when ``ip:A`` / ``cidr:B`` lies inside ``cidr:C`` (and is not the same thing)."""
    try:
        p_type, _, p_value = (proposal_target or "").partition(":")
        t_type, _, t_value = (task_target or "").partition(":")
        if t_type != "cidr" or p_type not in ("ip", "cidr"):
            return False
        task_net = ipaddress.ip_network(t_value, strict=False)
        if p_type == "ip":
            return ipaddress.ip_address(p_value) in task_net
        proposal_net = ipaddress.ip_network(p_value, strict=False)
        return proposal_net != task_net and proposal_net.subnet_of(task_net)
    except (ValueError, TypeError):
        return False


def compare(
    *, task_id: str, task: dict[str, Any] | None, action: str,
    canonical_target: str | None, identity_key: str | None,
) -> TaskRelation:
    """The relation, from a task row (or ``None``) and the proposal's own identity. Total: it
    raises only on a value it was not meant to receive."""
    if task is None:
        return TaskRelation(TASK_NOT_LIVE, TASK_NOT_FOUND, task_id)
    status = task["status"]
    if status not in LIVE_STATUSES:
        return TaskRelation(TASK_NOT_LIVE, TASK_STATUS_NOT_LIVE, task_id, status)
    if task["identity_key"] is None:
        return TaskRelation(DIFFERS_FROM_TASK, TASK_TARGET_NOT_CANONICAL, task_id, status)
    if identity_key is None:
        return TaskRelation(DIFFERS_FROM_TASK, PROPOSAL_TARGET_NOT_CANONICAL, task_id, status)
    if identity_key == task["identity_key"]:
        return TaskRelation(MATCHES_TASK, None, task_id, status)
    same_action = task["action"] == action
    same_target = task["canonical_target"] == canonical_target
    if same_action and _inside(canonical_target, task["canonical_target"]):
        cause = INSIDE_TASK_TARGET
    elif same_action:
        cause = DIFFERENT_TARGET
    elif same_target:
        cause = DIFFERENT_ACTION
    else:
        cause = DIFFERENT_ACTION_AND_TARGET
    return TaskRelation(DIFFERS_FROM_TASK, cause, task_id, status)


def assess_task_relation(
    conn: Connection, *, task_id: str | None, action: str,
    canonical_target: str | None, identity_key: str | None,
) -> TaskRelation:
    """Read the task the proposal names (RLS-confined: another engagement's task is not visible,
    so it reads as ``task_not_found``) and compare."""
    if not task_id:
        return TaskRelation(NO_TASK, TASK_ID_ABSENT)
    row = conn.execute(
        text("SELECT status, action, canonical_target, identity_key FROM tasks "
             "WHERE task_id = :t"),
        {"t": task_id},
    ).mappings().one_or_none()
    return compare(task_id=task_id, task=dict(row) if row else None, action=action,
                   canonical_target=canonical_target, identity_key=identity_key)
