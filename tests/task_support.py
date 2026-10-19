"""A task for a proposal (D68 S1).

A proposal that goes through ``propose_action`` names the task it serves, as a Worker's does
(``worker.propose(task=..., task_id=...)``). Until D68 nothing compared the two, so a fixture could
leave the task out and nothing noticed; from P1 on a proposal with no task, or one that differs from
its task, is an approval reason. These helpers give a fixture the task a real harness would have
created first -- through the product's own ``create_task``, committed, with the same canonicalizer
for the identity -- so a fixture states what it is, rather than relying on a check that was
not there.

They create the task **from the proposal**: the action, the target and the scope object are the
proposal's, so ``identity_key`` is equal by construction. The goal is a sentence built from the
action and the host (:data:`GOALS`), so that a model later shown the triple sees a coherent one.

What does not use these, and why, is the checked-in list in ``tests/test_task_less_callers.py``.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from agents.base_agent import ProposedAction, ProposedTask
from control_plane.api.function_api import create_task
from control_plane.state.db import engagement_scope

#: One sentence per action class. ``{host}`` is the target's logical identity value.
GOALS = {
    "network.scan": "Scan {host} for open ports and the services behind them",
    "network.recon": "Find out which hosts at {host} are up",
    "web.get": "Fetch {host} over HTTP to see what it serves",
    "web.post": "Submit a request to {host} to see how it responds",
    "web.render": "Render {host} in a browser to see what its scripts generate",
    "code.scan": "Scan the source at {host} for insecure patterns",
    "code.secrets": "Scan the repository at {host} for committed secrets",
    "ad.collect": "Collect the Active Directory relationships of {host}",
}


def goal_for(proposal: ProposedAction) -> str:
    identity: Any = (proposal.target.get("logical_identity") or {})
    host = identity.get("value", "the target")
    return GOALS.get(proposal.action, "Carry out {action} against {host}").format(
        host=host, action=proposal.action)


def task_for(
    engagement_id: str, proposal: ProposedAction, *, goal: str | None = None,
    created_by: str = "supervisor",
) -> str:
    """Create, and commit, the task this proposal serves; return its id."""
    task = ProposedTask(
        goal=goal or goal_for(proposal), target=dict(proposal.target),
        action=proposal.action,
        scope_object_id=str(proposal.authorization.get("scope_object_id") or ""),
    )
    with engagement_scope(engagement_id) as conn:
        return create_task(conn, engagement_id=engagement_id, task=task, created_by=created_by)


def attach_task(
    engagement_id: str, proposal: ProposedAction, *, goal: str | None = None,
    created_by: str = "supervisor",
) -> ProposedAction:
    """``proposal``, naming a task created for it."""
    return dataclasses.replace(
        proposal, task_id=task_for(engagement_id, proposal, goal=goal, created_by=created_by))
