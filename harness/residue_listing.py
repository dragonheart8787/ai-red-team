"""D69 H5c2 (F): the tasks a run leaves behind, listed -- and nothing else (plan item 47, 3.7 B).

After a fault (exit code 12) an engagement can hold a task that is ``claimed`` (the one the fault
happened on, with a lease of five minutes) and tasks that are still ``queued``; the next run is
refused by the start-up check (exit code 10) until they are gone. **Nothing in this repository
completes, requeues or clears the tasks another run left**: ``complete_task`` takes any task, and
it is called only by the live-run scripts (``scripts/live_run/``, for the tasks they claimed
themselves) and by the harness's own adapter (for its own). This module lists the leftovers so
that a person can see what there is.

It only reads. The read is made in a **read-only transaction** (the database refuses a write in
it), through ``query_state`` -- the same function and the same three states as the start-up check
(``harness.loop_adapter.LIVE_STATUSES``). It prints the ids, the status, the agent that holds a
claimed task and the lease; it does not print a task's goal, which a Supervisor wrote.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import text

from control_plane.api.function_api import query_state
from control_plane.state.db import engagement_scope
from harness.loop_adapter import LIVE_STATUSES

NO_TOOL = ("Nothing in this repository completes, requeues or clears the tasks another run left; "
           "this listing changes nothing. A person completes them by hand (H6 writes the recovery "
           "down).")


@dataclass(frozen=True)
class ResidueTask:
    engagement_id: str
    task_id: str
    status: str
    owner_agent_id: str | None
    lease_expires_at: object


def list_residue(engagement_ids: Sequence[str], *, limit: int) -> tuple[ResidueTask, ...]:
    """The queued, claimed and running tasks of these engagements, oldest first, at most ``limit``
    for each (``limit`` is required)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit is a positive integer")
    found: list[ResidueTask] = []
    for engagement_id in engagement_ids:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            state = query_state(
                conn, engagement_id=engagement_id, task_status=LIVE_STATUSES,
                task_limit=limit, decision_limit=0)
        found.extend(
            ResidueTask(engagement_id, row["task_id"], row["status"], row["owner_agent_id"],
                        row["lease_expires_at"])
            for row in state["tasks"])
    return tuple(found)


def _plain(value: object) -> str:
    """A stored name as it is printed: quoted when it is not a plain word, so it cannot move the
    cursor or pose as another line."""
    shown = str(value)
    return shown if shown.replace("-", "").replace("_", "").replace(".", "").replace(
        ":", "").isalnum() else repr(shown)


def format_residue(tasks: Sequence[ResidueTask]) -> str:
    lines = [f"{len(tasks)} live task(s)"]
    for t in tasks:
        lines.append(f"{_plain(t.engagement_id)} {_plain(t.task_id)} status={t.status} "
                     f"owner={_plain(t.owner_agent_id)} lease_expires_at={t.lease_expires_at}")
    lines.append(NO_TOOL)
    return "\n".join(lines)
