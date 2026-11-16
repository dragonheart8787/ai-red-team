"""D69 H5a2 (a5): the start-up check, and the ownership check at claim time.

**The start-up check.** The loop keeps the tasks it created in memory only (plan item 59), so a
process that starts on an engagement that already has a live task cannot tell whether the task is
its own earlier work or somebody else's. v0 does not guess: any live task refuses the start
(plan item 57, exit code 10). :func:`decide_startup` takes the rows ``live_tasks`` returned --
tasks that are queued, claimed or running, and no others -- and answers ``proceed`` for none,
``refuse`` for one or more. Which of the three states a row is in does not matter, and a page that
is full does not matter either: one row is enough to refuse.

**Ownership.** A claim returns a task id. :func:`owns` says whether the id is one the loop itself
created and has not yet claimed on that engagement; anything else is a foreign task (exit code
11) and is neither proposed for nor completed.

Pure: no state, no database, no clock.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence

STARTUP_PROCEED = "proceed"
STARTUP_REFUSE = "refuse"


def decide_startup(rows: Sequence[object]) -> str:
    """``refuse`` when ``rows`` holds any live task, ``proceed`` when it is empty."""
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
        raise ValueError("the rows of live tasks are a sequence")
    if rows:
        return STARTUP_REFUSE
    return STARTUP_PROCEED


def owns(task_id: object, own_set: Collection[str]) -> bool:
    """Whether ``task_id`` is a non-empty string in ``own_set``."""
    return isinstance(task_id, str) and task_id != "" and task_id in own_set
