"""D69 H5a1 (a1): why the loop stops, and the exit code each reason ends with.

The scheduler's table is the pattern (``scripts/run_scheduler.py``): the same numbers keep the
same meaning, and the harness's own reasons start at 10. This module only *names* things; it
reads no state, starts no process and calls nothing.

::

     0  stopped by a signal, or ``--once`` finished
     1  an exception nothing in the process caught
     2  another instance holds the lock
     3  an audit record could not be written
     4  the database connection was lost
     5  Docker is unreachable
     6  the lock was lost
     7  not used. Reserved: no reason maps to it, so a 7 seen by an operator is not ours.
    10  the start-up check refused (a live task already on an engagement)
    11  a task that is not this process's own was claimed
    12  a fault outside the closed list (an exception from ``propose_action``, an
        idempotency-key conflict, ...): the loop itself decided to stop
    13  a cap was reached
    14  no progress

Every stop reason has exactly one code, and no two reasons share one: an operator who reads an
exit status must be able to tell which reason it was. Code 1 is for what the process did not
catch; code 12 is for a stop the loop itself makes -- the two are different on purpose.

:func:`cleans_up_unclaimed` says whether the loop, on this reason, completes the tasks of its own
that it created and never claimed (plan item 49 and item 58): a controlled stop does, a fault
or a lost lock, database or Docker does not.
"""

from __future__ import annotations

import enum

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_LOCK_HELD = 2
EXIT_AUDIT_FAILED = 3
EXIT_DB_LOST = 4
EXIT_DOCKER_LOST = 5
EXIT_LOCK_LOST = 6
EXIT_STARTUP_REFUSED = 10
EXIT_FOREIGN_TASK = 11
EXIT_FAULT_OUTSIDE_LIST = 12
EXIT_CAP_REACHED = 13
EXIT_NO_PROGRESS = 14

#: Codes no stop reason may map to. 7 is the scheduler's "a dispatched proposal was still
#: approved"; the harness dispatches nothing, so it has no meaning here and is not reused.
RESERVED_CODES = frozenset({7})


class StopReason(enum.Enum):
    """The closed list of reasons the loop stops. The value is a stable name, not a code."""

    SIGNAL_OR_ONCE = "signal_or_once"
    UNEXPECTED = "unexpected_error"
    LOCK_HELD = "lock_held"
    AUDIT_FAILED = "audit_failed"
    DB_LOST = "db_lost"
    DOCKER_UNREACHABLE = "docker_unreachable"
    LOCK_LOST = "lock_lost"
    STARTUP_REFUSED = "startup_check_refused"
    FOREIGN_TASK = "foreign_task"
    FAULT_OUTSIDE_LIST = "fault_outside_the_list"
    CAP_REACHED = "cap_reached"
    NO_PROGRESS = "no_progress"


EXIT_CODE = {
    StopReason.SIGNAL_OR_ONCE: EXIT_OK,
    StopReason.UNEXPECTED: EXIT_UNEXPECTED,
    StopReason.LOCK_HELD: EXIT_LOCK_HELD,
    StopReason.AUDIT_FAILED: EXIT_AUDIT_FAILED,
    StopReason.DB_LOST: EXIT_DB_LOST,
    StopReason.DOCKER_UNREACHABLE: EXIT_DOCKER_LOST,
    StopReason.LOCK_LOST: EXIT_LOCK_LOST,
    StopReason.STARTUP_REFUSED: EXIT_STARTUP_REFUSED,
    StopReason.FOREIGN_TASK: EXIT_FOREIGN_TASK,
    StopReason.FAULT_OUTSIDE_LIST: EXIT_FAULT_OUTSIDE_LIST,
    StopReason.CAP_REACHED: EXIT_CAP_REACHED,
    StopReason.NO_PROGRESS: EXIT_NO_PROGRESS,
}

#: The reasons that are a controlled stop: the loop is in a state it understands and leaves
#: nothing of its own behind. A fault, a lost lock, database or Docker is not one.
_CLEANS_UP = frozenset({
    StopReason.SIGNAL_OR_ONCE,
    StopReason.STARTUP_REFUSED,
    StopReason.CAP_REACHED,
    StopReason.NO_PROGRESS,
})


def _checked(reason: object) -> StopReason:
    if not isinstance(reason, StopReason):
        raise ValueError(f"not a stop reason: {reason!r}")
    return reason


def exit_code(reason: StopReason) -> int:
    """The exit code of ``reason``."""
    return EXIT_CODE[_checked(reason)]


def cleans_up_unclaimed(reason: StopReason) -> bool:
    """Whether a stop for ``reason`` completes the loop's own unclaimed tasks as ``not_run``."""
    return _checked(reason) in _CLEANS_UP
