"""D69 H5a1 (a3): the idempotency key of a proposal, derived from the task and the attempt.

``propose_action`` left without a key gives every call a fresh one (``idem-<proposal id>``), so
two calls for the same task are two proposals. The harness gives it ``h5:<task_id>:<attempt>``
instead (plan item 47, choice 3.5): the same task and attempt is the same key, so a second call
resumes the first and never makes a second proposal, and a key reused for different work is
refused by the pipeline.

The attempt starts at 1. In v0 nothing retries inside the process (a stopped call is never
asked again), and the start-up check refuses an engagement that already has live tasks, so the
attempt is 1 in practice; the key still carries it so that a retry, if one is ever added, has a
different key from the first try.

Pure: no state, no clock, no randomness. The same input is the same output, every time.
"""

from __future__ import annotations

KEY_PREFIX = "h5"


def derive_key(task_id: str, attempt: int) -> str:
    """``h5:<task_id>:<attempt>``. ``task_id`` a non-empty string without ``:``, ``attempt`` an
    ``int`` (not a ``bool``) of at least 1; anything else is a ``ValueError``."""
    if not isinstance(task_id, str) or not task_id or ":" in task_id:
        raise ValueError("a task id is a non-empty string without ':'")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise ValueError("an attempt is an int of at least 1")
    return f"{KEY_PREFIX}:{task_id}:{attempt}"
