"""Skipped proposals, for the operator (D62): why an approved proposal has not run.

A skipped proposal is not closed; it stays ``approved`` until its approval lapses, and the code
recorded in ``scheduler_state`` is the operator's only explanation. Read as ``scheduler_reader``, so
``scripts/approvals.py awaiting-dispatch`` can show it without any new grant on ``cyberorch_app``.
"""

from __future__ import annotations

from sqlalchemy import text

from control_plane.state.db import scheduler_reader_scope


def skip_reasons(engagement_id: str) -> dict[str, tuple[str, object]]:
    """proposal_id -> (reason_code, since) for every proposal the scheduler has skipped."""
    with scheduler_reader_scope(engagement_id) as conn:
        return {r[0]: (r[1], r[2]) for r in conn.execute(text(
            "SELECT proposal_id, reason_code, since FROM scheduler_state "
            "WHERE disposition = 'skipped'"))}
