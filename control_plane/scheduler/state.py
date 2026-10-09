"""The scheduler's memory between ticks: ``scheduler_state``, as ``scheduler_state_writer`` (D62).

Closed vocabulary only -- the table's ``CHECK`` constraints refuse any disposition or reason code
that is not one of the lists in ``vocab`` -- so what is stored here can be shown to an operator
without being sanitised first. Nothing in this module reads the pipeline.
"""

from __future__ import annotations

from sqlalchemy import text

from control_plane.state.db import scheduler_state_writer_scope


def record_engagement(engagement_id: str, disposition: str, reason_code: str | None) -> None:
    """Set the engagement-level disposition ('served' / 'deferred')."""
    with scheduler_state_writer_scope(engagement_id) as conn:
        conn.execute(text("""
            INSERT INTO scheduler_state (engagement_id, proposal_id, kind, disposition, reason_code)
            VALUES (:e, NULL, 'engagement', :d, :r)
            ON CONFLICT (engagement_id, (COALESCE(proposal_id, '')))
            DO UPDATE SET disposition = EXCLUDED.disposition,
                          reason_code = EXCLUDED.reason_code, since = now()
        """), {"e": engagement_id, "d": disposition, "r": reason_code})


def record_proposal(
    engagement_id: str, proposal_id: str, disposition: str, reason_code: str | None
) -> None:
    """Set a proposal-level disposition ('skipped' / 'dispatch_decided')."""
    with scheduler_state_writer_scope(engagement_id) as conn:
        conn.execute(text("""
            INSERT INTO scheduler_state (engagement_id, proposal_id, kind, disposition, reason_code)
            VALUES (:e, :p, 'proposal', :d, :r)
            ON CONFLICT (engagement_id, (COALESCE(proposal_id, '')))
            DO UPDATE SET disposition = EXCLUDED.disposition,
                          reason_code = EXCLUDED.reason_code, since = now()
        """), {"e": engagement_id, "p": proposal_id, "d": disposition, "r": reason_code})
