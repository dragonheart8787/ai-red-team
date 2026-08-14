"""Append-only audit writer (§4.4, §8.6).

Append-only is enforced by grants, not by this module: ``cyberorch_app`` holds
INSERT and SELECT on ``audit_log`` and nothing else, so there is no code path —
here or anywhere — that can revise a record after the fact.

Deliverable 8 completes this module (coverage of every decision point, plus the
read/query side). What is here now is the write path the registries and
resolvers need.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Connection, text


def record_audit(
    conn: Connection,
    *,
    engagement_id: str,
    actor: str,
    event_type: str,
    subject_type: str | None = None,
    subject_id: str | None = None,
    decision: str | None = None,
    reasons: Sequence[str] = (),
    payload: dict[str, Any] | None = None,
) -> int:
    """Append one audit record; returns its id.

    Takes the caller's connection so the record lands in the same transaction
    as the thing it describes. A separate connection would let the audit trail
    and the action it documents disagree about whether anything happened.
    """
    return conn.execute(
        text("""
            INSERT INTO audit_log (engagement_id, actor, event_type, subject_type,
                                   subject_id, decision, reasons, payload)
            VALUES (:eid, :actor, :event, :stype, :sid, :decision, :reasons,
                    CAST(:payload AS jsonb))
            RETURNING audit_id
        """),
        {
            "eid": engagement_id,
            "actor": actor,
            "event": event_type,
            "stype": subject_type,
            "sid": subject_id,
            "decision": decision,
            "reasons": list(reasons),
            "payload": _json(payload or {}),
        },
    ).scalar_one()


def _json(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, default=str, sort_keys=True)
