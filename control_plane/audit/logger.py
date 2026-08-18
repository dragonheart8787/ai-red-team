"""Append-only audit writer (§4.4, §8.6).

Append-only is enforced by grants, not by this module: ``cyberorch_app`` holds
INSERT and SELECT on ``audit_log`` and nothing else, so no code path here or
anywhere can revise a record after the fact.

**Records commit on their own connection, immediately.** This is the second
half of append-only, and the reason is a bug this design already produced once:
``issue_capability`` wrote a refusal record and then raised, the exception
propagated out of the caller's transaction, and the rollback took the record of
the refusal with it. Every refused issuance would have gone unaudited. Fixing
that one call site would have left the same trap armed at every other one — an
audit trail that survives only when the caller happens to commit is not an
audit trail, it is a side effect.

The cost, stated plainly because it changes what a record means: an audit entry
can now outlive the transaction it describes. If a caller writes a state change,
audits it, and then rolls back, the record remains and asserts something that
did not end up happening. That is over-recording rather than under-recording,
which is the right direction for a security log — losing evidence of a decision
is far worse than holding evidence of one that was later abandoned — but it
does mean a record documents *a decision the control plane made*, not *state
that exists*. Reconstructing what is actually true requires reading the state
tables, and an investigator comparing the two may legitimately find an audited
action with no corresponding row.

tests/test_audit_logger.py pins both halves of that behaviour so neither is
rediscovered by accident.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from sqlalchemy import text

from control_plane.state.db import audit_scope


def record_audit(
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
    """Append one audit record on a dedicated connection; returns its id.

    Deliberately takes no ``conn``. Accepting one would let a caller opt back
    into the failure mode above, and the whole point is that no caller can.
    """
    if not engagement_id:
        raise ValueError("audit records must name an engagement")
    if not actor:
        raise ValueError("audit records must name an actor")

    with audit_scope(engagement_id) as conn:
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
                "payload": json.dumps(payload or {}, default=str, sort_keys=True),
            },
        ).scalar_one()
