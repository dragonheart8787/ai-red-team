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

**When the audit write itself fails**, the operation fails with it. A system
whose security machinery worked but left no record is indistinguishable, from
outside, from one whose machinery did not run — and over any useful time span
the two are equally dangerous. So :class:`AuditWriteError` propagates rather
than being swallowed, and the caller's transaction rolls back with it, leaving
no unaudited state change behind.

Before raising, the record is written to the application log at CRITICAL. That
channel does not depend on ``audit_log``, which matters precisely here: the
database is the thing that just failed. It is a weaker record — mutable, and
subject to whatever retention the deployment gives it — but a weaker record is
worth a great deal more than none, and it means the content of the lost entry
is recoverable.

tests/test_audit_logger.py pins all of this so none of it is rediscovered by
accident.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from control_plane.state.db import audit_scope, global_audit_scope

logger = logging.getLogger("cyberorch.audit")


class AuditWriteError(RuntimeError):
    """The audit record could not be written.

    Callers must not catch this to continue. The operation it describes has to
    fail too, or the system produces exactly the state the audit log exists to
    make impossible: a security-relevant action with no record of it.
    """


def record_audit(
    *,
    engagement_id: str | None,
    actor: str,
    event_type: str,
    subject_type: str | None = None,
    subject_id: str | None = None,
    decision: str | None = None,
    reasons: Sequence[str] = (),
    payload: dict[str, Any] | None = None,
    scope: str = "engagement",
) -> int:
    """Append one audit record on a dedicated connection; returns its id.

    Deliberately takes no ``conn``. Accepting one would let a caller opt back
    into the failure mode above, and the whole point is that no caller can.

    ``scope`` is ``'engagement'`` (the default, so every existing caller is
    unchanged) or ``'global'`` (D11-7). A global record belongs to no engagement:
    it carries ``engagement_id IS NULL`` and is written through the no-engagement
    connection, so a globally-scoped operation finally has a globally-scoped
    record. The two must agree, which the ``audit_scope_consistent`` CHECK
    enforces regardless of what reaches here.

    Raises :class:`AuditWriteError` if the record cannot be written.
    """
    if scope not in ("engagement", "global"):
        raise ValueError(f"unknown audit scope {scope!r}")
    if scope == "engagement" and not engagement_id:
        raise ValueError("engagement-scoped audit records must name an engagement")
    if scope == "global":
        # A global record has no engagement, whatever the caller passed.
        engagement_id = None
    if not actor:
        raise ValueError("audit records must name an actor")

    record = {
        "engagement_id": engagement_id,
        "scope": scope,
        "actor": actor,
        "event_type": event_type,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "decision": decision,
        "reasons": list(reasons),
        "payload": payload or {},
    }

    params = {
        "eid": engagement_id, "scope": scope, "actor": actor,
        "event": event_type, "stype": subject_type, "sid": subject_id,
        "decision": decision, "reasons": list(reasons),
        "payload": json.dumps(record["payload"], default=str, sort_keys=True),
    }
    insert = text("""
        INSERT INTO audit_log (engagement_id, scope, actor, event_type,
            subject_type, subject_id, decision, reasons, payload)
        VALUES (:eid, :scope, :actor, :event, :stype, :sid, :decision,
                :reasons, CAST(:payload AS jsonb))
    """)
    try:
        # A global record is written on a connection with no engagement bound; an
        # engagement record on one scoped to its engagement. Opening the scope is
        # inside the try so a connection failure is wrapped, not raw.
        scope_cm = global_audit_scope() if scope == "global" else audit_scope(engagement_id)
        with scope_cm as conn:
            # The engagement path reads its id straight back with RETURNING. The
            # global path cannot: no role that may *write* a global row may
            # *read* one (only global_auditor reads them), so RETURNING would
            # trip the SELECT side of RLS on the row it just inserted. lastval()
            # is the session's own sequence value — no table read, no policy.
            if scope == "global":
                conn.execute(insert, params)
                return conn.execute(text("SELECT lastval()")).scalar_one()
            return conn.execute(
                text(insert.text + " RETURNING audit_id"), params
            ).scalar_one()
    except SQLAlchemyError as exc:
        # The independent channel. Everything the lost record would have said
        # goes here, so the entry is recoverable from the application log even
        # though the database rejected it.
        logger.critical(
            "AUDIT WRITE FAILED — record not persisted: %s | record=%s",
            exc, json.dumps(record, default=str, sort_keys=True),
        )
        raise AuditWriteError(
            f"could not write audit record {event_type!r} for "
            f"{subject_type}:{subject_id}: {exc}"
        ) from exc
