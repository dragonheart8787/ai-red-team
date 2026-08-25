"""Global-scope audit attribution and its isolation (D11-7, DEFERRED 11.2).

A globally-scoped operation (a global policy overlay) now leaves a globally-scoped
audit record: ``scope='global'``, ``engagement_id IS NULL``, readable only by the
``global_auditor`` role. These tests pin four things: the record is written and
readable by that role; no other role can read it; that role can read nothing
else and write nothing; and the two structural guards (the CHECK that keeps
scope and engagement_id consistent, and the RLS condition that confines global
reads to the one role) actually hold.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from control_plane.audit.logger import record_audit
from control_plane.audit.query import list_global_audit
from control_plane.state.db import (
    engagement_scope,
    global_auditor_scope,
    registry_admin_scope,
)


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _insufficient_privilege(err) -> bool:
    return isinstance(err.value.orig, psycopg.errors.InsufficientPrivilege)


# ---------------------------------------------------------------------------
# The record is written, and global_auditor can read it
# ---------------------------------------------------------------------------

def test_a_global_record_is_written_and_read_back_by_its_actor(engagement_id):
    marker = _uid("GLOBAL-OVERLAY")
    record_audit(
        engagement_id=None, scope="global", actor="incident-commander",
        event_type="policy_layer.published", subject_type="policy_layer",
        subject_id=marker, payload={"layer": "emergency_overlay"},
    )
    with global_auditor_scope() as conn:
        events = list_global_audit(conn, event_types=["policy_layer.published"])
    mine = [e for e in events if e.subject_id == marker]
    assert len(mine) == 1
    # The whole point of D11-7: who and when, not "published by: unknown".
    assert mine[0].actor == "incident-commander"


def test_global_auditor_does_not_see_engagement_scoped_rows(engagement_id):
    """An engagement's ordinary audit trail is invisible to the global reader."""
    record_audit(
        engagement_id=engagement_id, actor="worker",
        event_type="task.created", subject_type="task", subject_id=_uid("TASK"),
    )
    with global_auditor_scope() as conn:
        rows = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE scope = 'engagement'")
        ).scalar_one()
    assert rows == 0


# ---------------------------------------------------------------------------
# Isolation: no other role reads global; global_auditor reads nothing else
# ---------------------------------------------------------------------------

def test_cyberorch_app_cannot_read_global_audit(engagement_id):
    """I4, extended: the runtime role sees no global row. This is what the RLS
    role condition on audit_global_read protects — remove it and this fails."""
    marker = _uid("GLOBAL")
    record_audit(engagement_id=None, scope="global", actor="op",
                 event_type="policy_layer.published", subject_id=marker)
    with engagement_scope(engagement_id) as conn:
        seen = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE scope = 'global'")
        ).scalar_one()
    assert seen == 0


def test_registry_admin_cannot_read_global_audit(engagement_id):
    marker = _uid("GLOBAL")
    record_audit(engagement_id=None, scope="global", actor="op",
                 event_type="policy_layer.published", subject_id=marker)
    with registry_admin_scope(engagement_id) as conn:
        seen = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE scope = 'global'")
        ).scalar_one()
    assert seen == 0


@pytest.mark.parametrize("table", ["scope_registry", "metadata_registry",
                                   "findings", "evidence"])
def test_global_auditor_cannot_touch_any_other_table(table):
    with pytest.raises(ProgrammingError) as err:
        with global_auditor_scope() as conn:
            conn.execute(text(f"SELECT * FROM {table} LIMIT 1"))
    assert _insufficient_privilege(err)


def test_global_auditor_cannot_write_audit_log():
    """Read-only: it cannot even append, let alone to another table."""
    with pytest.raises(ProgrammingError) as err:
        with global_auditor_scope() as conn:
            conn.execute(text(
                "INSERT INTO audit_log (engagement_id, scope, actor, event_type, "
                "reasons, payload) VALUES (NULL,'global','x','y','{}','{}')"
            ))
    assert _insufficient_privilege(err)


# ---------------------------------------------------------------------------
# The query writes nothing (D14's md5 check)
# ---------------------------------------------------------------------------

def test_reading_global_audit_writes_nothing(engagement_id):
    record_audit(engagement_id=None, scope="global", actor="op",
                 event_type="policy_layer.published", subject_id=_uid("G"))

    def snapshot():
        # Read the digests as migration_owner-independent: use the app role for
        # the engagement tables and count global rows via a fresh auditor read.
        with engagement_scope(engagement_id) as conn:
            return [
                conn.execute(text(
                    f"SELECT md5(coalesce(string_agg(t::text, '' ORDER BY t::text), '')) "
                    f"FROM {table} t"
                )).scalar_one()
                for table in ("tasks", "findings", "action_proposals", "evidence")
            ]

    before = snapshot()
    with global_auditor_scope() as conn:
        list_global_audit(conn)
        n_before = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE scope='global'")
        ).scalar_one()
        list_global_audit(conn, event_types=["policy_layer.published"])
        n_after = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE scope='global'")
        ).scalar_one()
    assert n_before == n_after
    assert snapshot() == before


# ---------------------------------------------------------------------------
# The structural guards
# ---------------------------------------------------------------------------

def test_the_check_constraint_forbids_an_inconsistent_row(engagement_id):
    """scope='global' with a non-null engagement_id must be impossible.

    Inserted with engagement_id = the connection's own engagement so the row
    passes the per-engagement RLS WITH CHECK — isolating the failure to the
    audit_scope_consistent CHECK rather than RLS. Remove that constraint and this
    row inserts cleanly; the mutation test relies on that.
    """
    with pytest.raises(IntegrityError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(
                text("INSERT INTO audit_log (engagement_id, scope, actor, "
                     "event_type, reasons, payload) "
                     "VALUES (:eid, 'global', 'x', 'y', '{}', '{}')"),
                {"eid": engagement_id},
            )
    assert isinstance(err.value.orig, psycopg.errors.CheckViolation)


def test_the_check_constraint_covers_both_directions(engagement_id):
    """The other direction — scope='engagement' with a NULL engagement_id —
    cannot be driven through RLS (nothing lets a NULL-engagement row that is not
    global past the write policies), so it is confirmed at the source: the
    constraint definition names both the global and the engagement case, so the
    guarantee is symmetric rather than one-sided.
    """
    with engagement_scope(engagement_id) as conn:
        definition = conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'audit_scope_consistent'"
        )).scalar_one()
    assert "global" in definition and "engagement" in definition
    assert "IS NULL" in definition and "IS NOT NULL" in definition
