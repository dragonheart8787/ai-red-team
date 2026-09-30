"""Schema-level security properties (§4.4, §8.6, I4).

These assert things the database enforces, not things the application promises.
Each one corresponds to a way the design says RLS or append-only storage is
commonly implemented and silently defeated.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from control_plane.state.db import (
    engagement_scope,
    get_engine,
    get_global_policy_admin_engine,
)
from control_plane.state.models import metadata as sa_metadata

# Kept in step with ENGAGEMENT_SCOPED in the migration.
ENGAGEMENT_SCOPED = [
    "engagements", "scope_registry", "metadata_registry", "tasks",
    "action_proposals", "credentials", "capabilities", "approvals", "tool_runs",
    "evidence", "findings", "provenance_edges", "audit_log", "policy_layers",
]
APPEND_ONLY = ["evidence", "audit_log", "provenance_edges"]


def test_runtime_role_cannot_bypass_rls(db_available):
    """§8.6: superuser or BYPASSRLS on the runtime role would void every policy."""
    with get_engine().connect() as conn:
        row = conn.execute(text("""
            SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
            FROM pg_roles WHERE rolname = 'cyberorch_app'
        """)).one()
    assert row.rolsuper is False
    assert row.rolbypassrls is False
    assert row.rolcreatedb is False
    assert row.rolcreaterole is False


def test_runtime_role_owns_no_table(db_available):
    """§8.6: a table's owner escapes its own RLS policies unless FORCE is set.

    FORCE is set below, but ownership is the belt to that suspenders: the
    runtime role should have nothing to own in the first place.
    """
    with get_engine().connect() as conn:
        owned = conn.execute(text("""
            SELECT c.relname FROM pg_class c
            JOIN pg_roles r ON r.oid = c.relowner
            WHERE r.rolname = 'cyberorch_app' AND c.relkind IN ('r','p','v','m','S')
        """)).scalars().all()
    assert owned == []


@pytest.mark.parametrize("table", ENGAGEMENT_SCOPED)
def test_rls_enabled_and_forced(db_available, table):
    """ENABLE without FORCE is the half-done case §8.6 calls out by name."""
    with get_engine().connect() as conn:
        row = conn.execute(
            text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                 "WHERE relname = :t AND relnamespace = 'public'::regnamespace"),
            {"t": table},
        ).one()
    assert row.relrowsecurity is True, f"{table}: RLS not enabled"
    assert row.relforcerowsecurity is True, f"{table}: RLS not FORCEd"


def test_cross_engagement_read_is_blocked(engagement_id):
    """I4: engagement B must not see engagement A's findings."""
    finding_id = f"FINDING-{uuid.uuid4().hex[:8]}"
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO findings
                    (finding_id, engagement_id, claim, state, evidence_strength)
                VALUES (:fid, :eid, 'test claim', 'candidate', 'E1')
            """),
            {"fid": finding_id, "eid": engagement_id},
        )
        mine = conn.execute(
            text("SELECT count(*) FROM findings WHERE finding_id = :fid"),
            {"fid": finding_id},
        ).scalar_one()
    assert mine == 1

    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(other) as conn:
        seen = conn.execute(
            text("SELECT count(*) FROM findings WHERE finding_id = :fid"),
            {"fid": finding_id},
        ).scalar_one()
    assert seen == 0, "RLS did not isolate engagements"


def test_forgetting_the_guc_shows_nothing(engagement_id):
    """Fail-closed (I10): an unset GUC must yield no rows, not all rows."""
    with get_engine().begin() as conn:  # no set_config call
        assert conn.execute(text("SELECT count(*) FROM findings")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM engagements")).scalar_one() == 0


def test_cannot_write_into_another_engagement(engagement_id):
    """WITH CHECK: a row cannot be smuggled into a different engagement."""
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(
                text("""
                    INSERT INTO findings
                        (finding_id, engagement_id, claim, state, evidence_strength)
                    VALUES (:fid, 'ENG-SOMEONE-ELSE', 'smuggled', 'candidate', 'E1')
                """),
                {"fid": f"FINDING-{uuid.uuid4().hex[:8]}"},
            )
    assert "row-level security" in str(err.value).lower()


@pytest.mark.parametrize("table", APPEND_ONLY)
def test_append_only_tables_reject_update_and_delete(engagement_id, table):
    """§4.4: immutability is a grant, not a naming convention."""
    for stmt in (f"UPDATE {table} SET engagement_id = engagement_id",
                 f"DELETE FROM {table}"):
        with pytest.raises(ProgrammingError) as err:
            with engagement_scope(engagement_id) as conn:
                conn.execute(text(stmt))
        assert isinstance(err.value.orig, psycopg.errors.InsufficientPrivilege), stmt


def test_evidence_insert_and_select_still_work(engagement_id):
    """Append-only must not mean unusable."""
    eid = f"NMAP-{uuid.uuid4().hex[:8]}"
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("""
                INSERT INTO evidence (evidence_id, engagement_id, type,
                    raw_artifact_path, raw_sha256, raw_collected_at,
                    derived_view, tool, tool_version)
                VALUES (:id, :eng, 'tool_output', '/tmp/x.bin', 'abc', now(),
                    '{"untrusted_content": true}'::jsonb, 'nmap', '7.94')
            """),
            {"id": eid, "eng": engagement_id},
        )
        assert conn.execute(
            text("SELECT count(*) FROM evidence WHERE evidence_id = :id"), {"id": eid}
        ).scalar_one() == 1


def test_emergency_overlay_cannot_carry_scope_allow(db_available):
    """§4.5: the overlay may only tighten, enforced by the schema itself.

    A global overlay row is written by ``global_policy_admin`` (5.37); the runtime role is
    refused before the CHECK is reached, which would leave the CHECK untested."""
    with pytest.raises(IntegrityError) as err:
        with get_global_policy_admin_engine().begin() as conn:
            conn.execute(text("""
                INSERT INTO policy_layers (layer, version, document)
                VALUES ('emergency_overlay', 99, '{"scope_allow": ["*"]}'::jsonb)
            """))
    assert "emergency_overlay_can_only_tighten" in str(err.value)


def test_emergency_overlay_cannot_allow_an_action(db_available):
    with pytest.raises(IntegrityError) as err:
        with get_global_policy_admin_engine().begin() as conn:
            conn.execute(text("""
                INSERT INTO policy_layers (layer, version, document)
                VALUES ('emergency_overlay', 98,
                        '{"actions": {"network.scan": "ALLOW"}}'::jsonb)
            """))
    assert "emergency_overlay_can_only_tighten" in str(err.value)


def test_emergency_overlay_may_deny(db_available):
    with get_global_policy_admin_engine().begin() as conn:
        conn.execute(text("""
            INSERT INTO policy_layers (layer, version, document)
            VALUES ('emergency_overlay', 97,
                    '{"actions": {"network.scan": "DENY"}, "data_deny": ["PII"]}'::jsonb)
            ON CONFLICT DO NOTHING
        """))


def test_findings_has_no_confidence_column(db_available):
    """§4.3: the withdrawn weighted-confidence field must not creep back in."""
    with get_engine().connect() as conn:
        cols = conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'findings'"
        )).scalars().all()
    assert "confidence" not in cols


def test_security_graph_tables_have_no_classification_columns(db_available):
    """D42-3 Option A: Postgres's Metadata Registry is the sole classification
    authority. security_graph_nodes/edges hold opaque identities and edges
    only, and the boundary is enforced by the schema's own absence of a
    column to hold one -- checked directly, the same shape as
    test_findings_has_no_confidence_column above, rather than trusted to a
    design doc nobody re-reads at review time.
    """
    forbidden_substrings = ("class", "classif", "sensitiv", "resource_class", "data_class")
    with get_engine().connect() as conn:
        for table in ("security_graph_nodes", "security_graph_edges"):
            cols = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :t"
            ), {"t": table}).scalars().all()
            assert cols, f"{table} has no columns at all -- did the migration run?"
            offenders = [
                c for c in cols
                if any(s in c.lower() for s in forbidden_substrings)
            ]
            assert not offenders, (
                f"{table} has classification-shaped column(s) {offenders} -- "
                f"D42-3 Option A requires metadata_registry to be the only "
                f"place classification is ever stored"
            )


def test_models_match_the_database(db_available):
    """models.py is a mirror of the migration; drift between them is a bug."""
    with get_engine().connect() as conn:
        rows = conn.execute(text("""
            SELECT table_name, column_name FROM information_schema.columns
            WHERE table_schema = 'public'
        """)).all()
    actual: dict[str, set[str]] = {}
    for table_name, column_name in rows:
        actual.setdefault(table_name, set()).add(column_name)

    for table in sa_metadata.sorted_tables:
        assert table.name in actual, f"{table.name} missing from database"
        declared = {c.name for c in table.columns}
        missing = declared - actual[table.name]
        extra = actual[table.name] - declared
        assert not missing, f"{table.name}: models.py declares unknown columns {missing}"
        assert not extra, f"{table.name}: models.py is missing columns {extra}"
