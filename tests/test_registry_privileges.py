"""Registry write privileges are enforced by the database (§5).

§5 calls the two registries the highest value attack surface in the system:
whoever can write them can authorize themselves, or reclassify a customer
database as a static site. Before this split, cyberorch_app — the role every
component connects as — could do both, and the guarantee that resolvers only
trust AUTHORITATIVE classifications rested on application code choosing not to
write them.

These tests assert the backstop directly: the runtime role is refused by
PostgreSQL, not merely unlikely to try. They matter precisely for the case the
application layer cannot cover — a component taken over and issuing SQL of its
own.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import (
    engagement_scope,
    get_engine,
    get_registry_admin_engine,
    registry_admin_scope,
)

REGISTRY_TABLES = ["scope_registry", "metadata_registry"]


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _insufficient_privilege(err) -> bool:
    return isinstance(err.value.orig, psycopg.errors.InsufficientPrivilege)


# ---------------------------------------------------------------------------
# The runtime role cannot write the registries
# ---------------------------------------------------------------------------

def test_app_role_cannot_insert_a_scope_object(engagement_id):
    """The direct attack: grant yourself authorization."""
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(
                text("""
                    INSERT INTO scope_registry (scope_object_id, engagement_id,
                        type, value, allowed_actions, registered_by)
                    VALUES (:sid, :eid, 'cidr', '0.0.0.0/0', ARRAY['*'], 'attacker')
                """),
                {"sid": _uid("SCOPE"), "eid": engagement_id},
            )
    assert _insufficient_privilege(err)


def test_app_role_cannot_insert_an_authoritative_classification(engagement_id):
    """The subtler attack: declare a PII database harmless, at the top tier.

    This is the I6b bypass that does not look like a bypass. Nothing overrides
    a DENY; the deny simply never fires, because the fact it depends on was
    rewritten at the source.
    """
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(
                text("""
                    INSERT INTO metadata_registry (asset_id, engagement_id,
                        identity_type, identity_value, data_class,
                        classification_source, classification_authority)
                    VALUES (:aid, :eid, 'fqdn', 'db.customer-a.com', ARRAY[]::text[],
                            'forged', 'AUTHORITATIVE')
                """),
                {"aid": _uid("ASSET"), "eid": engagement_id},
            )
    assert _insufficient_privilege(err)


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_app_role_cannot_update_a_registry(engagement_id, table):
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text(f"UPDATE {table} SET engagement_id = engagement_id"))
    assert _insufficient_privilege(err)


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_app_role_cannot_delete_from_a_registry(engagement_id, table):
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text(f"DELETE FROM {table}"))
    assert _insufficient_privilege(err)


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_app_role_can_still_read_a_registry(engagement_id, table):
    """Read access must survive: the resolvers query these on every decision."""
    with engagement_scope(engagement_id) as conn:
        conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()


def test_registry_helpers_refuse_the_wrong_connection(engagement_id):
    """A clearer error than a permission denial three frames down."""
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(PermissionError, match="registry_admin"):
            register_scope_object(
                conn, engagement_id=engagement_id, scope_object_id=_uid("SCOPE"),
                type="fqdn", value="app.customer-a.com", allowed_actions=["web.*"],
                actor="em",
            )
        with pytest.raises(PermissionError, match="registry_admin"):
            register_metadata(
                conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
                identity_type="fqdn", identity_value="app.customer-a.com",
                authority="AUTHORITATIVE", source="customer_declared", actor="em",
            )


# ---------------------------------------------------------------------------
# registry_admin is a writer, not an administrator
# ---------------------------------------------------------------------------

def test_registry_admin_can_write_the_registries(engagement_id, registry):
    scope = registry.scope(
        scope_object_id=_uid("SCOPE"), type="cidr", value="10.20.0.0/24",
        allowed_actions=["network.scan"],
    )
    assert scope.allowed_actions == ("network.scan",)


def test_registry_admin_cannot_bypass_rls(db_available):
    """§5 asks for a writer, not a global administrator.

    Write access to the registries is not permission to cross an engagement
    boundary. If this role carried BYPASSRLS, splitting it out would have
    traded one over-broad grant for another.
    """
    with get_registry_admin_engine().connect() as conn:
        row = conn.execute(text("""
            SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
            FROM pg_roles WHERE rolname = 'registry_admin'
        """)).one()
    assert row.rolsuper is False
    assert row.rolbypassrls is False
    assert row.rolcreatedb is False
    assert row.rolcreaterole is False


def test_registry_admin_owns_no_table(db_available):
    with get_engine().connect() as conn:
        owned = conn.execute(text("""
            SELECT c.relname FROM pg_class c
            JOIN pg_roles r ON r.oid = c.relowner
            WHERE r.rolname = 'registry_admin' AND c.relkind IN ('r','p','v','m','S')
        """)).scalars().all()
    assert owned == []


def test_registry_admin_is_still_confined_to_one_engagement(engagement_id, registry):
    """RLS applies to the writer too."""
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.scan"])

    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with registry_admin_scope(other) as conn:
        seen = conn.execute(
            text("SELECT count(*) FROM scope_registry WHERE scope_object_id = :s"),
            {"s": sid},
        ).scalar_one()
    assert seen == 0


def test_registry_admin_cannot_write_into_another_engagement(engagement_id):
    """WITH CHECK still applies: no smuggling rows across the boundary."""
    with pytest.raises(ProgrammingError) as err:
        with registry_admin_scope(engagement_id) as conn:
            conn.execute(
                text("""
                    INSERT INTO scope_registry (scope_object_id, engagement_id,
                        type, value, allowed_actions, registered_by)
                    VALUES (:sid, 'ENG-SOMEONE-ELSE', 'cidr', '10.0.0.0/8',
                            ARRAY['*'], 'em')
                """),
                {"sid": _uid("SCOPE")},
            )
    assert "row-level security" in str(err.value).lower()


@pytest.mark.parametrize("table", REGISTRY_TABLES)
def test_registry_admin_cannot_delete(engagement_id, table):
    """Rows are retired with active = FALSE so history survives (§5 audit)."""
    with pytest.raises(ProgrammingError) as err:
        with registry_admin_scope(engagement_id) as conn:
            conn.execute(text(f"DELETE FROM {table}"))
    assert _insufficient_privilege(err)


def test_registry_admin_cannot_touch_findings_or_evidence(engagement_id):
    """Scoped to its job: two writable tables, not a general-purpose role."""
    for stmt in (
        "INSERT INTO findings (finding_id, engagement_id, claim, state, "
        "evidence_strength) VALUES ('F-1', :eid, 'x', 'candidate', 'E1')",
        "UPDATE evidence SET tool = tool",
    ):
        with pytest.raises(ProgrammingError) as err:
            with registry_admin_scope(engagement_id) as conn:
                conn.execute(text(stmt), {"eid": engagement_id})
        assert _insufficient_privilege(err), stmt
