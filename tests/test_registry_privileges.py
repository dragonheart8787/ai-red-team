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


# ---------------------------------------------------------------------------
# I4 across the two-role operation D9 added
# ---------------------------------------------------------------------------

def test_retire_scope_object_cannot_reach_into_another_engagement(engagement_id):
    """I4 against retire_scope_object, which spans two roles (§5, D9).

    Worth its own test rather than inheriting D2's and D4.5's coverage. Those
    proved that each role individually is confined by RLS; this operation opens
    a registry_admin connection *and* a cyberorch_app connection, and the
    question is whether the pair can do something neither can do alone.

    Concretely, the failure mode: attacker holds ENG-A, names ENG-B's scope
    object. The registry_admin half sees nothing to deactivate under ENG-A's
    RLS, and the cyberorch_app half must likewise revoke nothing — the risk is
    a cascade keyed on scope_object_id that reaches ENG-B's capabilities
    because the id matched even though the engagement did not.

    What actually holds the line, established by mutation: RLS. Neutralising
    the cascade's explicit ``engagement_id = :eid`` predicate leaves this test
    passing, because the policy on ``capabilities`` already makes the victim's
    rows invisible on an ENG-A connection. The explicit filter is defence in
    depth, not the load-bearing part — worth knowing, since a future change
    that loosened RLS would not be caught by the filter's presence.
    """
    from control_plane.capability.broker import Budget, get_capability, issue_capability
    from control_plane.orchestrator.engagement import retire_scope_object
    from control_plane.registry.scope_registry import register_scope_object

    victim = f"ENG-VICTIM-{uuid.uuid4().hex[:10]}"
    victim_scope = _uid("SCOPE")
    victim_capability = _uid("CAP")

    with engagement_scope(victim) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-VICTIM', 1)"),
            {"e": victim},
        )
    with registry_admin_scope(victim) as conn:
        register_scope_object(
            conn, engagement_id=victim, scope_object_id=victim_scope,
            type="cidr", value="10.55.0.0/24", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
    with engagement_scope(victim) as conn:
        assert issue_capability(
            conn, engagement_id=victim, capability_id=victim_capability,
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            constraints={"host": "10.55.0.9"}, budget=Budget(), ttl_seconds=60,
            scope_object_id=victim_scope,
        ).issued is True

    # The attacking engagement names the victim's scope object by id.
    revoked = retire_scope_object(
        engagement_id=engagement_id, scope_object_id=victim_scope,
        actor="attacker", reason="cross-engagement attempt",
    )

    # Nothing of the victim's was touched, by either half of the operation.
    assert revoked == ()
    with engagement_scope(victim) as conn:
        assert get_capability(conn, victim_capability).revoked is False
        still_active = conn.execute(
            text("SELECT active FROM scope_registry WHERE scope_object_id = :s"),
            {"s": victim_scope},
        ).scalar_one()
    assert still_active is True


def test_revoke_credential_cannot_reach_into_another_engagement(engagement_id):
    """The same question for D9's other cascade.

    revoke_credential runs on one connection rather than two, so RLS alone
    should confine it — but the cascade is keyed on credential_id, and an id is
    not an engagement. This is the assertion that says so.

    As above, RLS is the mechanism doing the work; the UPDATE's own
    ``engagement_id`` predicate is redundant while the policy holds.
    """
    from control_plane.capability.broker import Budget, get_capability, issue_capability
    from control_plane.orchestrator.engagement import revoke_credential

    victim = f"ENG-VICTIM-{uuid.uuid4().hex[:10]}"
    victim_credential = _uid("CRED")
    victim_capability = _uid("CAP")

    with engagement_scope(victim) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-VICTIM', 1)"),
            {"e": victim},
        )
        conn.execute(
            text("INSERT INTO credentials (credential_id, engagement_id, label) "
                 "VALUES (:c, :e, 'victim credential')"),
            {"c": victim_credential, "e": victim},
        )
        assert issue_capability(
            conn, engagement_id=victim, capability_id=victim_capability,
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(), ttl_seconds=60, credential_id=victim_credential,
        ).issued is True

    with engagement_scope(engagement_id) as conn:
        revoked = revoke_credential(
            conn, engagement_id=engagement_id, credential_id=victim_credential,
            actor="attacker", reason="cross-engagement attempt",
        )

    assert revoked == ()
    with engagement_scope(victim) as conn:
        assert get_capability(conn, victim_capability).revoked is False
        assert conn.execute(
            text("SELECT revoked FROM credentials WHERE credential_id = :c"),
            {"c": victim_credential},
        ).scalar_one() is False
