"""What the runtime role may do to ``policy_layers`` and ``engagements`` (ACCEPTANCE 5.36).

Migration 0001 granted ``cyberorch_app`` SELECT, INSERT, UPDATE and DELETE on every table, and
only the append-only tables and (at D5 and D39) the registries and INSERT/DELETE on
``engagements`` were ever narrowed. So the role every Worker, Reviewer and Supervisor call runs
as could, until migration 0013:

* rewrite the ``document`` of a published policy layer, or any other column, or delete the row;
* rewrite any column of ``engagements`` -- ``customer_id``, or ``policy_snapshot_version``, the
  pointer §4.5's frozen baseline would be read from.

Production code never did either: it inserts layers, flips ``active`` to FALSE, and updates
``status`` / ``kill_switch_engaged`` / ``updated_at``. So that is exactly what remains. These
tests assert the backstop the way D5 and D39 did -- PostgreSQL refuses, not "the application does
not try" -- with the negative controls that show the operations that legitimately use each
privilege still work.
"""

from __future__ import annotations

import json
import uuid

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from control_plane.orchestrator.engagement import (
    complete_engagement,
    engage_kill_switch,
    pause_engagement,
    resume_engagement,
)
from control_plane.policy.layers import deactivate_policy_layer, publish_policy_layer
from control_plane.state.db import engagement_scope
from tests.helpers import make_engagement


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _refused(err) -> bool:
    return isinstance(err.value.orig, psycopg.errors.InsufficientPrivilege)


@pytest.fixture
def layer(engagement_id):
    """An engagement-scoped layer to attack. Scoped so it cannot touch any other test."""
    with engagement_scope(engagement_id) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement",
            version=uuid.uuid4().int % 2_000_000_000, document={"data_deny": ["x"]},
            actor="engagement-manager", scoped_to_engagement=True,
        )
    return layer_id


# ---------------------------------------------------------------------------
# policy_layers: the runtime role can add and retire, and nothing else
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("assignment", [
    "document = '{}'::jsonb",
    "layer = 'baseline_global'",
    "version = 1",
    "engagement_id = NULL",
    "customer_id = 'CUST-ATTACK'",
    "created_at = now()",
    "id = id + 1000000",
])
def test_app_role_cannot_rewrite_a_policy_layer(engagement_id, layer, assignment):
    """The direct attack on §4.5: edit what a published layer says, or which scope it is in
    (``engagement_id = NULL`` promotes it to every engagement's). Only ``active`` is writable."""
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text(f"UPDATE policy_layers SET {assignment} WHERE id = :i"),
                         {"i": layer})
    assert _refused(err), assignment


def test_app_role_cannot_delete_a_policy_layer(engagement_id, layer):
    """Layers are retired by ``active``, never removed; the history is the record of what
    was in force."""
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text("DELETE FROM policy_layers WHERE id = :i"), {"i": layer})
    assert _refused(err)


def test_app_role_can_still_publish_and_retire_a_layer(engagement_id):
    """The negative control: the two things the code does. ``publish`` is an INSERT,
    ``deactivate`` flips ``active`` -- neither may notice the tightening."""
    with engagement_scope(engagement_id) as conn:
        layer_id = publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement",
            version=uuid.uuid4().int % 2_000_000_000, document={"data_deny": ["y"]},
            actor="engagement-manager", scoped_to_engagement=True,
        )
        assert deactivate_policy_layer(
            conn, engagement_id=engagement_id, layer_id=layer_id, actor="engagement-manager")
        active = conn.execute(text("SELECT active FROM policy_layers WHERE id = :i"),
                              {"i": layer_id}).scalar_one()
    assert active is False


def test_app_role_can_still_flip_the_active_flag_either_way(engagement_id, layer):
    """Reactivation is not a production operation, but ``active`` is the one column the role
    is granted, and the D14 tests set it back to TRUE. Pins that the grant is the column, not
    just one direction of it."""
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE policy_layers SET active = FALSE WHERE id = :i"), {"i": layer})
        conn.execute(text("UPDATE policy_layers SET active = TRUE WHERE id = :i"), {"i": layer})
        assert conn.execute(text("SELECT active FROM policy_layers WHERE id = :i"),
                            {"i": layer}).scalar_one() is True


def test_the_overlay_check_still_holds_for_the_runtime_roles_own_rows(engagement_id):
    """5.36 must not have traded one guarantee for another: an engagement-scoped overlay that
    would relax is still refused by the table's own CHECK (D16). (A *global* overlay is not the
    runtime role's to write at all since 5.37; tests/test_policy_layers.py covers the CHECK
    through the role that is.)"""
    from sqlalchemy.exc import IntegrityError

    with engagement_scope(engagement_id) as conn:
        with pytest.raises(IntegrityError, match="emergency_overlay_can_only_tighten"):
            conn.execute(
                text("INSERT INTO policy_layers (layer, version, engagement_id, document) "
                     "VALUES ('emergency_overlay', 98, :e, CAST(:d AS jsonb))"),
                {"e": engagement_id, "d": json.dumps({"actions": {"network.scan": "ALLOW"}})},
            )


# ---------------------------------------------------------------------------
# engagements: only the columns the four lifecycle operations write
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("assignment", [
    "customer_id = 'CUST-ATTACK'",
    "policy_snapshot_version = 0",
    "created_at = now() - interval '1 year'",
    "engagement_id = engagement_id || '-x'",
])
def test_app_role_cannot_rewrite_an_engagements_identity_or_snapshot(engagement_id, assignment):
    """``customer_id`` decides which customer-scoped policy applies (5.35) and the snapshot
    pointer is what §4.5's frozen baseline would consult; neither is the runtime role's."""
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text(f"UPDATE engagements SET {assignment} "
                              "WHERE engagement_id = :e"), {"e": engagement_id})
    assert _refused(err), assignment


@pytest.mark.parametrize("assignment", [
    "updated_at = now()",
    "status = 'paused'",
    "kill_switch_engaged = TRUE",
])
def test_app_role_can_still_write_the_lifecycle_columns(db_available, assignment):
    """The negative control, column by column. Each engagement is fresh so the kill switch
    does not leak into another test."""
    eid = _uid("ENG-COLS")
    make_engagement(eid)
    with engagement_scope(eid) as conn:
        assert conn.execute(text(f"UPDATE engagements SET {assignment} "
                                 "WHERE engagement_id = :e"), {"e": eid}).rowcount == 1


def test_pause_resume_complete_and_kill_are_unaffected(db_available):
    """The four operations themselves, through the real functions, on the real role."""
    paused, killed = _uid("ENG-LIFE"), _uid("ENG-KILL")
    make_engagement(paused)
    make_engagement(killed)
    with engagement_scope(paused) as conn:
        assert pause_engagement(
            conn, engagement_id=paused, actor="op", reason="test").status == "paused"
        assert resume_engagement(
            conn, engagement_id=paused, actor="op", reason="test").status == "active"
        assert complete_engagement(
            conn, engagement_id=paused, actor="op", summary="done").status == "completed"
    with engagement_scope(killed) as conn:
        state = engage_kill_switch(conn, engagement_id=killed, actor="op", reason="test")
    assert state.kill_switch_engaged is True


# ---------------------------------------------------------------------------
# The whole matrix, so a later blanket GRANT cannot quietly undo it
# ---------------------------------------------------------------------------

TABLE_PRIVILEGES = {
    # role: {table: privileges the role may hold at table level}
    "cyberorch_app": {"policy_layers": {"SELECT", "INSERT"}, "engagements": {"SELECT"}},
    "registry_admin": {"policy_layers": {"SELECT"}, "engagements": {"SELECT", "INSERT"}},
    "credential_admin": {"policy_layers": set(), "engagements": {"SELECT"}},
    "ui_reader": {"policy_layers": set(), "engagements": {"SELECT"}},
    "global_auditor": {"policy_layers": set(), "engagements": set()},
    # 5.37: the only writer of global policy layers; nothing on engagements.
    "global_policy_admin": {"policy_layers": {"SELECT", "INSERT"}, "engagements": set()},
}
ALL_TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")

#: Column-level UPDATE that ``cyberorch_app`` alone holds, and nothing wider.
APP_UPDATABLE_COLUMNS = {
    "policy_layers": {"active"},
    "engagements": {"status", "kill_switch_engaged", "updated_at"},
}


@pytest.mark.parametrize("role", sorted(TABLE_PRIVILEGES))
@pytest.mark.parametrize("table", ["policy_layers", "engagements"])
def test_table_privileges_are_exactly_these(db_available, role, table):
    """Catalogue check, in the D5/D39 spirit. A future migration that re-runs the blanket
    ``GRANT … ON ALL TABLES`` fails here rather than silently restoring UPDATE/DELETE."""
    expected = TABLE_PRIVILEGES[role][table]
    with engagement_scope(_uid("ENG-CAT")) as conn:
        held = {
            p for p in ALL_TABLE_PRIVILEGES
            if conn.execute(text("SELECT has_table_privilege(:r, :t, :p)"),
                            {"r": role, "t": table, "p": p}).scalar_one()
        }
    # Column-level UPDATE is reported by has_table_privilege as False, which is the point:
    # the table-level UPDATE is what must be absent.
    assert held == expected, (
        f"{role} on {table}: holds {sorted(held)}, expected {sorted(expected)}. If this "
        "widening is deliberate, change TABLE_PRIVILEGES and say why in the migration.")


@pytest.mark.parametrize("table", ["policy_layers", "engagements"])
def test_the_app_roles_column_updates_are_exactly_these(db_available, table):
    with engagement_scope(_uid("ENG-CAT")) as conn:
        columns = [r[0] for r in conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :t"), {"t": table})]
        updatable = {
            c for c in columns
            if conn.execute(text("SELECT has_column_privilege('cyberorch_app', :t, :c, 'UPDATE')"),
                            {"t": table, "c": c}).scalar_one()
        }
    assert updatable == APP_UPDATABLE_COLUMNS[table]


#: The one other role that may update anything on these tables: the global policy writer, and
#: only the column that retires a layer (row-confined to global rows by migration 0014).
OTHER_ROLE_UPDATABLE = {("global_policy_admin", "policy_layers"): {"active"}}


@pytest.mark.parametrize("role", ["registry_admin", "credential_admin", "ui_reader",
                                  "global_auditor", "global_policy_admin"])
@pytest.mark.parametrize("table", ["policy_layers", "engagements"])
def test_no_other_role_can_update_either_table_beyond_its_one_column(db_available, role, table):
    """None of them held UPDATE before 0013 and none may after, except the global policy
    writer's ``active`` (5.37): this is about the runtime role, and a fix that reached for a
    different role would only move the gap."""
    with engagement_scope(_uid("ENG-CAT")) as conn:
        columns = [r[0] for r in conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :t"), {"t": table})]
        updatable = {
            c for c in columns
            if conn.execute(text("SELECT has_column_privilege(:r, :t, :c, 'UPDATE')"),
                            {"r": role, "t": table, "c": c}).scalar_one()
        }
    assert updatable == OTHER_ROLE_UPDATABLE.get((role, table), set())
