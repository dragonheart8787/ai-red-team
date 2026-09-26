"""create_engagement() — the operation D11-9 found missing (D39).

Until this deliverable nothing created an engagement: every caller wrote the
row directly, on ``cyberorch_app``, which — as ``test_registry_privileges.py``
now shows directly — has always had the raw grant to do it and to delete it,
unused only because nothing called it. These tests are about the operation
itself: who may call it, what it records, and what happens when it is called
twice for the same id.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from control_plane.audit.query import audited_event_types
from control_plane.capability.broker import current_policy_version
from control_plane.orchestrator.engagement import (
    EngagementAlreadyExists,
    create_engagement,
    get_engagement,
)
from control_plane.policy.layers import publish_policy_layer
from control_plane.state.db import engagement_scope, registry_admin_scope


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _version() -> int:
    """A version nobody else in the suite will pick (see test_policy_layers.py
    for why: ``policy_layers_identity`` is unique over (layer, version,
    engagement_id, customer_id), and a global layer's engagement_id is NULL, so
    two tests publishing "baseline_global version 1" collide across the whole
    run and across runs, since nothing truncates the table)."""
    return int(uuid.uuid4().int % 1_000_000_000)


# ---------------------------------------------------------------------------
# Who may call it
# ---------------------------------------------------------------------------

def test_the_wrong_connection_is_refused_before_any_sql(engagement_id):
    """The same defence-in-depth register_scope_object/register_metadata use.

    engagement_id already exists here (the fixture created it), so this is
    also checking that create_engagement does not fall back to some silent
    update path on the wrong role — it refuses outright.
    """
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(PermissionError, match="registry_admin"):
            create_engagement(
                conn, engagement_id=_uid("ENG-WRONGROLE"),
                customer_id="CUST-TEST", actor="attacker",
            )


def test_registry_admin_can_create_one(db_available):
    eid = _uid("ENG-NEW")
    with registry_admin_scope(eid) as conn:
        state = create_engagement(
            conn, engagement_id=eid, customer_id="CUST-NEW", actor="engagement-manager",
        )
    assert state.engagement_id == eid
    assert state.status == "active"
    assert state.kill_switch_engaged is False
    assert state.revoked_capabilities == ()

    with engagement_scope(eid) as conn:
        stored = get_engagement(conn, eid)
    assert stored is not None
    assert stored.accepts_work is True


# ---------------------------------------------------------------------------
# The policy snapshot: a real value, honestly not consulted by anything yet
# ---------------------------------------------------------------------------

def test_the_policy_snapshot_is_the_real_current_version(engagement_id):
    """Not the old literal 1 -- the actual current_policy_version at creation.

    Published against ``engagement_id`` (an existing, already-created
    engagement) so there is a real global-plus-this-engagement version to
    compare against; the new engagement created here starts with a *different*
    id, so its own snapshot reads only the global layers, computed
    independently here rather than assumed to match.
    """
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="baseline_global",
            version=_version(), document={"actions": {_uid("action"): "ALLOW"}},
            actor="platform-owner",
        )

    eid = _uid("ENG-SNAP")
    with registry_admin_scope(eid) as conn:
        expected = current_policy_version(conn, eid)
        state = create_engagement(
            conn, engagement_id=eid, customer_id="CUST-SNAP", actor="engagement-manager",
        )

    with engagement_scope(state.engagement_id) as conn:
        stored = conn.execute(
            text("SELECT policy_snapshot_version FROM engagements WHERE engagement_id = :e"),
            {"e": eid},
        ).scalar_one()
    assert stored == expected
    assert stored > 0, "the published baseline_global layer should be counted"


def test_load_effective_policy_does_not_read_the_snapshot(engagement_id):
    """Honesty check on the docstring's claim (DEFERRED 5.20).

    A layer published *after* creation is still live-merged in, because
    load_effective_policy never consults policy_snapshot_version -- the
    frozen-baseline enforcement §4.5 describes has not been built. This would
    fail if it ever silently got built without updating the claim.
    """
    from control_plane.policy.layers import load_effective_policy

    eid = _uid("ENG-LIVE")
    with registry_admin_scope(eid) as conn:
        create_engagement(
            conn, engagement_id=eid, customer_id="CUST-LIVE", actor="engagement-manager",
        )

    token = _uid("post_creation_class")
    with engagement_scope(eid) as conn:
        before = load_effective_policy(conn, eid)
        assert token not in before.data_deny

        publish_policy_layer(
            conn, engagement_id=eid, layer="baseline_global",
            version=_version(), document={"data_deny": [token]}, actor="platform-owner",
        )
        after = load_effective_policy(conn, eid)
    assert token in after.data_deny, (
        "a post-creation baseline publish did not apply -- if this starts "
        "failing, the frozen-baseline enforcement has been built and 5.20 "
        "should be closed, not silently left stale"
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def test_the_audit_record_names_the_actor_and_the_snapshot(db_available):
    eid = _uid("ENG-AUDIT")
    with registry_admin_scope(eid) as conn:
        create_engagement(
            conn, engagement_id=eid, customer_id="CUST-AUDIT", actor="engagement-manager",
        )

    with engagement_scope(eid) as conn:
        assert "engagement.created" in audited_event_types(conn)
        row = conn.execute(
            text("SELECT actor, decision, payload FROM audit_log "
                 "WHERE event_type = 'engagement.created' AND subject_id = :e"),
            {"e": eid},
        ).mappings().one()

    assert row["actor"] == "engagement-manager"
    assert row["decision"] == "ALLOW"
    assert row["payload"]["customer_id"] == "CUST-AUDIT"
    assert isinstance(row["payload"]["policy_snapshot_version"], int)
    # Explicit None, not an absent key -- the trail should say "no scope yet"
    # rather than leave a reader to infer it from the key's absence.
    assert "initial_scope_object_id" in row["payload"]
    assert row["payload"]["initial_scope_object_id"] is None


# ---------------------------------------------------------------------------
# Calling it twice
# ---------------------------------------------------------------------------

def test_a_duplicate_id_raises_a_named_error_not_a_raw_constraint_violation():
    eid = _uid("ENG-DUP")
    with registry_admin_scope(eid) as conn:
        create_engagement(
            conn, engagement_id=eid, customer_id="CUST-FIRST", actor="engagement-manager",
        )

    with pytest.raises(EngagementAlreadyExists, match=eid):
        with registry_admin_scope(eid) as conn:
            create_engagement(
                conn, engagement_id=eid, customer_id="CUST-SECOND", actor="attacker",
            )

    # The failed attempt changed nothing: the original row and its audit trail
    # stand, and no second engagement.created was appended for the collision.
    with engagement_scope(eid) as conn:
        stored = conn.execute(
            text("SELECT customer_id FROM engagements WHERE engagement_id = :e"),
            {"e": eid},
        ).scalar_one()
        created_count = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE event_type = 'engagement.created' "
                 "AND subject_id = :e"),
            {"e": eid},
        ).scalar_one()
    assert stored == "CUST-FIRST"
    assert created_count == 1


def test_the_connection_is_usable_after_a_duplicate_is_refused():
    """The aborted INSERT must not poison anything the caller does next.

    create_engagement raises inside the caller's own `with registry_admin_scope`
    block, so the engine rolls the (poisoned) transaction back on the way out;
    a fresh scope afterward must work normally.
    """
    eid = _uid("ENG-DUP2")
    with registry_admin_scope(eid) as conn:
        create_engagement(
            conn, engagement_id=eid, customer_id="CUST-A", actor="engagement-manager",
        )

    with pytest.raises(EngagementAlreadyExists):
        with registry_admin_scope(eid) as conn:
            create_engagement(
                conn, engagement_id=eid, customer_id="CUST-B", actor="attacker",
            )

    other = _uid("ENG-DUP3")
    with registry_admin_scope(other) as conn:
        state = create_engagement(
            conn, engagement_id=other, customer_id="CUST-C", actor="engagement-manager",
        )
    assert state.engagement_id == other
