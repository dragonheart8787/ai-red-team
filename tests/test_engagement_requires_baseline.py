"""``create_engagement`` refuses when no global baseline is in force (5.20 follow-up, D54).

An engagement freezes the global baseline that exists when it is created. Created with none, it
would be frozen at an *empty* baseline and every action would default to DENY until its own layers
said otherwise -- silently, because nothing would have failed. This is the ordering dependency the
freeze introduced, found after it was built; the refusal is a follow-up, **not one of the seven
decisions taken at D54**, and is recorded that way.

The refusal is a named exception (:class:`NoBaselinePublished`), not a bare ``PermissionError`` or a
database error, and its message says what is missing and what to run next. The "no baseline in
force" state cannot be produced by emptying a shared database (a retired layer cannot be brought
back, and other tests share the global rows), so the refusal is driven by making the shared
applicability fragment report none, which is the question the check asks.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.orchestrator.engagement import NoBaselinePublished, create_engagement
from control_plane.policy import layers as layers_module
from control_plane.policy.layers import has_global_baseline
from control_plane.state.db import engagement_scope, registry_admin_scope
from tests.helpers import deactivate_global_layer, publish_global_layer


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _create(eid: str, customer: str = "CUST-REQ"):
    with registry_admin_scope(eid) as conn:
        return create_engagement(conn, engagement_id=eid, customer_id=customer, actor="operator")


def _rows(sql: str, **params):
    with engagement_scope(params.get("e", "ENG-NONE")) as conn:
        return conn.execute(text(sql), params).all()


def _without_a_baseline(monkeypatch, *, others=()):
    """The applicability fragment reports layers, none of them a global baseline."""
    monkeypatch.setattr(layers_module, "_select_applicable", lambda *a, **k: list(others))


# ---------------------------------------------------------------------------
# The refusal
# ---------------------------------------------------------------------------

def test_creating_an_engagement_with_no_baseline_is_refused_with_a_way_forward(
    db_available, monkeypatch
):
    eid = _uid("ENG-NOBASE")
    _without_a_baseline(monkeypatch)
    with pytest.raises(NoBaselinePublished) as err:
        _create(eid)

    message = str(err.value)
    assert "no published baseline_global" in message
    assert "DENY" in message                                   # what would have happened
    assert "global_policy_admin" in message                    # over which connection
    assert "scripts/manage_global_policy.py publish --layer baseline_global" in message
    assert err.value.engagement_id == eid and err.value.customer_id == "CUST-REQ"


def test_the_refusal_is_a_named_exception_not_a_bare_permission_or_database_error(
    db_available, monkeypatch
):
    _without_a_baseline(monkeypatch)
    with pytest.raises(NoBaselinePublished) as err:
        _create(_uid("ENG-NOBASE"))
    assert not isinstance(err.value, PermissionError | DBAPIError)
    assert isinstance(err.value, RuntimeError)


def test_a_refusal_writes_no_engagement_and_says_so_on_the_trail(db_available, monkeypatch):
    eid = _uid("ENG-NOBASE")
    _without_a_baseline(monkeypatch)
    with pytest.raises(NoBaselinePublished):
        _create(eid)

    assert _rows("SELECT 1 FROM engagements WHERE engagement_id = :e", e=eid) == []
    events = {r[0]: r for r in _rows(
        "SELECT event_type, decision, reasons FROM audit_log WHERE subject_id = :e", e=eid)}
    assert "engagement.created" not in events
    assert events["engagement.creation_refused"][1] == "DENY"
    assert list(events["engagement.creation_refused"][2]) == ["no_baseline_published"]


@pytest.mark.parametrize("what", ["an overlay only", "an engagement-scoped baseline_global",
                                  "a customer layer"])
def test_only_a_global_baseline_satisfies_it(db_available, monkeypatch, what):
    """Other layers being present does not make an empty baseline a baseline."""
    others = {
        "an overlay only": [{"id": 1, "layer": "emergency_overlay", "engagement_id": None}],
        "an engagement-scoped baseline_global":
            [{"id": 2, "layer": "baseline_global", "engagement_id": "ENG-OTHER"}],
        "a customer layer": [{"id": 3, "layer": "customer", "engagement_id": None}],
    }[what]
    _without_a_baseline(monkeypatch, others=others)
    with pytest.raises(NoBaselinePublished):
        _create(_uid("ENG-NOBASE"))


def test_a_baseline_scoped_to_another_customer_does_not_count(db_available):
    """5.35: the check asks for a baseline in force for *this* customer, so a baseline published
    for someone else is not one -- otherwise this customer's engagement would be frozen at an
    empty baseline all the same. Uses the real fragment: a customer-scoped row is invisible to an
    engagement of another customer, and a baseline naming no customer is visible to all."""
    other, mine = _uid("CUST-OTHER"), _uid("CUST-MINE")
    row = publish_global_layer(
        layer="baseline_global", version=uuid.uuid4().int % 2_000_000_000,
        document={"data_deny": [_uid("x")]}, actor="platform-owner", customer_id=other)
    try:
        eid = _uid("ENG-PROBE")
        with registry_admin_scope(eid) as conn:
            rows = layers_module._select_applicable(
                conn, eid, "id, layer, engagement_id", customer_id=mine)
        assert row not in {r["id"] for r in rows}
        with registry_admin_scope(eid) as conn:
            rows = layers_module._select_applicable(
                conn, eid, "id, layer, engagement_id", customer_id=other)
        assert row in {r["id"] for r in rows}
    finally:
        deactivate_global_layer(row)


# ---------------------------------------------------------------------------
# The positive control: with a baseline, nothing changes
# ---------------------------------------------------------------------------

def test_with_a_baseline_in_force_creation_is_exactly_what_it_was(db_available):
    """The session guarantees one (tests/conftest.py); this pins that the ordinary path is
    untouched: a row, a freeze point, a ``created`` record, no refusal record."""
    eid = _uid("ENG-OK")
    with registry_admin_scope(eid) as conn:
        assert has_global_baseline(conn, eid, customer_id="CUST-REQ") is True
    state = _create(eid)

    assert state.status == "active" and state.kill_switch_engaged is False
    (row,) = _rows("SELECT customer_id, baseline_frozen_through FROM engagements "
                   "WHERE engagement_id = :e", e=eid)
    assert row[0] == "CUST-REQ" and row[1] is not None
    events = {r[0] for r in _rows(
        "SELECT event_type FROM audit_log WHERE subject_id = :e", e=eid)}
    assert "engagement.created" in events
    assert "engagement.creation_refused" not in events


def test_a_duplicate_id_is_still_reported_as_a_duplicate(db_available):
    """The new check must not shadow the older, more specific refusal."""
    from control_plane.orchestrator.engagement import EngagementAlreadyExists

    eid = _uid("ENG-DUP")
    _create(eid)
    with pytest.raises(EngagementAlreadyExists):
        _create(eid)
