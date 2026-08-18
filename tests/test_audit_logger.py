"""Audit records commit independently of the caller (§4.4).

Two properties, both deliberate, both pinned here so neither is rediscovered
the hard way:

* A record survives the caller's rollback. This is the point — an audit trail
  that only survives when the caller happens to commit is a side effect, not a
  trail. The design already produced this bug once, in issue_capability.
* A record can therefore outlive the thing it describes. Over-recording, not
  under-recording. Worth stating in a test so that an investigator who finds an
  audited action with no matching row knows it is the design, not corruption.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from control_plane.audit.logger import record_audit
from control_plane.capability.broker import Budget, issue_capability
from control_plane.state.db import engagement_scope


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _audit_rows(engagement_id, subject_id):
    with engagement_scope(engagement_id) as conn:
        return conn.execute(
            text("SELECT event_type, actor, decision, reasons FROM audit_log "
                 "WHERE subject_id = :s ORDER BY audit_id"),
            {"s": subject_id},
        ).mappings().all()


def test_record_survives_the_callers_rollback(engagement_id):
    """The property this refactor exists for."""
    subject = _uid("SUBJ")

    with pytest.raises(RuntimeError, match="deliberate"):
        with engagement_scope(engagement_id) as conn:
            conn.execute(
                text("INSERT INTO findings (finding_id, engagement_id, claim, "
                     "state, evidence_strength) "
                     "VALUES (:f, :e, 'rolled back', 'candidate', 'E1')"),
                {"f": _uid("FINDING"), "e": engagement_id},
            )
            record_audit(
                engagement_id=engagement_id, actor="orchestrator",
                event_type="test.event", subject_type="test", subject_id=subject,
            )
            raise RuntimeError("deliberate failure after the audit write")

    rows = _audit_rows(engagement_id, subject)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "test.event"


def test_a_rolled_back_action_still_leaves_its_audit_record(engagement_id):
    """The cost of the above, made explicit.

    A capability is issued, audited, and then the caller's transaction is
    rolled back. The capability does not exist; the record of issuing it does.
    An investigator comparing audit_log against state will find this, and it is
    the design rather than a fault: losing evidence of a decision is worse than
    holding evidence of one that was abandoned.
    """
    capability_id = _uid("CAP")

    with pytest.raises(RuntimeError, match="deliberate"):
        with engagement_scope(engagement_id) as conn:
            result = issue_capability(
                conn, engagement_id=engagement_id, capability_id=capability_id,
                agent_id="fake-worker", action="network.scan", actor="orchestrator",
                budget=Budget(), ttl_seconds=60,
            )
            assert result.issued is True
            raise RuntimeError("deliberate failure after issuance")

    with engagement_scope(engagement_id) as conn:
        exists = conn.execute(
            text("SELECT count(*) FROM capabilities WHERE capability_id = :c"),
            {"c": capability_id},
        ).scalar_one()
    assert exists == 0, "the capability itself must not survive the rollback"

    rows = _audit_rows(engagement_id, capability_id)
    assert [r["event_type"] for r in rows] == ["capability.issued"]


def test_refusals_are_recorded_even_when_the_caller_aborts(engagement_id):
    """The original bug, from the other direction.

    A refused issuance inside a transaction that then fails must still leave
    the refusal on record — that combination is exactly what went unaudited
    before.
    """
    capability_id = _uid("CAP")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("UPDATE engagements SET kill_switch_engaged = TRUE "
                 "WHERE engagement_id = :e"),
            {"e": engagement_id},
        )

    with pytest.raises(RuntimeError, match="deliberate"):
        with engagement_scope(engagement_id) as conn:
            result = issue_capability(
                conn, engagement_id=engagement_id, capability_id=capability_id,
                agent_id="fake-worker", action="network.scan", actor="orchestrator",
                budget=Budget(), ttl_seconds=60,
            )
            assert result.issued is False
            raise RuntimeError("deliberate failure after refusal")

    rows = _audit_rows(engagement_id, capability_id)
    assert [r["event_type"] for r in rows] == ["capability.refused"]
    assert rows[0]["decision"] == "DENY"


def test_record_audit_takes_no_connection(engagement_id):
    """Structural: no caller can opt back into the shared transaction."""
    import inspect

    params = set(inspect.signature(record_audit).parameters)
    assert "conn" not in params
    assert "connection" not in params


@pytest.mark.parametrize("missing", ["engagement_id", "actor"])
def test_audit_records_must_be_attributable(engagement_id, missing):
    kwargs = {
        "engagement_id": engagement_id, "actor": "orchestrator",
        "event_type": "test.event",
    }
    kwargs[missing] = ""
    with pytest.raises(ValueError):
        record_audit(**kwargs)


def test_audit_writes_are_still_append_only(engagement_id):
    """The grants from §4.4 are unchanged by writing on a separate connection."""
    import psycopg
    from sqlalchemy.exc import ProgrammingError

    record_audit(
        engagement_id=engagement_id, actor="orchestrator",
        event_type="test.event", subject_id=_uid("SUBJ"),
    )
    with pytest.raises(ProgrammingError) as err:
        with engagement_scope(engagement_id) as conn:
            conn.execute(text("UPDATE audit_log SET actor = 'tampered'"))
    assert isinstance(err.value.orig, psycopg.errors.InsufficientPrivilege)
