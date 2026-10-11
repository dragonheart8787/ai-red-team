"""``decision`` is NULL at ``received`` and at no other stage (0021, D63; ACCEPTANCE 5.69).

The stages in which NULL is legal were listed from the code (see the migration's docstring). This
pins the list against the database itself, as the application role, on a real connection: every
stage of the pipeline is tried with no decision, and only ``received`` is accepted. Each attempt is
rolled back, so nothing it writes outlives it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from control_plane.orchestrator import stages
from control_plane.state.db import engagement_scope

CONSTRAINT = "action_proposals_decision_past_received"
LEGAL_NULL_STAGES = {stages.RECEIVED}


def _fresh_proposal(conn, engagement_id: str) -> str:
    pid = f"PROP-DS-{uuid.uuid4().hex[:8]}"
    conn.execute(text(
        'INSERT INTO action_proposals (proposal_id, engagement_id, agent_id, '
        'request_idempotency_key, action, target, "authorization", discovery) '
        "VALUES (:p, :e, 'a', :k, 'network.scan', '{}', '{}', '{}')"),
        {"p": pid, "e": engagement_id, "k": f"k-{pid}"})
    return pid


def _move(conn, pid: str, stage: str, decision: str | None) -> None:
    conn.execute(text(
        "UPDATE action_proposals SET pipeline_stage = :s, decision = :d WHERE proposal_id = :p"),
        {"s": stage, "d": decision, "p": pid})


def test_the_list_of_legal_null_stages_covers_every_stage_the_pipeline_has():
    assert set(stages.STAGES) == {
        "received", "decided", "awaiting_approval", "approved", "capability_issued",
        "dispatching", "recorded", "closed"}, "a stage was added: is NULL legal there?"
    assert LEGAL_NULL_STAGES <= set(stages.STAGES)


@pytest.mark.parametrize("stage", stages.STAGES)
def test_a_stage_accepts_a_missing_decision_only_if_it_is_received(engagement_id, stage):
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            if stage in LEGAL_NULL_STAGES:
                with conn.begin_nested():
                    _move(conn, pid, stage, None)                    # accepted
            else:
                with pytest.raises(IntegrityError) as refused:
                    with conn.begin_nested():
                        _move(conn, pid, stage, None)
                assert CONSTRAINT in str(refused.value)
        finally:
            conn.rollback()


@pytest.mark.parametrize("stage", stages.STAGES)
@pytest.mark.parametrize("decision", ["ALLOW", "DENY", "HUMAN_APPROVAL"])
def test_every_stage_accepts_a_real_decision(engagement_id, stage, decision):
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            with conn.begin_nested():
                _move(conn, pid, stage, decision)
        finally:
            conn.rollback()


def test_the_constraint_is_validated_and_says_what_it_is_for(engagement_id):
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(text(
            "SELECT convalidated, pg_get_constraintdef(oid), obj_description(oid, 'pg_constraint') "
            "FROM pg_constraint WHERE conname = :n"), {"n": CONSTRAINT}).one()
    assert row[0] is True
    assert "decision IS NOT NULL" in row[1] and "received" in row[1]
    assert row[2] and "received" in row[2]
