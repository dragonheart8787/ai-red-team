"""``decision`` is NULL at ``received`` and ``abandoned`` and at no other stage (0021, 0022;
ACCEPTANCE 5.69, 5.78).

The stages in which NULL is legal were listed from the code (see the migrations' docstrings). This
pins the list against the database itself, as the application role, on a real connection: every
stage of the pipeline is tried with no decision, and only ``received`` and ``abandoned`` are
accepted -- ``abandoned`` only with its one reason, and *never with a decision* (an abandoned
proposal was by definition not decided). Each attempt is rolled back, so nothing it writes outlives
it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from control_plane.orchestrator import stages
from control_plane.state.db import engagement_scope

CONSTRAINT = "action_proposals_decision_past_received"
LEGAL_NULL_STAGES = {stages.RECEIVED, stages.ABANDONED}
ABANDONED_CHECK = "action_proposals_abandoned_is_undecided"


def _fresh_proposal(conn, engagement_id: str) -> str:
    pid = f"PROP-DS-{uuid.uuid4().hex[:8]}"
    conn.execute(text(
        'INSERT INTO action_proposals (proposal_id, engagement_id, agent_id, '
        'request_idempotency_key, action, target, "authorization", discovery) '
        "VALUES (:p, :e, 'a', :k, 'network.scan', '{}', '{}', '{}')"),
        {"p": pid, "e": engagement_id, "k": f"k-{pid}"})
    return pid


def _accepted(conn, pid: str, stage: str, decision: str | None, detail: str | None = None) -> None:
    """A move the database must accept; a refusal is a failed assertion, not a stack trace."""
    try:
        with conn.begin_nested():
            _move(conn, pid, stage, decision, detail)
    except IntegrityError as refused:
        pytest.fail(f"{stage} (decision {decision!r}) was refused: "
                    f"{str(refused.orig).splitlines()[0]}")


def _move(conn, pid: str, stage: str, decision: str | None, detail: str | None = None) -> None:
    if stage == stages.ABANDONED and detail is None:
        detail = stages.ABANDON_REASONS[0]                      # its one reason
    conn.execute(text(
        "UPDATE action_proposals SET pipeline_stage = :s, decision = :d, stage_detail = :x "
        "WHERE proposal_id = :p"),
        {"s": stage, "d": decision, "x": detail, "p": pid})


def test_the_list_of_legal_null_stages_covers_every_stage_the_pipeline_has():
    assert set(stages.STAGES) == {
        "received", "decided", "awaiting_approval", "approved", "capability_issued",
        "dispatching", "recorded", "closed", "abandoned"}, "a stage was added: is NULL legal there?"
    assert LEGAL_NULL_STAGES <= set(stages.STAGES)
    assert LEGAL_NULL_STAGES == set(stages.UNDECIDED_STAGES), "stages.py and this test disagree"


@pytest.mark.parametrize("stage", stages.STAGES)
def test_a_stage_accepts_a_missing_decision_only_if_it_is_received_or_abandoned(
    engagement_id, stage,
):
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            if stage in LEGAL_NULL_STAGES:
                _accepted(conn, pid, stage, None)                    # accepted
            else:
                with pytest.raises(IntegrityError) as refused:
                    with conn.begin_nested():
                        _move(conn, pid, stage, None)
                assert CONSTRAINT in str(refused.value)
        finally:
            conn.rollback()


@pytest.mark.parametrize("stage", [s for s in stages.STAGES if s != stages.ABANDONED])
@pytest.mark.parametrize("decision", ["ALLOW", "DENY", "HUMAN_APPROVAL"])
def test_every_stage_but_abandoned_accepts_a_real_decision(engagement_id, stage, decision):
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            _accepted(conn, pid, stage, decision)
        finally:
            conn.rollback()


@pytest.mark.parametrize("decision", ["ALLOW", "DENY", "HUMAN_APPROVAL"])
def test_an_abandoned_proposal_cannot_carry_a_decision(engagement_id, decision):
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            with pytest.raises(IntegrityError) as refused:
                with conn.begin_nested():
                    _move(conn, pid, stages.ABANDONED, decision)
            assert ABANDONED_CHECK in str(refused.value)
        finally:
            conn.rollback()


@pytest.mark.parametrize("detail", [None, "", "closed", "undecided", "UNDECIDED_PAST_GRACE",
                                    "undecided_past_grace "])
def test_an_abandoned_proposal_needs_exactly_its_one_reason_and_null_is_refused(
    engagement_id, detail,
):
    """5.69, met a second time: written as ``... AND stage_detail = '...'`` the CHECK passes on a
    NULL detail, and an abandoned row with no reason was accepted. The ``IS NOT NULL`` is
    explicit."""
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            with pytest.raises(IntegrityError) as refused:
                with conn.begin_nested():
                    conn.execute(text(
                        "UPDATE action_proposals SET pipeline_stage = 'abandoned', "
                        "stage_detail = :d WHERE proposal_id = :p"), {"d": detail, "p": pid})
            assert ABANDONED_CHECK in str(refused.value), str(refused.value)[:200]
        finally:
            conn.rollback()


def test_the_one_reason_is_accepted(engagement_id):
    with engagement_scope(engagement_id) as conn:
        pid = _fresh_proposal(conn, engagement_id)
        try:
            _accepted(conn, pid, stages.ABANDONED, None, stages.ABANDON_REASONS[0])
        finally:
            conn.rollback()


def test_the_constraint_is_validated_and_says_what_it_is_for(engagement_id):
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(text(
            "SELECT convalidated, pg_get_constraintdef(oid), obj_description(oid, 'pg_constraint') "
            "FROM pg_constraint WHERE conname = :n"), {"n": CONSTRAINT}).one()
    assert row[0] is True
    assert "decision IS NOT NULL" in row[1] and "received" in row[1] and "abandoned" in row[1]
    assert row[2] and "received" in row[2] and "abandoned" in row[2]
