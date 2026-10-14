"""Shared rows for the reconciler's tests: proposals at a stage, with whatever hangs off them.

Every row made here is **backdated to 1970** so that it sorts first in
``reconciler_stuck_proposals()`` (which returns the oldest rows of the whole database), and every
engagement it touched is **closed out when the test ends**: a long-lived development database would
otherwise collect stuck rows from every run until the function's page (5,000 rows) no longer reached
the new ones. The close-out uses the table owner with the engagement bound -- the owner is subject
to the same row-level security as anyone -- and writes only ``closed`` / ``abandoned``, the two
terminal stages a row with or without a decision may be in.
"""

from __future__ import annotations

import os
import uuid

from sqlalchemy import create_engine, text

from control_plane.reconciler import emit
from control_plane.state.db import engagement_scope

EPOCH = "1970-01-02 00:00:00+00"
STUCK = ("received", "decided", "approved", "capability_issued", "dispatching")

#: engagements a test put rows into, closed out by ``close_touched`` after the test
TOUCHED: set[str] = set()




# ---------------------------------------------------------------------------------------------
# fixtures: proposals at a stage, with whatever hangs off them
# ---------------------------------------------------------------------------------------------

def _proposal(eid: str, stage: str, *, age_s: int = 0, key: str | None = None) -> str:
    """A proposal at ``stage`` whose ``stage_updated_at`` is backdated to 1970 (+ ``age_s``)."""
    TOUCHED.add(eid)
    pid = f"PROP-{uuid.uuid4().hex[:12]}"
    decision = None if stage in ("received", "abandoned") else "ALLOW"
    detail = "undecided_past_grace" if stage == "abandoned" else None
    with engagement_scope(eid) as conn:
        conn.execute(text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, action, target, "authorization", discovery, decision,
                pipeline_stage, stage_detail, stage_updated_at)
            VALUES (:p, :e, 'agent', :k, 'network.scan', '{}', '{}', '{}', :d, :s, :det,
                    CAST(:t AS timestamptz) + make_interval(secs => :age)
            )"""), {"p": pid, "e": eid, "k": key or f"k-{pid}", "d": decision, "s": stage,
                    "det": detail, "t": EPOCH, "age": age_s})
    return pid


def _capability(eid: str, pid: str, budget: str, *, lease: str = "now() + interval '1 hour'",
                revoked: bool = False) -> str:
    cid = f"CAP-{uuid.uuid4().hex[:12]}"
    with engagement_scope(eid) as conn:
        conn.execute(text(f"""
            INSERT INTO capabilities (capability_id, engagement_id, agent_id, proposal_id, action,
                policy_version, lease_expires_at, budget, revoked)
            VALUES (:c, :e, 'agent', :p, 'network.scan', 1, {lease}, CAST(:b AS jsonb), :r)"""),
            {"c": cid, "e": eid, "p": pid, "b": budget, "r": revoked})
    return cid


def _approval(eid: str, pid: str, *, valid: str = "now() + interval '1 hour'") -> str:
    aid = f"APR-{uuid.uuid4().hex[:12]}"
    with engagement_scope(eid) as conn:
        conn.execute(text(f"""
            INSERT INTO approvals (approval_id, engagement_id, proposal_id, action_class,
                valid_until, approved_by, approved_scope)
            VALUES (:a, :e, :p, 'active', {valid}, 'tester', 'this_proposal_only')"""),
            {"a": aid, "e": eid, "p": pid})
    return aid


def _run(eid: str, pid: str, cid: str | None, status: str = "running") -> str:
    rid = f"RUN-{uuid.uuid4().hex[:12]}"
    with engagement_scope(eid) as conn:
        conn.execute(text("""
            INSERT INTO tool_runs (run_id, engagement_id, proposal_id, capability_id, tool,
                tool_version, normalized_target, execution_fingerprint, status)
            VALUES (:r, :e, :p, :c, 'nmap', '1', 't', 'fp', :s)"""),
            {"r": rid, "e": eid, "p": pid, "c": cid, "s": status})
    return rid


def close_touched() -> None:
    """Move every stuck row of every engagement a test touched to a terminal stage, and its
    in-flight runs to ``unknown_outcome`` (the session end counts what a file leaves: 5.71)."""
    if not TOUCHED:
        return
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        for eid in sorted(TOUCHED):
            with engine.begin() as conn:
                conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                             {"e": eid})
                conn.execute(text("""
                    UPDATE action_proposals
                    SET pipeline_stage = CASE WHEN decision IS NULL
                                              THEN 'abandoned' ELSE 'closed' END,
                        stage_detail = CASE WHEN decision IS NULL THEN 'undecided_past_grace'
                                            ELSE 'test_cleanup' END,
                        stage_updated_at = now()
                    WHERE pipeline_stage = ANY(:stuck)"""), {"stuck": list(STUCK)})
                conn.execute(text("""
                    UPDATE tool_runs
                    SET status = 'unknown_outcome', finished_at = coalesce(finished_at, now())
                    WHERE status IN ('queued', 'dispatching', 'running')"""))
    finally:
        engine.dispose()
        TOUCHED.clear()


def residue_world(eid):
    """One row of each class the state-only mode can move."""
    received = _proposal(eid, "received")
    decided = _proposal(eid, "decided")
    lapsed = _proposal(eid, "capability_issued")
    _capability(eid, lapsed, '{"max_duration_seconds": 60}',
                lease="TIMESTAMPTZ '1970-01-02 01:00:00+00'")
    approved = _proposal(eid, "approved")
    _approval(eid, approved, valid="TIMESTAMPTZ '1970-01-03 00:00:00+00'")
    dispatching = _proposal(eid, "dispatching")
    cap = _capability(eid, dispatching, '{"max_duration_seconds": 120}')
    _run(eid, dispatching, cap, "running")
    return dict(received=received, decided=decided, lapsed=lapsed, approved=approved,
                dispatching=dispatching)


EXPECTED = {
    "received": ("abandoned", "undecided_past_grace", emit.PROPOSAL_ABANDONED),
    "decided": ("closed", "abandoned_after_decision", emit.PROPOSAL_CLOSED),
    "lapsed": ("closed", "capability_not_live", emit.PROPOSAL_CLOSED),
    "approved": ("closed", "approval_expired", emit.PROPOSAL_CLOSED),
    "dispatching": ("recorded", "unknown_outcome", emit.DISPATCH_UNKNOWN_OUTCOME),
}


def freshen(eid: str, pid: str) -> None:
    """Make a row's ``stage_updated_at`` now: a proposal a live driver is working on."""
    with engagement_scope(eid) as conn:
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = now() "
                          "WHERE proposal_id = :p"), {"p": pid})


def make_room_in_the_page() -> None:
    """Close out stuck rows older than an hour, in every engagement, so that a test which needs a
    *fresh* stuck row to be within the first 5,000 that ``reconciler_stuck_proposals()`` returns can
    have it. A CI database is new and needs nothing; a long-lived development database collects
    stuck rows from every run of the whole suite. The owner switches row-level security off for the
    one statement, in one transaction, as migrations 0020-0022 do -- a failure rolls both back."""
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY"))
            conn.execute(text("""
                UPDATE action_proposals
                SET pipeline_stage = CASE WHEN decision IS NULL
                                          THEN 'abandoned' ELSE 'closed' END,
                    stage_detail = CASE WHEN decision IS NULL THEN 'undecided_past_grace'
                                        ELSE 'test_cleanup' END,
                    stage_updated_at = now()
                WHERE pipeline_stage = ANY(:stuck)
                  AND stage_updated_at < now() - interval '1 hour'"""), {"stuck": list(STUCK)})
            conn.execute(text("ALTER TABLE action_proposals FORCE ROW LEVEL SECURITY"))
    finally:
        engine.dispose()
