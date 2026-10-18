"""Audit events against state transitions, pair by pair (D66).

What the design says, and so what is checked (fixed before the first run):

* **Every state change has its audit event.** ``record_audit`` takes no connection of its own
  caller: it commits on a connection of its own, and the pipeline writes it *before* its stage
  commits (``function_api._decide``: the conditional ``UPDATE``, then ``record_audit``, then the
  commit), so that an action with no record is impossible. A state row with **no** audit event is
  therefore never allowed, at any moment, in any fault: ``missing`` is a failure.
* **An audit event may be ahead of the state, for one reason.** A process killed between the audit
  commit and the stage commit leaves an event with no state (and a retry then writes a second
  one). So ``extra`` (an event whose subject has no state row) and ``duplicate`` (two events of one
  type for one subject) are failures **unless** the newest of them falls inside the window of a
  fault that kills a writer -- ``kill9_control_plane``, ``kill9_scheduler``, ``postgres_restart``,
  ``docker_restart`` -- from its start to five minutes after it ended. Each one allowed is listed
  with the fault that explains it.
* **The reconciler's proposal transitions and their events are one transaction**
  (``act._transition``: the ``UPDATE``, then ``record`` on the same connection). No ``extra``, no
  ``missing``, no window: a kill of the reconciler must not separate them.
* ``scheduler.dispatched`` is "decided to attempt" and is written before the capability exists
  (D62 section 6): a proposal that has a capability issued for an approval must have one; an event
  without a capability is reported, not judged.

An observation is made three times, five seconds apart, and only what is still wrong each time
counts: an event committed a moment before its stage is not a finding.
"""

from __future__ import annotations

import json
import time

from scripts.soak import lib
from scripts.soak.checks import Result, _quote

KILLERS = ("kill9_control_plane", "kill9_scheduler", "postgres_restart", "docker_restart")
AFTER_FAULT_S = 300.0
RECONCILER_CLOSE_REASONS = ("abandoned_after_decision", "capability_not_live", "approval_expired",
                            "approval_revoked", "engagement_killed")

#: (name, SQL of the state subjects -- ``%E%`` is the engagement array --, audit event types,
#:  whether an extra / duplicate event may be explained by a fault)
PAIRS = [
    ("proposal.submitted", "SELECT proposal_id AS id FROM action_proposals "
     "WHERE engagement_id = ANY(%E%)", ("proposal.submitted",), True),
    ("policy.decided", "SELECT proposal_id AS id FROM action_proposals "
     "WHERE engagement_id = ANY(%E%) AND decision IS NOT NULL", ("policy.decided",), True),
    ("capability.issued", "SELECT capability_id AS id FROM capabilities "
     "WHERE engagement_id = ANY(%E%)", ("capability.issued",), True),
    # (a run the sandbox refused before it began has `tool_run.started` too, written before the
    # sandbox was asked, and then `tool_run.refused`; it has `refusal_code` and status `failed`)
    ("tool_run.started", "SELECT run_id AS id FROM tool_runs "
     "WHERE engagement_id = ANY(%E%)", ("tool_run.started",), True),
    ("tool_run.refused", "SELECT run_id AS id FROM tool_runs "
     "WHERE engagement_id = ANY(%E%) AND refusal_code IS NOT NULL", ("tool_run.refused",), True),
    ("tool_run.succeeded", "SELECT run_id AS id FROM tool_runs "
     "WHERE engagement_id = ANY(%E%) AND status = 'succeeded'", ("tool_run.succeeded",), True),
    ("tool_run.failed", "SELECT run_id AS id FROM tool_runs "
     "WHERE engagement_id = ANY(%E%) AND status = 'failed' AND refusal_code IS NULL",
     ("tool_run.failed",), True),
    ("evidence.recorded", "SELECT evidence_id AS id FROM evidence "
     "WHERE engagement_id = ANY(%E%)", ("evidence.recorded",), True),
    ("approval.granted", "SELECT DISTINCT proposal_id AS id FROM approvals "
     "WHERE engagement_id = ANY(%E%)", ("approval.granted",), True),
    ("reconciler.proposal_abandoned", "SELECT proposal_id AS id FROM action_proposals "
     "WHERE engagement_id = ANY(%E%) AND pipeline_stage = 'abandoned'",
     ("reconciler.proposal_abandoned",), False),
    ("reconciler.proposal_closed", "SELECT proposal_id AS id FROM action_proposals "
     "WHERE engagement_id = ANY(%E%) AND pipeline_stage = 'closed' AND stage_detail IN ("
     + ", ".join(f"'{r}'" for r in RECONCILER_CLOSE_REASONS) + ")",
     ("reconciler.proposal_closed",), False),
]


def _rows(name: str, state_sql: str, events: tuple[str, ...], engagements: list[str]):
    arr = _quote(engagements)
    kinds = ", ".join(f"'{e}'" for e in events)
    sql = (f"WITH s AS ({state_sql.replace('%E%', arr)}), "
           f"a AS (SELECT subject_id, count(*) AS n, max(extract(epoch FROM ts)) AS last_ts "
           f"FROM audit_log WHERE engagement_id = ANY({arr}) AND event_type IN ({kinds}) "
           f"GROUP BY subject_id) "
           f"SELECT 'missing', s.id, 0, 0 FROM s LEFT JOIN a ON a.subject_id = s.id "
           f"WHERE a.subject_id IS NULL "
           f"UNION ALL SELECT 'extra', a.subject_id, a.n, a.last_ts FROM a "
           f"LEFT JOIN s ON s.id = a.subject_id WHERE s.id IS NULL "
           f"UNION ALL SELECT 'duplicate', a.subject_id, a.n, a.last_ts FROM a "
           f"JOIN s ON s.id = a.subject_id WHERE a.n > 1")
    return [(kind, sid, int(n), float(ts)) for kind, sid, n, ts in lib.psql(sql)]


def _counts(engagements: list[str]) -> dict[str, int]:
    out = {}
    arr = _quote(engagements)
    for name, state_sql, events, _ in PAIRS:
        state = int(lib.psql(f"SELECT count(*) FROM ({state_sql.replace('%E%', arr)}) q")[0][0])
        kinds = ", ".join(f"'{e}'" for e in events)
        audit = int(lib.psql(f"SELECT count(DISTINCT subject_id) FROM audit_log WHERE "
                             f"engagement_id = ANY({arr}) AND event_type IN ({kinds})")[0][0])
        out[name] = (state, audit)
    return out


def explained_by(last_ts: float, windows: list[dict]) -> str | None:
    """The fault whose window (start to five minutes after its end) holds ``last_ts``."""
    for w in windows:
        if w["began"] - 1 <= last_ts <= w["ended"] + AFTER_FAULT_S:
            return f"{w['kind']} at {w['began_at']}"
    return None


def classify(rows, tolerated: bool, windows: list[dict]):
    """``(failures, allowed)`` from the three kinds of difference of one pair."""
    failures, allowed = [], []
    for kind, sid, n, last_ts in rows:
        if kind == "missing":
            failures.append(f"{sid}: a state row with no audit event")
            continue
        why = explained_by(last_ts, windows) if tolerated else None
        line = f"{sid}: {kind} ({n} event{'s' if n != 1 else ''})"
        if why:
            allowed.append(f"{line}, in the window of {why}")
        else:
            failures.append(line + (" outside any fault's window" if tolerated else
                                    " (one transaction with its transition: never allowed)"))
    return failures, allowed


def scheduler_dispatch(engagements: list[str]) -> tuple[list[str], int]:
    """Capabilities issued for an approval, whose proposal has no ``scheduler.dispatched``; and the
    number of ``scheduler.dispatched`` events that have no capability (reported, not judged)."""
    arr = _quote(engagements)
    bad = lib.psql(
        f"SELECT DISTINCT c.proposal_id FROM capabilities c WHERE c.engagement_id = ANY({arr}) "
        f"AND c.approval_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE "
        f"a.subject_id = c.proposal_id AND a.event_type = 'scheduler.dispatched')")
    without = lib.psql(
        f"SELECT count(DISTINCT a.subject_id) FROM audit_log a WHERE a.engagement_id = "
        f"ANY({arr}) AND a.event_type = 'scheduler.dispatched' AND NOT EXISTS (SELECT 1 FROM "
        f"capabilities c WHERE c.proposal_id = a.subject_id)")
    return [r[0] for r in bad], int(without[0][0])


def compare(engagements: list[str], windows: list[dict] | None = None) -> Result:
    windows = [w for w in (windows or []) if w.get("kind") in KILLERS]
    persistent: dict[str, set] = {}
    seen_rows: dict[str, list] = {}
    for attempt in range(3):
        for name, state_sql, events, _ in PAIRS:
            rows = _rows(name, state_sql, events, engagements)
            keys = {(k, sid) for k, sid, _n, _t in rows}
            persistent[name] = keys if attempt == 0 else persistent[name] & keys
            seen_rows[name] = rows
        if attempt < 2:
            time.sleep(5)
    failures, allowed = [], []
    for name, _sql, _events, tolerated in PAIRS:
        rows = [r for r in seen_rows[name] if (r[0], r[1]) in persistent[name]]
        f, a = classify(rows, tolerated, windows)
        failures += [f"{name}: {line}" for line in f]
        allowed += [f"{name}: {line}" for line in a]
    unmatched, orphan_dispatch = scheduler_dispatch(engagements)
    failures += [f"scheduler.dispatched: {p} has a capability issued for an approval and no "
                 f"scheduler.dispatched" for p in unmatched]
    counts = _counts(engagements)
    summary = ", ".join(f"{n} {s}/{a}" for n, (s, a) in counts.items())
    detail = (f"state/audit subjects: {summary}; scheduler.dispatched with no capability: "
              f"{orphan_dispatch}; allowed by a fault window: {len(allowed)}")
    if allowed:
        detail += " " + json.dumps(allowed[:6])
    return Result("audit events match state transitions", not failures,
                  "; ".join(failures[:6]) + (" | " + detail if failures else "") if failures
                  else detail)


__all__ = ["compare", "classify", "explained_by", "PAIRS"]
