"""The two events that say a proposal's outcome is unknown, and who reads them (D64 pre-deletion
item 5, ACCEPTANCE 5.87).

There are two writers for the same fact. ``dispatch.unknown_outcome`` is the older one, written by
``reconcile_stale_dispatches``; ``reconciler.dispatch_unknown_outcome`` is the reconciler's, whose
payload is held by a whitelist to ids and closed codes. The new name exists because the older
payload -- a boolean and a sentence -- cannot pass that whitelist. The report that said so called
the sentence "free text"; this file establishes what it is, and then what reads either name:

* **where the sentence comes from**: it is one string literal in ``dispatch.py``. Two proposals with
  nothing in common (a target, a run, an error) get byte-identical payloads, so nothing from
  outside reaches it. (The events that *do* carry exception text are other events:
  ``tool_run.unknown_outcome`` and ``tool_run.refused``.)
* **the consumers**: ``reconstruct_decision`` shows either event in the execution stage, in order;
  ``unknown_outcome_events`` returns both; and no other module names either event by its literal --
  a reader that asked for one name only would silently miss the other writer.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.audit import query
from control_plane.audit.query import (
    STAGE_OF_EVENT,
    UNKNOWN_OUTCOME_EVENTS,
    reconstruct_decision,
    unknown_outcome_events,
)
from control_plane.orchestrator.dispatch import reconcile_stale_dispatches
from control_plane.reconciler import act, emit, vocab
from control_plane.reconciler.model import Action
from control_plane.state.db import engagement_scope
from tests.helpers import committing_scope
from tests.reconciler_support import _capability, _proposal, _run

REPO = Path(__file__).resolve().parents[1]
LEGACY, NEW = UNKNOWN_OUTCOME_EVENTS


def in_flight(eid: str, *, tool_target: str = "10.0.0.5", run_text: str = "") -> str:
    """A proposal the sweeper will take: ``dispatching``, with an in-flight run of its own."""
    pid = _proposal(eid, "dispatching")
    cid = _capability(eid, pid, '{"max_duration_seconds": 60}')
    _run(eid, pid, cid, "running")
    with engagement_scope(eid) as conn:
        conn.execute(text("UPDATE action_proposals SET dispatch_state = 'dispatching', "
                          "target = CAST(:t AS jsonb) WHERE proposal_id = :p"),
                     {"p": pid, "t": json.dumps({"value": tool_target, "note": run_text})})
    return pid


def sweep(eid: str) -> list[str]:
    with committing_scope(eid) as conn:
        return reconcile_stale_dispatches(conn, engagement_id=eid, older_than_seconds=0,
                                          actor="sweeper")


def legacy_events(eid: str, pid: str) -> list:
    with committing_scope(eid) as conn:
        return unknown_outcome_events(conn, proposal_id=pid)


def close_as_unknown_by_reconciler(eid: str, pid: str) -> None:
    with engagement_scope(eid) as conn:
        us = conn.execute(text(
            "SELECT (extract(epoch FROM stage_updated_at) * 1000000)::bigint "
            "FROM action_proposals WHERE proposal_id = :p"), {"p": pid}).scalar_one()
    a = Action(kind=vocab.MARK_UNKNOWN_OUTCOME, reason_code=vocab.UNKNOWN_OUTCOME, subject_id=pid,
               engagement_id=eid, expected_stage="dispatching", planned_stage_updated_us=us)

    def record(conn, action):
        event_type, payload, engagement_id, subject_type, subject_id = emit.for_proposal_action(
            action)
        emit.emit_in_transaction(conn, event_type, payload, engagement_id=engagement_id,
                                 subject_type=subject_type, subject_id=subject_id)

    assert act.carry_out([a], act.Settings(act.Mode.STATE_ONLY), record=record)[0].outcome == "done"


# ---------------------------------------------------------------------------------------------
# where the older event's sentence comes from
# ---------------------------------------------------------------------------------------------

def test_the_older_events_payload_is_the_same_whatever_the_proposal_was(engagement_id):
    """Two proposals with nothing in common get the same bytes: the sentence is not made from
    anything that came in."""
    first = in_flight(engagement_id, tool_target="10.0.0.5", run_text="plain")
    second = in_flight(engagement_id, tool_target="secret-host.example", run_text="x" * 400)
    swept = sweep(engagement_id)
    assert {first, second} <= set(swept)
    payloads = []
    for pid in (first, second):
        (event,) = legacy_events(engagement_id, pid)
        assert event.event_type == LEGACY
        assert event.reasons == ("interrupted_before_result",)
        payloads.append(event.payload)
    assert payloads[0] == payloads[1] == {
        "requires_human_review": True,
        "note": "not retried: the action may already have executed"}


def test_the_sentence_is_one_string_literal_in_the_writer_and_nothing_is_interpolated():
    source = (REPO / "control_plane" / "orchestrator" / "dispatch.py").read_text()
    tree = ast.parse(source)
    writers = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and any(k.arg == "event_type" and isinstance(k.value, ast.Constant)
                       and k.value.value == LEGACY for k in n.keywords)]
    assert len(writers) == 1
    (payload,) = [k.value for k in writers[0].keywords if k.arg == "payload"]
    assert isinstance(payload, ast.Dict)
    assert all(isinstance(v, ast.Constant) for v in payload.values), ast.unparse(payload)


def test_the_older_payload_could_not_pass_the_reconcilers_whitelist():
    """Which is why the reconciler's event has its own name."""
    for payload in ({"requires_human_review": True,
                     "note": "not retried: the action may already have executed"},):
        with pytest.raises(emit.PayloadRejected):
            emit.validate(emit.DISPATCH_UNKNOWN_OUTCOME, payload)


def test_the_events_that_do_carry_exception_text_are_other_events():
    """A census, so that 'free text' is said about the right events: the older unknown-outcome
    event carries a constant; the *run-level* ones carry what an exception said."""
    source = (REPO / "control_plane" / "orchestrator" / "dispatch.py").read_text()
    tree = ast.parse(source)
    interpolated = set()
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        events = [k.value.value for k in call.keywords if k.arg == "event_type"
                  and isinstance(k.value, ast.Constant)]
        payload = [k.value for k in call.keywords if k.arg == "payload"]
        if events and payload and any(isinstance(n, ast.Call) and getattr(n.func, "id", "") == "str"
                                      for n in ast.walk(payload[0])):
            interpolated.add(events[0])
    assert "tool_run.unknown_outcome" in interpolated and "tool_run.refused" in interpolated
    assert LEGACY not in interpolated and NEW not in interpolated


# ---------------------------------------------------------------------------------------------
# the readers
# ---------------------------------------------------------------------------------------------

def test_both_names_are_in_the_execution_stage_of_a_proposals_chain():
    assert STAGE_OF_EVENT.get(LEGACY) == STAGE_OF_EVENT.get(NEW) == "execution"
    # and so is every other proposal event the reconciler writes: none falls into 'other'
    for event in emit.TRANSACTIONAL_EVENTS:
        assert event in STAGE_OF_EVENT, event


@pytest.mark.parametrize("writer", ["sweeper", "reconciler"])
def test_a_proposal_ended_unknown_by_either_writer_is_in_its_decision_chain_and_in_the_query(
        engagement_id, writer):
    pid = in_flight(engagement_id)
    if writer == "sweeper":
        assert pid in sweep(engagement_id)
        expected = LEGACY
    else:
        close_as_unknown_by_reconciler(engagement_id, pid)
        expected = NEW
    with committing_scope(engagement_id) as conn:
        chain = reconstruct_decision(conn, proposal_id=pid)
        found = unknown_outcome_events(conn, proposal_id=pid)
    mine = [e for e in chain.events if e.event_type in UNKNOWN_OUTCOME_EVENTS]
    assert [e.event_type for e in mine] == [expected]
    assert mine[0].stage == "execution"
    assert [e.event_type for e in found] == [expected]


def test_the_query_returns_both_writers_events_oldest_first(engagement_id):
    swept, closed = in_flight(engagement_id), in_flight(engagement_id)
    close_as_unknown_by_reconciler(engagement_id, closed)
    assert swept in sweep(engagement_id)
    with committing_scope(engagement_id) as conn:
        everything = unknown_outcome_events(conn)
    mine = [(e.event_type, e.subject_id) for e in everything if e.subject_id in (swept, closed)]
    assert sorted(mine) == sorted([(LEGACY, swept), (NEW, closed)])
    ids = [e.audit_id for e in everything]
    assert ids == sorted(ids)


def test_a_run_level_unknown_outcome_is_not_a_proposals(engagement_id):
    """``tool_run.unknown_outcome`` is a third name for a different fact (the sandbox was
    unreachable); the proposal-level query must not return it."""
    assert "tool_run.unknown_outcome" not in UNKNOWN_OUTCOME_EVENTS
    from control_plane.audit.logger import record_audit
    record_audit(engagement_id=engagement_id, actor="x", event_type="tool_run.unknown_outcome",
                 subject_type="tool_run", subject_id="RUN-X", payload={"error": "boom"})
    with committing_scope(engagement_id) as conn:
        assert all(e.event_type in UNKNOWN_OUTCOME_EVENTS for e in unknown_outcome_events(conn))


def test_no_module_names_either_event_by_its_literal_except_the_writers_and_the_one_reader():
    allowed = {"control_plane/orchestrator/dispatch.py": {LEGACY},
               "control_plane/reconciler/emit.py": {NEW},
               "control_plane/audit/query.py": {LEGACY, NEW}}
    found: dict[str, set[str]] = {}
    for root in ("control_plane", "tool_gateway", "agents", "scripts"):
        for path in (REPO / root).rglob("*.py"):
            tree = ast.parse(path.read_text())
            docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                          if isinstance(n, ast.Module | ast.FunctionDef | ast.ClassDef) and n.body
                          and isinstance(n.body[0], ast.Expr)
                          and isinstance(n.body[0].value, ast.Constant)}
            names = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                     and isinstance(n.value, str) and id(n) not in docstrings
                     and n.value in UNKNOWN_OUTCOME_EVENTS}
            if names:
                found[str(path.relative_to(REPO))] = names
    found.pop("scripts/mutations_d64.py", None)             # edits quote source lines verbatim
    assert found == allowed, found


def test_the_query_module_exposes_the_pair_in_one_place():
    assert query.UNKNOWN_OUTCOME_EVENTS == (
        "dispatch.unknown_outcome", "reconciler.dispatch_unknown_outcome")
