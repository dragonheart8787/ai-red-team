"""The reconciler's audit vocabulary: a closed list, payloads of ids, reason codes and counts only
(D64 §4, step 6d).

* the list of events is exactly the design's, every one named ``reconciler.*``, each with a schema
  of exact keys; an event of another name, a payload with an extra or a missing key, a value that is
  not what its validator takes (text, a nested document, a boolean count, a path, a CIDR) is
  **refused**, never written;
* every reason code an event can carry is one the plan/act vocabularies produce, and every one they
  produce that reaches an event is on its list (so adding a reason is one line in ``vocab`` and one
  test failure here until the event knows it);
* an event for an action is made only from a **verified** result; a result that is not ``done`` has
  no event, and a failed one has exactly ``reconciler.action_failed``;
* written for real, an event lands in the audit trail with the actor ``reconciler``, the right
  scope, and a payload equal to what was validated -- nothing added on the way.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from control_plane.reconciler import emit, vocab
from control_plane.reconciler.emit import PayloadRejected
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import (
    CHANGED,
    DETAIL_CODES,
    DONE,
    DRY_RUN,
    FAILED,
    GONE,
    LOST_RACE,
    SKIPPED_OFF,
    Result,
)
from control_plane.state.db import engagement_scope
from tests.helpers import committing_scope

DESIGN_EVENTS = {
    "reconciler.started", "reconciler.stopped", "reconciler.start_refused",
    "reconciler.proposal_abandoned", "reconciler.proposal_closed",
    "reconciler.dispatch_unknown_outcome", "reconciler.container_killed",
    "reconciler.container_removed", "reconciler.proxy_removed", "reconciler.network_removed",
    "reconciler.files_removed", "reconciler.action_intended", "reconciler.action_failed",
    "reconciler.failure_summary",
}

GOOD = {
    emit.STARTED: {"instance_id": "RECON-abc", "mode": "state_only",
                   "planned": {"abandon:undecided_past_grace": 3, "report:run_unknown": 1}},
    emit.STOPPED: {"instance_id": "RECON-abc", "reason_code": "signal"},
    emit.START_REFUSED: {"instance_id": "RECON-abc", "reason_code": "lock_held"},
    emit.PROPOSAL_ABANDONED: {"proposal_id": "PROP-1", "reason_code": "undecided_past_grace"},
    emit.PROPOSAL_CLOSED: {"proposal_id": "PROP-1", "reason_code": "capability_not_live"},
    emit.DISPATCH_UNKNOWN_OUTCOME: {"proposal_id": "PROP-1", "reason_code": "unknown_outcome"},
    emit.CONTAINER_KILLED: {"run_id": "RUN-1", "reason_code": "overran_deadline"},
    emit.CONTAINER_REMOVED: {"run_id": "RUN-1", "reason_code": "run_finished"},
    emit.PROXY_REMOVED: {"run_id": "RUN-1", "reason_code": "owner_run_ended"},
    emit.NETWORK_REMOVED: {"network_id": "0123456789ab", "reason_code": "idle_sweep"},
    emit.FILES_REMOVED: {"kind": "tls_leaf", "count": 1},
    emit.ACTION_INTENDED: {"kind": "remove_container", "subject_id": "RUN-1",
                           "reason_code": "run_finished"},
    emit.ACTION_FAILED: {"kind": "kill_container", "subject_id": "RUN-1",
                         "reason_code": "still_running_after_kill"},
    emit.FAILURE_SUMMARY: {"instance_id": "RECON-abc", "passes": 12,
                           "failed": {"kill_container:daemon_error": 3}},
}
ENGAGEMENT_SCOPED = {emit.PROPOSAL_ABANDONED, emit.PROPOSAL_CLOSED, emit.DISPATCH_UNKNOWN_OUTCOME,
                     emit.CONTAINER_KILLED, emit.CONTAINER_REMOVED, emit.PROXY_REMOVED}


def test_the_closed_list_is_the_designs_and_every_event_has_a_schema_and_a_good_example():
    assert set(emit.EVENTS) == DESIGN_EVENTS == set(emit.SCHEMAS) == set(GOOD)
    assert all(e.startswith("reconciler.") for e in emit.EVENTS)
    for event, payload in GOOD.items():
        assert emit.validate(event, payload) == payload
        assert set(payload) == set(emit.SCHEMAS[event][1])


@pytest.mark.parametrize("event", sorted(DESIGN_EVENTS))
def test_an_event_refuses_an_extra_key_a_missing_key_and_a_nested_value(event):
    payload = GOOD[event]
    with pytest.raises(PayloadRejected):
        emit.validate(event, {**payload, "target": "10.0.0.5"})
    with pytest.raises(PayloadRejected):
        emit.validate(event, {k: v for k, v in list(payload.items())[1:]})
    first = next(iter(payload))
    with pytest.raises(PayloadRejected):
        emit.validate(event, {**payload, first: {"nested": payload[first]}})
    with pytest.raises(PayloadRejected):
        emit.validate(event, {**payload, first: ["a", "list"]})


@pytest.mark.parametrize("bad", [
    "has a space", "../etc/passwd", "10.0.0.0/24", "a" * 129, "", "-leading", "semi;colon",
    "newline\n", "ünïcode", "x'; DROP TABLE audit_log; --", "/tmp/cyberorch-cred-abcd1234"])
def test_an_id_is_an_id_and_not_text_a_path_or_a_cidr(bad):
    with pytest.raises(PayloadRejected):
        emit.validate(emit.PROPOSAL_CLOSED, {"proposal_id": bad, "reason_code": "approval_expired"})
    with pytest.raises(PayloadRejected):
        emit.validate(emit.CONTAINER_KILLED, {"run_id": bad, "reason_code": "overran_deadline"})


@pytest.mark.parametrize("bad", [True, False, -1, 1.5, "3", None, [3]])
def test_a_count_is_a_non_negative_integer_and_not_a_boolean(bad):
    with pytest.raises(PayloadRejected):
        emit.validate(emit.FILES_REMOVED, {"kind": "tls_leaf", "count": bad})
    with pytest.raises(PayloadRejected):
        emit.validate(emit.FAILURE_SUMMARY, {"instance_id": "RECON-1", "passes": 1,
                                             "failed": {"kill_container:daemon_error": bad}})


def test_a_reason_code_outside_its_events_list_is_refused():
    for event, key, wrong in [
        (emit.PROPOSAL_CLOSED, "reason_code", "undecided_past_grace"),     # that is an abandon
        (emit.PROPOSAL_ABANDONED, "reason_code", "capability_not_live"),
        (emit.CONTAINER_KILLED, "reason_code", "run_finished"),
        (emit.CONTAINER_REMOVED, "reason_code", "overran_deadline"),
        (emit.NETWORK_REMOVED, "reason_code", "range_conflict"),            # not built in v1
        (emit.STOPPED, "reason_code", "because"),
        (emit.START_REFUSED, "reason_code", "grace_below_floor"),
        (emit.ACTION_FAILED, "reason_code", "free text"),
        (emit.FILES_REMOVED, "kind", "private_key"),
        (emit.STARTED, "mode", "full"),
        (emit.ACTION_FAILED, "kind", "explode"),
    ]:
        with pytest.raises(PayloadRejected):
            emit.validate(event, {**GOOD[event], key: wrong})


def test_an_event_of_another_name_is_refused_even_with_a_valid_payload():
    for name in ("scheduler.dispatched", "reconciler.deleted_everything",
                 "dispatch.unknown_outcome", "", "reconciler."):
        with pytest.raises(PayloadRejected):
            emit.validate(name, GOOD[emit.PROPOSAL_CLOSED])
        with pytest.raises(PayloadRejected):
            emit.emit(name, GOOD[emit.PROPOSAL_CLOSED], engagement_id="ENG-1")


def test_an_engagement_scoped_event_needs_an_engagement_and_a_global_one_ignores_it():
    for event in ENGAGEMENT_SCOPED - set(emit.TRANSACTIONAL_EVENTS):
        with pytest.raises(PayloadRejected):
            emit.emit(event, GOOD[event])


def test_a_proposal_event_is_never_written_on_the_audit_paths_own_connection():
    """These three say "this transition committed": written apart from it, a crash could leave the
    change without its record or the record without its change."""
    assert set(emit.TRANSACTIONAL_EVENTS) == {
        emit.PROPOSAL_ABANDONED, emit.PROPOSAL_CLOSED, emit.DISPATCH_UNKNOWN_OUTCOME}
    for event in emit.TRANSACTIONAL_EVENTS:
        with pytest.raises(PayloadRejected):
            emit.emit(event, GOOD[event], engagement_id="ENG-1")


def test_the_in_transaction_writer_takes_proposal_events_only_and_needs_an_engagement(
        engagement_id):
    with engagement_scope(engagement_id) as conn:
        for event in set(emit.EVENTS) - set(emit.TRANSACTIONAL_EVENTS):
            with pytest.raises(PayloadRejected):
                emit.emit_in_transaction(conn, event, GOOD[event], engagement_id=engagement_id)
        with pytest.raises(PayloadRejected):
            emit.emit_in_transaction(conn, emit.PROPOSAL_CLOSED, GOOD[emit.PROPOSAL_CLOSED],
                                     engagement_id="")
        with pytest.raises(PayloadRejected):          # and the whitelist applies here too
            emit.emit_in_transaction(
                conn, emit.PROPOSAL_CLOSED,
                {**GOOD[emit.PROPOSAL_CLOSED], "target": "10.0.0.5"}, engagement_id=engagement_id)


def test_the_reason_codes_of_events_are_the_plans_and_acts_vocabularies():
    schema = {e: s[1] for e, s in emit.SCHEMAS.items()}

    def codes(event: str) -> set[str]:
        check = schema[event]["reason_code"]
        accepted = set()
        for candidate in (*vocab.REASONS["close"], *vocab.REASONS["abandon"],
                          *vocab.REASONS["mark_unknown_outcome"], *vocab.REASONS["kill_container"],
                          *vocab.REASONS["remove_container"], *vocab.REASONS["remove_proxy"],
                          *vocab.REASONS["remove_network"], *vocab.REASONS["unlink_file"],
                          *DETAIL_CODES):
            try:
                check(candidate)
                accepted.add(candidate)
            except PayloadRejected:
                pass
        return accepted

    assert codes(emit.PROPOSAL_CLOSED) == set(vocab.REASONS["close"])
    assert codes(emit.PROPOSAL_ABANDONED) == set(vocab.REASONS["abandon"])
    assert codes(emit.DISPATCH_UNKNOWN_OUTCOME) == set(vocab.REASONS["mark_unknown_outcome"])
    assert codes(emit.CONTAINER_KILLED) == set(vocab.REASONS["kill_container"])
    assert codes(emit.CONTAINER_REMOVED) == set(vocab.REASONS["remove_container"])
    assert codes(emit.PROXY_REMOVED) == set(vocab.REASONS["remove_proxy"])
    assert codes(emit.NETWORK_REMOVED) == set(vocab.REASONS["remove_network"])
    assert codes(emit.ACTION_FAILED) == set(DETAIL_CODES)
    irreversible = {r for k in (*vocab.DOCKER_ACTIONS, vocab.UNLINK_FILE)
                    for r in vocab.REASONS[k]}
    assert codes(emit.ACTION_INTENDED) == irreversible


# --- from a verified result to an event -------------------------------------------------------

def act(kind, reason, **kw) -> Action:
    return Action(kind=kind, reason_code=reason, subject_id=kw.pop("subject_id", "S-1"), **kw)


CASES = [
    (act(vocab.ABANDON, "undecided_past_grace", subject_id="PROP-1", engagement_id="ENG-1"),
     emit.PROPOSAL_ABANDONED, {"proposal_id": "PROP-1", "reason_code": "undecided_past_grace"},
     "ENG-1"),
    (act(vocab.CLOSE, "engagement_killed", subject_id="PROP-2", engagement_id="ENG-1"),
     emit.PROPOSAL_CLOSED, {"proposal_id": "PROP-2", "reason_code": "engagement_killed"}, "ENG-1"),
    (act(vocab.MARK_UNKNOWN_OUTCOME, "unknown_outcome", subject_id="PROP-3", engagement_id="ENG-1"),
     emit.DISPATCH_UNKNOWN_OUTCOME,
     {"proposal_id": "PROP-3", "reason_code": "unknown_outcome"}, "ENG-1"),
    (act(vocab.KILL_CONTAINER, "overran_deadline", subject_id="a" * 64, run_id="RUN-1",
         expected_owner="ENG-1"),
     emit.CONTAINER_KILLED, {"run_id": "RUN-1", "reason_code": "overran_deadline"}, "ENG-1"),
    (act(vocab.REMOVE_CONTAINER, "no_run_row_past_grace", subject_id="a" * 64, run_id="RUN-1",
         expected_owner="ENG-1"),
     emit.CONTAINER_REMOVED, {"run_id": "RUN-1", "reason_code": "no_run_row_past_grace"}, "ENG-1"),
    (act(vocab.REMOVE_PROXY, "owner_run_ended", subject_id="a" * 64, run_id="RUN-1",
         expected_owner="ENG-1"),
     emit.PROXY_REMOVED, {"run_id": "RUN-1", "reason_code": "owner_run_ended"}, "ENG-1"),
    (act(vocab.REMOVE_NETWORK, "idle_sweep", subject_id="b" * 64,
         name="cyberorch-allow-0123456789ab"),
     emit.NETWORK_REMOVED, {"network_id": "0123456789ab", "reason_code": "idle_sweep"}, None),
]


@pytest.mark.parametrize("action, event, payload, engagement", CASES)
def test_a_verified_result_becomes_exactly_its_event_and_validates(action, event, payload,
                                                                    engagement):
    made = emit.for_result(Result(action, DONE))
    assert made[0] == event and made[1] == payload and made[2] == engagement
    assert emit.validate(made[0], made[1]) == payload


def test_a_removed_file_is_one_event_with_the_name_as_its_subject():
    a = act(vocab.UNLINK_FILE, "tls_leaf", subject_id="cyberorch-tls-abcd1234.pem",
            name="cyberorch-tls-abcd1234.pem")
    event, payload, engagement, subject_type, subject_id = emit.for_result(Result(a, DONE))
    assert (event, payload, engagement, subject_type, subject_id) == (
        emit.FILES_REMOVED, {"kind": "tls_leaf", "count": 1}, None, "host_file",
        "cyberorch-tls-abcd1234.pem")
    assert emit.validate(event, payload) == payload


@pytest.mark.parametrize("outcome", [DRY_RUN, LOST_RACE, SKIPPED_OFF, GONE, CHANGED, FAILED])
def test_a_result_that_was_not_verified_has_no_event(outcome):
    for action, *_ in CASES:
        with pytest.raises(ValueError):
            emit.for_result(Result(action, outcome, "daemon_error"))


def test_a_failure_is_reported_as_a_failure_with_a_fixed_code_and_nothing_else():
    a = CASES[3][0]
    event, payload, engagement, subject_type = emit.failure(Result(a, FAILED, "daemon_error"))
    assert (event, payload, engagement) == (
        emit.ACTION_FAILED,
        {"kind": "kill_container", "subject_id": "RUN-1", "reason_code": "daemon_error"}, "ENG-1")
    assert emit.validate(event, payload) == payload
    for bad in (Result(a, DONE), Result(a, LOST_RACE), Result(a, FAILED, None),
                Result(a, FAILED, "free text from an exception")):
        with pytest.raises(ValueError):
            emit.failure(bad)


# --- written for real -------------------------------------------------------------------------

def _written(engagement_id: str | None, event: str):
    sql = ("SELECT actor, scope, engagement_id, payload, reasons FROM audit_log "
           "WHERE event_type = :e")
    if engagement_id:
        with committing_scope(engagement_id) as conn:
            return conn.execute(text(sql + " ORDER BY audit_id DESC LIMIT 1"),
                                {"e": event}).mappings().one()
    from control_plane.state.db import global_auditor_scope
    with global_auditor_scope() as conn:
        return conn.execute(text(sql + " ORDER BY audit_id DESC LIMIT 1"),
                            {"e": event}).mappings().one()


def _write(event, payload, engagement_id, **kw):
    """Write ``event`` the way the service does: a proposal event inside the transaction of the
    engagement's connection, every other one on the audit path's own connection."""
    if event in emit.TRANSACTIONAL_EVENTS:
        with engagement_scope(engagement_id) as conn:
            emit.emit_in_transaction(conn, event, payload, engagement_id=engagement_id, **kw)
    else:
        emit.emit(event, payload, engagement_id=engagement_id, **kw)


@pytest.mark.parametrize("event", sorted(DESIGN_EVENTS))
def test_each_event_is_written_with_the_right_scope_and_exactly_its_payload(event, engagement_id):
    scoped = event in ENGAGEMENT_SCOPED
    payload = GOOD[event]
    if event in (emit.ACTION_FAILED, emit.ACTION_INTENDED):   # either: theirs, with an engagement
        emit.emit(event, payload, engagement_id=engagement_id, subject_type="x", subject_id="S-1")
        row = _written(engagement_id, event)
        assert row["scope"] == "engagement" and row["engagement_id"] == engagement_id
        emit.emit(event, payload, subject_type="x", subject_id="S-1")
        assert _written(None, event)["scope"] == "global"
        return
    _write(event, payload, engagement_id if scoped else None, subject_type="x", subject_id="S-1")
    row = _written(engagement_id if scoped else None, event)
    assert row["actor"] == "reconciler"
    assert row["payload"] == payload
    assert row["scope"] == ("engagement" if scoped else "global")
    assert row["engagement_id"] == (engagement_id if scoped else None)
    if "reason_code" in payload:
        assert list(row["reasons"]) == [payload["reason_code"]]


# --- the intent: announced before an irreversible call, paired with its result -----------------

IRREVERSIBLE = [c for c in CASES if c[0].kind in emit.IRREVERSIBLE_KINDS] + [
    (act(vocab.UNLINK_FILE, "tls_leaf", subject_id="cyberorch-tls-abcd1234.pem",
         name="cyberorch-tls-abcd1234.pem", directory="/tmp"), emit.FILES_REMOVED,
     {"kind": "tls_leaf", "count": 1}, None)]


@pytest.mark.parametrize("action, event, payload, engagement", IRREVERSIBLE)
def test_an_intent_names_the_same_subject_as_the_result_that_will_close_it(
        action, event, payload, engagement):
    intent = emit.intent_for(action)
    result = emit.for_result(Result(action, DONE))
    assert intent[0] == emit.ACTION_INTENDED
    assert intent[1] == {"kind": action.kind, "subject_id": intent[4],
                         "reason_code": action.reason_code}
    assert emit.validate(intent[0], intent[1]) == intent[1]
    # the pairing key: same engagement, same subject type, same subject id
    assert (intent[2], intent[3], intent[4]) == (result[2], result[3], result[4])
    assert emit.RESULT_EVENT_OF_KIND[action.kind] == result[0] == event


def test_a_proposal_action_has_no_intent():
    for action, *_ in CASES[:3]:
        with pytest.raises(ValueError):
            emit.intent_for(action)


def test_the_kind_to_result_table_covers_every_irreversible_kind_and_the_query_agrees():
    from control_plane.audit.query import RECONCILER_RESULT_EVENT_OF_KIND
    assert set(emit.RESULT_EVENT_OF_KIND) == set(emit.IRREVERSIBLE_KINDS)
    assert emit.RESULT_EVENT_OF_KIND == RECONCILER_RESULT_EVENT_OF_KIND
