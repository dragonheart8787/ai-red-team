"""The reconciler's audit events, and the whitelist that keeps their payloads clean (D64 §4).

Every event the reconciler can write is declared here with the exact keys its payload may carry and
a validator for each: **ids, closed reason codes and counts** -- never a target, a CIDR, a command,
a path or text taken from a document. An event with another type, an extra or missing key, or a
value its validator does not accept is a bug and is **refused** (``PayloadRejected``), not written.

How an event relates to the change it describes (D64 item 4,
``docs/D64_PREDELETION_COMPLETION.md``):

* a **proposal transition** (``proposal_abandoned``, ``proposal_closed``,
  ``dispatch_unknown_outcome``) is written *in the same database transaction* as the change
  (:func:`emit_in_transaction`): the event exists exactly when the change committed;
* an **irreversible act on a Docker object or a host file** is preceded by
  ``reconciler.action_intended`` (:func:`intent_for`, written on its own connection and committed
  *before* the call) and followed by the result event, written **only after the action was
  verified** (D64 §1.7: ``reconciler.container_removed`` means "this container was seen gone"), or
  by ``reconciler.action_failed``. An intent with neither is a process that died in between, and
  ``audit.query.unresolved_reconciler_intents`` lists it.

Result events are produced by :func:`for_result`, the one place that turns an act ``Result`` into an
event, and only for a ``done`` result. Audit failure is fail-closed for the service (it stops with
``audit_failed``); where the change and its record are one transaction, nothing is left changed
and unrecorded.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from control_plane.audit.logger import record_audit, record_audit_in_transaction
from control_plane.reconciler import vocab
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import (
    DETAIL_CODES,
    DONE,
    FAILED,
    Result,
)

ACTOR = "reconciler"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")

# --- the closed list of events ----------------------------------------------------------------
STARTED = "reconciler.started"
STOPPED = "reconciler.stopped"
START_REFUSED = "reconciler.start_refused"
PROPOSAL_ABANDONED = "reconciler.proposal_abandoned"
PROPOSAL_CLOSED = "reconciler.proposal_closed"
DISPATCH_UNKNOWN_OUTCOME = "reconciler.dispatch_unknown_outcome"
CONTAINER_KILLED = "reconciler.container_killed"
CONTAINER_REMOVED = "reconciler.container_removed"
PROXY_REMOVED = "reconciler.proxy_removed"
NETWORK_REMOVED = "reconciler.network_removed"
FILES_REMOVED = "reconciler.files_removed"
ACTION_INTENDED = "reconciler.action_intended"
ACTION_FAILED = "reconciler.action_failed"
FAILURE_SUMMARY = "reconciler.failure_summary"

EVENTS = (STARTED, STOPPED, START_REFUSED, PROPOSAL_ABANDONED, PROPOSAL_CLOSED,
          DISPATCH_UNKNOWN_OUTCOME, CONTAINER_KILLED, CONTAINER_REMOVED, PROXY_REMOVED,
          NETWORK_REMOVED, FILES_REMOVED, ACTION_INTENDED, ACTION_FAILED, FAILURE_SUMMARY)

#: the proposal events: written in the transaction that makes the change
TRANSACTIONAL_EVENTS = (PROPOSAL_ABANDONED, PROPOSAL_CLOSED, DISPATCH_UNKNOWN_OUTCOME)

# --- reason codes of the service's own events -------------------------------------------------
STOP_SIGNAL = "signal"
STOP_LOCK_LOST = "lock_lost"
STOP_DB_LOST = "db_lost"
STOP_DOCKER_LOST = "docker_lost"
STOP_AUDIT_FAILED = "audit_failed"
STOP_UNEXPECTED = "unexpected_error"
STOP_REASONS = (STOP_SIGNAL, STOP_LOCK_LOST, STOP_DB_LOST, STOP_DOCKER_LOST, STOP_AUDIT_FAILED,
                STOP_UNEXPECTED)
LOCK_HELD = "lock_held"
CONFIG_REFUSED = "config_refused"
REFUSAL_REASONS = (LOCK_HELD, CONFIG_REFUSED)
MODES = ("state_only",)                      # a dry run writes no audit record at all


class PayloadRejected(ValueError):
    """A reconciler payload carried something the whitelist does not allow."""


def _id(value: Any) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise PayloadRejected(f"not an id: {value!r:.40}")
    return value


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PayloadRejected(f"not a count: {value!r:.40}")
    return value


def _counts(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise PayloadRejected("expected a mapping of id to count")
    return {_id(k): _count(v) for k, v in value.items()}


def _one_of(allowed: tuple[str, ...]) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if value not in allowed:
            raise PayloadRejected(f"not an allowed code: {value!r:.40}")
        return value
    return check


FAILURE_CODES = tuple(c for c in DETAIL_CODES)
FILE_KINDS = tuple(vocab.REASONS[vocab.UNLINK_FILE])
#: the actions that cannot be undone, and every reason one of them can carry
IRREVERSIBLE_KINDS = vocab.DOCKER_ACTIONS + (vocab.UNLINK_FILE,)
INTENT_REASONS = tuple(sorted({r for k in IRREVERSIBLE_KINDS for r in vocab.REASONS[k]}))
#: the event that says an irreversible action was carried out and verified, by kind
RESULT_EVENT_OF_KIND = {
    vocab.KILL_CONTAINER: CONTAINER_KILLED, vocab.REMOVE_CONTAINER: CONTAINER_REMOVED,
    vocab.REMOVE_PROXY: PROXY_REMOVED, vocab.REMOVE_NETWORK: NETWORK_REMOVED,
    vocab.UNLINK_FILE: FILES_REMOVED,
}

#: event -> (scope, {payload key: validator}).
SCHEMAS: dict[str, tuple[str, dict[str, Callable[[Any], Any]]]] = {
    STARTED: ("global", {"instance_id": _id, "mode": _one_of(MODES), "planned": _counts}),
    STOPPED: ("global", {"instance_id": _id, "reason_code": _one_of(STOP_REASONS)}),
    START_REFUSED: ("global", {"instance_id": _id, "reason_code": _one_of(REFUSAL_REASONS)}),
    PROPOSAL_ABANDONED: ("engagement", {
        "proposal_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.ABANDON])}),
    PROPOSAL_CLOSED: ("engagement", {
        "proposal_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.CLOSE])}),
    DISPATCH_UNKNOWN_OUTCOME: ("engagement", {
        "proposal_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.MARK_UNKNOWN_OUTCOME])}),
    CONTAINER_KILLED: ("engagement", {
        "run_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.KILL_CONTAINER])}),
    CONTAINER_REMOVED: ("engagement", {
        "run_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.REMOVE_CONTAINER])}),
    PROXY_REMOVED: ("engagement", {
        "run_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.REMOVE_PROXY])}),
    NETWORK_REMOVED: ("global", {
        "network_id": _id, "reason_code": _one_of(vocab.REASONS[vocab.REMOVE_NETWORK])}),
    FILES_REMOVED: ("global", {"kind": _one_of(FILE_KINDS), "count": _count}),
    ACTION_INTENDED: ("either", {
        "kind": _one_of(IRREVERSIBLE_KINDS), "subject_id": _id,
        "reason_code": _one_of(INTENT_REASONS)}),
    ACTION_FAILED: ("either", {
        "kind": _one_of(vocab.ACTION_KINDS), "subject_id": _id,
        "reason_code": _one_of(FAILURE_CODES)}),
    FAILURE_SUMMARY: ("global", {
        "instance_id": _id, "passes": _count, "failed": _counts}),
}


def validate(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """The payload as it will be written, or ``PayloadRejected``."""
    if event_type not in SCHEMAS:
        raise PayloadRejected(f"not a reconciler event: {event_type!r:.40}")
    _scope, schema = SCHEMAS[event_type]
    if set(payload) != set(schema):
        raise PayloadRejected(
            f"{event_type}: payload keys {sorted(payload)} != allowed {sorted(schema)}")
    return {key: schema[key](payload[key]) for key in schema}


def emit(event_type: str, payload: Mapping[str, Any], *, engagement_id: str | None = None,
         subject_type: str | None = None, subject_id: str | None = None) -> int:
    """Write one reconciler event on the audit path's own connection. Raises ``PayloadRejected`` or
    ``AuditWriteError``. A proposal event is refused: :func:`emit_in_transaction` writes it."""
    if event_type in TRANSACTIONAL_EVENTS:
        raise PayloadRejected(f"{event_type!r:.40} is written in the transaction of its change")
    clean = validate(event_type, payload)
    scope, _ = SCHEMAS[event_type]
    reasons = tuple(v for k, v in clean.items() if k == "reason_code")
    if scope == "either":
        scope = "engagement" if engagement_id else "global"
    if scope == "global":
        return record_audit(
            engagement_id=None, scope="global", actor=ACTOR, event_type=event_type,
            subject_type=subject_type, subject_id=subject_id, reasons=reasons, payload=clean)
    if not engagement_id:
        raise PayloadRejected(f"{event_type} is engagement-scoped")
    return record_audit(
        engagement_id=_id(engagement_id), actor=ACTOR, event_type=event_type,
        subject_type=subject_type, subject_id=subject_id, reasons=reasons, payload=clean)


def emit_in_transaction(conn: Any, event_type: str, payload: Mapping[str, Any], *,
                        engagement_id: str, subject_type: str | None = None,
                        subject_id: str | None = None) -> int:
    """Write one **proposal** event on ``conn``, the transaction that makes the change it describes.

    Only the events in ``TRANSACTIONAL_EVENTS`` may be written this way: they say "this transition
    committed", so they must commit and roll back with it. Raises ``PayloadRejected`` or
    ``AuditWriteError``; either way the caller's transaction must roll back.
    """
    if event_type not in TRANSACTIONAL_EVENTS:
        raise PayloadRejected(f"{event_type!r:.40} is not written inside a transaction")
    clean = validate(event_type, payload)
    reasons = tuple(v for k, v in clean.items() if k == "reason_code")
    return record_audit_in_transaction(
        conn, engagement_id=_id(engagement_id), actor=ACTOR, event_type=event_type,
        subject_type=subject_type, subject_id=subject_id, reasons=reasons, payload=clean)


# --- from a verified result to its event -------------------------------------------------------

_PROPOSAL_EVENT = {
    vocab.ABANDON: PROPOSAL_ABANDONED, vocab.CLOSE: PROPOSAL_CLOSED,
    vocab.MARK_UNKNOWN_OUTCOME: DISPATCH_UNKNOWN_OUTCOME,
}
_CONTAINER_EVENT = {
    vocab.KILL_CONTAINER: CONTAINER_KILLED, vocab.REMOVE_CONTAINER: CONTAINER_REMOVED,
    vocab.REMOVE_PROXY: PROXY_REMOVED,
}


def for_proposal_action(
    action: Action,
) -> tuple[str, dict[str, Any], str | None, str, str]:
    """``(event type, payload, engagement id, subject type, subject id)`` of the event a proposal
    action is recorded as. The same value serves the in-transaction write and :func:`for_result`."""
    if action.kind not in _PROPOSAL_EVENT:
        raise ValueError("not a proposal action")
    return (_PROPOSAL_EVENT[action.kind],
            {"proposal_id": action.subject_id, "reason_code": action.reason_code},
            action.engagement_id, "action_proposal", action.subject_id)


def _subject_of(action: Action) -> tuple[str | None, str, str]:
    """``(engagement id, subject type, subject id)`` as the intent and the result both name it."""
    if action.kind in _CONTAINER_EVENT:
        run = action.run_id or ""
        return action.expected_owner, "tool_run", run
    if action.kind == vocab.REMOVE_NETWORK:
        network = (action.name or "").rsplit("-", 1)[-1]
        return None, "sandbox_network", network
    if action.kind == vocab.UNLINK_FILE:
        return None, "host_file", action.name or ""
    raise ValueError("not an irreversible action")


def intent_for(
    action: Action,
) -> tuple[str, dict[str, Any], str | None, str, str]:
    """``(event type, payload, engagement id, subject type, subject id)`` of
    ``reconciler.action_intended`` for an irreversible action: written before the call is made."""
    engagement, subject_type, subject_id = _subject_of(action)
    return (ACTION_INTENDED,
            {"kind": action.kind, "subject_id": subject_id, "reason_code": action.reason_code},
            engagement, subject_type, subject_id)


def for_result(
    result: Result,
) -> tuple[str, dict[str, Any], str | None, str | None, str | None] | None:
    """``(event type, payload, engagement id, subject type, subject id)`` for a **done** result.
    Raises ``ValueError`` for a result that is not done: an unverified action is never an event."""
    if result.outcome != DONE:
        raise ValueError("only a verified result becomes an event")
    action = result.action
    if action.kind in _PROPOSAL_EVENT:
        return for_proposal_action(action)
    engagement, subject_type, subject_id = _subject_of(action)
    if action.kind in _CONTAINER_EVENT:
        return (_CONTAINER_EVENT[action.kind],
                {"run_id": subject_id, "reason_code": action.reason_code},
                engagement, subject_type, subject_id)
    if action.kind == vocab.REMOVE_NETWORK:
        return (NETWORK_REMOVED, {"network_id": subject_id, "reason_code": action.reason_code},
                None, subject_type, subject_id)
    # one event per file, so that the file's intent has a result to be paired with
    return (FILES_REMOVED, {"kind": action.reason_code, "count": 1}, None, subject_type,
            subject_id)


def failure(result: Result) -> tuple[str, dict[str, Any], str | None, str]:
    """``(event type, payload, engagement id, subject type)`` of ``reconciler.action_failed`` for a
    ``failed`` result; ``ValueError`` for any other (a failure is the only thing reported so)."""
    if result.outcome != FAILED or result.detail not in FAILURE_CODES:
        raise ValueError("only a failed result with a fixed reason code is reported as failed")
    action = result.action
    subject = action.subject_id
    if action.kind in _CONTAINER_EVENT:
        subject = action.run_id or action.subject_id
    elif action.kind == vocab.REMOVE_NETWORK:
        subject = (action.name or action.subject_id).rsplit("-", 1)[-1]
    engagement = action.engagement_id or action.expected_owner
    return (ACTION_FAILED, {"kind": action.kind, "subject_id": subject,
                            "reason_code": result.detail}, engagement, "reconciler_action")
