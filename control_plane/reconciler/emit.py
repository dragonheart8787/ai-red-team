"""The reconciler's audit events, and the whitelist that keeps their payloads clean (D64 §4).

Every event the reconciler can write is declared here with the exact keys its payload may carry and
a validator for each: **ids, closed reason codes and counts** -- never a target, a CIDR, a command,
a path or text taken from a document. An event with another type, an extra or missing key, or a
value its validator does not accept is a bug and is **refused** (``PayloadRejected``), not written.

The events that report an action are written **only after the action was verified** (D64 §1.7): the
text of ``reconciler.container_removed`` is "this container was seen gone". They are produced by
:func:`for_result`, the one place that turns an act ``Result`` into an event, and only for a
``done`` result.

Audit failure is fail-closed for the service (it stops with ``audit_failed``); the act half has
already done what it did, which is why an action is audited at all.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from control_plane.audit.logger import record_audit
from control_plane.reconciler import vocab
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
ACTION_FAILED = "reconciler.action_failed"
FAILURE_SUMMARY = "reconciler.failure_summary"

EVENTS = (STARTED, STOPPED, START_REFUSED, PROPOSAL_ABANDONED, PROPOSAL_CLOSED,
          DISPATCH_UNKNOWN_OUTCOME, CONTAINER_KILLED, CONTAINER_REMOVED, PROXY_REMOVED,
          NETWORK_REMOVED, FILES_REMOVED, ACTION_FAILED, FAILURE_SUMMARY)

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
    """Write one reconciler event. Raises ``PayloadRejected`` or ``AuditWriteError``."""
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


# --- from a verified result to its event -------------------------------------------------------

_PROPOSAL_EVENT = {
    vocab.ABANDON: PROPOSAL_ABANDONED, vocab.CLOSE: PROPOSAL_CLOSED,
    vocab.MARK_UNKNOWN_OUTCOME: DISPATCH_UNKNOWN_OUTCOME,
}
_CONTAINER_EVENT = {
    vocab.KILL_CONTAINER: CONTAINER_KILLED, vocab.REMOVE_CONTAINER: CONTAINER_REMOVED,
    vocab.REMOVE_PROXY: PROXY_REMOVED,
}


def for_result(
    result: Result,
) -> tuple[str, dict[str, Any], str | None, str | None, str | None] | None:
    """``(event type, payload, engagement id, subject type, subject id)`` for a **done** result,
    ``None`` for one that has no event of its own (a removed file is counted, not reported alone).
    Raises ``ValueError`` for a result that is not done: an unverified action is never an event."""
    if result.outcome != DONE:
        raise ValueError("only a verified result becomes an event")
    action = result.action
    if action.kind in _PROPOSAL_EVENT:
        return (_PROPOSAL_EVENT[action.kind],
                {"proposal_id": action.subject_id, "reason_code": action.reason_code},
                action.engagement_id, "action_proposal", action.subject_id)
    if action.kind in _CONTAINER_EVENT:
        run = action.run_id or ""
        return (_CONTAINER_EVENT[action.kind], {"run_id": run, "reason_code": action.reason_code},
                action.expected_owner, "tool_run", run)
    if action.kind == vocab.REMOVE_NETWORK:
        network = (action.name or "").rsplit("-", 1)[-1]
        return (NETWORK_REMOVED, {"network_id": network, "reason_code": action.reason_code},
                None, "sandbox_network", network)
    return None


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
