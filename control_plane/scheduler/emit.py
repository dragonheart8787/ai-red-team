"""The scheduler's audit events, and the whitelist that keeps their payloads clean (D62).

Every event the scheduler can write is declared here with the exact keys its payload may carry and a
validator for each: ids, closed reason codes and counts -- never text taken from a goal, a target, a
scope value or evidence. An event with another type, an extra key, or a value that is not what its
validator accepts is a bug and is **refused** (``PayloadRejected``), not written.

Audit failure is fail-closed: ``AuditWriteError`` propagates and the service stops. A decision that
cannot be recorded is not carried out.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from control_plane.audit.logger import record_audit
from control_plane.scheduler import vocab

ACTOR = "scheduler"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class PayloadRejected(ValueError):
    """A scheduler payload carried something the whitelist does not allow."""


def _id(value: Any) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise PayloadRejected(f"not an id: {value!r:.40}")
    return value


def _ids(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise PayloadRejected("expected a list of ids")
    return [_id(v) for v in value]


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


#: event -> (scope, {payload key: validator}).
SCHEMAS: dict[str, tuple[str, dict[str, Callable[[Any], Any]]]] = {
    vocab.STARTED: ("global", {
        "instance_id": _id, "enrolled": _ids, "missing": _ids, "dispatching": _counts,
        "capability_issued": _counts, "approved_waiting": _counts, "approved_redispatch": _counts,
    }),
    vocab.STOPPED: ("global", {
        "instance_id": _id, "reason_code": _one_of(vocab.STOP_REASONS)}),
    vocab.START_REFUSED: ("global", {
        "instance_id": _id, "reason_code": _one_of((vocab.LOCK_HELD,))}),
    vocab.ENROLLED: ("global", {"engagement_id": _id, "by": _id}),
    vocab.WITHDRAWN: ("global", {"engagement_id": _id, "by": _id}),
    vocab.DISPATCHED: ("engagement", {
        "proposal_id": _id, "reason_code": _one_of((vocab.APPROVED_AND_IDLE,))}),
    vocab.DEFERRED: ("engagement", {
        "reason_code": _one_of(vocab.DEFER_REASONS), "waiting_count": _count}),
    vocab.RESUMED: ("engagement", {"deferred_seconds": _count, "waiting_count": _count}),
    vocab.SKIPPED: ("engagement", {
        "proposal_id": _id, "reason_code": _one_of(vocab.SKIP_REASONS)}),
}


def validate(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """The payload as it will be written, or ``PayloadRejected``."""
    if event_type not in SCHEMAS:
        raise PayloadRejected(f"not a scheduler event: {event_type!r:.40}")
    _scope, schema = SCHEMAS[event_type]
    if set(payload) != set(schema):
        raise PayloadRejected(
            f"{event_type}: payload keys {sorted(payload)} != allowed {sorted(schema)}")
    return {key: schema[key](payload[key]) for key in schema}


def emit(
    event_type: str, payload: Mapping[str, Any], *, engagement_id: str | None = None,
    actor: str = ACTOR, subject_type: str | None = None, subject_id: str | None = None,
) -> int:
    """Write one scheduler event. Raises ``PayloadRejected`` or ``AuditWriteError``."""
    clean = validate(event_type, payload)
    scope, _ = SCHEMAS[event_type]
    reasons = tuple(v for k, v in clean.items() if k == "reason_code")
    if scope == "global":
        return record_audit(
            engagement_id=None, scope="global", actor=actor, event_type=event_type,
            subject_type=subject_type, subject_id=subject_id, reasons=reasons, payload=clean)
    if not engagement_id:
        raise PayloadRejected(f"{event_type} is engagement-scoped")
    return record_audit(
        engagement_id=_id(engagement_id), actor=actor, event_type=event_type,
        subject_type=subject_type, subject_id=subject_id, reasons=reasons, payload=clean)
