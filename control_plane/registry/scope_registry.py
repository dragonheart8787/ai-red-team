"""Scope Registry — typed scope objects (§4.1.5).

The single source of truth for "is this authorized". §5 requires that agents,
tool adapters and the Policy Reviewer have no write access here: whoever can
write this table can grant themselves authorization, which makes it the highest
value target in the system.

In MVP-Kernel that boundary is drawn in the application layer — the function
API in §2 exposes no registry write, and the only writer is
:func:`register_scope_object`, which demands an ``actor`` and audits every
call. A dedicated database role for registry writes is the natural next turn of
the screw; see the note in README.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit


@dataclass(frozen=True)
class ScopeObject:
    scope_object_id: str
    engagement_id: str
    type: str
    value: str
    allowed_actions: tuple[str, ...]
    version: int
    active: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.scope_object_id,
            "type": self.type,
            "value": self.value,
            "allowed_actions": list(self.allowed_actions),
            "version": self.version,
        }


_SELECT = """
    SELECT scope_object_id, engagement_id, type, value, allowed_actions,
           version, active, valid_from, valid_until
    FROM scope_registry
    WHERE active IS TRUE
      AND valid_from <= now()
      AND (valid_until IS NULL OR valid_until > now())
"""


def get_scope_object(conn: Connection, scope_object_id: str) -> ScopeObject | None:
    """Fetch one live scope object. RLS confines this to the current engagement."""
    row = conn.execute(
        text(_SELECT + " AND scope_object_id = :sid"), {"sid": scope_object_id}
    ).mappings().one_or_none()
    return _to_scope_object(row) if row else None


def list_scope_objects(conn: Connection) -> list[ScopeObject]:
    """All live scope objects for the current engagement.

    OPA receives these as ``input.policy.scope_objects`` so it can re-derive
    authorization itself rather than trusting a boolean computed elsewhere.
    """
    rows = conn.execute(text(_SELECT + " ORDER BY scope_object_id")).mappings().all()
    return [_to_scope_object(r) for r in rows]


def register_scope_object(
    conn: Connection,
    *,
    engagement_id: str,
    scope_object_id: str,
    type: str,
    value: str,
    allowed_actions: Sequence[str],
    actor: str,
) -> ScopeObject:
    """Register a scope object. Engagement Manager only (§5).

    ``actor`` is mandatory and audited: §5 asks for a record of who changed
    which scope object to what, because this table is what authorization means.
    """
    if not actor:
        raise ValueError("registry writes must name an actor (§5)")
    row = conn.execute(
        text("""
            INSERT INTO scope_registry (scope_object_id, engagement_id, type, value,
                                        allowed_actions, registered_by)
            VALUES (:sid, :eid, :type, :value, :actions, :actor)
            ON CONFLICT (scope_object_id) DO UPDATE
                SET type = EXCLUDED.type,
                    value = EXCLUDED.value,
                    allowed_actions = EXCLUDED.allowed_actions,
                    version = scope_registry.version + 1,
                    updated_at = now()
            RETURNING scope_object_id, engagement_id, type, value, allowed_actions,
                      version, active
        """),
        {
            "sid": scope_object_id,
            "eid": engagement_id,
            "type": type,
            "value": value,
            "actions": list(allowed_actions),
            "actor": actor,
        },
    ).mappings().one()

    record_audit(
        conn,
        engagement_id=engagement_id,
        actor=actor,
        event_type="scope_object.registered",
        subject_type="scope_object",
        subject_id=scope_object_id,
        payload={
            "type": type,
            "value": value,
            "allowed_actions": list(allowed_actions),
            "version": row["version"],
        },
    )
    return _to_scope_object(row)


def deactivate_scope_object(
    conn: Connection, *, engagement_id: str, scope_object_id: str, actor: str
) -> None:
    conn.execute(
        text("UPDATE scope_registry SET active = FALSE, updated_at = now() "
             "WHERE scope_object_id = :sid"),
        {"sid": scope_object_id},
    )
    record_audit(
        conn,
        engagement_id=engagement_id,
        actor=actor,
        event_type="scope_object.deactivated",
        subject_type="scope_object",
        subject_id=scope_object_id,
    )


def _to_scope_object(row) -> ScopeObject:
    return ScopeObject(
        scope_object_id=row["scope_object_id"],
        engagement_id=row["engagement_id"],
        type=row["type"],
        value=row["value"],
        allowed_actions=tuple(row["allowed_actions"]),
        version=row["version"],
        active=row["active"],
    )
