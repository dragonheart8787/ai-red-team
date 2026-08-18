"""Scope Registry — typed scope objects (§4.1.5).

The single source of truth for "is this authorized". §5 requires that agents,
tool adapters and the Policy Reviewer have no write access here: whoever can
write this table can grant themselves authorization, which makes it the highest
value target in the system.

The boundary is drawn twice. In the application layer the §2 function API
exposes no registry write at all. In the database, writes require the
``registry_admin`` role, which only the Engagement Manager connects as;
``cyberorch_app`` — the role every other component uses — holds SELECT and
nothing more. An application-layer bug, or a component taken over and talking
to the database directly, still cannot change what is authorized.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.state.db import REGISTRY_ADMIN_ROLE, assert_registry_admin


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

    Requires a :func:`registry_admin_scope` connection. ``actor`` is mandatory
    and audited: §5 asks for a record of who changed which scope object to
    what, because this table is what authorization *means*.
    """
    if not actor:
        raise ValueError("registry writes must name an actor (§5)")
    assert_registry_admin(conn)

    # Read the current row first so the audit record can say what changed, not
    # merely what it now says. "SCOPE-18 allows web.*" is far less useful after
    # an incident than "SCOPE-18 allowed web.get and now allows web.*".
    before = conn.execute(
        text("SELECT type, value, allowed_actions, version, active "
             "FROM scope_registry WHERE scope_object_id = :sid"),
        {"sid": scope_object_id},
    ).mappings().one_or_none()

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
        engagement_id=engagement_id,
        actor=actor,
        event_type="scope_object.registered" if before is None else "scope_object.updated",
        subject_type="scope_object",
        subject_id=scope_object_id,
        payload={
            "db_role": REGISTRY_ADMIN_ROLE,
            "before": _snapshot(before),
            "after": {
                "type": row["type"],
                "value": row["value"],
                "allowed_actions": list(row["allowed_actions"]),
                "version": row["version"],
                "active": row["active"],
            },
        },
    )
    return _to_scope_object(row)


def deactivate_scope_object(
    conn: Connection, *, engagement_id: str, scope_object_id: str, actor: str
) -> None:
    """Retire a scope object. Engagement Manager only (§5).

    Deactivation rather than deletion: the row stays, so the audit trail keeps
    something to point at. Neither role holds DELETE on this table.
    """
    if not actor:
        raise ValueError("registry writes must name an actor (§5)")
    assert_registry_admin(conn)

    before = conn.execute(
        text("SELECT type, value, allowed_actions, version, active "
             "FROM scope_registry WHERE scope_object_id = :sid"),
        {"sid": scope_object_id},
    ).mappings().one_or_none()

    conn.execute(
        text("UPDATE scope_registry SET active = FALSE, updated_at = now() "
             "WHERE scope_object_id = :sid"),
        {"sid": scope_object_id},
    )
    record_audit(
        engagement_id=engagement_id,
        actor=actor,
        event_type="scope_object.deactivated",
        subject_type="scope_object",
        subject_id=scope_object_id,
        payload={
            "db_role": REGISTRY_ADMIN_ROLE,
            "before": _snapshot(before),
            "after": dict(_snapshot(before) or {}, active=False) if before else None,
        },
    )


def _snapshot(row) -> dict[str, Any] | None:
    """Serialize a scope_registry row for the audit record."""
    if row is None:
        return None
    return {
        "type": row["type"],
        "value": row["value"],
        "allowed_actions": list(row["allowed_actions"]),
        "version": row["version"],
        "active": row["active"],
    }


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
