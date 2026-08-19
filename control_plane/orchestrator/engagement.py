"""Engagement lifecycle: pause, resume, kill switch (§1.2e, §4.6, I9).

The D8 coverage audit turned this up, and it is worth stating plainly: the
Capability Broker has checked ``status`` and ``kill_switch_engaged`` on every
issue and every renewal since D5, but nothing in the system could *set* them.
The controls were enforced and unreachable. Every test that exercised them did
so with raw SQL, which is why the gap survived three deliverables — the
behaviour was covered, the operation was not.

An unreachable control is not a control. It also cannot be audited, since there
is no operation to audit, so "who stopped this engagement and when" had no
answer.

§1.2(e) asks what happens to work already in flight. The answer here is that
the kill switch does not wait for the next heartbeat: it revokes every live
capability immediately, and renewal remains the backstop for anything issued in
the same instant. A control that only takes effect at the next heartbeat is a
control with a delay measured in whatever the lease happens to be.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.capability.broker import (
    CREDENTIAL_REVOKED,
    KILL_SWITCH,
    SCOPE_OBJECT_DEACTIVATED,
    revoke_all_for_engagement,
    revoke_capabilities_for_credential,
    revoke_capabilities_for_scope_object,
)
from control_plane.registry.scope_registry import deactivate_scope_object
from control_plane.state.db import engagement_scope, registry_admin_scope

ACTIVE = "active"
PAUSED = "paused"
COMPLETED = "completed"
KILLED = "killed"

PAUSE_REASON = "engagement_paused"
COMPLETION_REASON = "engagement_completed"


@dataclass(frozen=True)
class EngagementState:
    engagement_id: str
    status: str
    kill_switch_engaged: bool
    revoked_capabilities: tuple[str, ...] = ()

    @property
    def accepts_work(self) -> bool:
        return self.status == ACTIVE and not self.kill_switch_engaged


def get_engagement(conn: Connection, engagement_id: str) -> EngagementState | None:
    row = conn.execute(
        text("SELECT engagement_id, status, kill_switch_engaged FROM engagements "
             "WHERE engagement_id = :eid"),
        {"eid": engagement_id},
    ).mappings().one_or_none()
    if row is None:
        return None
    return EngagementState(
        engagement_id=row["engagement_id"], status=row["status"],
        kill_switch_engaged=row["kill_switch_engaged"],
    )


def pause_engagement(
    conn: Connection, *, engagement_id: str, actor: str, reason: str
) -> EngagementState:
    """Stop new work and revoke what is running.

    Capabilities are revoked rather than left to lapse. A paused engagement
    whose in-flight scans continue until their leases expire is not paused; it
    is paused-ish for up to one lease.
    """
    _set_status(conn, engagement_id, PAUSED)
    revoked = revoke_all_for_engagement(
        conn, engagement_id=engagement_id, reason=PAUSE_REASON, actor=actor,
    )
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="engagement.paused",
        subject_type="engagement", subject_id=engagement_id, decision="DENY",
        reasons=(reason,),
        payload={"revoked_capabilities": revoked, "capability_count": len(revoked)},
    )
    return EngagementState(engagement_id, PAUSED, False, tuple(revoked))


def resume_engagement(
    conn: Connection, *, engagement_id: str, actor: str, reason: str
) -> EngagementState:
    """Return an engagement to active.

    Resuming does not restore the capabilities the pause revoked, and must not:
    I9 makes revocation terminal, so work continues by obtaining new
    authorization rather than by reviving old. Refused outright once the kill
    switch has been engaged — that is not a pause.
    """
    current = get_engagement(conn, engagement_id)
    if current is None:
        raise ValueError(f"unknown engagement {engagement_id!r}")
    if current.kill_switch_engaged:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="engagement.resume_refused", subject_type="engagement",
            subject_id=engagement_id, decision="DENY", reasons=(KILL_SWITCH,),
            payload={"reason": reason},
        )
        raise ValueError(
            "cannot resume an engagement whose kill switch is engaged; "
            "the kill switch is not a pause"
        )

    _set_status(conn, engagement_id, ACTIVE)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="engagement.resumed",
        subject_type="engagement", subject_id=engagement_id, decision="ALLOW",
        reasons=(reason,),
        payload={"note": "capabilities revoked by the pause are not restored (I9)"},
    )
    return EngagementState(engagement_id, ACTIVE, False)


def engage_kill_switch(
    conn: Connection, *, engagement_id: str, actor: str, reason: str
) -> EngagementState:
    """Stop everything, now, and do not allow it to be undone (§1.2e).

    Deliberately one-way. A kill switch that can be flicked back is a pause
    with an alarming name, and the situation it exists for — something is
    wrong and nobody yet knows how wrong — is exactly the situation in which
    restarting should require a deliberate, separate act rather than the same
    operator toggling the same flag back.
    """
    conn.execute(
        text("UPDATE engagements SET kill_switch_engaged = TRUE, status = :killed, "
             "updated_at = now() WHERE engagement_id = :eid"),
        {"eid": engagement_id, "killed": KILLED},
    )
    revoked = revoke_all_for_engagement(
        conn, engagement_id=engagement_id, reason=KILL_SWITCH, actor=actor,
    )
    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="engagement.kill_switch_engaged", subject_type="engagement",
        subject_id=engagement_id, decision="DENY", reasons=(KILL_SWITCH, reason),
        payload={
            "revoked_capabilities": revoked,
            "capability_count": len(revoked),
            # §1.2(e): with a container sandbox, revocation plus namespace
            # teardown stops in-flight work rather than waiting for it.
            "note": "irreversible; in-flight capabilities revoked immediately",
        },
    )
    return EngagementState(engagement_id, KILLED, True, tuple(revoked))


def complete_engagement(
    conn: Connection, *, engagement_id: str, actor: str, summary: str
) -> EngagementState:
    """Close an engagement normally, revoking anything still outstanding."""
    _set_status(conn, engagement_id, COMPLETED)
    revoked = revoke_all_for_engagement(
        conn, engagement_id=engagement_id, reason=COMPLETION_REASON, actor=actor,
    )
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="engagement.completed",
        subject_type="engagement", subject_id=engagement_id,
        payload={"summary": summary, "revoked_capabilities": revoked},
    )
    return EngagementState(engagement_id, COMPLETED, False, tuple(revoked))


def revoke_credential(
    conn: Connection, *, engagement_id: str, credential_id: str, actor: str,
    reason: str,
) -> tuple[str, ...]:
    """Revoke a credential and stop everything holding it (§1.3.2, I9).

    Until D9 this operation did not exist. ``check_preconditions`` had read
    ``credentials.revoked`` since D5, and ``revoke_capability``'s docstring
    named "credential cascade" among its callers — but nothing revoked a
    credential, and nothing cascaded. Every test that needed a revoked
    credential wrote the column directly, which is exactly how the kill switch
    stayed unimplemented for three deliverables while appearing covered.

    Eager, like the kill switch and for the same reason: a credential pulled
    because it leaked is not pulled in one lease's time. The renewal check
    remains the backstop for anything issued in the same instant.
    """
    conn.execute(
        text("UPDATE credentials SET revoked = TRUE, revoked_at = now() "
             "WHERE credential_id = :cid AND engagement_id = :eid"),
        {"cid": credential_id, "eid": engagement_id},
    )
    revoked = revoke_capabilities_for_credential(
        conn, engagement_id=engagement_id, credential_id=credential_id,
        actor=actor, reason=CREDENTIAL_REVOKED,
    )
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="credential.revoked",
        subject_type="credential", subject_id=credential_id, decision="DENY",
        reasons=(reason,),
        payload={"revoked_capabilities": revoked, "capability_count": len(revoked)},
    )
    return tuple(revoked)


def retire_scope_object(
    *, engagement_id: str, scope_object_id: str, actor: str, reason: str,
) -> tuple[str, ...]:
    """Retire a scope object and revoke what it authorized (§4.5, I1).

    The operation D9's stateful test showed was missing. Deactivating a scope
    object revoked nothing, so a capability authorized by it stayed live and
    renewable, and I1 — "any executed action's target is in scope" — held only
    until someone retired the scope it rested on.

    Opens both connections itself, which is the one place in this module that
    happens and needs justifying. The two halves require different database
    roles: only ``registry_admin`` may write the Scope Registry, and only
    ``cyberorch_app`` may touch capabilities. Neither role can do both, and
    that separation is deliberate (§5) — a role that could retire a scope
    object *and* mint capabilities is the role worth stealing. Making the
    caller supply two correctly-scoped connections would put the constraint in
    everyone's hands rather than in one place.

    So it is two transactions, not one, and the order is the safe one. The
    retirement commits first: if the revocation then fails, the system is in
    the lazy state — the scope object is retired and ``check_preconditions``
    refuses the next heartbeat — rather than one where capabilities were
    revoked for a scope object still live. Fail-closed either way, and the
    backstop covers the gap.
    """
    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            actor=actor,
        )

    with engagement_scope(engagement_id) as conn:
        revoked = revoke_capabilities_for_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            actor=actor, reason=SCOPE_OBJECT_DEACTIVATED,
        )
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="scope_object.retired", subject_type="scope_object",
            subject_id=scope_object_id, decision="DENY", reasons=(reason,),
            payload={
                "revoked_capabilities": revoked,
                "capability_count": len(revoked),
            },
        )
    return tuple(revoked)


def _set_status(conn: Connection, engagement_id: str, status: str) -> None:
    conn.execute(
        text("UPDATE engagements SET status = :s, updated_at = now() "
             "WHERE engagement_id = :eid"),
        {"eid": engagement_id, "s": status},
    )
