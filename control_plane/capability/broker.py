"""Capability Broker — issuance, lease and heartbeat renewal (§4.6, I9).

A capability is a lease, not a token that ripens into a permission. §4.6 is
explicit that renewal must not be a mechanical TTL extension:

    heartbeat arrives
          │
          ▼
    re-check: policy version changed? approval still inside valid_until?
              credential revoked? engagement paused? kill switch engaged?
          │
       ┌──┴───┐
      all pass   any fails
       │            │
     renew       REVOKE → cut the tool's network access → terminate

I9 states the reason: renewal *is* obtaining a new execution authorization, not
the automatic continuation of the old one. A capability issued ten minutes ago
under a policy that has since been tightened is not still authorized; it merely
has not been asked yet.

The same checks run at issue time. Issuing is the first acquisition of
execution authorization, and refusing to issue into a paused engagement is the
same rule as refusing to renew into one.

Scope: this module touches capabilities, approvals, credentials, policy_layers
and engagements. It never reads or writes the Scope Registry or the
Authoritative Metadata Registry, and so runs entirely on the ``cyberorch_app``
connection — the role that holds no write access to either (§5). Whether an
action is *authorized against a target* was settled by the resolvers and OPA
before a capability was ever requested; the broker's question is narrower and
strictly later: is that decision still in force right now.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit

# Revocation reasons. Each names a state the capability depended on that has
# since changed — the dependencies I9 requires renewal to re-check.
POLICY_CHANGED = "policy_version_changed"
APPROVAL_EXPIRED = "approval_expired"
APPROVAL_REVOKED = "approval_revoked"
APPROVAL_MISSING = "approval_not_found"
CREDENTIAL_REVOKED = "credential_revoked"
CREDENTIAL_MISSING = "credential_not_found"
ENGAGEMENT_NOT_ACTIVE = "engagement_not_active"
KILL_SWITCH = "kill_switch_engaged"
LEASE_EXPIRED = "lease_expired"
BUDGET_EXHAUSTED = "budget_exhausted"
ALREADY_REVOKED = "already_revoked"
NOT_FOUND = "capability_not_found"

DEFAULT_LEASE_SECONDS = 60


class CapabilityError(RuntimeError):
    """Raised by :func:`issue_or_raise` when a capability is refused."""


@dataclass(frozen=True)
class Budget:
    """§4.6 budget.

    The control plane owns only the tool-independent dimensions. Anything
    tool-specific lives in ``tool``, whose shape each adapter defines for
    itself — §4.6 says to keep that minimal until there is a second tool to
    generalize from, so MVP-Kernel carries one dimension and no schema.
    """

    max_duration_seconds: int = 600
    max_targets: int = 1
    max_concurrency: int = 1
    tool: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_duration_seconds": self.max_duration_seconds,
            "max_targets": self.max_targets,
            "max_concurrency": self.max_concurrency,
            "tool": dict(self.tool),
        }

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any] | None) -> Budget:
        doc = doc or {}
        return cls(
            max_duration_seconds=int(doc.get("max_duration_seconds", 600)),
            max_targets=int(doc.get("max_targets", 1)),
            max_concurrency=int(doc.get("max_concurrency", 1)),
            tool=dict(doc.get("tool") or {}),
        )


@dataclass(frozen=True)
class Capability:
    capability_id: str
    engagement_id: str
    agent_id: str
    action: str
    constraints: Mapping[str, Any]
    budget: Budget
    requests_used: int
    revoked: bool
    revoked_reason: str | None
    policy_version: int
    approval_id: str | None
    credential_id: str | None
    proposal_id: str | None
    issued_at: datetime
    lease_expires_at: datetime
    last_heartbeat_at: datetime | None
    renewal_count: int

    def is_live(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return not self.revoked and self.lease_expires_at > now

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "engagement_id": self.engagement_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "constraints": dict(self.constraints),
            "budget": self.budget.as_dict(),
            "requests_used": self.requests_used,
            "revoked": self.revoked,
            "revoked_reason": self.revoked_reason,
            "policy_version": self.policy_version,
            "lease_expires_at": self.lease_expires_at.isoformat(),
            "renewal_count": self.renewal_count,
        }


@dataclass(frozen=True)
class IssueResult:
    """The outcome of an issuance request.

    A refusal is returned, not raised. Raising looked natural and was wrong:
    the exception propagates out of the transaction that wrote the audit
    record, and the rollback takes the record of the refusal with it. A refused
    capability that leaves no trace is worse than one that leaves a trace and
    no capability — §5 wants the decision recorded either way.

    :func:`issue_or_raise` is available where a caller genuinely wants the
    exception, and commits the audit record before raising.
    """

    issued: bool
    capability: Capability | None
    reasons: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RenewalResult:
    """The outcome of a heartbeat.

    ``renewed`` is deliberately not the inverse of ``revoked``: a heartbeat
    against a capability that was already revoked neither renews nor revokes
    anything, and callers must treat that as "stop" rather than as "nothing
    happened".
    """

    renewed: bool
    capability: Capability | None
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def must_terminate(self) -> bool:
        return not self.renewed


_SELECT_CAPABILITY = """
    SELECT capability_id, engagement_id, agent_id, action, constraints, budget,
           requests_used, revoked, revoked_reason, policy_version, approval_id,
           credential_id, proposal_id, issued_at, lease_expires_at,
           last_heartbeat_at, renewal_count
    FROM capabilities
    WHERE capability_id = :cid
"""


def current_policy_version(conn: Connection, engagement_id: str) -> int:
    """The version of the policy currently in force for this engagement.

    Defined as the highest id among active policy layers that apply here —
    global layers (engagement_id IS NULL, which includes the Emergency Overlay)
    plus this engagement's own. Publishing any new layer inserts a row with a
    higher id, so the version moves and every outstanding capability is
    re-checked against it on its next heartbeat.

    Deactivating a layer does not move the version, and that is sound rather
    than an oversight: removing a layer can only widen the effective policy
    (allow lists intersect, deny lists union, rate limits take the minimum), and
    I9 is about a capability outliving a *tightening*. A widening leaves an
    existing capability no more permissive than it already was.
    """
    return conn.execute(
        text("""
            SELECT coalesce(max(id), 0) FROM policy_layers
            WHERE active IS TRUE
              AND (engagement_id IS NULL OR engagement_id = :eid)
        """),
        {"eid": engagement_id},
    ).scalar_one()


def check_preconditions(
    conn: Connection,
    *,
    engagement_id: str,
    approval_id: str | None,
    credential_id: str | None,
    policy_version: int | None = None,
) -> tuple[str, ...]:
    """Re-check every state a capability depends on (§4.6).

    Returns the reasons that failed, empty when everything holds. Used by both
    issue and renewal, because "may this start" and "may this continue" are the
    same question asked at different times — writing them as two lists is how
    they drift apart.

    All reasons are collected rather than returning on the first failure: the
    audit record should say everything that was wrong, not just whichever check
    happened to run first.
    """
    reasons: list[str] = []

    engagement = conn.execute(
        text("SELECT status, kill_switch_engaged FROM engagements "
             "WHERE engagement_id = :eid"),
        {"eid": engagement_id},
    ).mappings().one_or_none()

    if engagement is None:
        # RLS also lands here for another engagement's id: it does not exist
        # from in here, and that is the correct answer either way.
        reasons.append(ENGAGEMENT_NOT_ACTIVE)
    else:
        if engagement["kill_switch_engaged"]:
            reasons.append(KILL_SWITCH)
        if engagement["status"] != "active":
            reasons.append(ENGAGEMENT_NOT_ACTIVE)

    if approval_id is not None:
        approval = conn.execute(
            text("SELECT valid_until, revoked FROM approvals WHERE approval_id = :aid"),
            {"aid": approval_id},
        ).mappings().one_or_none()
        if approval is None:
            reasons.append(APPROVAL_MISSING)
        else:
            if approval["revoked"]:
                reasons.append(APPROVAL_REVOKED)
            # §4.7: an approval granted a month ago must not back today's
            # action. The window is checked on every renewal, so a capability
            # cannot outlive the approval that justified it.
            if approval["valid_until"] <= datetime.now(UTC):
                reasons.append(APPROVAL_EXPIRED)

    if credential_id is not None:
        credential = conn.execute(
            text("SELECT revoked FROM credentials WHERE credential_id = :cid"),
            {"cid": credential_id},
        ).mappings().one_or_none()
        if credential is None:
            reasons.append(CREDENTIAL_MISSING)
        elif credential["revoked"]:
            reasons.append(CREDENTIAL_REVOKED)

    if policy_version is not None:
        if current_policy_version(conn, engagement_id) != policy_version:
            reasons.append(POLICY_CHANGED)

    return tuple(reasons)


def issue_capability(
    conn: Connection,
    *,
    engagement_id: str,
    capability_id: str,
    agent_id: str,
    action: str,
    actor: str,
    constraints: Mapping[str, Any] | None = None,
    budget: Budget | None = None,
    ttl_seconds: int = DEFAULT_LEASE_SECONDS,
    approval_id: str | None = None,
    credential_id: str | None = None,
    proposal_id: str | None = None,
) -> IssueResult:
    """Issue a capability, or refuse (§4.6).

    The policy version in force is recorded on the capability so renewal has
    something to compare against. Nothing else captures it: the merged policy
    is computed per decision and not stored, so without this the "has policy
    changed" question would have no baseline.
    """
    budget = budget or Budget()

    reasons = check_preconditions(
        conn, engagement_id=engagement_id,
        approval_id=approval_id, credential_id=credential_id,
    )
    if reasons:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="capability.refused", subject_type="capability",
            subject_id=capability_id, decision="DENY", reasons=reasons,
            payload={"action": action, "agent_id": agent_id},
        )
        return IssueResult(False, None, reasons)

    policy_version = current_policy_version(conn, engagement_id)
    # The lease never outlives the budget: max_duration_seconds bounds the
    # capability's whole life, not each individual lease window.
    lease_seconds = min(ttl_seconds, budget.max_duration_seconds)

    row = conn.execute(
        text("""
            INSERT INTO capabilities (capability_id, engagement_id, agent_id,
                proposal_id, action, constraints, budget, policy_version,
                approval_id, credential_id, lease_expires_at)
            VALUES (:cid, :eid, :agent, :pid, :action, CAST(:constraints AS jsonb),
                    CAST(:budget AS jsonb), :pver, :aid, :crid,
                    now() + make_interval(secs => :lease))
            RETURNING capability_id, engagement_id, agent_id, action, constraints,
                      budget, requests_used, revoked, revoked_reason, policy_version,
                      approval_id, credential_id, proposal_id, issued_at,
                      lease_expires_at, last_heartbeat_at, renewal_count
        """),
        {
            "cid": capability_id, "eid": engagement_id, "agent": agent_id,
            "pid": proposal_id, "action": action,
            "constraints": _json(constraints or {}), "budget": _json(budget.as_dict()),
            "pver": policy_version, "aid": approval_id, "crid": credential_id,
            "lease": lease_seconds,
        },
    ).mappings().one()

    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="capability.issued", subject_type="capability",
        subject_id=capability_id, decision="ALLOW",
        payload={
            "action": action, "agent_id": agent_id, "policy_version": policy_version,
            "budget": budget.as_dict(), "lease_seconds": lease_seconds,
            "approval_id": approval_id, "credential_id": credential_id,
        },
    )
    return IssueResult(True, _to_capability(row))


def issue_or_raise(conn: Connection, **kwargs) -> Capability:
    """Issue, raising :class:`CapabilityError` on refusal.

    For callers that treat a refusal as exceptional. The audit record is
    written by :func:`issue_capability` before this raises, but note that the
    exception will still roll back the surrounding transaction unless the
    caller commits or handles it -- prefer :func:`issue_capability` and check
    ``issued``.
    """
    result = issue_capability(conn, **kwargs)
    if not result.issued:
        raise CapabilityError(
            f"capability refused: {', '.join(result.reasons)}"
        )
    return result.capability


def renew_capability(
    conn: Connection,
    *,
    engagement_id: str,
    capability_id: str,
    actor: str,
    ttl_seconds: int = DEFAULT_LEASE_SECONDS,
) -> RenewalResult:
    """Process a heartbeat: re-authorize, then extend — or revoke (§4.6, I9).

    The row is locked for the duration so a renewal cannot race a revocation
    and win.
    """
    row = conn.execute(
        text(_SELECT_CAPABILITY + " FOR UPDATE"), {"cid": capability_id}
    ).mappings().one_or_none()

    if row is None:
        return RenewalResult(False, None, (NOT_FOUND,))

    capability = _to_capability(row)

    if capability.revoked:
        # Not an error, and emphatically not a renewal. A revoked capability
        # stays revoked; there is no path back (I9).
        return RenewalResult(False, capability, (ALREADY_REVOKED,))

    now = datetime.now(UTC)
    reasons: list[str] = []

    # A heartbeat arriving after the lease lapsed is not a renewal request, it
    # is evidence something went wrong. §4.6 treats a missing heartbeat as an
    # anomaly worth terminating over, so a late one cannot resurrect the lease.
    if capability.lease_expires_at <= now:
        reasons.append(LEASE_EXPIRED)

    reasons.extend(check_preconditions(
        conn,
        engagement_id=engagement_id,
        approval_id=capability.approval_id,
        credential_id=capability.credential_id,
        policy_version=capability.policy_version,
    ))

    if reasons:
        revoked = _revoke(
            conn, engagement_id=engagement_id, capability_id=capability_id,
            reasons=tuple(reasons), actor=actor, event="capability.revoked_on_renewal",
        )
        return RenewalResult(False, revoked, tuple(reasons))

    # The whole-life budget still binds: renewal may extend the lease up to
    # issued_at + max_duration_seconds and no further, so an agent cannot
    # heartbeat its way past the budget one window at a time.
    deadline = capability.issued_at + timedelta(
        seconds=capability.budget.max_duration_seconds
    )
    new_expiry = min(now + timedelta(seconds=ttl_seconds), deadline)
    if new_expiry <= now:
        revoked = _revoke(
            conn, engagement_id=engagement_id, capability_id=capability_id,
            reasons=(BUDGET_EXHAUSTED,), actor=actor,
            event="capability.revoked_on_renewal",
        )
        return RenewalResult(False, revoked, (BUDGET_EXHAUSTED,))

    renewed = conn.execute(
        text("""
            UPDATE capabilities
            SET lease_expires_at = :expiry,
                last_heartbeat_at = now(),
                renewal_count = renewal_count + 1
            WHERE capability_id = :cid AND revoked IS FALSE
            RETURNING capability_id, engagement_id, agent_id, action, constraints,
                      budget, requests_used, revoked, revoked_reason, policy_version,
                      approval_id, credential_id, proposal_id, issued_at,
                      lease_expires_at, last_heartbeat_at, renewal_count
        """),
        {"cid": capability_id, "expiry": new_expiry},
    ).mappings().one()

    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="capability.renewed", subject_type="capability",
        subject_id=capability_id, decision="ALLOW",
        payload={
            "renewal_count": renewed["renewal_count"],
            "lease_expires_at": new_expiry.isoformat(),
            "policy_version": capability.policy_version,
        },
    )
    return RenewalResult(True, _to_capability(renewed))


def revoke_capability(
    conn: Connection, *, engagement_id: str, capability_id: str, reason: str, actor: str
) -> Capability | None:
    """Revoke explicitly (kill switch, operator action, credential cascade)."""
    return _revoke(
        conn, engagement_id=engagement_id, capability_id=capability_id,
        reasons=(reason,), actor=actor, event="capability.revoked",
    )


def revoke_all_for_engagement(
    conn: Connection, *, engagement_id: str, reason: str, actor: str
) -> list[str]:
    """Revoke every live capability in an engagement.

    §1.3.2 asks for a revocation cascade: when a credential is pulled or the
    kill switch trips, capabilities already issued must stop, not merely fail
    their next heartbeat. Renewal is the backstop; this is the immediate path.
    """
    rows = conn.execute(
        text("""
            UPDATE capabilities
            SET revoked = TRUE, revoked_reason = :reason, revoked_at = now()
            WHERE engagement_id = :eid AND revoked IS FALSE
            RETURNING capability_id
        """),
        {"eid": engagement_id, "reason": reason},
    ).scalars().all()

    for capability_id in rows:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="capability.revoked", subject_type="capability",
            subject_id=capability_id, decision="DENY", reasons=(reason,),
            payload={"cascade": True},
        )
    return list(rows)


def consume_request(
    conn: Connection, *, capability_id: str, max_requests: int
) -> bool:
    """Atomic check-and-increment against a tool-specific request budget (§8.5).

    Written as a single conditional UPDATE rather than a read followed by a
    write: two concurrent requests that both read ``requests_used = 2`` against
    a limit of 3 would both consider themselves within budget and both proceed.
    The predicate and the increment have to be one statement.
    """
    updated = conn.execute(
        text("""
            UPDATE capabilities SET requests_used = requests_used + 1
            WHERE capability_id = :cid
              AND revoked IS FALSE
              AND lease_expires_at > now()
              AND requests_used < :maximum
            RETURNING requests_used
        """),
        {"cid": capability_id, "maximum": max_requests},
    ).scalar_one_or_none()
    return updated is not None


def get_capability(conn: Connection, capability_id: str) -> Capability | None:
    row = conn.execute(
        text(_SELECT_CAPABILITY), {"cid": capability_id}
    ).mappings().one_or_none()
    return _to_capability(row) if row else None


def _revoke(
    conn: Connection, *, engagement_id: str, capability_id: str,
    reasons: tuple[str, ...], actor: str, event: str,
) -> Capability | None:
    """Mark revoked. Idempotent: the first reason recorded is the one kept."""
    row = conn.execute(
        text("""
            UPDATE capabilities
            SET revoked = TRUE,
                revoked_reason = coalesce(revoked_reason, :reason),
                revoked_at = coalesce(revoked_at, now())
            WHERE capability_id = :cid
            RETURNING capability_id, engagement_id, agent_id, action, constraints,
                      budget, requests_used, revoked, revoked_reason, policy_version,
                      approval_id, credential_id, proposal_id, issued_at,
                      lease_expires_at, last_heartbeat_at, renewal_count
        """),
        {"cid": capability_id, "reason": ",".join(reasons)},
    ).mappings().one_or_none()

    if row is None:
        return None

    record_audit(
        engagement_id=engagement_id, actor=actor, event_type=event,
        subject_type="capability", subject_id=capability_id, decision="DENY",
        reasons=reasons, payload={"action": row["action"]},
    )
    return _to_capability(row)


def _to_capability(row) -> Capability:
    return Capability(
        capability_id=row["capability_id"],
        engagement_id=row["engagement_id"],
        agent_id=row["agent_id"],
        action=row["action"],
        constraints=row["constraints"] or {},
        budget=Budget.from_dict(row["budget"]),
        requests_used=row["requests_used"],
        revoked=row["revoked"],
        revoked_reason=row["revoked_reason"],
        policy_version=row["policy_version"],
        approval_id=row["approval_id"],
        credential_id=row["credential_id"],
        proposal_id=row["proposal_id"],
        issued_at=row["issued_at"],
        lease_expires_at=row["lease_expires_at"],
        last_heartbeat_at=row["last_heartbeat_at"],
        renewal_count=row["renewal_count"],
    )


def _json(value: Mapping[str, Any]) -> str:
    import json

    return json.dumps(dict(value), default=str, sort_keys=True)
