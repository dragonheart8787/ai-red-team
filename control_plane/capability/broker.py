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
and engagements, and reads one row of the Scope Registry by id. It never touches
the Authoritative Metadata Registry and never writes either registry, so it runs
entirely on the ``cyberorch_app`` connection — the role that holds SELECT and no
more on both (§5).

That one registry read needs stating precisely, because the line it sits on is
easy to erase. The broker does **not** re-run the Authorization Resolver and does
**not** compare a target against a scope object. It asks a strictly narrower
question about a decision already made: the scope object that authorized this
capability — is it still active, and does it still permit this action? That is
the same kind of question as "has this credential been revoked", and it is
answered the same way, by a single lookup on a recorded id.

The distinction matters because re-resolving would mean deciding authorization
here, which belongs upstream in the resolvers and OPA: two places deciding the
same thing is how they come to disagree. Checking that an existing decision's
premises still hold is not deciding. ``test_broker_reads_scope_only_as_a_liveness
_check`` pins the difference structurally.

DEFERRED — heartbeat_required is declared but not enforced
----------------------------------------------------------
``capabilities.heartbeat_required`` exists in the schema, defaults to TRUE, and
is read by nothing. §4.6's capability object carries the field, so the column
matches the design; what is missing is the enforcement it implies — a sweeper
that revokes a capability whose heartbeat has stopped arriving.

Not implemented for MVP-Kernel, and the column is kept rather than dropped
because the gap is in behaviour, not in the schema. Today a capability with no
heartbeat simply lapses when its lease expires, which is safe but slower than
§4.6 intends: the lease is the deadline rather than the heartbeat interval.

Two things have to exist first, and neither does yet. There is no scheduler in
MVP-Kernel — ``reconcile_stale_dispatches`` is called by tests, not by anything
periodic — so a sweeper would have nothing to run it. And ``last_heartbeat_at``
is only meaningful once an agent heartbeats on its own schedule rather than
when a test calls ``renew_capability``; with a real worker loop the expected
interval becomes definable, and until then any staleness threshold would be a
number invented to make a test pass.

When both exist: sweep for ``heartbeat_required AND last_heartbeat_at <
now() - interval``, revoke with a distinct reason, and treat a missed heartbeat
as the anomaly §4.6 calls it rather than as an expiry.
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
SCOPE_OBJECT_DEACTIVATED = "scope_object_deactivated"
SCOPE_OBJECT_MISSING = "scope_object_not_found"
SCOPE_ACTION_WITHDRAWN = "scope_action_no_longer_allowed"
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
    scope_object_id: str | None
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
           credential_id, scope_object_id, proposal_id, issued_at,
           lease_expires_at, last_heartbeat_at, renewal_count
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

    Deactivating a layer *does* move the version, downward, because the maximum
    is taken over active rows only. An earlier version of this docstring claimed
    the opposite — that deactivation left the version alone, and that this was
    sound because removing a layer can only widen. The reasoning was fine and
    the claim was false: retiring the highest-id layer drops the maximum to the
    next one, and every outstanding capability is then revoked on its next
    heartbeat for POLICY_CHANGED.

    That over-revokes on a widening, which is the harmless direction to be wrong
    in, so it is left as it stands rather than papered over with a monotonic
    counter that would make the version stop describing which layers are live.
    ``test_deactivating_a_layer_widens_and_revokes_nothing`` pins the real
    behaviour so the next reader is not misled the way this comment was.

    The version never repeats: ids come from a sequence and nothing reactivates
    a layer, so a decreased maximum is still a value no earlier capability
    recorded.
    """
    return conn.execute(
        text("""
            SELECT coalesce(max(id), 0) FROM policy_layers
            WHERE active IS TRUE
              AND (engagement_id IS NULL OR engagement_id = :eid)
        """),
        {"eid": engagement_id},
    ).scalar_one()


def _check_scope_object_still_live(
    conn: Connection, *, scope_object_id: str, action: str
) -> tuple[str, ...]:
    """Is the scope object that authorized this capability still standing?

    A liveness check on a recorded fact, not an authorization decision. It reads
    one row by id and asks two things of it: is it still active, and does it
    still permit this action. It does not look at the target, does not call the
    Authorization Resolver, and cannot authorize anything — the only outcomes
    are "no objection" and a reason to revoke.

    Target containment is deliberately not re-checked. A scope object's ``value``
    is immutable in practice (retirement is a soft delete, and a changed CIDR is
    a new object), so re-deriving containment would re-run work the resolver
    already did and, worse, put a second implementation of ``scope_covers_target``
    where it could drift from the first.
    """
    row = conn.execute(
        text("SELECT active, allowed_actions FROM scope_registry "
             "WHERE scope_object_id = :sid"),
        {"sid": scope_object_id},
    ).mappings().one_or_none()

    if row is None:
        # Also where RLS lands for another engagement's scope object: from in
        # here it does not exist, and a capability cannot rest on it either way.
        return (SCOPE_OBJECT_MISSING,)
    if not row["active"]:
        return (SCOPE_OBJECT_DEACTIVATED,)
    # Membership, not pattern matching. Narrowing allowed_actions after issue is
    # a withdrawal of exactly this capability's authorization; the wildcard
    # semantics that decided the original grant live in the resolver.
    if action not in row["allowed_actions"]:
        return (SCOPE_ACTION_WITHDRAWN,)
    return ()


def check_preconditions(
    conn: Connection,
    *,
    engagement_id: str,
    approval_id: str | None,
    credential_id: str | None,
    policy_version: int | None = None,
    scope_object_id: str | None = None,
    action: str | None = None,
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

    # A capability issued before scope_object_id existed carries NULL, which is
    # unknown rather than authorized: there is no recorded premise to re-check,
    # so this check abstains instead of inventing a verdict either way.
    if scope_object_id is not None and action is not None:
        reasons.extend(_check_scope_object_still_live(
            conn, scope_object_id=scope_object_id, action=action,
        ))

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
    scope_object_id: str | None = None,
) -> IssueResult:
    """Issue a capability, or refuse (§4.6).

    The policy version in force is recorded on the capability so renewal has
    something to compare against. Nothing else captures it: the merged policy
    is computed per decision and not stored, so without this the "has policy
    changed" question would have no baseline.

    ``scope_object_id`` serves the same purpose for authorization (I8): the
    caller has already had the resolver authorize this target against that scope
    object, and recording which one lets every later heartbeat confirm the
    premise still holds.
    """
    budget = budget or Budget()

    reasons = check_preconditions(
        conn, engagement_id=engagement_id,
        approval_id=approval_id, credential_id=credential_id,
        scope_object_id=scope_object_id, action=action,
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
                approval_id, credential_id, scope_object_id, lease_expires_at)
            VALUES (:cid, :eid, :agent, :pid, :action, CAST(:constraints AS jsonb),
                    CAST(:budget AS jsonb), :pver, :aid, :crid, :sid,
                    now() + make_interval(secs => :lease))
            RETURNING capability_id, engagement_id, agent_id, action, constraints,
                      budget, requests_used, revoked, revoked_reason, policy_version,
                      approval_id, credential_id, scope_object_id, proposal_id,
                      issued_at, lease_expires_at, last_heartbeat_at, renewal_count
        """),
        {
            "cid": capability_id, "eid": engagement_id, "agent": agent_id,
            "pid": proposal_id, "action": action,
            "constraints": _json(constraints or {}), "budget": _json(budget.as_dict()),
            "pver": policy_version, "aid": approval_id, "crid": credential_id,
            "sid": scope_object_id, "lease": lease_seconds,
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
        # The scope object recorded at issue, not one supplied by the caller: a
        # heartbeat that could nominate its own scope object would be able to
        # renew against whichever one happens to still be active.
        scope_object_id=capability.scope_object_id,
        action=capability.action,
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
                      approval_id, credential_id, scope_object_id, proposal_id,
                      issued_at, lease_expires_at, last_heartbeat_at, renewal_count
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
    """Revoke one capability explicitly (operator action)."""
    return _revoke(
        conn, engagement_id=engagement_id, capability_id=capability_id,
        reasons=(reason,), actor=actor, event="capability.revoked",
    )


def _revoke_where(
    conn: Connection, *, engagement_id: str, predicate: str,
    params: Mapping[str, Any], reason: str, actor: str, payload: Mapping[str, Any],
) -> list[str]:
    """Revoke every live capability matching a predicate, and audit each one.

    One conditional UPDATE rather than select-then-update: a capability issued
    between the two would slip through the gap, and the gap is exactly when a
    revocation cascade is running.
    """
    rows = conn.execute(
        text(f"""
            UPDATE capabilities
            SET revoked = TRUE, revoked_reason = coalesce(revoked_reason, :reason),
                revoked_at = coalesce(revoked_at, now())
            WHERE engagement_id = :eid AND revoked IS FALSE AND {predicate}
            RETURNING capability_id
        """),
        {**params, "eid": engagement_id, "reason": reason},
    ).scalars().all()

    for capability_id in rows:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="capability.revoked", subject_type="capability",
            subject_id=capability_id, decision="DENY", reasons=(reason,),
            payload={"cascade": True, **payload},
        )
    return list(rows)


def revoke_capabilities_for_scope_object(
    conn: Connection, *, engagement_id: str, scope_object_id: str, actor: str,
    reason: str = SCOPE_OBJECT_DEACTIVATED,
) -> list[str]:
    """Revoke exactly the capabilities one scope object authorized (I1).

    Precise by construction. Revoking the whole engagement would also be
    fail-closed, and would be wrong: a control that stops unrelated work is one
    operators learn to route around, and the audit trail would then blame a
    scope retirement for capabilities it had nothing to do with.

    Capabilities with a NULL scope_object_id are not matched. They predate the
    column and have no recorded link to this scope object; revoking them here
    would be a guess, and ``check_preconditions`` abstains on them for the same
    reason.
    """
    return _revoke_where(
        conn, engagement_id=engagement_id,
        predicate="scope_object_id = :sid", params={"sid": scope_object_id},
        reason=reason, actor=actor, payload={"scope_object_id": scope_object_id},
    )


def revoke_capabilities_for_credential(
    conn: Connection, *, engagement_id: str, credential_id: str, actor: str,
    reason: str = CREDENTIAL_REVOKED,
) -> list[str]:
    """Revoke exactly the capabilities holding one credential (§1.3.2, I9)."""
    return _revoke_where(
        conn, engagement_id=engagement_id,
        predicate="credential_id = :crid", params={"crid": credential_id},
        reason=reason, actor=actor, payload={"credential_id": credential_id},
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
    conn: Connection, *, capability_id: str, max_requests: int,
    engagement_id: str | None = None, actor: str = "tool_gateway",
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

    # Refusals are audited; successful consumption is not. A refusal is a
    # decision — the budget stopped something — while a successful request is
    # bookkeeping already visible in capabilities.requests_used and in the
    # tool_run record. Auditing every one would bury the decisions among them,
    # and an audit log nobody can search is one nobody reads.
    if updated is None and engagement_id:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="capability.budget_exhausted", subject_type="capability",
            subject_id=capability_id, decision="DENY", reasons=(BUDGET_EXHAUSTED,),
            payload={"max_requests": max_requests},
        )
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
                      approval_id, credential_id, scope_object_id, proposal_id,
                      issued_at, lease_expires_at, last_heartbeat_at, renewal_count
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
        scope_object_id=row["scope_object_id"],
        proposal_id=row["proposal_id"],
        issued_at=row["issued_at"],
        lease_expires_at=row["lease_expires_at"],
        last_heartbeat_at=row["last_heartbeat_at"],
        renewal_count=row["renewal_count"],
    )


def _json(value: Mapping[str, Any]) -> str:
    import json

    return json.dumps(dict(value), default=str, sort_keys=True)
