"""Human approval — the operator surface for HUMAN_APPROVAL proposals (§4.7, D24).

The DEFERRED item recorded before D10.5 as "experience, not a security gap, do
it in Phase 1". The three-role stage (D10–D22) drove a real model into the
HUMAN_APPROVAL branch repeatedly — D11's escalation-by-narration, the D17
Supervisor pressure arm's `blocked` — so the queue is genuinely triggered, and
until now the only way to see or clear it was raw SQL. This is the same
operational gap D11-6 was: the next person has no better tool than the last.

This module is the read/decide surface. Five constraints bind it and are not
negotiable:

1. **OPA owns "ask a human", not this code.** A proposal is here only because
   ``propose_action`` recorded ``decision = 'HUMAN_APPROVAL'``. Nothing here adds
   a risk judgement of its own about what to surface; it lists what OPA already
   flagged and nothing else.
2. **The approval object stays §4.7-structured.** Granting writes a full
   ``approvals`` row — ``action_class`` / ``resource`` / ``constraints`` /
   ``valid_until`` / ``approved_by`` / ``approved_scope`` — and ``approved_scope``
   is chosen from §4.7's set (``this_proposal_only`` / ``this_task`` /
   ``this_resource``). There is no bare "approve everything".
3. **The decision is audited; the viewing is not.** Listing is read-only and
   writes nothing (like D14's `list_effective_policy_layers`). Granting and
   denying go through the existing ``audit/logger.py`` — who, when, which
   ``approved_scope``, which proposal — no second audit path.
4. **Fail-closed.** A proposal that cannot be re-authorized, or any error, leaves
   the proposal pending and issues nothing. Approval and denial are only ever
   explicit operator actions; nothing here decides by default.
5. **It does not mint capabilities.** Granting creates the Approval object and
   then issues through the *existing* Capability Broker, citing ``approval_id``;
   the broker re-checks everything it always does. Denial issues nothing.

The lease interaction (constraint 5 of the brief) needed no new code: a
HUMAN_APPROVAL proposal never got a capability (``propose_action`` returns before
the broker), so no capability lease or heartbeat touches it, and its
``dispatch_state`` stays ``'queued'`` — not in ``reconcile_stale_dispatches``'s
``IN_FLIGHT`` set — so the stale-dispatch sweep skips it too. A test pins that
"legitimately waiting for a human" is not mistaken for "stuck".
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.canonicalizer.authorization import resolve_authorization
from control_plane.canonicalizer.target import normalize_target
from control_plane.capability.broker import Budget, issue_capability

HUMAN_APPROVAL = "HUMAN_APPROVAL"

#: §4.7's approval scopes, matching the CHECK constraint on ``approvals``.
#: Offered as an explicit choice, never collapsed into a single yes/no.
APPROVED_SCOPES = ("this_proposal_only", "this_task", "this_resource")

#: How long an approval is good for by default. §4.7: an approval must not
#: back an action indefinitely, and the capability issued from it cannot outlive
#: it (the broker re-checks ``valid_until`` on issue and renewal).
DEFAULT_APPROVAL_SECONDS = 3600

#: Matches ``propose_action``'s own default, so an approved proposal is issued
#: with the budget OPA evaluated at proposal time rather than a different one.
_APPROVED_BUDGET_SECONDS = 120


class ApprovalError(RuntimeError):
    """An approval or denial could not proceed. Nothing was issued (fail-closed)."""


@dataclass(frozen=True)
class ApprovalOutcome:
    """The result of granting an approval."""

    approval_id: str
    proposal_id: str
    approved_scope: str
    issued: bool
    capability_id: str | None = None
    reasons: tuple[str, ...] = field(default_factory=tuple)


def list_pending_approvals(
    conn: Connection, *, engagement_id: str, limit: int = 50
) -> list[dict[str, Any]]:
    """Proposals OPA sent to HUMAN_APPROVAL that no human has decided yet.

    Pending = ``decision = 'HUMAN_APPROVAL'`` with no live approval and no
    recorded denial. Read-only and RLS-confined; writes nothing (constraint 3).
    The ``decision_reasons`` are OPA's — this function adds no judgement of its
    own about what belongs in the queue (constraint 1).
    """
    rows = conn.execute(
        text("""
            SELECT proposal_id, task_id, agent_id, action, target,
                   decision_reasons, created_at
            FROM action_proposals p
            WHERE decision = :ha
              AND NOT EXISTS (
                  SELECT 1 FROM approvals a
                  WHERE a.proposal_id = p.proposal_id AND a.revoked IS FALSE)
              AND NOT EXISTS (
                  SELECT 1 FROM audit_log al
                  WHERE al.subject_id = p.proposal_id
                    AND al.event_type = 'approval.denied')
            ORDER BY created_at ASC
            LIMIT :limit
        """),
        {"ha": HUMAN_APPROVAL, "limit": max(0, int(limit))},
    ).mappings().all()
    return [dict(r) for r in rows]


def _load_resolvable(conn: Connection, proposal_id: str) -> dict[str, Any]:
    """Load a proposal that a human may still decide, or refuse (fail-closed).

    Refuses — rather than silently doing nothing — when the proposal is absent
    (RLS also lands here for another engagement's id), is not awaiting approval,
    or has already been approved or denied. Every one of those is a reason not
    to act, and acting anyway is the failure this guards.
    """
    row = conn.execute(
        text("""
            SELECT proposal_id, action, target, "authorization", agent_id,
                   decision, task_id, requested_capability_ttl_seconds
            FROM action_proposals WHERE proposal_id = :pid
        """),
        {"pid": proposal_id},
    ).mappings().one_or_none()
    if row is None:
        raise ApprovalError(f"proposal {proposal_id!r} not found in this engagement")
    if row["decision"] != HUMAN_APPROVAL:
        raise ApprovalError(
            f"proposal {proposal_id!r} is {row['decision']!r}, not awaiting a "
            "human — only OPA-escalated proposals can be approved (constraint 1)"
        )
    if conn.execute(
        text("SELECT 1 FROM approvals WHERE proposal_id = :pid AND revoked IS FALSE"),
        {"pid": proposal_id},
    ).first():
        raise ApprovalError(f"proposal {proposal_id!r} already has a live approval")
    if conn.execute(
        text("SELECT 1 FROM audit_log WHERE subject_id = :pid "
             "AND event_type = 'approval.denied'"),
        {"pid": proposal_id},
    ).first():
        raise ApprovalError(f"proposal {proposal_id!r} was already denied")
    return dict(row)


def grant_approval(
    conn: Connection, *, engagement_id: str, proposal_id: str, approver: str,
    approved_scope: str, valid_for_seconds: int = DEFAULT_APPROVAL_SECONDS,
) -> ApprovalOutcome:
    """Approve an escalated proposal: write the §4.7 object, then issue (§4.7, D24).

    The Approval object is created and the capability is issued through the
    *existing* Capability Broker citing ``approval_id`` (constraint 5) — the
    broker re-checks the engagement, the approval's own validity and the scope
    object before it issues. Before any of that, the authorization is re-resolved
    from the registry; if the scope no longer covers this target (retired,
    withdrawn) the approval is refused and nothing is written (constraint 4).
    """
    if approved_scope not in APPROVED_SCOPES:
        raise ApprovalError(
            f"unknown approved_scope {approved_scope!r}; choose one of "
            f"{APPROVED_SCOPES} (§4.7) — there is no approve-everything"
        )
    if not approver:
        raise ApprovalError("an approval must name who granted it (§4.4)")

    row = _load_resolvable(conn, proposal_id)
    target = normalize_target(dict(row["target"]))
    authorization = dict(row["authorization"])

    # Fail-closed: the human is approving an escalation, not re-authorizing a
    # target the registry no longer covers. Re-resolve and refuse if it moved.
    resolution = resolve_authorization(
        conn, target=target, action=row["action"], authorization=authorization,
    )
    if not resolution.authorized:
        raise ApprovalError(
            f"authorization no longer holds for {proposal_id!r} "
            f"({', '.join(resolution.reasons)}); approval refused (fail-closed)"
        )

    approval_id = f"APPR-{uuid.uuid4().hex[:10]}"
    resource = f"{target.logical_identity.type}:{target.logical_identity.value}"
    stored_target = dict(row["target"])
    constraints = {
        "ports": stored_target.get("ports"),
        "scan_type": stored_target.get("scan_type"),
    }
    valid_until = datetime.now(UTC) + timedelta(seconds=valid_for_seconds)

    conn.execute(
        text("""
            INSERT INTO approvals (approval_id, engagement_id, proposal_id,
                action_class, resource, constraints, valid_until, approved_by,
                approved_scope)
            VALUES (:aid, :eid, :pid, :ac, :res, CAST(:con AS jsonb), :vu, :by, :scope)
        """),
        {"aid": approval_id, "eid": engagement_id, "pid": proposal_id,
         "ac": row["action"], "res": resource,
         "con": json.dumps(constraints, sort_keys=True),
         "vu": valid_until, "by": approver, "scope": approved_scope},
    )
    # Constraint 3: the decision is audited — who, when, which scope, which
    # proposal — through the existing path.
    record_audit(
        engagement_id=engagement_id, actor=approver,
        event_type="approval.granted", subject_type="action_proposal",
        subject_id=proposal_id, decision="APPROVED",
        payload={"approval_id": approval_id, "approved_scope": approved_scope,
                 "valid_until": valid_until.isoformat(),
                 "action_class": row["action"], "resource": resource},
    )

    # Constraint 5: issue through the broker, which records its own
    # capability.issued / capability.refused.
    capability_id = f"CAP-{uuid.uuid4().hex[:10]}"
    issued = issue_capability(
        conn, engagement_id=engagement_id, capability_id=capability_id,
        agent_id=row["agent_id"], action=row["action"], actor=approver,
        constraints={"host": target.logical_identity.value,
                     "ports": stored_target.get("ports", "8080"),
                     "scan_type": stored_target.get("scan_type", "connect")},
        budget=Budget(max_duration_seconds=_APPROVED_BUDGET_SECONDS),
        ttl_seconds=row["requested_capability_ttl_seconds"] or 60,
        approval_id=approval_id, proposal_id=proposal_id,
        scope_object_id=authorization.get("scope_object_id"),
    )
    return ApprovalOutcome(
        approval_id=approval_id, proposal_id=proposal_id,
        approved_scope=approved_scope, issued=issued.issued,
        capability_id=capability_id if issued.issued else None,
        reasons=tuple(issued.reasons),
    )


def deny_approval(
    conn: Connection, *, engagement_id: str, proposal_id: str, denier: str,
    reason: str = "",
) -> None:
    """Decline an escalated proposal. No capability, and the decision is audited.

    The proposal keeps its OPA decision (``HUMAN_APPROVAL`` — the fact that OPA
    escalated it stays true); the human denial is recorded as its own event, and
    that event is what removes it from the pending queue. Nothing is issued.
    """
    if not denier:
        raise ApprovalError("a denial must name who made it (§4.4)")
    _load_resolvable(conn, proposal_id)
    record_audit(
        engagement_id=engagement_id, actor=denier,
        event_type="approval.denied", subject_type="action_proposal",
        subject_id=proposal_id, decision="DENIED",
        reasons=(reason,) if reason else (),
        payload={"proposal_id": proposal_id, "reason": reason,
                 "note": "human declined the escalation; no capability issued"},
    )
