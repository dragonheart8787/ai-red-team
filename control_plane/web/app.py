"""Web console (D29): a read-only dashboard and the §4.7 Approval Resolver.

The browser-facing face of two things that already exist: D24's approval
functions and the read interfaces D17 and D26 built. It adds no decision logic
of its own, and the shape of the module is what keeps that true.

**What this is not.** There is no endpoint that creates a task, submits a
proposal, or invokes a tool, and no free-text field anywhere that reaches a
model. The console reads what the existing query interfaces return and performs
exactly two writes, both of which are D24 calls made with the same arguments the
CLI passes (D29 constraints 1 and 5). ``scripts/approvals.py`` and this module
are two front ends over one implementation; there is no second copy of the
approval logic to drift.

**Who decides to ask a human.** OPA, and only OPA. The queue is whatever
``list_pending_approvals`` returns — proposals OPA marked HUMAN_APPROVAL —
and nothing here re-scores, re-ranks or filters by a risk judgement of its own.
That is D24's binding constraint 1, and changing the interface does not reopen
it (D29 constraint 2).

**Two roles, on purpose** (D29 constraint 4):

* Reads run as ``ui_reader`` (:func:`ui_reader_scope`), which holds SELECT on
  the dashboard's tables and no INSERT anywhere — not even ``audit_log``. A
  defect in a read endpoint of a browser-facing service is therefore a read
  defect.
* Approve and deny run as ``cyberorch_app`` (:func:`engagement_scope`), because
  they must write the §4.7 object, audit the decision, and issue through the
  Capability Broker. That is the D24 path exactly.

**Engagement scope.** Every endpoint names an engagement and opens a connection
pinned to it; RLS does the rest (I4). There is deliberately no "all engagements"
view — see :func:`get_overview` for the reasoning, which is the same reasoning
``query_state``'s docstring gives for having no cross-engagement variant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from control_plane.api.approvals import (
    APPROVED_SCOPES,
    DEFAULT_APPROVAL_SECONDS,
    ApprovalError,
    deny_approval,
    grant_approval,
    list_pending_approvals,
    preview_approval,
)
from control_plane.api.function_api import query_evidence, query_findings, query_state
from control_plane.audit.query import reconstruct_task_history
from control_plane.state.db import engagement_scope, ui_reader_scope

STATIC = Path(__file__).parent / "static"

app = FastAPI(
    title="Cyberorch console",
    description="Read-only engagement dashboard and the §4.7 Approval Resolver.",
)


# ---------------------------------------------------------------------------
# Request bodies — closed shapes, not free text
# ---------------------------------------------------------------------------
# Every field an operator can send is enumerated and typed. There is no
# free-form parameter anywhere in this module, which is what keeps D29
# constraint 1 ("no interface that drives Supervisor/Worker") a property of the
# schema rather than of the handler bodies.

class ApproveBody(BaseModel):
    approver: str = Field(min_length=1)
    approved_scope: str
    valid_for_seconds: int = Field(default=DEFAULT_APPROVAL_SECONDS, gt=0, le=86400)


class DenyBody(BaseModel):
    denier: str = Field(min_length=1)
    reason: str = ""


def _approval_error(exc: ApprovalError) -> HTTPException:
    """D24 refusals are the operator's answer, not a server fault.

    ``_load_resolvable`` refuses a proposal that is absent, not escalated, or
    already decided. Those are all 409s: the request was well-formed and the
    system declined it, and the message says which case it was.
    """
    return HTTPException(status_code=409, detail=str(exc))


# ---------------------------------------------------------------------------
# Reads — ui_reader, SELECT only
# ---------------------------------------------------------------------------

@app.get("/api/engagements/{engagement_id}/overview")
def get_overview(engagement_id: str) -> dict[str, Any]:
    """Engagement state plus the counts the dashboard header shows.

    ``engagement_id`` names the connection's own scope; it does not select which
    engagement to read, because RLS has already decided that. Passing another
    engagement's id yields that engagement's *empty* view rather than its data,
    which is I4 doing its job.

    There is no endpoint that lists engagements, and that is a decision (D29
    constraint 4). ``engagements`` is RLS-scoped like every other table, so a
    connection with no engagement bound matches nothing; showing all of them at
    once would need either a cross-engagement policy or a role that bypasses
    RLS. Both would make this console the first component in the system able to
    see across the I4 boundary, and it would be for convenience. An operator
    watching two engagements opens the console twice.
    """
    with ui_reader_scope(engagement_id) as conn:
        state = query_state(conn, engagement_id=engagement_id)
        findings = query_findings(conn, engagement_id=engagement_id, limit=1000)
        pending = list_pending_approvals(conn, engagement_id=engagement_id, limit=1000)
    return {
        "engagement_id": engagement_id,
        "state": state,
        "counts": {
            "findings": len(findings),
            "pending_approvals": len(pending),
        },
    }


@app.get("/api/engagements/{engagement_id}/findings")
def get_findings(engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """§4.3 findings.

    ``evidence_strength`` and ``verifier_state`` are what the rows carry, and
    what the console displays. There is no confidence number to show: §4.3
    withdrew it, on the grounds that a single figure with no statistical
    calibration is false precision dressed up as certainty.
    """
    with ui_reader_scope(engagement_id) as conn:
        return query_findings(conn, engagement_id=engagement_id, limit=limit)


@app.get("/api/engagements/{engagement_id}/evidence/{evidence_id}")
def get_evidence(engagement_id: str, evidence_id: str) -> dict[str, Any]:
    """The derived view of one piece of evidence.

    ``query_evidence`` returns the derived view and never the raw artifact
    (§4.4), so the raw bytes cannot reach a browser through this route any more
    than they can reach a model.
    """
    with ui_reader_scope(engagement_id) as conn:
        row = query_evidence(conn, evidence_id=evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return row


@app.get("/api/engagements/{engagement_id}/tasks/{task_id}/history")
def get_task_history(engagement_id: str, task_id: str) -> dict[str, Any]:
    """The task's decision history, via D26's aggregator.

    ``reconstruct_task_history`` calls ``reconstruct_decision`` once per
    proposal, so the console shows the same reconstruction the CLI and the audit
    report show rather than a third rendering of the audit log.
    """
    with ui_reader_scope(engagement_id) as conn:
        return reconstruct_task_history(conn, task_id=task_id).as_dict()


@app.get("/api/engagements/{engagement_id}/approvals")
def get_pending(engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """The pending-approval queue, exactly as OPA left it (D24 constraint 1)."""
    with ui_reader_scope(engagement_id) as conn:
        return list_pending_approvals(conn, engagement_id=engagement_id, limit=limit)


@app.get("/api/engagements/{engagement_id}/approvals/{proposal_id}/preview")
def get_approval_preview(
    engagement_id: str, proposal_id: str,
    valid_for_seconds: int = DEFAULT_APPROVAL_SECONDS,
) -> dict[str, Any]:
    """What approving would write — the §4.7 object, before it is written.

    D29 constraint 3: the operator sees action_class, resource, constraints and
    valid_until, and chooses approved_scope explicitly. The fields come from the
    same derivation ``grant_approval`` uses, so what is shown is what is stored.
    """
    with ui_reader_scope(engagement_id) as conn:
        try:
            return preview_approval(
                conn, proposal_id=proposal_id, valid_for_seconds=valid_for_seconds
            )
        except ApprovalError as exc:
            raise _approval_error(exc) from exc


# ---------------------------------------------------------------------------
# The two writes — cyberorch_app, through D24
# ---------------------------------------------------------------------------

@app.post("/api/engagements/{engagement_id}/approvals/{proposal_id}/approve")
def post_approve(
    engagement_id: str, proposal_id: str, body: ApproveBody
) -> dict[str, Any]:
    """Approve one escalated proposal (§4.7).

    A thin call into D24. Note what is *not* here: no risk check, no override,
    no "approve all", and no branch that decides whether a human was needed —
    ``grant_approval`` refuses anything OPA did not escalate, and re-resolves
    authorization before it writes. The audit record is written by that function
    on the shared path, so a console approval and a CLI approval are the same
    row (D29 constraint 5).
    """
    if body.approved_scope not in APPROVED_SCOPES:
        raise HTTPException(
            status_code=422,
            detail=(f"approved_scope must be one of {list(APPROVED_SCOPES)} "
                    "(§4.7) — there is no approve-everything"),
        )
    with engagement_scope(engagement_id) as conn:
        try:
            outcome = grant_approval(
                conn, engagement_id=engagement_id, proposal_id=proposal_id,
                approver=body.approver, approved_scope=body.approved_scope,
                valid_for_seconds=body.valid_for_seconds,
            )
        except ApprovalError as exc:
            raise _approval_error(exc) from exc
    return {
        "approval_id": outcome.approval_id,
        "proposal_id": outcome.proposal_id,
        "approved_scope": outcome.approved_scope,
        "issued": outcome.issued,
        "capability_id": outcome.capability_id,
        "reasons": list(outcome.reasons),
    }


@app.post("/api/engagements/{engagement_id}/approvals/{proposal_id}/deny")
def post_deny(engagement_id: str, proposal_id: str, body: DenyBody) -> dict[str, str]:
    """Decline one escalated proposal. No capability, and the decision is audited."""
    with engagement_scope(engagement_id) as conn:
        try:
            deny_approval(
                conn, engagement_id=engagement_id, proposal_id=proposal_id,
                denier=body.denier, reason=body.reason,
            )
        except ApprovalError as exc:
            raise _approval_error(exc) from exc
    return {"proposal_id": proposal_id, "decision": "DENIED"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")
