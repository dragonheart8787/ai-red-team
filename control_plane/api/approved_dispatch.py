"""Dispatch an approved proposal: issue the capability at the moment of use (D58-8, D61).

``grant_approval`` records one fact -- *a human approved this proposal* -- and stops. It issues no
capability. Until D61 it did (a 60-second one), and nothing in ``control_plane/`` or ``agents/``
ever dispatched it: the capability simply aged out while the proposal sat approved. A capability's
lease is anchored to the transaction that issues it, so issuing at grant time guaranteed the lease
was spent on the human's latency (D58: 3 s TTL + a 4 s reviewer = born expired). The two problems
have one cause -- the capability was issued when the decision was made, not when it was used.

:func:`dispatch_approved` is the "approved, awaiting dispatch" path. It is an explicit call, not a
scheduler: whoever decides *when* approved work runs (the production orchestrator, D58-1..4)
calls it for one proposal. It then:

1. reads the approved proposal back from committed rows (the proposal, the approval, the facts the
   decision stage established) -- nothing is carried in memory from the grant;
2. asks the broker **now** -- engagement active, kill switch, approval live and unexpired, scope
   object still standing, policy unchanged since the decision (``expected_policy_version``) --
   and issues the capability in that same transaction as the ``approved -> capability_issued``
   transition;
3. dispatches immediately through the same dispatch functions the ALLOW path uses.

Steps 2 and 3 are **the D60 stages, not a copy of them**: this module builds a ``_Run`` and hands
it to ``function_api._drive``, whose ``_issue`` takes the conditional UPDATE and ``_dispatch``
takes the next one. There is no second transaction handler to drift from the first.

What is *not* here: the approved capability is credential-less, because an approval names no
credential (D58 report §5). ``ad.collect`` therefore still cannot run on this path -- see
:func:`dispatch_approved` and ACCEPTANCE 5.56. Choosing a credential for an approved proposal is
D58-15's question and is not answered by threading a caller-supplied id through here.

The state a proposal sits in between the grant and this call is ``approved`` (``stages.APPROVED``),
visible with :func:`list_approved_awaiting_dispatch`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Connection, text

from agents.base_agent import ProposedAction
from control_plane.api import function_api as fa
from control_plane.api.approvals import _APPROVED_BUDGET_SECONDS, approval_fields
from control_plane.canonicalizer.target import normalize_target
from control_plane.capability.broker import Budget
from control_plane.orchestrator import stages
from control_plane.state.db import engagement_scope


def list_approved_awaiting_dispatch(
    conn: Connection, *, engagement_id: str, older_than_seconds: float | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Proposals a human approved that nothing has dispatched yet, oldest first (D61).

    The externally queryable form of the ``approved`` stage, in the sense D60's stages are:
    committed state, readable without running anything. It is also the interface D58-9's
    reconciler will use -- ``older_than_seconds`` selects the ones that have waited too long, and
    ``approval_live`` says whether the approval itself has since expired or been revoked (in which
    case a dispatch attempt would be refused and the proposal needs a human, not a retry).

    Read-only, RLS-confined, writes nothing. It does not decide that anything is *stuck*: a
    proposal can be approved and legitimately waiting its turn. Deciding what "too long" means is
    the caller's.
    """
    rows = conn.execute(
        text("""
            SELECT p.proposal_id, p.task_id, p.agent_id, p.action,
                   p.target ->> 'normalized' AS target, p.stage_detail AS approval_id,
                   p.stage_updated_at AS approved_at,
                   EXTRACT(EPOCH FROM (now() - p.stage_updated_at)) AS waiting_seconds,
                   a.approved_by, a.approved_scope, a.valid_until,
                   (a.approval_id IS NOT NULL AND a.revoked IS FALSE
                        AND a.valid_until > now()) AS approval_live
            FROM action_proposals p
            LEFT JOIN approvals a ON a.approval_id = p.stage_detail
            WHERE p.pipeline_stage = :approved
              AND (CAST(:older AS double precision) IS NULL
                   OR p.stage_updated_at <= now() - make_interval(secs => :older))
            ORDER BY p.stage_updated_at ASC, p.proposal_id ASC
            LIMIT :limit
        """),
        {"approved": stages.APPROVED, "older": older_than_seconds,
         "limit": max(0, int(limit))},
    ).mappings().all()
    return [dict(r) for r in rows]


def dispatch_approved(
    *,
    engagement_id: str,
    proposal_id: str,
    actor: str = "orchestrator",
    sandbox=None,
    network_allowlist: Sequence[str] | None = None,
    execution_context: Mapping[str, Any] | None = None,
    proxy_url: str | None = None,
    ca_cert_pem: str | None = None,
    proxy_cert_spki: str | None = None,
) -> fa.ActionOutcome:
    """Issue the capability for an approved proposal now, and dispatch it.

    Takes no connection, like :func:`~control_plane.api.function_api.propose_action`: the stages
    it drives open their own short transactions. It does not choose *which* proposal or *when*;
    it is called for one.

    * ``approved``                 -- issued and dispatched; the outcome is the run's.
    * ``awaiting_approval``        -- refused (``not_approved``): a human has not said yes.
    * any later or terminal stage  -- reported from the committed rows, **not re-run**. Calling
      this twice dispatches once: the first call's ``approved -> capability_issued`` transition is
      a conditional UPDATE, so the second finds the stage moved on. A proposal found
      ``dispatching`` is the reconciler's, as in ``propose_action``.
    * unknown to this engagement   -- refused (``unknown_proposal``); RLS makes another
      engagement's id the same.

    If the broker refuses (approval expired or revoked, kill switch, engagement no longer active,
    scope object withdrawn, policy changed since the decision) the proposal **closes** with
    ``capability_refused:<reasons>`` and the outcome is a DENY -- the same handling as an ALLOW
    whose issue is refused. Fail-closed: a refused approval is not retried by a side door; the
    operator re-proposes.

    No ``credential_id``: the approved capability carries none, so ``ad.collect`` is refused by
    ``dispatch_collection`` (``unbuildable_plan``) exactly as before. See the module docstring.
    """
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("""
                SELECT proposal_id, action, target, "authorization", discovery, task_id,
                       agent_id, resources, expected_data, writes_data, changes_state, reason,
                       requested_capability_ttl_seconds, pipeline_stage, stage_detail,
                       decided_policy_version
                FROM action_proposals WHERE proposal_id = :p
            """),
            {"p": proposal_id},
        ).mappings().one_or_none()

    if row is None:
        return fa.ActionOutcome(
            decision=fa.DENY, proposal_id=proposal_id, failure="unknown_proposal",
        )
    target = normalize_target(dict(row["target"]))
    proposal = ProposedAction(
        action=row["action"], target=dict(row["target"]),
        authorization=dict(row["authorization"]), discovery=dict(row["discovery"]),
        task_id=row["task_id"], resources=tuple(row["resources"]),
        expected_data=tuple(row["expected_data"]), writes_data=row["writes_data"],
        changes_state=row["changes_state"], reason=row["reason"] or "",
        requested_capability_ttl_seconds=row["requested_capability_ttl_seconds"] or 60,
    )
    run = fa._Run(
        engagement_id=engagement_id, proposal=proposal, target=target, reviewer=None,
        policy=None, agent_id=row["agent_id"], actor=actor, sandbox=sandbox,
        network_allowlist=network_allowlist, execution_context=execution_context,
        capability_ttl_seconds=row["requested_capability_ttl_seconds"] or 60,
        requested_budget=Budget(max_duration_seconds=_APPROVED_BUDGET_SECONDS),
        proxy_url=proxy_url, ca_cert_pem=ca_cert_pem, proxy_cert_spki=proxy_cert_spki,
        credential_id=None,
    )
    stage = row["pipeline_stage"]
    if stage == stages.AWAITING_APPROVAL:
        return fa.ActionOutcome(
            decision=fa.HUMAN_APPROVAL, proposal_id=proposal_id, failure="not_approved",
        )
    if stage == stages.APPROVED:
        # The approval the grant recorded in the stage detail, committed with the transition.
        # Whether it is still *valid* is not decided here -- the broker asks, at issue.
        approval_id = row["stage_detail"]
        if not approval_id:
            return fa.ActionOutcome(
                decision=fa.HUMAN_APPROVAL, proposal_id=proposal_id,
                failure="approval_missing",
            )
        run.jit = fa._JitIssue(
            approval_id=approval_id,
            # approval_fields is the derivation the grant recorded and the console previewed.
            constraints=approval_fields(row, target, valid_for_seconds=0)[
                "capability_constraints"],
            expected_policy_version=row["decided_policy_version"],
        )
    # Any other stage: _drive reports it from the rows and runs nothing.
    return fa._drive(run, proposal_id)
