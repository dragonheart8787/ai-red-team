"""The narrow function API — the only surface an agent may call (§2).

    create_task / claim_task / propose_action / complete_task / query_*

:func:`propose_action` is the whole pipeline behind one call:

    Target Canonicalizer
        → Authorization Resolver    (Scope Registry)
        → Metadata Resolver         (Authoritative Metadata Registry)
        → Policy Reviewer           (fake now, a real model at MVP-0)
        → OPA
        → Capability Broker
        → Tool Gateway

It is one function on purpose. An orchestration that agents assemble step by
step is an orchestration whose steps can be skipped — and the interesting
skips are precisely the ones that matter: consult the reviewer but not the
registry, obtain a capability without a decision, dispatch without a
capability. Tests drive this function for the same reason. A test that wires
the stages together by hand verifies the wiring the test wrote, not the wiring
production uses, and the two drift apart silently.

MVP-0 replaces exactly one argument: ``reviewer``. Nothing else here changes
when a real model arrives, which is the point of doing it this way now.

**Ordering is a security property, not a style choice.** The reviewer runs
after both resolvers, and its opinion is placed only where the policy reads it
for escalation. It cannot see a decision to influence, and it cannot supply a
fact anything depends on (I6b). After a DENY the function returns; the broker
and the gateway are not reached, rather than reached and refused.

**Where the reviewer's output is recorded, and why not in the registry.** The
reviewer's claim goes to ``audit_log``, beside the authoritative classification
it contradicts. It does *not* become an ``LLM_HINT`` row in the Authoritative
Metadata Registry, even though that tier exists and the resolver already
surfaces such rows as observations.

The reason is §5, which states that the Policy Reviewer AI has no write access
to the registry at all. Since D4.5 that is enforced by the database:
``registry_admin`` writes the registries and this pipeline runs as
``cyberorch_app``. A reviewer able to file its own observation would be writing
to the table the Metadata Resolver reads — the exact channel I6b exists to
close, reached from a different direction. The tier is for classifications an
Engagement Manager records *about* model output, not a channel a model writes
to itself.

So the observations mechanism stays reachable only through the registry_admin
path, and the live reviewer's claim is preserved in the audit trail instead.
That still answers the question §10 cares about — proving the AI lied and the
kernel was not fooled — because the claim and the contradicting classification
are recorded together and can be read back with
``audit.query.reconstruct_decision``.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Connection, text

from agents.base_agent import ProposedAction, ProposedTask, ReviewerOpinion
from control_plane.audit.logger import record_audit
from control_plane.canonicalizer.authorization import resolve_authorization
from control_plane.canonicalizer.metadata import resolve_metadata
from control_plane.canonicalizer.target import CanonicalizationError, normalize_target
from control_plane.capability.broker import Budget, issue_capability
from control_plane.orchestrator.dispatch import dispatch_scan
from control_plane.policy.engine import build_policy_input, evaluate
from control_plane.policy.merge import EffectivePolicy
from control_plane.provenance import graph
from control_plane.registry.scope_registry import list_scope_objects

ALLOW = "ALLOW"
DENY = "DENY"
HUMAN_APPROVAL = "HUMAN_APPROVAL"


@dataclass(frozen=True)
class ActionOutcome:
    """Everything the pipeline decided and did, in one object."""

    decision: str
    proposal_id: str
    deny_reasons: tuple[str, ...] = field(default_factory=tuple)
    approval_reasons: tuple[str, ...] = field(default_factory=tuple)
    capability_id: str | None = None
    run_id: str | None = None
    evidence_id: str | None = None
    reviewer_opinion: ReviewerOpinion | None = None
    metadata_authority: str | None = None
    canonical_data_class: tuple[str, ...] = field(default_factory=tuple)
    failure: str | None = None

    @property
    def executed(self) -> bool:
        return self.run_id is not None


# ---------------------------------------------------------------------------
# Task lifecycle (§4.2, §6)
# ---------------------------------------------------------------------------

def create_task(
    conn: Connection, *, engagement_id: str, task: ProposedTask, created_by: str
) -> str:
    task_id = f"TASK-{uuid.uuid4().hex[:10]}"
    conn.execute(
        text("""
            INSERT INTO tasks (task_id, engagement_id, goal, created_by, priority)
            VALUES (:tid, :eid, :goal, :by, :priority)
        """),
        {"tid": task_id, "eid": engagement_id, "goal": task.goal,
         "by": created_by, "priority": task.priority},
    )
    record_audit(
        engagement_id=engagement_id, actor=created_by, event_type="task.created",
        subject_type="task", subject_id=task_id, payload={"goal": task.goal},
    )
    return task_id


def claim_task(conn: Connection, *, engagement_id: str, agent_id: str) -> str | None:
    """Claim one queued task (§6).

    ``FOR UPDATE SKIP LOCKED`` plus a lease, so two workers cannot take the
    same task and a worker that dies does not strand it.
    """
    task_id = conn.execute(
        text("""
            UPDATE tasks
            SET status = 'claimed', owner_agent_id = :agent,
                lease_expires_at = now() + interval '5 minutes', updated_at = now()
            WHERE task_id = (
                SELECT task_id FROM tasks
                WHERE status = 'queued' AND engagement_id = :eid
                ORDER BY priority DESC, created_at ASC
                FOR UPDATE SKIP LOCKED LIMIT 1
            )
            RETURNING task_id
        """),
        {"agent": agent_id, "eid": engagement_id},
    ).scalar_one_or_none()
    if task_id is not None:
        # Which agent took which task, and when. Without this the audit trail
        # attributes everything downstream to the orchestrator, and the agent
        # that actually did the work appears nowhere.
        record_audit(
            engagement_id=engagement_id, actor=agent_id, event_type="task.claimed",
            subject_type="task", subject_id=task_id,
            payload={"lease_seconds": 300},
        )
    return task_id


def complete_task(
    conn: Connection, *, engagement_id: str, task_id: str, result_summary: str, actor: str
) -> None:
    conn.execute(
        text("UPDATE tasks SET status = 'completed', result_summary = :s, "
             "updated_at = now() WHERE task_id = :tid"),
        {"tid": task_id, "s": result_summary},
    )
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="task.completed",
        subject_type="task", subject_id=task_id, payload={"result": result_summary},
    )


# ---------------------------------------------------------------------------
# propose_action — the pipeline
# ---------------------------------------------------------------------------

def propose_action(
    conn: Connection,
    *,
    engagement_id: str,
    proposal: ProposedAction,
    reviewer,
    policy: EffectivePolicy,
    agent_id: str,
    actor: str = "orchestrator",
    sandbox=None,
    network_allowlist: Sequence[str] | None = None,
    execution_context: Mapping[str, Any] | None = None,
    capability_ttl_seconds: int | None = None,
    budget: Budget | None = None,
) -> ActionOutcome:
    """Canonicalize, resolve, review, decide, and only then act."""
    proposal_id = f"PROP-{uuid.uuid4().hex[:10]}"

    # --- 1. Target Canonicalizer -------------------------------------------
    try:
        target = normalize_target(proposal.target)
    except CanonicalizationError as exc:
        # I10: a target that cannot be normalized is not a target that gets a
        # best guess. Nothing downstream runs.
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="proposal.rejected", subject_type="action_proposal",
            subject_id=proposal_id, decision=DENY,
            reasons=("target_not_canonicalizable",), payload={"error": str(exc)},
        )
        return ActionOutcome(
            decision=DENY, proposal_id=proposal_id,
            deny_reasons=("target_not_canonicalizable",), failure=str(exc),
        )

    _persist_proposal(conn, engagement_id, proposal_id, proposal, target, agent_id)
    # Attributed to the agent, unlike everything after it, which the
    # orchestrator does. "Which agent asked for this" is otherwise only in the
    # proposal row, and the audit trail should stand on its own.
    record_audit(
        engagement_id=engagement_id, actor=agent_id, event_type="proposal.submitted",
        subject_type="action_proposal", subject_id=proposal_id,
        payload={
            "action": proposal.action,
            "target": target.normalized,
            "authorization": dict(proposal.authorization),
            "discovery": dict(proposal.discovery),
            "task_id": proposal.task_id,
        },
    )

    # --- 2. Authorization Resolver ------------------------------------------
    authorization = resolve_authorization(
        conn, target=target, action=proposal.action,
        authorization=proposal.authorization,
    )

    # --- 3. Metadata Resolver ------------------------------------------------
    metadata = resolve_metadata(conn, target=target)

    # --- 4. Policy Reviewer --------------------------------------------------
    # Runs after the resolvers so it cannot influence what they found, and its
    # output is recorded before the decision so a later reader can see what the
    # reviewer claimed alongside what the registry said. That pairing is the
    # evidence for "the AI lied and the kernel was not fooled"; without it the
    # audit trail would show only that the AI said nothing.
    opinion: ReviewerOpinion = reviewer.review(proposal=proposal, canonical_target=target)
    record_audit(
        engagement_id=engagement_id, actor=opinion.reviewer_id,
        event_type="policy_reviewer.opinion", subject_type="action_proposal",
        subject_id=proposal_id,
        payload={
            "opinion": opinion.as_dict(),
            # Recorded side by side on purpose. The reviewer's claim is only
            # interesting next to the classification it contradicts.
            "authoritative_classification": {
                "authority": metadata.authority,
                "known": metadata.known,
                "data_class": list(metadata.data_class),
            },
            "note": "advisory only; may tighten the decision, never satisfy a "
                    "prerequisite (I6b)",
        },
    )

    # --- 5. OPA --------------------------------------------------------------
    # Resolved before the decision rather than at step 6, because since D12 the
    # policy checks the requested budget against the size of the target (I3).
    # The same object then goes to the broker, so what OPA judged and what was
    # issued cannot come apart.
    requested_budget = budget or Budget(max_duration_seconds=120)
    policy_input = build_policy_input(
        target=target, action=proposal.action, authorization=authorization,
        metadata=metadata, policy=policy,
        scope_objects=list_scope_objects(conn),
        # The reviewer's words enter here and only here. Both fields are read
        # by approval_reasons alone, so the worst a dishonest reviewer can do
        # is ask for a human.
        risk_hint=opinion.risk_hint,
        possible_sensitive_data_hint=opinion.possible_sensitive_data_hint,
        discovery=proposal.discovery,
        writes_data=proposal.writes_data,
        changes_state=proposal.changes_state,
        capability_request=requested_budget.as_dict(),
    )
    decision = evaluate(policy_input)

    _record_decision(conn, proposal_id, decision)
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="policy.decided",
        subject_type="action_proposal", subject_id=proposal_id,
        decision=decision.decision,
        reasons=decision.deny_reasons + decision.approval_reasons,
        payload={
            "authorization": authorization.as_dict(),
            "resource_metadata": metadata.as_dict(),
            "reviewer_opinion": opinion.as_dict(),
            "engine_error": decision.engine_error,
        },
    )
    if authorization.scope_object_id:
        graph.record_edge(
            conn, engagement_id=engagement_id, from_type="scope_object",
            from_id=authorization.scope_object_id, to_type="action_proposal",
            to_id=proposal_id, relation=graph.AUTHORIZED,
        )
    if metadata.asset_id:
        graph.record_edge(
            conn, engagement_id=engagement_id, from_type="asset",
            from_id=metadata.asset_id, to_type="action_proposal",
            to_id=proposal_id, relation=graph.CLASSIFIED,
        )

    common = {
        "proposal_id": proposal_id,
        "deny_reasons": decision.deny_reasons,
        "approval_reasons": decision.approval_reasons,
        "reviewer_opinion": opinion,
        "metadata_authority": metadata.authority,
        "canonical_data_class": metadata.data_class,
    }

    if decision.decision != ALLOW:
        # The function returns here. The Capability Broker and the Tool Gateway
        # are not called — not called and refused, not called with an empty
        # budget. Nothing downstream of this line runs.
        return ActionOutcome(decision=decision.decision, **common)

    # --- 6. Capability Broker ------------------------------------------------
    capability_id = f"CAP-{uuid.uuid4().hex[:10]}"
    issued = issue_capability(
        conn, engagement_id=engagement_id, capability_id=capability_id,
        agent_id=agent_id, action=proposal.action, actor=actor,
        constraints={"host": target.logical_identity.value,
                     "ports": proposal.target.get("ports", "8080"),
                     "scan_type": proposal.target.get("scan_type", "connect")},
        budget=requested_budget,
        ttl_seconds=capability_ttl_seconds or proposal.requested_capability_ttl_seconds,
        proposal_id=proposal_id,
        # The scope object the resolver actually authorized against, carried
        # forward so every later heartbeat can re-check that it still stands
        # (I8). Taken from the resolution rather than from the proposal: the
        # proposal is what an agent asked for, the resolution is what was
        # granted, and only the second is a fact about this system.
        scope_object_id=authorization.scope_object_id,
    )
    if not issued.issued:
        # The policy said yes and the broker said no. Both are recorded; the
        # disagreement is the interesting part and must not be flattened.
        return ActionOutcome(
            decision=DENY, deny_reasons=tuple(issued.reasons),
            failure="capability_refused",
            **{k: v for k, v in common.items() if k != "deny_reasons"},
        )

    graph.record_edge(
        conn, engagement_id=engagement_id, from_type="action_proposal",
        from_id=proposal_id, to_type="capability", to_id=capability_id,
        relation=graph.ISSUED,
    )

    # --- 7. Tool Gateway ------------------------------------------------------
    outcome = dispatch_scan(
        conn, engagement_id=engagement_id, proposal_id=proposal_id,
        capability=issued.capability, target=target.logical_identity.value,
        actor=actor, sandbox=sandbox,
        network_allowlist=list(network_allowlist) if network_allowlist else None,
        execution_context=execution_context,
    )

    if outcome.run_id:
        graph.record_edge(
            conn, engagement_id=engagement_id, from_type="capability",
            from_id=capability_id, to_type="tool_run", to_id=outcome.run_id,
            relation=graph.EXECUTED,
        )
    if outcome.evidence_id:
        graph.record_edge(
            conn, engagement_id=engagement_id, from_type="tool_run",
            from_id=outcome.run_id, to_type="evidence", to_id=outcome.evidence_id,
            relation=graph.PRODUCED,
        )
    if proposal.task_id and outcome.run_id:
        graph.record_edge(
            conn, engagement_id=engagement_id, from_type="task",
            from_id=proposal.task_id, to_type="action_proposal",
            to_id=proposal_id, relation=graph.PROPOSED,
        )

    return ActionOutcome(
        decision=ALLOW, capability_id=capability_id, run_id=outcome.run_id,
        evidence_id=outcome.evidence_id, failure=outcome.reason, **common,
    )


# ---------------------------------------------------------------------------
# Read-only queries agents may make (§2)
# ---------------------------------------------------------------------------

def query_evidence(conn: Connection, *, evidence_id: str) -> dict[str, Any] | None:
    """Return the derived view only.

    §4.4: the raw artifact never enters an LLM context. Not returning it here
    means no caller has to remember that.
    """
    row = conn.execute(
        text("SELECT evidence_id, run_id, tool, tool_version, derived_view "
             "FROM evidence WHERE evidence_id = :e"),
        {"e": evidence_id},
    ).mappings().one_or_none()
    return dict(row) if row else None


def query_state(
    conn: Connection,
    *,
    engagement_id: str,
    task_status: Sequence[str] | None = None,
    task_limit: int = 50,
    decision_limit: int = 20,
) -> dict[str, Any]:
    """What has happened in this engagement so far (§2).

    Counts alone were enough while the only planner was scripted. A real
    Supervisor (D17) has to decide what to do *next*, and a summary that cannot
    say which tasks already exist leaves it no way to answer that except by
    guessing — so this returns the task ledger and the recent decisions as well.

    **Read-only, and deliberately not an execution interface.** §2 draws the
    line at what an agent may *call*, not at what it may know: tool invocation,
    shell, network and registry writes stay absent, and adding a way to read
    state does not move that line. Three properties keep it on the right side:

    * Nothing here writes, and the whole function runs on the ordinary
      ``cyberorch_app`` connection, which holds SELECT and no more on these
      tables. D17 added no grant.
    * Every row is confined to the current engagement by RLS, exactly as the
      rest of the pipeline is (I4). There is no engagement-wide or
      cross-engagement variant of this call and no parameter that could ask for
      one — the ``engagement_id`` argument names the connection's own scope for
      the audit trail's benefit, it does not select which engagement to read.
    * ``filter`` in §2's signature is spelled here as explicit keyword
      arguments rather than a free-form predicate. A filter object that became
      SQL would be a query interface an agent could widen from the inside;
      ``task_status`` is checked against a fixed set and everything else is a
      bound parameter.

    What it does newly expose, stated plainly rather than glossed: an agent can
    now see decisions on proposals *other agents* made in the same engagement.
    Each such row was already returned to whoever submitted it — this is the
    same content with a wider readership, bounded by the engagement. §5's
    isolation boundary is the engagement, not the agent, so this is inside it;
    it is still a widening, and D17's report says so.
    """
    counts = conn.execute(
        text("""
            SELECT
              (SELECT count(*) FROM tasks) AS tasks,
              (SELECT count(*) FROM action_proposals) AS proposals,
              (SELECT count(*) FROM capabilities WHERE revoked IS FALSE) AS capabilities,
              (SELECT count(*) FROM tool_runs) AS runs,
              (SELECT count(*) FROM evidence) AS evidence
        """)
    ).mappings().one()

    statuses = _valid_task_statuses(task_status)
    tasks = conn.execute(
        text("""
            SELECT task_id, goal, status, owner_agent_id, created_by,
                   parent_task_id, overlaps_with, priority, result_summary,
                   lease_expires_at, created_at
            FROM tasks
            WHERE (:all_statuses OR status = ANY(:statuses))
            ORDER BY created_at ASC
            LIMIT :limit
        """),
        {"all_statuses": statuses is None, "statuses": list(statuses or ()),
         "limit": max(0, int(task_limit))},
    ).mappings().all()

    decisions = conn.execute(
        text("""
            SELECT proposal_id, task_id, agent_id, action,
                   target -> 'logical_identity' ->> 'value' AS target_value,
                   target -> 'logical_identity' ->> 'type' AS target_type,
                   decision, decision_reasons, created_at
            FROM action_proposals
            WHERE decision IS NOT NULL
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        {"limit": max(0, int(decision_limit))},
    ).mappings().all()

    return {
        "counts": dict(counts),
        "tasks": [dict(r) for r in tasks],
        # Newest first: a planner reading this wants the most recent refusal,
        # and truncating at ``decision_limit`` must drop the oldest rather than
        # the ones that explain why the last attempt failed.
        "recent_decisions": [dict(r) for r in decisions],
    }


#: §4.2's status vocabulary. Checked against rather than interpolated: the
#: status filter is the one place a caller supplies something that reaches a
#: WHERE clause, and an allowlist is what keeps it a filter rather than an
#: opening.
TASK_STATUSES = (
    "queued", "claimed", "running", "completed", "failed", "cancelled",
)

#: §4.3's states, for the same reason.
FINDING_STATES = (
    "candidate", "hypothesis", "pending_verification", "verified", "rejected",
    "mitigated", "accepted_risk",
)


def _valid_task_statuses(requested: Sequence[str] | None) -> tuple[str, ...] | None:
    if requested is None:
        return None
    unknown = [s for s in requested if s not in TASK_STATUSES]
    if unknown:
        raise ValueError(f"unknown task status(es) {unknown}; expected {TASK_STATUSES}")
    return tuple(requested)


def query_findings(
    conn: Connection,
    *,
    engagement_id: str,
    state: Sequence[str] | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Findings for this engagement (§2, §4.3).

    §2 has listed this since v0.1 and nothing implemented it, because until
    D17 no component needed it: the Worker is given one task and the Reviewer
    one proposal, and neither plans. A Supervisor does, and "what has this
    engagement actually established so far" is the question its whole job rests
    on.

    Read-only and RLS-confined, on the same terms as :func:`query_state`. Note
    that ``claim`` is *derived from tool output* and therefore carries whatever
    a target put in front of the system — a caller showing these to a model must
    wrap them in the untrusted block (§8.1), which the Supervisor's prompt
    builder does (D17).

    ``confidence`` is deliberately absent, because §4.3 removed the column. The
    strength of a finding is ``evidence_strength`` plus ``verifier_state``, two
    discrete fields, and a planner that wants to rank findings has to reason
    about those rather than sort by a number nobody computed.
    """
    if state is not None:
        unknown = [s for s in state if s not in FINDING_STATES]
        if unknown:
            raise ValueError(
                f"unknown finding state(s) {unknown}; expected {FINDING_STATES}"
            )
    rows = conn.execute(
        text("""
            SELECT finding_id, claim, state, evidence_strength, verifier_state,
                   evidence_ids, affects, attack_path_ids,
                   verification_conflict, created_at, confirmed_at
            FROM findings
            WHERE (:all_states OR state = ANY(:states))
            ORDER BY created_at ASC
            LIMIT :limit
        """),
        {"all_states": state is None, "states": list(state or ()),
         "limit": max(0, int(limit))},
    ).mappings().all()
    return [dict(r) for r in rows]


def _persist_proposal(
    conn: Connection, engagement_id: str, proposal_id: str,
    proposal: ProposedAction, target, agent_id: str,
) -> None:
    import json

    conn.execute(
        text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, task_id,
                agent_id, request_idempotency_key, action, target, "authorization",
                discovery, resources, expected_data, writes_data, changes_state,
                reason, requested_capability_ttl_seconds)
            VALUES (:pid, :eid, :tid, :agent, :key, :action, CAST(:target AS jsonb),
                    CAST(:auth AS jsonb), CAST(:disc AS jsonb), :resources,
                    :expected, :writes, :changes, :reason, :ttl)
        """),
        {
            "pid": proposal_id, "eid": engagement_id, "tid": proposal.task_id,
            "agent": agent_id, "key": f"idem-{proposal_id}", "action": proposal.action,
            "target": json.dumps(target.as_dict(), default=str),
            "auth": json.dumps(dict(proposal.authorization), default=str),
            "disc": json.dumps(dict(proposal.discovery), default=str),
            "resources": list(proposal.resources),
            "expected": list(proposal.expected_data),
            "writes": proposal.writes_data, "changes": proposal.changes_state,
            "reason": proposal.reason,
            "ttl": proposal.requested_capability_ttl_seconds,
        },
    )


def _record_decision(conn: Connection, proposal_id: str, decision) -> None:
    conn.execute(
        text("UPDATE action_proposals SET decision = :d, decision_reasons = :r, "
             "updated_at = now() WHERE proposal_id = :p"),
        {"p": proposal_id, "d": decision.decision,
         "r": list(decision.deny_reasons + decision.approval_reasons)},
    )
