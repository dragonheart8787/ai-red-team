"""Reading the audit trail (§4.4, §8.10).

Writing records is only half of an audit log. The Scenario A and B tests each
grew their own SELECT and their own idea of how to group the results, which is
how a log stops being usable: the reconstruction lives in whoever last needed
it, and two readers answer the same question differently.

:func:`reconstruct_decision` is the canonical answer to "what happened to this
proposal, and why". It returns the events in order, grouped by the stage of the
pipeline they came from, so the sequence reads the way the pipeline ran rather
than the way the rows happened to be inserted.

Everything here is read-only. The grants make that structural — ``audit_log``
gives the application INSERT and SELECT and nothing else — but it is worth
saying: a module that could both write and revise the audit trail would be a
module worth attacking.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

# The pipeline stage each event belongs to. Ordering the groups this way lets a
# reader see at a glance how far a proposal got before it stopped.
STAGE_OF_EVENT = {
    "task.created": "planning",
    "task.claimed": "planning",
    "task.completed": "planning",
    "proposal.submitted": "proposal",
    "proposal.rejected": "proposal",
    "policy_reviewer.opinion": "review",
    "policy.decided": "decision",
    "capability.issued": "capability",
    "capability.refused": "capability",
    "capability.renewed": "capability",
    "capability.revoked": "capability",
    "capability.revoked_on_renewal": "capability",
    "capability.budget_exhausted": "capability",
    "tool_run.started": "execution",
    "tool_run.succeeded": "execution",
    "tool_run.failed": "execution",
    "tool_run.unknown_outcome": "execution",
    "evidence.recorded": "execution",
    "dispatch.unknown_outcome": "execution",
    "engagement.paused": "engagement",
    "engagement.resumed": "engagement",
    "engagement.completed": "engagement",
    "engagement.kill_switch_engaged": "engagement",
    "engagement.resume_refused": "engagement",
    "scope_object.registered": "registry",
    "scope_object.updated": "registry",
    "scope_object.deactivated": "registry",
    "scope_object.retired": "registry",
    "credential.revoked": "capability",
    "metadata.registered": "registry",
    "metadata.reclassified": "registry",
    "metadata.deactivated": "registry",
}

STAGE_ORDER = [
    "planning", "proposal", "review", "decision", "capability", "execution",
    "registry", "engagement", "other",
]


@dataclass(frozen=True)
class AuditEvent:
    audit_id: int
    ts: datetime
    actor: str
    event_type: str
    subject_type: str | None
    subject_id: str | None
    decision: str | None
    reasons: tuple[str, ...]
    payload: dict[str, Any]

    @property
    def stage(self) -> str:
        return STAGE_OF_EVENT.get(self.event_type, "other")

    def as_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "ts": self.ts.isoformat(),
            "stage": self.stage,
            "actor": self.actor,
            "event_type": self.event_type,
            "subject": f"{self.subject_type}:{self.subject_id}",
            "decision": self.decision,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class DecisionChain:
    """Everything recorded about one proposal, in order."""

    proposal_id: str
    events: tuple[AuditEvent, ...]
    capability_ids: tuple[str, ...] = field(default_factory=tuple)
    run_ids: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def decision(self) -> str | None:
        for event in self.events:
            if event.event_type == "policy.decided":
                return event.decision
        return None

    @property
    def reached_stages(self) -> tuple[str, ...]:
        seen = {e.stage for e in self.events}
        return tuple(s for s in STAGE_ORDER if s in seen)

    @property
    def executed(self) -> bool:
        return any(e.event_type.startswith("tool_run.") for e in self.events)

    def by_stage(self) -> dict[str, list[AuditEvent]]:
        grouped: dict[str, list[AuditEvent]] = {}
        for event in self.events:
            grouped.setdefault(event.stage, []).append(event)
        return {s: grouped[s] for s in STAGE_ORDER if s in grouped}

    def why(self) -> tuple[str, ...]:
        """The reasons the decision carried. Empty for a clean ALLOW."""
        for event in self.events:
            if event.event_type == "policy.decided":
                return event.reasons
        return ()

    def reviewer_claim(self) -> dict[str, Any] | None:
        """What the Policy Reviewer said, if it was asked.

        The half of the record that makes an adversarial reviewer provable
        after the fact: without it, "the AI lied and was ignored" and "the AI
        was never consulted" look identical in the log.
        """
        for event in self.events:
            if event.event_type == "policy_reviewer.opinion":
                return event.payload.get("opinion")
        return None

    def contradicted_classification(self) -> dict[str, Any] | None:
        """The authoritative classification recorded beside the reviewer's claim."""
        for event in self.events:
            if event.event_type == "policy_reviewer.opinion":
                return event.payload.get("authoritative_classification")
        return None


def _to_event(row) -> AuditEvent:
    return AuditEvent(
        audit_id=row["audit_id"], ts=row["ts"], actor=row["actor"],
        event_type=row["event_type"], subject_type=row["subject_type"],
        subject_id=row["subject_id"], decision=row["decision"],
        reasons=tuple(row["reasons"] or ()), payload=row["payload"] or {},
    )


_SELECT = """
    SELECT audit_id, ts, actor, event_type, subject_type, subject_id,
           decision, reasons, payload
    FROM audit_log
"""


def reconstruct_decision(conn: Connection, *, proposal_id: str) -> DecisionChain:
    """Every event belonging to one proposal, in the order it happened.

    Follows the chain outward: the proposal's own events, then the capabilities
    issued from it, then the runs those capabilities executed, then the evidence
    those runs produced. Subject ids are followed rather than joined, because
    audit_log holds no foreign keys by design (see migration 0003) and the
    subjects live in different tables.

    Outward only, and that boundary is worth stating because it is invisible
    from the result. The chain does **not** include the task the proposal came
    from — ``task.created``, ``task.claimed``, ``task.completed`` are recorded
    against the task id, which sits *behind* the proposal rather than ahead of
    it. Nor does it include the engagement's registry setup, whose subjects are
    scope objects and assets.

    So "why was this action allowed, and what did it do" is fully answerable
    here, while "which agent was asked to do this, and when" is not. That second
    question is answerable from :func:`engagement_timeline`, or by following
    ``action_proposals.task_id``. ``test_reconstruct_decision_matches_the_raw_
    audit_query_it_replaced`` pins the exact difference against the
    whole-engagement query this function replaced, so a future widening has a
    test to update rather than a surprise to discover.

    DEFERRED — walking backwards to the task
    -----------------------------------------
    Extending the chain to include the originating task is a small change and
    is deliberately not made yet. It needs a decision the design does not
    record: whether a task's events belong to *every* proposal that task
    produced, which would make one task's claim appear in several chains and
    make "the events belonging to one proposal" stop being a partition. Until a
    planner emits more than one proposal per task — MVP-Kernel's Fake Planner
    emits exactly one — there is no case to design against, and guessing would
    fix the shape before the requirement exists.
    """
    events = [
        _to_event(r) for r in conn.execute(
            text(_SELECT + " WHERE subject_id = :pid ORDER BY audit_id"),
            {"pid": proposal_id},
        ).mappings().all()
    ]

    capability_ids = tuple(
        conn.execute(
            text("SELECT capability_id FROM capabilities WHERE proposal_id = :pid "
                 "ORDER BY issued_at"),
            {"pid": proposal_id},
        ).scalars().all()
    )
    run_ids = tuple(
        conn.execute(
            text("SELECT run_id FROM tool_runs WHERE proposal_id = :pid "
                 "ORDER BY created_at"),
            {"pid": proposal_id},
        ).scalars().all()
    )
    # Evidence belongs to the proposal that caused it, one hop further out
    # through the run. Following it means "what did this proposal produce" is
    # answerable from the chain rather than needing a second query.
    evidence_ids = tuple(
        conn.execute(
            text("SELECT evidence_id FROM evidence WHERE run_id = ANY(:runs) "
                 "ORDER BY created_at"),
            {"runs": list(run_ids)},
        ).scalars().all()
    ) if run_ids else ()

    related = [*capability_ids, *run_ids, *evidence_ids]
    if related:
        events.extend(
            _to_event(r) for r in conn.execute(
                text(_SELECT + " WHERE subject_id = ANY(:ids) ORDER BY audit_id"),
                {"ids": list(related)},
            ).mappings().all()
        )

    events.sort(key=lambda e: e.audit_id)
    return DecisionChain(
        proposal_id=proposal_id, events=tuple(events),
        capability_ids=capability_ids, run_ids=run_ids,
        evidence_ids=evidence_ids,
    )


def events_for_subject(
    conn: Connection, *, subject_id: str, event_types: Sequence[str] | None = None
) -> list[AuditEvent]:
    sql = _SELECT + " WHERE subject_id = :sid"
    params: dict[str, Any] = {"sid": subject_id}
    if event_types:
        sql += " AND event_type = ANY(:types)"
        params["types"] = list(event_types)
    return [
        _to_event(r)
        for r in conn.execute(text(sql + " ORDER BY audit_id"), params).mappings().all()
    ]


def engagement_timeline(
    conn: Connection, *, limit: int = 500
) -> list[AuditEvent]:
    """Every event in the current engagement, oldest first (RLS-scoped)."""
    return [
        _to_event(r) for r in conn.execute(
            text(_SELECT + " ORDER BY audit_id LIMIT :limit"), {"limit": limit},
        ).mappings().all()
    ]


def list_global_audit(
    conn: Connection, *, event_types: Sequence[str] | None = None, limit: int = 200
) -> list[AuditEvent]:
    """Global-scope audit events, newest first (D11-7).

    Answers "who published this global overlay, and when" — the question the D11
    live run could not, because a global operation's record was scoped to the
    publisher's engagement and read back as ``published by: unknown``. Intended
    to run on the ``global_auditor`` connection, whose RLS returns exactly the
    global rows; the explicit ``scope = 'global'`` filter states the same intent
    and keeps the query honest if ever run elsewhere.
    """
    sql = _SELECT + " WHERE scope = 'global'"
    params: dict[str, Any] = {"limit": limit}
    if event_types:
        sql += " AND event_type = ANY(:types)"
        params["types"] = list(event_types)
    return [
        _to_event(r)
        for r in conn.execute(
            text(sql + " ORDER BY audit_id DESC LIMIT :limit"), params
        ).mappings().all()
    ]


def audited_event_types(conn: Connection) -> set[str]:
    """Distinct event types recorded for this engagement.

    Used by the coverage test: an operation that stops emitting its event is a
    regression the type list catches, and it is otherwise invisible.
    """
    return set(
        conn.execute(text("SELECT DISTINCT event_type FROM audit_log")).scalars().all()
    )
