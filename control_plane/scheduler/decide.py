"""The scheduling decision: what to do next, derived from what the database says now (D62).

**This module can reach exactly one connection: ``scheduler_reader``.** It imports no other scope,
no pipeline function, no vault and no audit writer (``tests/test_scheduler_structure.py`` scans for
that), so the decision cannot read what the reader was not granted -- a proposal's target, a task's
goal, evidence, a credential -- and cannot act on anything it reads. What it returns is a ``Plan``
of ids and closed codes; carrying the plan out is ``service``'s and ``execute``'s.

Level-triggered and stateless between ticks: nothing is cached here. The only memory is
``scheduler_state``, a closed-vocabulary table the reader may select, which is how an edge (an
engagement becoming deferred, a proposal being skipped) is recognised as *new* without remembering
anything in the process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import text

from control_plane.scheduler import vocab
from control_plane.state.db import scheduler_reader_enrollment_scope, scheduler_reader_scope

ACTIVE = "active"
PAUSED = "paused"


@dataclass(frozen=True)
class Waiting:
    """An approved proposal nothing has dispatched: ids and a closed action class only."""

    proposal_id: str
    action_class: str


@dataclass(frozen=True)
class Observation:
    """One engagement as the reader sees it right now."""

    engagement_id: str
    exists: bool
    status: str | None = None
    kill_switch_engaged: bool = False
    waiting: tuple[Waiting, ...] = ()
    #: 'served' / 'deferred' from the engagement's state row; None = no row (implicitly served)
    disposition: str | None = None
    deferred_reason: str | None = None
    since: datetime | None = None
    #: proposal_id -> skip reason already recorded
    skipped: dict[str, str] = field(default_factory=dict)
    #: proposals with a recorded decision to dispatch
    decided: frozenset[str] = frozenset()
    #: counts of proposals past ``approved`` that a crash can leave behind
    dispatching: int = 0
    capability_issued: int = 0

    @property
    def servable(self) -> bool:
        return self.exists and self.status == ACTIVE and not self.kill_switch_engaged

    @property
    def defer_reason(self) -> str:
        if self.kill_switch_engaged:
            return "engagement_killed"
        if self.status == PAUSED:
            return "engagement_paused"
        return "engagement_not_active"


@dataclass(frozen=True)
class Candidate:
    engagement_id: str
    proposal_id: str
    action_class: str


@dataclass(frozen=True)
class Transition:
    """An edge in an engagement's disposition: first deferred (with why), or served again."""

    kind: str                      # 'deferred' | 'resumed'
    engagement_id: str
    waiting_count: int
    reason_code: str | None = None
    deferred_seconds: int | None = None


@dataclass(frozen=True)
class SkipDecision:
    engagement_id: str
    proposal_id: str
    reason_code: str


@dataclass(frozen=True)
class Plan:
    engagement_id: str
    transitions: tuple[Transition, ...] = ()
    skips: tuple[SkipDecision, ...] = ()
    candidates: tuple[Candidate, ...] = ()


def read_enrollment() -> list[str]:
    """The live enrollment list -- re-read every tick, so a withdrawal takes effect at once."""
    with scheduler_reader_enrollment_scope() as conn:
        return [r[0] for r in conn.execute(text(
            "SELECT engagement_id FROM scheduler_enrollment WHERE withdrawn_at IS NULL "
            "ORDER BY enrollment_id"))]


def observe(engagement_id: str) -> Observation:
    """Everything the decision needs about one engagement, in one read-only transaction."""
    with scheduler_reader_scope(engagement_id) as conn:
        engagement = conn.execute(
            text("SELECT status, kill_switch_engaged FROM engagements "
                 "WHERE engagement_id = :e"), {"e": engagement_id},
        ).one_or_none()
        if engagement is None:
            return Observation(engagement_id=engagement_id, exists=False)
        waiting = tuple(
            Waiting(r[0], r[1]) for r in conn.execute(text(
                "SELECT proposal_id, action_class FROM scheduler_proposals "
                "WHERE pipeline_stage = 'approved' ORDER BY stage_updated_at, proposal_id")))
        stuck = dict(conn.execute(text(
            "SELECT pipeline_stage, count(*) FROM scheduler_proposals "
            "WHERE pipeline_stage IN ('dispatching', 'capability_issued') "
            "GROUP BY pipeline_stage")).all())
        state = conn.execute(text(
            "SELECT proposal_id, disposition, reason_code, since FROM scheduler_state")).all()

    disposition = reason = since = None
    skipped: dict[str, str] = {}
    decided: set[str] = set()
    for proposal_id, dispo, why, when in state:
        if proposal_id is None:
            disposition, reason, since = dispo, why, when
        elif dispo == vocab.SKIPPED_STATE:
            skipped[proposal_id] = why
        elif dispo == vocab.DISPATCH_DECIDED:
            decided.add(proposal_id)
    return Observation(
        engagement_id=engagement_id, exists=True, status=engagement[0],
        kill_switch_engaged=bool(engagement[1]), waiting=waiting, disposition=disposition,
        deferred_reason=reason, since=since, skipped=skipped, decided=frozenset(decided),
        dispatching=int(stuck.get("dispatching", 0)),
        capability_issued=int(stuck.get("capability_issued", 0)),
    )


def plan(obs: Observation, *, now: datetime) -> Plan:
    """What to do for one engagement this tick.

    * Not servable (paused / killed / not active): nothing is dispatched. If something is *waiting*
      -- only then is anything being delayed -- and the engagement was not already recorded as
      deferred for this same reason, that is an edge: one ``deferred`` transition.
    * Servable again after a recorded deferral: one ``resumed`` transition.
    * Each waiting proposal is either a candidate to dispatch, or -- for an action v0 does not
      dispatch -- skipped once (a recorded skip is not repeated).
    """
    if not obs.exists:
        return Plan(obs.engagement_id)

    if not obs.servable:
        if obs.waiting and not (
            obs.disposition == vocab.DEFERRED_STATE and obs.deferred_reason == obs.defer_reason
        ):
            return Plan(obs.engagement_id, transitions=(Transition(
                kind="deferred", engagement_id=obs.engagement_id,
                waiting_count=len(obs.waiting), reason_code=obs.defer_reason),))
        return Plan(obs.engagement_id)

    transitions: tuple[Transition, ...] = ()
    if obs.disposition == vocab.DEFERRED_STATE:
        seconds = int((now - obs.since).total_seconds()) if obs.since else 0
        transitions = (Transition(
            kind="resumed", engagement_id=obs.engagement_id, waiting_count=len(obs.waiting),
            deferred_seconds=max(seconds, 0)),)

    skips: list[SkipDecision] = []
    candidates: list[Candidate] = []
    for item in obs.waiting:
        if item.action_class not in vocab.SUPPORTED_ACTIONS:
            if obs.skipped.get(item.proposal_id) != vocab.ACTION_NOT_SUPPORTED:
                skips.append(SkipDecision(
                    obs.engagement_id, item.proposal_id, vocab.ACTION_NOT_SUPPORTED))
        else:
            candidates.append(Candidate(obs.engagement_id, item.proposal_id, item.action_class))
    return Plan(obs.engagement_id, transitions, tuple(skips), tuple(candidates))


def stage_of(engagement_id: str, proposal_id: str) -> str | None:
    """A proposal's pipeline stage right now (None if the reader cannot see it)."""
    with scheduler_reader_scope(engagement_id) as conn:
        return conn.execute(
            text("SELECT pipeline_stage FROM scheduler_proposals WHERE proposal_id = :p"),
            {"p": proposal_id},
        ).scalar_one_or_none()


def servable_now(engagement_id: str) -> bool:
    """Re-read immediately before a dispatch, so 'paused' is caught as a deferral, not a refusal."""
    return observe_status(engagement_id) == ACTIVE


def observe_status(engagement_id: str) -> str | None:
    """'active' only if the engagement exists, is active and its kill switch is not engaged."""
    with scheduler_reader_scope(engagement_id) as conn:
        row: Any = conn.execute(
            text("SELECT status, kill_switch_engaged FROM engagements WHERE engagement_id = :e"),
            {"e": engagement_id},
        ).one_or_none()
    if row is None or row[1]:
        return None if row is None else "killed"
    return row[0]
