"""Where a proposal is in the pipeline, as committed state (D58-5, D60).

``propose_action`` is no longer one transaction. It is a sequence of stages, each of which commits
on its own, and this module is the one place that says what the stages are and how a proposal moves
between them.

    received --> decided --> capability_issued --> dispatching --> recorded
        |            |               |                   |
        |            +-------------> closed <------------+   (closed: finished with no tool run)
        |                              ^
        +--> awaiting_approval --> approved --> capability_issued   (D61: the human path)
        |           |
        |           +--> closed   (denied: detail ``approval_denied``)
        |
        +--> abandoned   (D64: never decided, past a grace period; reconciler only, from here only)

* ``received``           the proposal row is committed; nothing has been decided.
* ``decided``            the policy decision and its reasons are committed (ALLOW; a DENY goes
                         straight to ``closed``).
* ``awaiting_approval``  (D61) the decision was HUMAN_APPROVAL and a human has not answered. Not
                         terminal: the *request* is still open, though no run will start until
                         someone approves.
* ``approved``           (D61) a human approved it -- the ``approvals`` row and this stage commit
                         together. **Awaiting dispatch**: no capability exists yet. It is issued,
                         and the tool dispatched, by ``dispatch_approved`` at the moment of use. A
                         proposal that stays here is one nothing has dispatched, or whose dispatch
                         attempt was refused before it could issue; ``stage_updated_at`` says since
                         when (what D58-9's reconciler will age).
* ``capability_issued``  the capability is committed.
* ``dispatching``        the ``tool_runs`` row is committed as ``running`` and the container is
                         about to start, or is running. This is the stage a crash leaves behind;
                         the existing ``reconcile_stale_dispatches`` finds it.
* ``recorded``           the run's outcome (succeeded, failed or ``unknown_outcome``) is committed.
                         ``recorded / unknown_outcome`` is the one non-final ``recorded``: the
                         reconciler declared a run unknown, and a result that arrives afterwards
                         replaces it in the dispatch's record transaction (``run.late_result``,
                         ACCEPTANCE 5.74).
* ``closed``             finished without a run: refused at the decision, the capability was
                         refused, the dispatch refused before a run row existed, or a dedup hit.
                         ``stage_detail`` says which.
* ``abandoned``          (D64, migration 0022) terminal: the proposal was received, **never
                         decided**, and the grace period passed. Not a refusal (nothing was
                         decided) and not ``closed`` (which means a decision was made). Reachable
                         only from ``received`` and written only by the reconciler; the database
                         refuses a decision on it and any detail but ``undecided_past_grace``. It
                         has no capability, no run, no approval. A caller that retries the same key
                         is told so (``abandoned_before_decision``) and must use a new one.

**A stage runs once.** :func:`advance` is a conditional UPDATE -- ``... WHERE pipeline_stage =
<expected>`` -- and the caller takes it as the *first* statement of the transaction that does the
stage's work. The row lock it takes makes a second driver (a retry, a restarted service, a second
worker) wait for the first to commit, after which its own UPDATE matches no row and it does not
repeat the work. The same shape as ``dispatch.claim_for_dispatch``, which guards one thing (the
dispatch itself); this guards each stage. Work and transition commit together or not at all, so the
stage a proposal reads as is always the last one whose work is fully committed.

The audit trail is the exception that makes the order matter: ``record_audit`` commits on its own
connection immediately, so a stage's audit records are written *after* its transition has been won
and before it commits. A stage that loses the race has written none.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Connection, text

RECEIVED = "received"
DECIDED = "decided"
AWAITING_APPROVAL = "awaiting_approval"
APPROVED = "approved"
CAPABILITY_ISSUED = "capability_issued"
DISPATCHING = "dispatching"
RECORDED = "recorded"
CLOSED = "closed"
ABANDONED = "abandoned"

STAGES = (
    RECEIVED, DECIDED, AWAITING_APPROVAL, APPROVED, CAPABILITY_ISSUED, DISPATCHING, RECORDED,
    CLOSED, ABANDONED,
)

#: Stages in which nothing further will happen to a proposal.
TERMINAL = (RECORDED, CLOSED, ABANDONED)

#: The stages in which a proposal may have no decision (migration 0021, 0022; ACCEPTANCE 5.69).
#: Kept equal to the database's ``action_proposals_decision_past_received`` by a test.
UNDECIDED_STAGES = (RECEIVED, ABANDONED)

#: Why a proposal is ``abandoned``: the closed vocabulary of ``stage_detail`` for that stage. One
#: code today. The database CHECK ``action_proposals_abandoned_is_undecided`` names it; a test keeps
#: the two equal, so adding a reason is a migration and a line here, together (A5).
ABANDON_REASONS = ("undecided_past_grace",)

#: Every stage before the container is started. What the dispatch boundary is taken *from*: a
#: proposal that a hand-written caller never moved past ``received`` may still be dispatched, but
#: not one that has already crossed the boundary.
BEFORE_DISPATCH = (RECEIVED, DECIDED, CAPABILITY_ISSUED)

#: Stages a person is the next mover from, not the pipeline. Neither is stuck in the crash sense: a
#: proposal here is waiting for a human (``awaiting_approval``) or for a dispatcher
#: (``approved``), and both are listable by stage.
WAITING = (AWAITING_APPROVAL, APPROVED)


class StageConflict(RuntimeError):
    """The stage this driver expected is no longer the proposal's stage.

    Raised inside the transaction that tried to take the transition, so everything that transaction
    did is rolled back and nothing is repeated. It is the *normal* outcome of losing a race, not a
    fault: the caller reloads the proposal and carries on from wherever it now is.
    """


def advance(
    conn: Connection, proposal_id: str, *, expected: str | Sequence[str], new: str,
    detail: str | None = None,
) -> bool:
    """Move a proposal from ``expected`` to ``new``; False if it was not in ``expected``.

    One conditional UPDATE. Reading the stage and then writing it would let two drivers both read
    ``decided`` and both proceed.

    ``abandoned`` is not a stage this can move to: it has one writer, :func:`abandon` (D64, A3),
    which also compares the timestamp the reconciler planned from. A scan of the source says who
    calls what; this refuses at run time, so a caller that computes ``new`` cannot get round it.
    """
    if new == ABANDONED:
        raise ValueError("`abandoned` is written by stages.abandon alone")
    stages = [expected] if isinstance(expected, str) else list(expected)
    moved = conn.execute(
        text("""
            UPDATE action_proposals
            SET pipeline_stage = :new, stage_detail = :detail,
                stage_updated_at = now(), updated_at = now()
            WHERE proposal_id = :pid AND pipeline_stage = ANY(:expected)
            RETURNING proposal_id
        """),
        {"pid": proposal_id, "new": new, "detail": detail, "expected": stages},
    ).scalar_one_or_none()
    return moved is not None


def take(
    conn: Connection, proposal_id: str, *, expected: str | Sequence[str], new: str,
    detail: str | None = None,
) -> None:
    """:func:`advance`, raising :class:`StageConflict` when the transition is not ours."""
    if not advance(conn, proposal_id, expected=expected, new=new, detail=detail):
        raise StageConflict(
            f"proposal {proposal_id!r} is no longer in stage {expected!r}"
        )


def abandon(conn: Connection, proposal_id: str, *, stage_updated_at: Any) -> bool:
    """``received -> abandoned``, the one writer of that stage (D64, A2/A3); False if not moved.

    A compare-and-set on the stage **and** on the ``stage_updated_at`` the reconciler planned
    from, so a proposal that was decided, or touched at all, between the plan and the act is left
    alone. The decision is not set (the database requires none, and refuses one), and the reason is
    the one code of :data:`ABANDON_REASONS`. Nothing here decides *whether* a proposal is old
    enough: that is the reconciler's grace period; this only makes the move safe.
    """
    moved = conn.execute(
        text("""
            UPDATE action_proposals
            SET pipeline_stage = :abandoned, stage_detail = :reason,
                stage_updated_at = now(), updated_at = now()
            WHERE proposal_id = :pid AND pipeline_stage = :received
              AND stage_updated_at = :planned
            RETURNING proposal_id
        """),
        {"pid": proposal_id, "abandoned": ABANDONED, "received": RECEIVED,
         "reason": ABANDON_REASONS[0], "planned": stage_updated_at},
    ).scalar_one_or_none()
    return moved is not None


def stage_of(conn: Connection, proposal_id: str) -> tuple[str, str | None] | None:
    """``(pipeline_stage, stage_detail)``, or None for an unknown proposal."""
    row = conn.execute(
        text("SELECT pipeline_stage, stage_detail FROM action_proposals "
             "WHERE proposal_id = :pid"),
        {"pid": proposal_id},
    ).one_or_none()
    return (row[0], row[1]) if row else None
