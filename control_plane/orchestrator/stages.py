"""Where a proposal is in the pipeline, as committed state (D58-5, D60).

``propose_action`` is no longer one transaction. It is a sequence of stages, each of which commits
on its own, and this module is the one place that says what the stages are and how a proposal moves
between them.

    received --> decided --> capability_issued --> dispatching --> recorded
                   |               |                   |
                   +-------------> closed <------------+      (closed: finished with no tool run)

* ``received``           the proposal row is committed; nothing has been decided.
* ``decided``            the policy decision and its reasons are committed (ALLOW; a DENY or a
                         HUMAN_APPROVAL goes straight to ``closed``).
* ``capability_issued``  the capability is committed.
* ``dispatching``        the ``tool_runs`` row is committed as ``running`` and the container is
                         about to start, or is running. This is the stage a crash leaves behind;
                         the existing ``reconcile_stale_dispatches`` finds it.
* ``recorded``           the run's outcome (succeeded, failed or ``unknown_outcome``) is committed.
* ``closed``             finished without a run: refused at the decision, the capability was
                         refused, the dispatch refused before a run row existed, or a dedup hit.
                         ``stage_detail`` says which.

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

from sqlalchemy import Connection, text

RECEIVED = "received"
DECIDED = "decided"
CAPABILITY_ISSUED = "capability_issued"
DISPATCHING = "dispatching"
RECORDED = "recorded"
CLOSED = "closed"

STAGES = (RECEIVED, DECIDED, CAPABILITY_ISSUED, DISPATCHING, RECORDED, CLOSED)

#: Stages in which nothing further will happen to a proposal.
TERMINAL = (RECORDED, CLOSED)

#: Every stage before the container is started. What the dispatch boundary is taken *from*: a
#: proposal that a hand-written caller never moved past ``received`` may still be dispatched, but
#: not one that has already crossed the boundary.
BEFORE_DISPATCH = (RECEIVED, DECIDED, CAPABILITY_ISSUED)


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
    """
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


def stage_of(conn: Connection, proposal_id: str) -> tuple[str, str | None] | None:
    """``(pipeline_stage, stage_detail)``, or None for an unknown proposal."""
    row = conn.execute(
        text("SELECT pipeline_stage, stage_detail FROM action_proposals "
             "WHERE proposal_id = :pid"),
        {"pid": proposal_id},
    ).one_or_none()
    return (row[0], row[1]) if row else None
