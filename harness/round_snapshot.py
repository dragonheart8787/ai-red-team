"""One round's view of the evidence, read once and handed to both roles (D69 H4).

A round reads the engagement's evidence window **once** (:func:`take_round_snapshot`) and from
that one read builds everything either role is shown:

* what the Supervisor sees as evidence -- :meth:`RoundSnapshot.supervisor_evidence`, the
  ``derived_view`` of each row exactly as the window returned it;
* what a Worker's ``_discovery_provenance`` is given for any task that Supervisor plans --
  :meth:`RoundSnapshot.observations_for_task`, the observations built from those same rows.

Why one read and one set. The Supervisor can write a task whose target it learned from text in
an evidence row, and that task goes to a Worker whose provenance check asks "was this target
named only by untrusted text?". It can only answer that from the rows the Supervisor was
shown. Two reads could differ (a row written between them), and a set narrowed to the task's
own target would hide exactly the row the lure came from. So there is one read, one set of
rows, and the set is the same for every task of the round -- it is **not** filtered by target,
which is why :meth:`observations_for_task` takes no argument.

Nothing here truncates, rewrites or filters a row, and nothing holds a connection after the
read. The rows and observations are held in tuples of frozen records; the ``derived_view``
objects inside them are the ones the database driver returned, shared and not copied.

The Supervisor's findings, task ledger and decisions are **not** read here. Findings are
fixed empty and the other two are whatever the caller passes (default empty): what those
fields may carry back into a prompt is the owner's open decision (the laundering path in the
plan's section 11), and H4 does not make it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import Connection

from agents.llm.supervisor_base import (
    DecisionRecord,
    EvidenceRecord,
    StateSummary,
    TaskRecord,
)
from agents.llm.worker_base import Observation
from harness.observations import (
    EvidenceWindowRow,
    observations_from_window,
    read_evidence_window,
)


@dataclass(frozen=True)
class RoundSnapshot:
    """The evidence window of one round, and what is built from it. Immutable."""

    rows: tuple[EvidenceWindowRow, ...]
    observations: tuple[Observation, ...]
    limit: int

    def supervisor_evidence(self) -> tuple[EvidenceRecord, ...]:
        """The rows as the Supervisor is shown them: the view as read, not transformed."""
        return tuple(
            EvidenceRecord(
                evidence_id=row.evidence_id,
                tool=row.tool,
                derived_view=row.derived_view,
            )
            for row in self.rows
        )

    def observations_for_task(self) -> tuple[Observation, ...]:
        """The observations of the whole window, the same for every task of the round."""
        return self.observations


def take_round_snapshot(conn: Connection, *, limit: int) -> RoundSnapshot:
    """Read the evidence window once and build the snapshot. ``limit`` is required."""
    rows = read_evidence_window(conn, limit=limit)
    return RoundSnapshot(
        rows=rows,
        observations=observations_from_window(rows),
        limit=limit,
    )


def build_state_summary(
    snapshot: RoundSnapshot,
    *,
    engagement_id: str,
    objective: str,
    tasks: Sequence[TaskRecord] = (),
    decisions: Sequence[DecisionRecord] = (),
) -> StateSummary:
    """What one planning call is shown. Findings are fixed empty; see the module docstring."""
    return StateSummary(
        engagement_id=engagement_id,
        objective=objective,
        tasks=tuple(tasks),
        decisions=tuple(decisions),
        findings=(),
        evidence=snapshot.supervisor_evidence(),
    )
