"""Provenance Graph — "why do we believe this?" (§8.10).

Separate from the Security Graph on purpose. That one answers how things
connect (User → Group → Server → App → DB); this one answers where a belief
came from, which is a different question with a different shape:

    TASK ──proposed──▶ PROPOSAL ──issued──▶ CAPABILITY ──executed──▶ RUN
                           ▲                                          │
                   authorized                                     produced
                           │                                          ▼
                     SCOPE_OBJECT                                  EVIDENCE

Two uses, both from §8.10. For audit, a confirmed finding can be walked back
through every step to the raw evidence and the scope object that authorized
collecting it — not just the last evidence id, but the whole chain. For
hallucination debugging, ``why(evidence)`` answers whether a claim was actually
observed or inferred by a model and then written into state as fact.

Edges are polymorphic by design: ``from_type``/``from_id`` name a row in
whichever table the step lives in. That rules out foreign keys, which is why
the table has none beyond ``engagement_id`` — see the note in migration 0003.
Postgres edges rather than Neo4j, per §9-D: at MVP volumes a recursive CTE is
enough, and a second datastore is a second thing to operate.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

# Relations used by the MVP-Kernel pipeline. Small and closed on purpose: a
# free-form relation vocabulary makes the graph unqueryable within a month.
PROPOSED = "proposed"
AUTHORIZED = "authorized"
CLASSIFIED = "classified"
ISSUED = "issued"
EXECUTED = "executed"
PRODUCED = "produced"
SUPPORTS = "supports"


@dataclass(frozen=True)
class Edge:
    from_type: str
    from_id: str
    to_type: str
    to_id: str
    relation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "from": f"{self.from_type}:{self.from_id}",
            "to": f"{self.to_type}:{self.to_id}",
            "relation": self.relation,
        }


def record_edge(
    conn: Connection,
    *,
    engagement_id: str,
    from_type: str,
    from_id: str,
    to_type: str,
    to_id: str,
    relation: str,
) -> None:
    """Append one edge. The table is INSERT/SELECT only for the app role."""
    conn.execute(
        text("""
            INSERT INTO provenance_edges (engagement_id, from_type, from_id,
                to_type, to_id, relation)
            VALUES (:eng, :ft, :fi, :tt, :ti, :rel)
        """),
        {"eng": engagement_id, "ft": from_type, "fi": from_id,
         "tt": to_type, "ti": to_id, "rel": relation},
    )


def record_edges(conn: Connection, *, engagement_id: str, edges: Sequence[Edge]) -> None:
    for edge in edges:
        record_edge(
            conn, engagement_id=engagement_id, from_type=edge.from_type,
            from_id=edge.from_id, to_type=edge.to_type, to_id=edge.to_id,
            relation=edge.relation,
        )


def why(conn: Connection, *, node_type: str, node_id: str, max_depth: int = 10) -> list[Edge]:
    """Walk backwards from a node to everything it rests on (§8.10).

    A recursive CTE rather than repeated round trips, with a depth bound so a
    cycle introduced by a future writer degrades into a truncated answer rather
    than a hung query.
    """
    rows = conn.execute(
        text("""
            WITH RECURSIVE chain AS (
                SELECT from_type, from_id, to_type, to_id, relation, 1 AS depth
                FROM provenance_edges
                WHERE to_type = :ntype AND to_id = :nid
              UNION ALL
                SELECT e.from_type, e.from_id, e.to_type, e.to_id, e.relation,
                       chain.depth + 1
                FROM provenance_edges e
                JOIN chain ON e.to_type = chain.from_type AND e.to_id = chain.from_id
                WHERE chain.depth < :max_depth
            )
            SELECT DISTINCT from_type, from_id, to_type, to_id, relation, depth
            FROM chain ORDER BY depth
        """),
        {"ntype": node_type, "nid": node_id, "max_depth": max_depth},
    ).mappings().all()
    return [
        Edge(r["from_type"], r["from_id"], r["to_type"], r["to_id"], r["relation"])
        for r in rows
    ]


def edges_from(conn: Connection, *, node_type: str, node_id: str) -> list[Edge]:
    rows = conn.execute(
        text("""
            SELECT from_type, from_id, to_type, to_id, relation
            FROM provenance_edges WHERE from_type = :t AND from_id = :i
            ORDER BY id
        """),
        {"t": node_type, "i": node_id},
    ).mappings().all()
    return [
        Edge(r["from_type"], r["from_id"], r["to_type"], r["to_id"], r["relation"])
        for r in rows
    ]


def record_edge_once(
    conn: Connection, *, engagement_id: str, from_type: str, from_id: str,
    to_type: str, to_id: str, relation: str,
) -> bool:
    """Append an edge unless that exact edge is already there; True if it was written.

    The table has no uniqueness constraint (polymorphic edges, see the module docstring), so the
    idempotency lives here. It is what lets :func:`record_provenance` be run again for a proposal
    -- after a failure, or by a later backfill -- and add only what is missing.
    """
    written = conn.execute(
        text("""
            INSERT INTO provenance_edges (engagement_id, from_type, from_id,
                to_type, to_id, relation)
            SELECT :eng, :ft, :fi, :tt, :ti, :rel
            WHERE NOT EXISTS (
                SELECT 1 FROM provenance_edges
                WHERE engagement_id = :eng AND from_type = :ft AND from_id = :fi
                  AND to_type = :tt AND to_id = :ti AND relation = :rel)
            RETURNING id
        """),
        {"eng": engagement_id, "ft": from_type, "fi": from_id,
         "tt": to_type, "ti": to_id, "rel": relation},
    ).scalar_one_or_none()
    return written is not None


def record_provenance(conn: Connection, *, engagement_id: str, proposal_id: str) -> bool:
    """Write a finished proposal's provenance edges, derived from committed rows (D60).

    Provenance used to be written in the same transaction as the result it describes, so one late,
    cheap edge insert that failed rolled back a tool run that had already succeeded. It is now a
    step of its own, run *after* the proposal's last stage has committed, and every edge is derived
    from rows that are already there -- the proposal, its capability, its runs, their evidence --
    rather than from values held in a caller's memory. So it can be run again: a second call adds
    only what is missing, and a proposal whose first attempt failed is repaired by calling it.

    Returns False without writing anything for a proposal that is not finished (its stage is not
    terminal): the edges describe what happened, and it has not finished happening.

    An edge for a run is drawn only if the run was *started* -- it succeeded, failed with an exit
    code, or ended ``unknown_outcome``. A run row the sandbox refused before any container existed
    (D59: a network refusal) has none of those, and has not executed anything.
    """
    proposal = conn.execute(
        text("""
            SELECT task_id, pipeline_stage, stage_detail,
                   authorized_scope_object_id, classified_asset_id
            FROM action_proposals WHERE proposal_id = :p
        """),
        {"p": proposal_id},
    ).mappings().one_or_none()
    if proposal is None or proposal["pipeline_stage"] not in ("recorded", "closed"):
        return False

    def edge(from_type, from_id, to_type, to_id, relation) -> None:
        record_edge_once(
            conn, engagement_id=engagement_id, from_type=from_type, from_id=from_id,
            to_type=to_type, to_id=to_id, relation=relation,
        )

    if proposal["authorized_scope_object_id"]:
        edge("scope_object", proposal["authorized_scope_object_id"],
             "action_proposal", proposal_id, AUTHORIZED)
    if proposal["classified_asset_id"]:
        edge("asset", proposal["classified_asset_id"], "action_proposal", proposal_id,
             CLASSIFIED)
    capabilities = conn.execute(
        text("SELECT capability_id FROM capabilities WHERE proposal_id = :p ORDER BY issued_at"),
        {"p": proposal_id},
    ).scalars().all()
    for capability_id in capabilities:
        edge("action_proposal", proposal_id, "capability", capability_id, ISSUED)

    ran = False
    runs = conn.execute(
        text("""
            SELECT run_id, capability_id FROM tool_runs
            WHERE proposal_id = :p
              AND (status IN ('succeeded', 'unknown_outcome') OR exit_code IS NOT NULL)
            ORDER BY started_at, run_id
        """),
        {"p": proposal_id},
    ).mappings().all()
    for run in runs:
        ran = True
        if run["capability_id"]:
            edge("capability", run["capability_id"], "tool_run", run["run_id"], EXECUTED)
        for evidence_id in conn.execute(
            text("SELECT evidence_id FROM evidence WHERE run_id = :r ORDER BY evidence_id"),
            {"r": run["run_id"]},
        ).scalars().all():
            edge("tool_run", run["run_id"], "evidence", evidence_id, PRODUCED)

    # A dedup hit ran nothing under this capability but is answered by an earlier run, and the
    # edge to it is how a reader finds out which (the stage detail carries its id).
    detail = proposal["stage_detail"] or ""
    if detail.startswith("dedup_hit:") and capabilities:
        cached = detail.removeprefix("dedup_hit:")
        edge("capability", capabilities[-1], "tool_run", cached, EXECUTED)
        ran = True

    if proposal["task_id"] and ran:
        edge("task", proposal["task_id"], "action_proposal", proposal_id, PROPOSED)

    conn.execute(
        text("UPDATE action_proposals SET provenance_complete = TRUE WHERE proposal_id = :p"),
        {"p": proposal_id},
    )
    return True
