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
