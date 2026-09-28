"""Security Graph writes (D42-6) — the append-only counterpart to ``queries.py``.

One entry point, ``record_batch``, called once per successful ``ad.collect``
dispatch (``dispatch_collection`` in ``control_plane.orchestrator.dispatch``).
Nodes are deduplicated by identity across collection runs (migration 0011's
``security_graph_nodes_identity`` unique index): a computer BloodHound
rediscovers in a later run reuses its existing ``node_id`` rather than
fragmenting into a second row with no edges connecting it to the first run's
graph. Edges are never deduplicated — the same relationship reported twice
across two runs is two rows, and a traversal in ``queries.py`` dedups by
node reached, not by edge, so this costs nothing at query time.

No classification of any kind is written here, and none can be — neither
table has a column for one (D42-3 Option A, enforced by the schema's
absence of the column rather than by this module's discipline).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import Connection, text

from control_plane.provenance.graph import PRODUCED, record_edge


@dataclass(frozen=True)
class GraphNode:
    identity_type: str
    identity_value: str
    kind: str  # 'user' | 'computer' | 'group'


@dataclass(frozen=True)
class GraphEdge:
    src: GraphNode
    dst: GraphNode
    edge_type: str


def record_batch(
    conn: Connection, *, engagement_id: str, run_id: str,
    nodes: Sequence[GraphNode], edges: Sequence[GraphEdge],
) -> int:
    """Bulk-write one collection run's discovered graph. Returns edge count.

    ``nodes`` must include every identity any edge in ``edges`` names as its
    ``src`` or ``dst`` — including one already known from an earlier run —
    since this function resolves edges against exactly the identities it was
    given, not against the whole table. A caller that omits one raises
    ``ValueError`` rather than silently dropping the edge.
    """
    node_id_by_identity = _upsert_nodes(
        conn, engagement_id=engagement_id, run_id=run_id, nodes=nodes,
    )

    missing = [
        (e.src.identity_type, e.src.identity_value)
        for e in edges if (e.src.identity_type, e.src.identity_value) not in node_id_by_identity
    ] + [
        (e.dst.identity_type, e.dst.identity_value)
        for e in edges if (e.dst.identity_type, e.dst.identity_value) not in node_id_by_identity
    ]
    if missing:
        raise ValueError(
            f"record_batch: edge references identities not present in nodes: {missing}"
        )

    if edges:
        conn.execute(
            text("""
                INSERT INTO security_graph_edges
                    (engagement_id, run_id, src_node_id, dst_node_id, edge_type)
                SELECT * FROM unnest(
                    CAST(:eng_ids AS text[]), CAST(:run_ids AS text[]),
                    CAST(:src_ids AS text[]), CAST(:dst_ids AS text[]), CAST(:edge_types AS text[])
                )
            """),
            {
                "eng_ids": [engagement_id] * len(edges),
                "run_ids": [run_id] * len(edges),
                "src_ids": [
                    node_id_by_identity[(e.src.identity_type, e.src.identity_value)]
                    for e in edges
                ],
                "dst_ids": [
                    node_id_by_identity[(e.dst.identity_type, e.dst.identity_value)]
                    for e in edges
                ],
                "edge_types": [e.edge_type for e in edges],
            },
        )

    # The one Provenance Graph touchpoint (ADR §2.4): this collection run
    # produced a Security Graph batch, recorded exactly like any other
    # RUN --produced--> EVIDENCE edge, pointing at this run_id rather than
    # duplicating the graph's own contents into provenance_edges.
    record_edge(
        conn, engagement_id=engagement_id, from_type="tool_run", from_id=run_id,
        to_type="security_graph_batch", to_id=run_id, relation=PRODUCED,
    )
    return len(edges)


def _upsert_nodes(
    conn: Connection, *, engagement_id: str, run_id: str, nodes: Sequence[GraphNode],
) -> dict[tuple[str, str], str]:
    """Insert any node identity not already known, return every id by identity."""
    if not nodes:
        return {}

    node_ids = [f"SGN-{uuid.uuid4().hex[:12]}" for _ in nodes]
    conn.execute(
        text("""
            INSERT INTO security_graph_nodes
                (node_id, engagement_id, first_seen_run_id, identity_type, identity_value, kind)
            SELECT * FROM unnest(
                CAST(:node_ids AS text[]), CAST(:eng_ids AS text[]), CAST(:run_ids AS text[]),
                CAST(:itypes AS text[]), CAST(:ivalues AS text[]), CAST(:kinds AS text[])
            )
            ON CONFLICT (engagement_id, identity_type, identity_value) DO NOTHING
        """),
        {
            "node_ids": node_ids,
            "eng_ids": [engagement_id] * len(nodes),
            "run_ids": [run_id] * len(nodes),
            "itypes": [n.identity_type for n in nodes],
            "ivalues": [n.identity_value for n in nodes],
            "kinds": [n.kind for n in nodes],
        },
    )

    rows = conn.execute(
        text("""
            SELECT node_id, identity_type, identity_value FROM security_graph_nodes
            WHERE engagement_id = :eng
              AND (identity_type, identity_value) IN (
                  SELECT * FROM unnest(CAST(:itypes AS text[]), CAST(:ivalues AS text[]))
              )
        """),
        {
            "eng": engagement_id,
            "itypes": [n.identity_type for n in nodes],
            "ivalues": [n.identity_value for n in nodes],
        },
    ).mappings().all()
    return {(r["identity_type"], r["identity_value"]): r["node_id"] for r in rows}
