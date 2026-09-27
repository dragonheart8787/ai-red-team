"""Security Graph queries (D42-6) — the one module that may write ``WITH RECURSIVE``
over ``security_graph_nodes``/``security_graph_edges``.

D42-2 (docs/D42_2_CTE_BENCHMARK.md) measured two formulations of the same
question against a synthetic AD-shaped graph: a recursive CTE that dedups on
``(node_id, depth)`` via ``UNION``, and one that tracks a per-path visited
array and dedups nothing via ``UNION ALL``. The first stayed under ~275ms at
19k nodes / 245k edges; the second was up to ~280x slower at a *smaller*
scale and timed out on 7 of 10 samples at the larger one. Every query below
uses the first formulation, and only the first formulation — this is not a
style preference, it is the difference between an answer in milliseconds
and a query that does not return.

That is why this module exists as a single, narrow surface rather than a
convention every future Security Graph query is trusted to follow on its
own. ``tests/test_graph_queries_structure.py`` enforces it three ways: no
other module in the tree defines ``WITH RECURSIVE`` over these two tables;
every recursive block here uses ``UNION`` and never ``UNION ALL``; and a
behavioral test against an adversarial hub-shaped fixture fails fast if
either guarantee is ever quietly reverted.

Two shapes only, matching what has actually been benchmarked
(docs/D42_2_CTE_BENCHMARK.md, docs/D42_6_PATHS_WITHIN_HOPS_BENCHMARK.md). A
third shape (e.g. "every user with a path to any Tier-0 asset") is not
implemented here and should not be added without its own benchmark first —
D42-1/D42-6's design doc is explicit that neither existing number may be
assumed to generalize to a new query shape.

No ``engagement_id`` parameter anywhere in this module. Both tables carry
``FORCE ROW LEVEL SECURITY`` (migration 0011); the caller's ordinary
``engagement_scope()`` connection is what confines every query here to one
engagement, the same way ``control_plane.provenance.graph.why()`` relies on
RLS rather than a manual predicate.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection, text


#: A caller names a Security Graph node by identity, the way every other
#: interface in this system names a resource — never by the opaque
#: ``node_id`` primary key, which is an implementation detail of how two
#: collection runs that rediscover the same computer are kept as one row
#: (migration 0011's unique index), not something a Worker or Supervisor
#: has ever been given a reason to know about.
@dataclass(frozen=True)
class NodeRef:
    identity_type: str
    identity_value: str


@dataclass(frozen=True)
class ReachableNode:
    """One row of a :func:`paths_within_hops` result."""

    identity_type: str
    identity_value: str
    kind: str
    depth: int


def _node_id(conn: Connection, ref: NodeRef) -> str | None:
    """The opaque id for one identity, or ``None`` if it was never observed."""
    return conn.execute(
        text("""
            SELECT node_id FROM security_graph_nodes
            WHERE identity_type = :t AND identity_value = :v
        """),
        {"t": ref.identity_type, "v": ref.identity_value},
    ).scalar_one_or_none()


_SHORTEST_PATH_QUERY = """
WITH RECURSIVE bfs(node_id, depth) AS (
    VALUES (CAST(:start AS text), 0)
    UNION
    SELECT e.dst_node_id, bfs.depth + 1
    FROM bfs
    JOIN security_graph_edges e ON e.src_node_id = bfs.node_id
    WHERE bfs.depth < :max_depth
)
SELECT MIN(depth) AS shortest_hops
FROM bfs
WHERE node_id = :target
"""


def shortest_path(
    conn: Connection, *, start: NodeRef, target: NodeRef, max_depth: int = 10,
) -> int | None:
    """Fewest hops from ``start`` to ``target``, or ``None`` if there is none
    within ``max_depth`` — including when either identity was never observed
    by any collection run in this engagement.

    Benchmarked at docs/D42_2_CTE_BENCHMARK.md: median well under 1ms, worst
    observed case 274ms, at a 19k-node/245k-edge synthetic domain.
    """
    start_id = _node_id(conn, start)
    target_id = _node_id(conn, target)
    if start_id is None or target_id is None:
        return None
    row = conn.execute(
        text(_SHORTEST_PATH_QUERY),
        {"start": start_id, "target": target_id, "max_depth": max_depth},
    ).mappings().one_or_none()
    return row["shortest_hops"] if row else None


_PATHS_WITHIN_HOPS_QUERY = """
WITH RECURSIVE bfs(node_id, depth) AS (
    VALUES (CAST(:start AS text), 0)
    UNION
    SELECT e.dst_node_id, bfs.depth + 1
    FROM bfs
    JOIN security_graph_edges e ON e.src_node_id = bfs.node_id
    WHERE bfs.depth < :max_depth
)
SELECT node_id, MIN(depth) AS depth
FROM bfs
WHERE depth > 0
GROUP BY node_id
"""


def paths_within_hops(
    conn: Connection, *, start: NodeRef, max_depth: int,
) -> list[ReachableNode]:
    """Every *other* node reachable from ``start`` within ``max_depth`` hops.

    ``start`` itself is never included (depth 0 is filtered out) — a caller
    asking what an identity can reach has no use for being told it can reach
    itself trivially. Note this is one row narrower than the benchmark
    query in docs/D42_6_PATHS_WITHIN_HOPS_BENCHMARK.md, which did not filter
    depth 0; that off-by-one in reported result-set size does not change
    the query's cost shape or that report's conclusions, but is called out
    here rather than silently glossed over.

    A different cost shape from :func:`shortest_path` — the result set
    itself can be large (a wide-fanout admin group can reach a fifth of a
    domain within a few hops) — and was benchmarked separately for exactly
    that reason: docs/D42_6_PATHS_WITHIN_HOPS_BENCHMARK.md, worst observed
    case 351ms against the same 19k-node/245k-edge domain, returning ~3,970
    nodes.
    """
    start_id = _node_id(conn, start)
    if start_id is None:
        return []
    rows = conn.execute(
        text(_PATHS_WITHIN_HOPS_QUERY),
        {"start": start_id, "max_depth": max_depth},
    ).mappings().all()
    if not rows:
        return []
    depth_by_id = {r["node_id"]: r["depth"] for r in rows}
    node_rows = conn.execute(
        text("""
            SELECT node_id, identity_type, identity_value, kind
            FROM security_graph_nodes WHERE node_id = ANY(:ids)
        """),
        {"ids": list(depth_by_id)},
    ).mappings().all()
    return [
        ReachableNode(
            identity_type=n["identity_type"],
            identity_value=n["identity_value"],
            kind=n["kind"],
            depth=depth_by_id[n["node_id"]],
        )
        for n in node_rows
    ]
