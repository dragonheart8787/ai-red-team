# D42-6: `paths_within_hops` benchmark

**Addendum, found while implementing `control_plane/graph/queries.py`
against this same query shape.** Like D42-2, this report's numbers are from
the throwaway `bh_bench` database (no RLS, single-column source index) —
and like D42-2, the real, RLS-enabled `security_graph_edges` table needed a
second, single-column index on `src_node_id` (in addition to the composite
`(engagement_id, src_node_id)` one) before the shipped `paths_within_hops`
matched these numbers; without it, the same query took tens of seconds
instead. See `docs/D42_2_CTE_BENCHMARK.md`'s own addendum and migration
`0011_bloodhound_security_graph.py`'s module docstring for the full
finding — it applies identically to both query shapes, since both are
recursive joins against the same table and index.

Closes the gate `docs/D42_1_D42_6_DESIGN.md` §2.6 sets on this query shape:
*"a query shape is not merged into [`control_plane/graph/queries.py`] until
its own D42-2-style benchmark exists... enumerating a bounded-hop
neighborhood is a different cost profile (the result set itself can be
large, where `shortest_path` returns one number), and D42-2's numbers say
nothing about it."*

**Script**: `scripts/bench/d42_6_paths_within_hops_bench.py`. **Raw
results**: `docs/d42_bench/d42_6_paths_within_hops_bench.json`. Reuses
`d42_bloodhound_cte_bench`'s graph generator and loader directly (imported,
not re-implemented), so these numbers are against the same synthetic
graphs D42-2 measured, at the same two scales (mid: 6,200 nodes / 36,599
edges; large: 19,000 nodes / 244,732 edges).

## Query and method

The same BFS-dedup `UNION` (not `UNION ALL`) formulation D42-2 validated,
adapted from "shortest hops to one target" to "every node reachable within
N hops, and at what depth":

```sql
WITH RECURSIVE bfs(node_id, depth) AS (
    VALUES (%(start)s::integer, 0)
    UNION
    SELECT e.dst, bfs.depth + 1
    FROM bfs
    JOIN bh_edges e ON e.src = bfs.node_id
    WHERE bfs.depth < %(max_depth)s
)
SELECT node_id, MIN(depth) AS depth
FROM bfs
GROUP BY node_id
```

Two starting-point populations, at three hop limits (3, 5, 10):

- **Random users** (30 samples) — the realistic case, since most principals
  in a real domain have narrow reach (their own group memberships and
  little else).
- **Wide-fanout nodes** (the 3 highest-out-degree `AdminTo` sources, i.e.
  the synthetic IT-admin groups) — the deliberate worst case for *result-set
  size*, which is what this shape adds over `shortest_path`: a query that
  returns one row can never be the expensive case, a query whose whole job
  is enumerating a neighborhood can.

## Results

| Scale | Start population | Depth | Latency (median / p95 / max) | Reachable count (median / max) |
|---|---|---|---|---|
| mid | random | 3 | 0.24ms / 1.87ms / 2.97ms | 8.5 / 578 |
| mid | random | 5 | 0.20ms / 5.78ms / 7.92ms | 8.5 / 1073 |
| mid | random | 10 | 0.21ms / 29.5ms / 31.0ms | 8.5 / 1119 |
| mid | wide-fanout | 3 | — / — / 6.18ms | — / 1092 |
| mid | wide-fanout | 5 | — / — / 14.9ms | — / 1117 |
| mid | wide-fanout | 10 | — / — / 41.2ms | — / 1117 |
| large | random | 3 | 0.34ms / 18.0ms / 23.5ms | 19.5 / 2799 |
| large | random | 5 | 0.24ms / 59.9ms / 66.7ms | 19.5 / 3970 |
| large | random | 10 | 0.23ms / 312ms / 351ms | 19.5 / 3970 |
| large | wide-fanout | 3 | — / — / 29.9ms | — / 3950 |
| large | wide-fanout | 5 | — / — / 108ms | — / 3969 |
| large | wide-fanout | 10 | — / — / 343ms | — / 3969 |

(wide-fanout is only 3 samples per cell, so median/p95 are not meaningful —
min/max are reported instead; see the raw JSON for exact figures.)

No timeouts (30s cap) anywhere. `EXPLAIN (ANALYZE, BUFFERS)` on the
representative depth-10 query at large scale reports sub-millisecond
planner-side execution, consistent with D42-2's own finding that wall-clock
numbers here are dominated by Python/`psycopg` round-trip overhead, not
server-side cost.

**Reading this plainly**: the worst case measured — a wide-fanout node,
depth 10, large scale, returning 3,969 of 19,000 nodes (21% of the whole
graph) — completes in 343ms. That is slower than any `shortest_path`
number D42-2 measured (max 274ms), which matches the design doc's own
prediction that this shape has a different, size-dependent cost profile —
but it is still comfortably inside what a Worker/Supervisor round-trip
tolerates elsewhere in this system, and the growth from depth 3 to depth
10 is smooth (11ms → 108ms → 343ms for wide-fanout at large scale), not a
cliff.

**One implementation discrepancy, noted rather than silently reconciled:**
the query this report measures includes the start node itself in the
result set (depth 0). `control_plane/graph/queries.py`'s shipped
`paths_within_hops` filters depth 0 out, since a caller asking what an
identity can reach has no use for being told it can reach itself. That
makes every "reachable count" figure above one row wider than what the
production function actually returns. It does not change any latency
number or the shape of the cost curve — one row out of a few thousand is
not what these times are measuring — so the benchmark was not re-run for
it, but the discrepancy is real and is recorded here rather than glossed
over.

## What this does not settle

Same caveats D42-2 named, unchanged: two realistic-not-extreme scales, no
concurrency, no measurement of a hop limit larger than 10, and no
measurement against a graph shape deliberately different from this
generator's own skew assumptions (see 5.23, added below, for the
concurrency gap specifically). A hop limit past 10 was not tested because
nothing in the design calls for one — BloodHound-style attack-path
questions are conventionally bounded well under that in practice, and a
caller wanting more should get its own measurement rather than an
extrapolation from this one.

## Verdict

`paths_within_hops` clears the D42-1/D42-6 design's gate: implemented as
specified in `control_plane/graph/queries.py`, using the same BFS-dedup
formulation this report measured.
