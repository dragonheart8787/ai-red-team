"""D42-6 benchmark: "list everything reachable within N hops" over the same graph.

D42-2 (docs/D42_2_CTE_BENCHMARK.md) measured one query shape --
shortest-path-to-one-named-target -- and the design doc for D42-1/D42-6
(docs/D42_1_D42_6_DESIGN.md §2.6) is explicit that a second shape does not
inherit those numbers by assumption: "enumerating a bounded-hop
neighborhood is a different cost profile (the result set itself can be
large, where shortest_path returns one number)." This is that second
shape's own measurement, required before `paths_within_hops` may be added
to `control_plane/graph/queries.py`.

Reuses d42_bloodhound_cte_bench's graph generator and loader rather than a
second implementation of either -- the whole point of a shared generator is
that these numbers are comparable to D42-2's, not a second synthetic model
someone has to keep in sync by hand.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

import psycopg
from d42_bloodhound_cte_bench import (
    DB_DSN,
    SCALES,
    ScaleConfig,
    generate_graph,
    load_graph,
    percentile,
)

PATHS_WITHIN_HOPS_QUERY = """
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
"""


def timed_paths_query(
    conn: psycopg.Connection, *, start: int, max_depth: int, timeout_ms: int
) -> tuple[float | None, int | None]:
    """Returns (elapsed_seconds, reachable_node_count). elapsed is None on timeout."""
    with conn.cursor() as cur:
        cur.execute(f"SET LOCAL statement_timeout = {timeout_ms}")
        start_t = time.perf_counter()
        try:
            cur.execute(PATHS_WITHIN_HOPS_QUERY, {"start": start, "max_depth": max_depth})
            rows = cur.fetchall()
        except psycopg.errors.QueryCanceled:
            conn.rollback()
            return None, None
        elapsed = time.perf_counter() - start_t
        conn.commit()
        return elapsed, len(rows)


def run_benchmark(cfg: ScaleConfig, *, seed: int, n_samples: int, max_depths: list[int]) -> dict:
    print(f"[{cfg.name}] generating graph (seed={seed})...")
    g, domain_admins, users, guaranteed_reachable = generate_graph(cfg, seed=seed)
    n_nodes = len(g.node_kind)
    n_edges = len(g.edges)

    # Recover the IT admin groups' node ids the same way the generator's own
    # RNG stream produced them, so this script never re-derives graph
    # structure by hand -- it just re-runs generate_graph() (already done
    # above) and mines the loaded edge table for the wide-fanout group ids.
    with psycopg.connect(DB_DSN, autocommit=False) as conn:
        print(f"[{cfg.name}] loading into Postgres...")
        load_graph(conn, g)

        # Wide-fanout starting points: the AdminTo source with the most
        # distinct destinations is (one of) the IT admin groups -- the
        # worst-case shape for "how large can one bounded-hop neighborhood
        # get" without hand-tracking which node ids generate_graph() chose.
        with conn.cursor() as cur:
            cur.execute("""
                SELECT src, COUNT(*) AS fanout FROM bh_edges
                WHERE edge_type = 'AdminTo'
                GROUP BY src ORDER BY fanout DESC LIMIT 3
            """)
            wide_fanout_nodes = [row[0] for row in cur.fetchall()]
        conn.rollback()

        import random

        rng = random.Random(seed + 2)
        sample_users = rng.sample(users, min(n_samples, len(users)))

        per_depth: dict[int, dict] = {}
        for max_depth in max_depths:
            print(f"[{cfg.name}] max_depth={max_depth}: {len(sample_users)} random-user queries...")
            lats: list[float] = []
            sizes: list[int] = []
            timeouts = 0
            for u in sample_users:
                elapsed, size = timed_paths_query(
                    conn, start=u, max_depth=max_depth, timeout_ms=30_000,
                )
                if elapsed is None:
                    timeouts += 1
                    continue
                lats.append(elapsed)
                sizes.append(size)

            print(
                f"[{cfg.name}] max_depth={max_depth}: "
                f"{len(wide_fanout_nodes)} wide-fanout-node queries..."
            )
            wide_lats: list[float] = []
            wide_sizes: list[int] = []
            wide_timeouts = 0
            for node in wide_fanout_nodes:
                elapsed, size = timed_paths_query(
                    conn, start=node, max_depth=max_depth, timeout_ms=30_000,
                )
                if elapsed is None:
                    wide_timeouts += 1
                    continue
                wide_lats.append(elapsed)
                wide_sizes.append(size)

            per_depth[max_depth] = {
                "random_users": {
                    "n_samples": len(sample_users),
                    "n_timeouts_30s": timeouts,
                    "latency_seconds": {
                        "min": min(lats) if lats else None,
                        "median": statistics.median(lats) if lats else None,
                        "p95": percentile(lats, 0.95) if lats else None,
                        "max": max(lats) if lats else None,
                    },
                    "reachable_count": {
                        "min": min(sizes) if sizes else None,
                        "median": statistics.median(sizes) if sizes else None,
                        "max": max(sizes) if sizes else None,
                    },
                },
                "wide_fanout_nodes": {
                    "description": "the highest-AdminTo-fanout source nodes -- worst case "
                                    "for result-set size, not a random sample",
                    "n_samples": len(wide_fanout_nodes),
                    "n_timeouts_30s": wide_timeouts,
                    "latency_seconds": {
                        "min": min(wide_lats) if wide_lats else None,
                        "max": max(wide_lats) if wide_lats else None,
                    },
                    "reachable_count": {
                        "min": min(wide_sizes) if wide_sizes else None,
                        "max": max(wide_sizes) if wide_sizes else None,
                    },
                },
            }

        # EXPLAIN ANALYZE for one representative query at the largest depth tested.
        rep_depth = max(max_depths)
        with conn.cursor() as cur:
            cur.execute(
                f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {PATHS_WITHIN_HOPS_QUERY}",
                {"start": sample_users[0], "max_depth": rep_depth},
            )
            explain_text = "\n".join(row[0] for row in cur.fetchall())
        conn.rollback()

    return {
        "scale": cfg.name,
        "seed": seed,
        "graph": {"n_nodes": n_nodes, "n_edges": n_edges},
        "per_max_depth": per_depth,
        "explain_analyze_at_max_depth": {"max_depth": rep_depth, "plan": explain_text},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scales", nargs="+", default=["mid", "large"], choices=list(SCALES))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--max-depths", nargs="+", type=int, default=[3, 5, 10])
    parser.add_argument(
        "--out", type=Path,
        default=Path("docs/d42_bench/d42_6_paths_within_hops_bench.json"),
    )
    args = parser.parse_args()

    results = []
    for scale_name in args.scales:
        cfg = SCALES[scale_name]
        results.append(
            run_benchmark(
                cfg, seed=args.seed, n_samples=args.samples, max_depths=args.max_depths,
            )
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {args.out}")
    for r in results:
        print(f"[{r['scale']}] nodes={r['graph']['n_nodes']} edges={r['graph']['n_edges']}")
        for depth, stats in r["per_max_depth"].items():
            ru = stats["random_users"]
            wf = stats["wide_fanout_nodes"]
            ru_lat, ru_reach = ru["latency_seconds"], ru["reachable_count"]
            wf_lat, wf_reach = wf["latency_seconds"], wf["reachable_count"]
            print(
                f"  depth={depth}: random median={ru_lat['median']:.4f}s "
                f"max={ru_lat['max']:.4f}s reach_median={ru_reach['median']} | "
                f"wide-fanout max={wf_lat['max']:.4f}s reach_max={wf_reach['max']}"
            )


if __name__ == "__main__":
    main()
