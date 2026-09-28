"""D42-2 benchmark: recursive-CTE reachability over a synthetic AD-shaped graph.

Standalone experiment, not part of the application. Connects to a throwaway
database (``bh_bench``) created outside any migration, never ``cyberorch`` --
this script does not touch, and cannot reach, any table the control plane
owns. It exists to answer one question the D42 ADR (§2.2/D42-2) left open:
does a Postgres recursive CTE answer "is there a path from user X to Domain
Admins" fast enough, on a graph shaped and sized like a real Active
Directory collection, to make purpose-built CTEs a credible alternative to
adopting Neo4j.

Graph model
-----------
Nodes: user / computer / group. Edges are the union of the relationship
types a BloodHound-style collector reports (MemberOf, AdminTo, and a
scattering of ACL-abuse edges: GenericAll / WriteDacl / Owns /
ForceChangePassword / AddMember), all stored as one directed edge type
for the purpose of this query: "src can reach/control dst". This mirrors
the actual baseline query BloodHound's own UI runs for "shortest path to
Domain Admins" -- a variable-length path over the union of these edge
types with no per-edge-type composition logic -- so it is a fair stand-in
for that specific query shape. It is *not* a faithful model of BloodHound's
full edge-composition semantics (e.g. session-hijack edges run in the
reverse direction of a HasSession edge); that distinction does not change
the shape of the traversal this benchmark measures, and is out of scope
per the ADR (which asks only whether the engine can do this query fast
enough, not whether this script computes real attack paths).

Membership/administration sizes are drawn from a heavy-tailed (Pareto)
distribution rather than uniformly at random, because real AD group sizes
and admin fan-out are famously skewed (a handful of "Domain Users"-shaped
groups hold nearly everyone; a handful of "IT" groups administer most of
the fleet) -- that skew, not raw node/edge count, is what makes a
"shortest path to Domain Admins" query expensive: it is what creates the
hub nodes a naive recursive CTE re-expands over and over.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path

import psycopg

#: Deliberately not `cyberorch`, and not any role from `db/roles.sql` --
#: this experiment has nothing to do with the application schema or its RLS
#: boundary, and must not be able to touch either even by accident. Set up
#: once, locally, with (as postgres superuser):
#:   CREATE ROLE bh_bench_user LOGIN PASSWORD '<throwaway, local-only>';
#:   CREATE DATABASE bh_bench OWNER bh_bench_user;
#: then export BH_BENCH_DSN accordingly. Nothing here is a secret worth
#: committing, so it is read from the environment rather than hardcoded.
DB_DSN = os.environ.get("BH_BENCH_DSN", "postgresql://bh_bench_user@127.0.0.1:5432/bh_bench")

ACL_EDGE_TYPES = ("GenericAll", "WriteDacl", "Owns", "ForceChangePassword", "AddMember")


@dataclass(frozen=True)
class ScaleConfig:
    name: str
    n_users: int
    n_computers: int
    n_groups: int
    n_da_members: int
    n_dcs: int
    n_it_groups: int


SCALES = {
    "mid": ScaleConfig(
        name="mid",
        n_users=5000,
        n_computers=800,
        n_groups=400,
        n_da_members=8,
        n_dcs=3,
        n_it_groups=5,
    ),
    "large": ScaleConfig(
        name="large",
        n_users=15000,
        n_computers=3000,
        n_groups=1000,
        n_da_members=15,
        n_dcs=5,
        n_it_groups=8,
    ),
}


@dataclass
class Graph:
    node_kind: list[str] = field(default_factory=list)  # index = node id
    node_name: list[str] = field(default_factory=list)
    edges: list[tuple[int, int, str]] = field(default_factory=list)  # (src, dst, type)

    def add_node(self, kind: str, name: str) -> int:
        node_id = len(self.node_kind)
        self.node_kind.append(kind)
        self.node_name.append(name)
        return node_id


def pareto_size(rng: random.Random, *, minimum: int, maximum: int, alpha: float = 1.5) -> int:
    """A heavy-tailed size in [minimum, maximum], most mass near ``minimum``."""
    raw = rng.paretovariate(alpha)
    size = minimum + int((raw - 1) * (maximum - minimum) / 4)
    return max(minimum, min(maximum, size))


def generate_graph(cfg: ScaleConfig, *, seed: int) -> tuple[Graph, int, list[int], set[int]]:
    """Build the synthetic graph.

    Returns (graph, domain_admins_id, all_user_ids, guaranteed_reachable_users).
    The last element is a deliberately-planted set of users with a known,
    real path to Domain Admins (see the nested-IT-group step below) -- used
    to also measure "found" query latency, since a uniformly random user in
    a real domain usually has *no* path at all, and reporting only that case
    would hide the found-path cost entirely.
    """
    rng = random.Random(seed)
    g = Graph()

    users = [g.add_node("user", f"user_{i}") for i in range(cfg.n_users)]
    computers = [g.add_node("computer", f"computer_{i}") for i in range(cfg.n_computers)]

    domain_users = g.add_node("group", "DOMAIN_USERS")
    domain_computers = g.add_node("group", "DOMAIN_COMPUTERS")
    domain_admins = g.add_node("group", "DOMAIN_ADMINS")
    normal_groups = [g.add_node("group", f"group_{i}") for i in range(cfg.n_groups - 3)]
    all_groups = [domain_users, domain_computers, domain_admins, *normal_groups]

    # Mega-group membership: most users/computers land in the big catch-all group.
    for u in users:
        if rng.random() < 0.9:
            g.edges.append((u, domain_users, "MemberOf"))
    for c in computers:
        if rng.random() < 0.9:
            g.edges.append((c, domain_computers, "MemberOf"))

    # Domain Admins: a small, explicit membership -- the actual target set.
    da_members = rng.sample(users, cfg.n_da_members)
    for u in da_members:
        g.edges.append((u, domain_admins, "MemberOf"))

    # Normal groups: heavy-tailed sizes, principals joined by weighted (skewed) draw.
    group_weights = [
        pareto_size(rng, minimum=2, maximum=max(3, cfg.n_users // 20)) for _ in normal_groups
    ]
    principals = users + computers
    group_members: dict[int, list[int]] = {}
    for group, weight in zip(normal_groups, group_weights, strict=True):
        members = rng.sample(principals, min(weight, len(principals)))
        group_members[group] = members
        for m in members:
            g.edges.append((m, group, "MemberOf"))

    # Nested group membership: a DAG (later index nests into an earlier one only).
    for idx, group in enumerate(normal_groups):
        if idx > 0 and rng.random() < 0.15:
            parent = normal_groups[rng.randrange(idx)]
            g.edges.append((group, parent, "MemberOf"))

    # IT admin groups: wide AdminTo fan-out over the computer fleet.
    it_groups = rng.sample(normal_groups, cfg.n_it_groups)
    for it_group in it_groups:
        frac = rng.uniform(0.3, 0.6)
        targets = rng.sample(computers, int(frac * len(computers)))
        for comp in targets:
            g.edges.append((it_group, comp, "AdminTo"))

    # A real-world pattern this graph would otherwise miss entirely: one (or
    # two, at "large" scale) of the IT admin groups is *itself* nested into
    # Domain Admins (a "Tier 0 admins" group that was, at some point, added
    # to DA and never removed). Anyone in that group has a genuine, findable
    # path -- this is what "guaranteed_reachable" below samples from.
    n_nested = 1 if cfg.name == "mid" else 2
    nested_it_groups = rng.sample(it_groups, n_nested)
    for grp in nested_it_groups:
        g.edges.append((grp, domain_admins, "MemberOf"))
    users_set = set(users)
    guaranteed_reachable = {
        m for grp in nested_it_groups for m in group_members.get(grp, []) if m in users_set
    }

    # Domain controllers: directly administered by Domain Admins.
    dcs = rng.sample(computers, cfg.n_dcs)
    for dc in dcs:
        g.edges.append((domain_admins, dc, "AdminTo"))

    # Local/delegated admin noise: every computer gets a couple of extra admins.
    for comp in computers:
        n_extra = rng.randint(1, 3)
        for _ in range(n_extra):
            admin = rng.choice(principals if rng.random() < 0.3 else users)
            g.edges.append((admin, comp, "AdminTo"))

    # ACL-abuse edges: sparse, mostly random noise, some deliberately near the target
    # to guarantee a handful of realistically short paths exist (real environments
    # always have a few, which is the entire premise of the attack-path query).
    acl_edge_count = int(0.005 * (cfg.n_users + cfg.n_groups))
    near_target_pool = [domain_admins, *it_groups, *da_members]
    for _ in range(acl_edge_count):
        src = rng.choice(principals)
        if rng.random() < 0.3:
            dst = rng.choice(near_target_pool)
        else:
            dst = rng.choice(all_groups + computers)
        if src == dst:
            continue
        edge_type = rng.choice(ACL_EDGE_TYPES)
        g.edges.append((src, dst, edge_type))

    return g, domain_admins, users, guaranteed_reachable


def load_graph(conn: psycopg.Connection, g: Graph) -> None:
    conn.execute("DROP TABLE IF EXISTS bh_edges")
    conn.execute("DROP TABLE IF EXISTS bh_nodes")
    conn.execute(
        """
        CREATE TABLE bh_nodes (
            id   INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            name TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE bh_edges (
            id        BIGSERIAL PRIMARY KEY,
            src       INTEGER NOT NULL,
            dst       INTEGER NOT NULL,
            edge_type TEXT NOT NULL
        )
        """
    )
    with conn.cursor().copy("COPY bh_nodes (id, kind, name) FROM STDIN") as copy:
        for i, (kind, name) in enumerate(zip(g.node_kind, g.node_name, strict=True)):
            copy.write_row((i, kind, name))
    with conn.cursor().copy("COPY bh_edges (src, dst, edge_type) FROM STDIN") as copy:
        for src, dst, edge_type in g.edges:
            copy.write_row((src, dst, edge_type))
    conn.execute("CREATE INDEX bh_edges_src_idx ON bh_edges (src)")
    conn.execute("ANALYZE bh_nodes")
    conn.execute("ANALYZE bh_edges")
    conn.commit()


BFS_QUERY = """
WITH RECURSIVE bfs(node_id, depth) AS (
    VALUES (%(start)s::integer, 0)
    UNION
    SELECT e.dst, bfs.depth + 1
    FROM bfs
    JOIN bh_edges e ON e.src = bfs.node_id
    WHERE bfs.depth < %(max_depth)s
)
SELECT MIN(depth) AS shortest_hops
FROM bfs
WHERE node_id = %(target)s
"""

# The naive, path-array-tracking version -- kept for comparison. Cycle
# prevention is per-path (a node can be re-visited by a different path),
# which is what makes it blow up on hub-shaped graphs: the number of
# distinct paths to a popular node grows combinatorially with depth.
NAIVE_QUERY = """
WITH RECURSIVE walk(node_id, depth, visited) AS (
    SELECT %(start)s::integer, 0, ARRAY[%(start)s::integer]
    UNION ALL
    SELECT e.dst, w.depth + 1, w.visited || e.dst
    FROM walk w
    JOIN bh_edges e ON e.src = w.node_id
    WHERE w.depth < %(max_depth)s
      AND NOT e.dst = ANY(w.visited)
)
SELECT MIN(depth) AS shortest_hops
FROM walk
WHERE node_id = %(target)s
"""


def timed_query(
    conn: psycopg.Connection, sql: str, params: dict, *, timeout_ms: int,
) -> tuple[float | None, int | None]:
    """Returns (elapsed_seconds, shortest_hops_or_None). elapsed is None on timeout."""
    with conn.cursor() as cur:
        cur.execute(f"SET LOCAL statement_timeout = {timeout_ms}")
        start = time.perf_counter()
        try:
            cur.execute(sql, params)
            row = cur.fetchone()
        except psycopg.errors.QueryCanceled:
            conn.rollback()
            return None, None
        elapsed = time.perf_counter() - start
        conn.commit()
        return elapsed, (row[0] if row else None)


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    k = (len(values) - 1) * p
    f, c = int(k), min(int(k) + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] + (values[c] - values[f]) * (k - f)


def run_benchmark(cfg: ScaleConfig, *, seed: int, n_samples: int, max_depth: int) -> dict:
    print(f"[{cfg.name}] generating graph (seed={seed})...")
    g, domain_admins, users, guaranteed_reachable = generate_graph(cfg, seed=seed)
    n_nodes = len(g.node_kind)
    n_edges = len(g.edges)
    edge_type_counts: dict[str, int] = {}
    for _, _, et in g.edges:
        edge_type_counts[et] = edge_type_counts.get(et, 0) + 1
    print(f"[{cfg.name}] {n_nodes} nodes, {n_edges} edges: {edge_type_counts}")

    with psycopg.connect(DB_DSN, autocommit=False) as conn:
        print(f"[{cfg.name}] loading into Postgres...")
        load_graph(conn, g)

        rng = random.Random(seed + 1)
        sample_users = rng.sample(users, min(n_samples, len(users)))
        guaranteed_list = sorted(guaranteed_reachable)
        known_positive_users = rng.sample(guaranteed_list, min(20, len(guaranteed_list)))

        def run_batch(label: str, batch: list[int]) -> tuple[list[float], list[int], int]:
            print(
                f"[{cfg.name}] running {len(batch)} BFS queries ({label}, max_depth={max_depth})..."
            )
            lats: list[float] = []
            hops: list[int] = []
            n_timeout = 0
            for u in batch:
                elapsed, h = timed_query(
                    conn, BFS_QUERY,
                    {"start": u, "target": domain_admins, "max_depth": max_depth},
                    timeout_ms=30_000,
                )
                if elapsed is None:
                    n_timeout += 1
                    continue
                lats.append(elapsed)
                if h is not None:
                    hops.append(h)
            return lats, hops, n_timeout

        latencies, hops_found, timeouts = run_batch("audit sweep, random users", sample_users)
        pos_latencies, pos_hops_found, pos_timeouts = run_batch(
            "known-positive users", known_positive_users
        )

        # EXPLAIN ANALYZE for one representative query.
        rep_user = sample_users[0]
        with conn.cursor() as cur:
            cur.execute(
                f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {BFS_QUERY}",
                {"start": rep_user, "target": domain_admins, "max_depth": max_depth},
            )
            explain_text = "\n".join(row[0] for row in cur.fetchall())
        conn.rollback()

        # Naive path-array variant, at the *same* max_depth as the BFS query above --
        # a handful of audit-sweep samples plus a handful of known-positive samples,
        # since a real path (not just a bounded no-path search) is where per-path
        # duplication has the most edges to multiply across.
        naive_batch = sample_users[:5] + known_positive_users[:5]
        print(
            f"[{cfg.name}] running naive path-array comparison "
            f"({len(naive_batch)} samples, max_depth={max_depth})..."
        )
        naive_latencies: list[float] = []
        naive_timeouts = 0
        for u in naive_batch:
            elapsed, _hops = timed_query(
                conn, NAIVE_QUERY,
                {"start": u, "target": domain_admins, "max_depth": max_depth},
                timeout_ms=20_000,
            )
            if elapsed is None:
                naive_timeouts += 1
            else:
                naive_latencies.append(elapsed)

    result = {
        "scale": cfg.name,
        "seed": seed,
        "graph": {
            "n_nodes": n_nodes,
            "n_edges": n_edges,
            "edge_type_counts": edge_type_counts,
            "n_users": cfg.n_users,
            "n_computers": cfg.n_computers,
            "n_groups": cfg.n_groups,
            "n_guaranteed_reachable_users": len(guaranteed_reachable),
        },
        "bfs_query_audit_sweep": {
            "description": "uniformly random users -- the realistic 'sweep everyone' case, "
                            "where most queries are expected to find no path at all",
            "max_depth": max_depth,
            "n_samples": len(sample_users),
            "n_timeouts_30s": timeouts,
            "n_paths_found": len(hops_found),
            "n_paths_not_found": len(latencies) - len(hops_found),
            "latency_seconds": {
                "min": min(latencies) if latencies else None,
                "median": statistics.median(latencies) if latencies else None,
                "p95": percentile(latencies, 0.95) if latencies else None,
                "max": max(latencies) if latencies else None,
            },
            "hops_found": {
                "min": min(hops_found) if hops_found else None,
                "median": statistics.median(hops_found) if hops_found else None,
                "max": max(hops_found) if hops_found else None,
            },
            "explain_analyze": explain_text,
        },
        "bfs_query_known_positive": {
            "description": "deliberately-planted users with a real path to Domain Admins "
                            "(member of an IT-admin group nested into DA) -- "
                            "measures found-path cost",
            "max_depth": max_depth,
            "n_samples": len(known_positive_users),
            "n_timeouts_30s": pos_timeouts,
            "n_paths_found": len(pos_hops_found),
            "latency_seconds": {
                "min": min(pos_latencies) if pos_latencies else None,
                "median": statistics.median(pos_latencies) if pos_latencies else None,
                "p95": percentile(pos_latencies, 0.95) if pos_latencies else None,
                "max": max(pos_latencies) if pos_latencies else None,
            },
            "hops_found": {
                "min": min(pos_hops_found) if pos_hops_found else None,
                "median": statistics.median(pos_hops_found) if pos_hops_found else None,
                "max": max(pos_hops_found) if pos_hops_found else None,
            },
        },
        "naive_path_array_query": {
            "description": "cycle-prevention via a per-path visited array, at the same max_depth "
                            "as the BFS query -- 5 audit-sweep + 5 known-positive samples",
            "max_depth": max_depth,
            "n_samples": len(naive_batch),
            "n_timeouts_20s": naive_timeouts,
            "latency_seconds": {
                "min": min(naive_latencies) if naive_latencies else None,
                "max": max(naive_latencies) if naive_latencies else None,
            },
        },
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scales", nargs="+", default=["mid", "large"], choices=list(SCALES))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--samples", type=int, default=50)
    parser.add_argument("--max-depth", type=int, default=10)
    parser.add_argument("--out", type=Path, default=Path("docs/d42_bench/d42_2_cte_bench.json"))
    args = parser.parse_args()

    results = []
    for scale_name in args.scales:
        cfg = SCALES[scale_name]
        results.append(
            run_benchmark(cfg, seed=args.seed, n_samples=args.samples, max_depth=args.max_depth)
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {args.out}")
    for r in results:
        bfs = r["bfs_query_audit_sweep"]
        pos = r["bfs_query_known_positive"]
        bfs_lat, pos_lat = bfs["latency_seconds"], pos["latency_seconds"]
        print(
            f"[{r['scale']}] nodes={r['graph']['n_nodes']} edges={r['graph']['n_edges']} | "
            f"audit sweep: median={bfs_lat['median']:.4f}s p95={bfs_lat['p95']:.4f}s "
            f"max={bfs_lat['max']:.4f}s found={bfs['n_paths_found']}/{bfs['n_samples']} | "
            f"known-positive: median={pos_lat['median']:.4f}s max={pos_lat['max']:.4f}s "
            f"found={pos['n_paths_found']}/{pos['n_samples']}"
        )


if __name__ == "__main__":
    main()
