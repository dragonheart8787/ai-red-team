# D42-2: Postgres recursive-CTE benchmark for BloodHound-shaped queries

This closes the measurement the D42 ADR (`docs/ADR_BLOODHOUND_NEO4J.md` §2.2)
left open, per the explicit decision: measure before deciding D42-5, rather
than proceed on the architectural argument alone.

**Question asked**: can a Postgres recursive CTE answer "is there a path
from user X to Domain Admins" fast enough, on a graph shaped and sized like
a real BloodHound collection, to make a purpose-built CTE a credible
alternative to Neo4j for this specific query?

**Script**: `scripts/bench/d42_bloodhound_cte_bench.py`. **Raw results**:
`docs/d42_bench/d42_2_cte_bench.json`. Both committed, following this
project's existing precedent (D40) of keeping raw run data alongside the
report it supports, so the numbers below can be re-derived rather than
taken on faith.

This is a standalone experiment against a throwaway `bh_bench` database
(a dedicated local role/database created outside any migration) — it does
not touch, and cannot reach, `cyberorch` or any table the control plane
owns.

## Method

A synthetic AD-shaped control graph: nodes are `user`/`computer`/`group`;
edges are the union of `MemberOf`, `AdminTo`, and a sparse set of
ACL-abuse edges (`GenericAll`/`WriteDacl`/`Owns`/`ForceChangePassword`/
`AddMember`), all treated as one directed "src can reach/control dst"
relation — which matches the actual baseline query BloodHound's own UI
runs for "shortest path to Domain Admins" (a variable-length path over the
union of these edge types, with no per-edge-type composition logic). Group
and admin-fan-out sizes are drawn from a heavy-tailed distribution rather
than uniformly, because that skew — not raw node/edge count — is what
makes this query shape expensive in practice. Full generation logic and
caveats are in the script's module docstring; this is a stand-in for the
query *shape*, not a faithful model of BloodHound's full edge-composition
semantics (see the ADR §2.2/§4.1 for why that distinction doesn't change
what this benchmark is measuring).

Two scales, both realistic mid/large-enterprise sizes rather than
theoretical extremes:

| Scale | Users | Computers | Groups | Nodes | Edges |
|---|---|---|---|---|---|
| mid | 5,000 | 800 | 400 | 6,200 | 36,599 |
| large | 15,000 | 3,000 | 1,000 | 19,000 | 244,732 |

Two query formulations were benchmarked:

1. **BFS-dedup** (the correct formulation): `UNION` (not `UNION ALL`) on
   `(node_id, depth)`, which bounds growth polynomially rather than
   letting duplicate paths to the same node multiply.
2. **Naive path-array**: cycle prevention via a per-path `visited` array —
   the formulation someone would likely reach for first, and the one the
   ADR flagged as a real risk.

Each was run against two populations of starting users: a uniformly
random **audit sweep** (the realistic case — most users in a real domain
have no path to Domain Admins at all) and a set of **known-positive**
users with a deliberately-planted real path (a member of an IT-admin
group nested into Domain Admins), so the "found" cost is measured
directly rather than inferred from a handful of lucky random draws.

## Results: BFS-dedup formulation (`max_depth = 10`)

| Scale | Population | n | found | median | p95 | max | hops (median) |
|---|---|---|---|---|---|---|---|
| mid | audit sweep (random) | 50 | 4/50 | 0.12 ms | 24.8 ms | 30.0 ms | 4 |
| mid | known-positive | 20 | 20/20 | 29.6 ms | 30.1 ms | 30.9 ms | 2 |
| large | audit sweep (random) | 50 | 11/50 | 0.23 ms | 234.2 ms | 249.8 ms | 3 |
| large | known-positive | 20 | 20/20 | 244.0 ms | 262.8 ms | 274.1 ms | 2 |

No timeouts (30 s cap) at either scale. `EXPLAIN (ANALYZE, BUFFERS)` on a
representative query: mid scale, 0.062 ms actual planner-reported time,
11 shared buffer hits; large scale, 0.079 ms, 62 shared buffer hits — both
orders of magnitude below the wall-clock numbers above, which include
Python-side round-trip and `psycopg` overhead, not just server execution.

Reading this plainly: **the "no path exists" case is the cheap one**
(sub-millisecond median at both scales, since most random users' BFS
frontier collapses quickly), and **the "path exists" case is the
expensive one**, because finding it means expanding the frontier out to
the full search radius before the deduplicated set stabilizes. Even so,
worst case at the large scale (19k nodes, 245k edges) was 274 ms for a
single query. A full sweep of the whole `large`-scale user population
(15,000 users) at the audit-sweep median (0.23 ms) would cost roughly
3.5 seconds sequentially — and the audit-sweep case, not the
known-positive case, is what a full-domain sweep actually looks like,
since a real domain's population is overwhelmingly users *without* a path.

## Results: naive path-array formulation (same `max_depth = 10`)

| Scale | n | timeouts (20 s cap) | min | max (of non-timeouts) |
|---|---|---|---|---|
| mid | 10 (5 audit-sweep + 5 known-positive) | 0 | 0.27 ms | **8.74 s** |
| large | 10 (5 audit-sweep + 5 known-positive) | **7 of 10** | 0.37 ms | 0.89 ms |

This is the concrete number the ADR's §2.2 concern was about, reproduced
rather than assumed: at `mid` scale the naive formulation is already up to
~280x slower than the BFS-dedup version in its worst observed case (8.74 s
vs 30.9 ms), and at `large` scale it **times out on 7 of 10 samples** at a
20-second cap — a formulation that works at small scale and becomes
unusable exactly where it would matter, which is the well-known failure
mode of per-path cycle prevention on a graph with converging/diverging
("diamond") structure: the number of distinct paths reaching a popular
node grows combinatorially with depth, even though the number of *nodes*
does not.

**This is the one qualification on "Postgres is fast enough" worth
stating plainly: it is fast enough with the correct query formulation,
and unusable with the naive one someone would likely write first.** That
is an engineering-discipline cost (this has to be gotten right and kept
right, e.g. in review, as more BloodHound-shaped queries are added), not
a performance cost — but it is a real cost the "recursive CTEs handle it
awkwardly" framing in the ADR was gesturing at, now with a number behind
it.

## Reading these numbers against D42-5

The measured numbers support the ADR's tentative lean: for the specific
query shape BloodHound needs ("is there a path," "what's the shortest
path," bounded by a sane hop limit), a correctly-written Postgres
recursive CTE stays well under 300 ms even at a large-enterprise-scale,
skewed-degree graph (19k nodes / 245k edges) — comfortably inside what a
Worker/Supervisor/Reviewer round-trip already tolerates elsewhere in this
system. Nothing measured here forces Neo4j on performance grounds at
these scales.

What this benchmark does **not** settle:

- **Scale ceiling.** Both scales tested are realistic, not extreme. A very
  large environment (100k+ users, millions of edges) was not measured; the
  BFS-dedup query's cost is dominated by frontier size at the depth where
  the path is found, so its scaling behavior at that range is not implied
  by these two points — a genuinely bigger graph would need its own run,
  not an extrapolation.
- **Concurrency.** All queries ran sequentially, single connection. A real
  audit sweep issued as N concurrent Worker-driven queries against a live
  `cyberorch`-sized Postgres instance, under whatever else is running on
  it, was not modeled.
- **Query variety.** Only "shortest path to one named target group" was
  benchmarked. "List all paths under N hops" or "all users with any path
  to any Tier-0 asset" are different query shapes the ADR mentions as
  candidates and were not measured here.

These are exactly the caveats the ADR's own D42-2 framing anticipated
("architectural argument vs. measured comparison") — the measurement now
exists for the specific case asked for; a decision to extend BloodHound
support beyond that case should get its own follow-up measurement rather
than assuming these numbers generalize.

## What this document does not do

No code, schema, migration, or Rego in the application was touched. The
benchmark's database (`bh_bench`) and role are local, throwaway, and
disjoint from `cyberorch`'s schema and roles — nothing here changes, or is
read by, anything D5/D25/D39's role-separation or RLS boundary covers.
