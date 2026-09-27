# D42-1 / D42-6 implementation design

Status: **design only. No code, schema, migration, or Rego change is made by
this document.** Builds directly on decisions already signed off in
`docs/ADR_BLOODHOUND_NEO4J.md` (D42-1 Option C, D42-3 Option A, D42-5:
Postgres-only) and `docs/D42_2_CTE_BENCHMARK.md` — this is not a second
ADR pass, it is the concrete schema/interface design for implementing
those two decisions, plus the three additional requirements raised against
the benchmark report.

## 0. Two citation corrections, made before anything else

Checked against the actual tree while writing this, and worth stating
plainly rather than quietly using the corrected version without saying so:

**D16 is not a database constraint.** It is a refuse-at-write guard in
application code: `register_scope_object` (`control_plane/registry/
scope_registry.py`) calls `canonicalize_scope_value` and raises
`ScopeValueError` if a scope object's value cannot be canonicalized, rather
than storing it and leaving every reader to guess. That is still the right
model for one piece of this design (§1.2 below), just not a schema-level
one. The actual precedent in this codebase for **"enforced by the schema
itself rather than by whoever writes the row"** is the emergency-overlay
monotonicity rule in `db/migrations/versions/0001_core_schema.py`:

```sql
CONSTRAINT emergency_overlay_can_only_tighten CHECK (
    layer <> 'emergency_overlay' OR (
        NOT (document ? 'scope_allow')
        AND NOT jsonb_path_exists(document, '$.actions.* ? (@ == "ALLOW")')
    )
)
```

That is the pattern §1.1 below actually follows.

**I6b/I6c do not already say "collection review is a different question from
action review."** I6b (Attribute Non-Escalation) and I6c (Trust
Monotonicity), per `ARCHITECTURE.md`'s invariant table, are about which
classification tier may satisfy an authorization prerequisite and which
direction a classification may move — not about review categories. The
collection-vs-action review distinction in §2.8 below is a new distinction
this design introduces, in the same spirit as I6b/I6c's tiering discipline,
not a restatement of them.

---

## 1. D42-1 — `ad_domain` scope, Option C (collection-only authorization)

### 1.1 Schema: no new column, one new CHECK constraint

`scope_registry.type` already includes `'ad_domain'` in its CHECK
(`db/migrations/versions/0001_core_schema.py:91-92`) — it has never been
usable, but the column accepts it today. `allowed_actions` is a plain
`TEXT[]`. Option C's entire authorization rule — *an `ad_domain` scope
object may only ever grant `ad.collect`, never anything else* — becomes a
schema-level guarantee with one constraint, added in the new migration:

```sql
ALTER TABLE scope_registry ADD CONSTRAINT ad_domain_collection_only CHECK (
    type <> 'ad_domain' OR allowed_actions <@ ARRAY['ad.collect']::TEXT[]
);
```

This is the real backstop. Whatever OPA, the resolver, or a future caller
of `register_scope_object` believes, an `ad_domain` row naming any action
besides `ad.collect` cannot exist in the table — the same shape as
`emergency_overlay_can_only_tighten`, applied to this invariant.

### 1.2 `register_scope_object`: refuse early too, for a better error

The constraint above is what actually holds the line; a guard in
`register_scope_object` (mirroring D16's own reasoning — refuse at the one
write path rather than let a constraint violation surface three frames
down as a bare Postgres error) turns a `CheckViolation` into a message that
names the actual mistake:

```python
if type == "ad_domain" and set(allowed_actions) - {"ad.collect"}:
    raise ScopeValueError(
        f"ad_domain scope objects may only grant ad.collect (D42-1); "
        f"refused {sorted(set(allowed_actions) - {'ad.collect'})}"
    )
```

Belt and suspenders, deliberately: the CHECK constraint is what makes this
true even if this guard is ever bypassed or forgotten; the guard just makes
the common case fail with a legible message.

### 1.3 New action: `ad.collect`

Namespace `ad.*`, matching the possible-future namespace `ARCHITECTURE.md`
§9 row E already names. One action in the namespace for now — no `ad.*`
sub-verbs are being introduced, since there is exactly one operation
(`ad.collect`) and inventing more would be speculative surface the way §2
of the ADR already warned against for the rest of this build.

### 1.4 Worker schema: `ad_domain` joins `TARGET_TYPES`

`agents/llm/worker_base.py`'s `TARGET_TYPES = ("ip", "cidr", "fqdn", "url")`
excludes `ad_domain` today for a reason stated in its own comment: *"MVP-
Kernel's only tool is a network scanner and offering a type no adapter can
execute invites a proposal that dies at the Tool Gateway instead of being
refused up front."* That reason no longer holds once `ad.collect` has an
adapter (§2.1). The change is one line:

```python
TARGET_TYPES = ("ip", "cidr", "fqdn", "url", "ad_domain")
```

Nothing else about the proposal schema changes. `action` is still an enum
over the actions the offered scope candidates actually allow (§2.9's
review-category distinction is enforced downstream, not by narrowing what
the Worker can name), and `scope_object_id` is still an enum over offered
candidates — a Worker offered no `ad_domain` scope object simply has no
candidate to select, the same as any other type today.

### 1.5 Authorization: no change to `scope_covers_target` itself

Checked against `control_plane/canonicalizer/authorization.py` and
`containment.py`: an `ad_domain` scope object already falls to the
catch-all exact-match rule (`child_type == parent_type and child_value ==
parent_value`, same bucket as `url` — D25 §2.2 already refused to invent
containment arithmetic for either). Authorization for an `ad.collect`
proposal against an `ad_domain` scope object is **already** just "does the
target's `ad_domain` identity string equal the scope object's value, and
does the scope object's `allowed_actions` include `ad.collect`" — the
existing generic resolver logic, unmodified. §1.1's constraint is what
prevents that same scope object from also being read as authorizing
anything else; the resolver does not need to know Option C exists.

### 1.6 Budget: `address_count` stays 1, and that is correct — not a gap to patch

The ADR's §1.2 described I3 as having "no way to size an `ad_domain`
target." Restated more precisely now that the shape is concrete: **that is
not a bug to patch, it is the correct behavior**, for the same reason
`address_count` already returns 1 for `fqdn` and `url` — one identity was
named, and `CanonicalTarget.address_count`'s own docstring is explicit that
it answers "how many addresses does this *identity* name," never "how many
things might this touch once it runs" (that reading is the v0.2 bug it
exists to prevent). `ad.collect`'s actual blast radius is bounded by a
**budget** dimension, not a target-count dimension — exactly Option C's own
resolution, just previously stated as an open problem rather than a design.

Concretely: `Budget.max_duration_seconds` (already the universal §4.6
dimension every tool gets) is the primary bound, enforced the same way
nmap's `--host-timeout` and the sandbox kill both enforce it (§2.1). No
change to `Budget`, no change to the I3 Rego rule, no carve-out. `max_targets`
for an `ad.collect` proposal is 1, same as any other non-`cidr` identity,
and it is telling the truth: one domain was named.

### 1.7 Metadata classification: no new write path — by omission, not by tier-tagging

The ADR's §1.6 said discovered entities should enter the system "as
`OBSERVED`, never `AUTHORITATIVE`." Checked against the actual code rather
than assumed: **nothing in this system today writes an `OBSERVED`-tier
`metadata_registry` row automatically from a tool run.** `register_metadata`
(`control_plane/registry/metadata_registry.py`) requires a
`registry_admin_scope` connection and is called only by live-run scripts
simulating an Engagement Manager — never by `dispatch_scan`, never by any
production control-plane path. So "never `AUTHORITATIVE`" for BloodHound-
discovered entities needs **no new mechanism at all**: it is automatically
true as long as this design does not build a write path from `ad.collect`
into `metadata_registry`, which it does not. The Security Graph tables
(§2.3) are structurally separate from `metadata_registry`; a node existing
there carries no classification of any kind, tier or otherwise. If a
customer or Engagement Manager later wants to formally classify a
discovered host, that is the same `register_metadata` call any other host
uses today — nothing BloodHound-specific.

### 1.8 Discovery provenance: a harness-composition responsibility, not a new mechanism

Separate from metadata classification is `agents/llm/worker_base.py`'s
`Observation`/`_discovery_provenance` — the mechanism that decides whether
a *later* Worker proposal naming a target counts as "established" (via
`Observation.observed_identities`) or "introduced by untrusted content."
This is unrelated to classification tiers and needs no change to
`_discovery_provenance` itself; the check is already generic over whatever
identities appear in `observed_identities`.

What changes is who populates that field. Today the harness scripts
(`scripts/live_run/*.py`) build `Observation` objects by hand from a prior
`tool_runs`/evidence row. For `ad.collect`, whoever drives a real
Supervisor/Worker/Reviewer loop against a live collection must do the same:
after a collection run, query the newly-written Security Graph rows for
that `run_id` (§2.3/§2.4) and pass the full set of discovered `fqdn`/`ip`
identities as `observed_identities` on the `Observation` built for
subsequent Worker calls — not the bounded summary in `derived_view`, which
exists only to keep the prompt small (§2.1). `observed_identities` is never
shown to the model; it is consulted only by the deterministic harness-side
check, so it can safely be the full list even when the prompt-facing
summary is truncated.

This is a design *note* for whoever writes that harness integration, not
new code this deliverable produces — the same way `d40_three_role.py`
was the harness, not a control-plane change.

### 1.9 I8 verification requirement (binding on implementation)

Before `ad.collect` ships, a test in the style of D13/D15's adversarial
fixtures must exist and pass:

1. A synthetic collection result naming an out-of-scope host with a
   fabricated high-privilege edge (e.g. `AttackerControlledUser
   —AdminTo→ DomainController`) is fed through the Security Graph write
   path.
2. Assert no `metadata_registry` row of any kind was created (§1.7).
3. Assert a subsequent proposal naming that host as an action target
   (e.g. `network.scan`) is still refused `target_out_of_scope` unless a
   real `fqdn`/`ip`/`cidr` scope object covering it exists — the collection
   result must not, by itself, satisfy authorization for anything.
4. Assert the Security Graph write itself does not create, renew, or
   otherwise affect any capability.

---

## 2. D42-6 — Tool Gateway integration, Option B (bulk collection action category)

### 2.1 Adapter: `tool_gateway/adapters/ad_collector.py`

Shaped like `nmap.py`, not like `http_get.py` — one dispatch is one bounded
collection run, not N separate requests, so there is no per-request
counter to wire through `consume_request`; duration is the only budget
dimension the broker needs to know about, exactly as nmap's own module
docstring argues for port scans ("one request" has no meaning here either).

```python
TOOL = "bloodhound-python"          # Impacket-based, pure Python, runs in
                                     # the existing Linux sandbox — unlike
                                     # SharpHound (.NET), needs no second
                                     # container base image or Windows host.
WRITES_DATA = False
CHANGES_STATE = False               # LDAP reads only; no adapter flag ever
                                     # requests a write.
REQUIRES_PROXY = False              # LDAP goes through the sandbox's raw
                                     # namespace like nmap's TCP, not through
                                     # the HTTP egress proxy (§8.3) — there is
                                     # no application-layer HTTP for a proxy
                                     # to read.

TOOL_STOP_GRACE_SECONDS = 5         # same D11-derived reasoning as nmap:
                                     # ask the tool to stop before the
                                     # sandbox kills it, so partial output
                                     # survives.

@dataclass(frozen=True)
class AdCollectPlan:
    command: tuple[str, ...]
    target: str                     # the ad_domain identity string
    max_duration_seconds: int
    max_queries_issued: int | None  # tool-owned safety cap, §4.6 tool sub-object

    def as_params(self) -> dict[str, Any]:
        return {"target": self.target, "max_queries_issued": self.max_queries_issued}
```

`build_plan(*, constraints, budget, target)` reads `budget.get("tool") or
{}` for `max_queries_issued` (mirroring `nmap.py`'s `allowed_ports` and
`_http.py`'s `http_budget`), passes it to the collector binary's own
result-count-limiting flag if the underlying tool exposes one, and reads
`max_duration_seconds` the same way every other adapter does. **No
credential parameter on this signature.** BloodHound-style collection
needs a domain-authenticated LDAP bind, and §4.3 of the ADR confirmed the
Credential Vault does not exist — this adapter has no live/production path
until it does, the same way `http_get`/`http_post` existed with no route to
a target before D34's proxy work. `build_plan` stays buildable and
testable against fixture output today; a real run is blocked on that
separate, already-flagged deliverable. This is not something to route
around with an ad hoc credential-passing shortcut.

`derive_view(stdout, stderr)` returns the bounded, prompt-facing summary —
`{"untrusted_content": True, "computers_seen": N, "users_seen": N,
"groups_seen": N, "notable_edges": [...]}` (a small, fixed-size sample, not
the full graph) — for exactly the reason §4.1 of the ADR gave: the full
graph belongs in the Security Graph tables (§2.3), not inline in a prompt,
or the first real run reproduces D40/5.21's argv-length crash at a much
larger scale.

### 2.2 Registry wiring

```python
# tool_gateway/registry.py
from tool_gateway.adapters import ad_collector
ADAPTERS = MappingProxyType({
    ...,
    "ad.collect": ad_collector,
})
```

Nothing else in `registry.py` changes — `side_effects_for`, `requires_proxy`
and `adapter_for` are all already generic over the action string.

### 2.3 Security Graph schema (new migration)

Two tables, following `tool_runs`/`evidence`'s existing conventions
exactly: `TEXT` primary keys, `engagement_id` FK, RLS via the existing
`ENGAGEMENT_SCOPED` list, append-only (added to `APPEND_ONLY`, no
`UPDATE`/`DELETE` grant for `cyberorch_app`).

```sql
CREATE TABLE security_graph_nodes (
    node_id        TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
    run_id         TEXT NOT NULL REFERENCES tool_runs(run_id),
    identity_type  TEXT NOT NULL,      -- 'fqdn' | 'ip' | opaque AD kind
    identity_value TEXT NOT NULL,      -- opaque per D42-3 Option A: no
                                        -- resource_class/data_class column
                                        -- here, ever -- Postgres's existing
                                        -- metadata_registry stays the only
                                        -- classification authority
    kind           TEXT NOT NULL,      -- 'user' | 'computer' | 'group'
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_graph_nodes_identity ON security_graph_nodes
    (engagement_id, identity_type, identity_value);

CREATE TABLE security_graph_edges (
    id             BIGSERIAL PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
    run_id         TEXT NOT NULL REFERENCES tool_runs(run_id),
    src_node_id    TEXT NOT NULL REFERENCES security_graph_nodes(node_id),
    dst_node_id    TEXT NOT NULL REFERENCES security_graph_nodes(node_id),
    edge_type      TEXT NOT NULL,      -- 'MemberOf' | 'AdminTo' | 'GenericAll' | ...
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_graph_edges_src ON security_graph_edges
    (engagement_id, src_node_id);
```

The `security_graph_edges_src` index is not incidental — it is the exact
index D42-2's benchmark ran against (`bh_edges_src_idx`) and its presence
is load-bearing for every number in that report. D42-3 Option A is
enforced by *absence*: no classification column exists on either table to
tempt a future writer.

### 2.4 Batch write: `control_plane/graph/store.py`

Mirrors `control_plane/provenance/graph.py`'s shape (small, explicit,
bulk-insert functions; no ORM):

```python
def record_batch(
    conn: Connection, *, engagement_id: str, run_id: str,
    nodes: Sequence[GraphNode], edges: Sequence[GraphEdge],
) -> str:
    """Bulk-write one collection run's discovered graph. Append-only."""
    # INSERT ... ON CONFLICT (engagement_id, run_id, identity_type,
    # identity_value) DO NOTHING for nodes (a collector may re-report the
    # same computer across queries within one run); plain INSERT for edges.
    ...
    record_edge(  # existing control_plane.provenance.graph function, unchanged
        conn, engagement_id=engagement_id, from_type="tool_run", from_id=run_id,
        to_type="security_graph_batch", to_id=run_id, relation=PRODUCED,
    )
    return run_id
```

The provenance edge is the one new fact recorded outside the two new
tables, and it uses the *existing* `provenance_edges` table and
`PRODUCED` relation unchanged (§2.4 of the ADR: this is "one more RUN
--produced--> EVIDENCE edge," not a new provenance mechanism). A batch is
identified by its `run_id`, so `why()` and `edges_from()` need no change
to walk to or from it.

### 2.5 Dispatch: `dispatch_collection()`, parallel to `dispatch_scan()`

A new function in `control_plane/orchestrator/dispatch.py`, not a
retrofit of `dispatch_scan` — Option B's own reasoning. It reuses the
`tool_runs` table, the `QUEUED → DISPATCHING → RUNNING → SUCCEEDED/FAILED`
state machine, `claim_for_dispatch`, `find_cached_run`/execution
fingerprinting, and the `tool_run.*` audit vocabulary completely unchanged
— a collection run is still one proposal, one capability, one `tool_runs`
row, one `evidence` row (the bounded summary). What is genuinely new is a
second write after the run succeeds:

```python
def dispatch_collection(conn, *, engagement_id, proposal_id, capability,
                         target, actor, sandbox=None, ...) -> DispatchOutcome:
    # ... identical shape through plan-building, fingerprinting, claiming,
    # and running the sandbox, reusing ad_collector.build_plan/derive_view ...

    if result.succeeded:
        nodes, edges = ad_collector.parse_graph(result.stdout)  # full,
                                                                  # unbounded
                                                                  # parse --
                                                                  # distinct
                                                                  # from
                                                                  # derive_view's
                                                                  # bounded
                                                                  # summary
        graph_store.record_batch(
            conn, engagement_id=engagement_id, run_id=run_id,
            nodes=nodes, edges=edges,
        )
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="security_graph.recorded", subject_type="tool_run",
            subject_id=run_id,
            payload={"node_count": len(nodes), "edge_count": len(edges)},
        )
    ...
```

`security_graph.recorded` follows the existing `<subject_noun>.<past-tense
verb>` convention (`metadata.registered`, `evidence.recorded`) and is
added to `control_plane/audit/query.py`'s `STAGE_OF_EVENT` under stage
`"execution"`, next to `evidence.recorded`. No new `tool_run.*` event is
invented — a collection run's start/success/failure is still exactly
`tool_run.started`/`tool_run.succeeded`/`tool_run.failed`, since it is
still, mechanically, a tool run.

Budget consumption: **no call to `consume_request`.** That function counts
separate dispatch calls against a capability (http.get's 3 GETs per
capability); `ad.collect` is one dispatch, one run, and its internal query
volume is bounded by the adapter's own `max_queries_issued` flag to the
collector binary (§2.1), the same way nmap's port-scan volume is bounded by
its own command construction rather than by the broker.

### 2.6 Query shape catalog: `control_plane/graph/queries.py`

**The one sanctioned module for recursive queries over
`security_graph_nodes`/`security_graph_edges`.** Two shapes, matching
requirement #2 exactly, both built on the BFS-dedup `UNION` (not `UNION
ALL`) formulation D42-2 measured:

```python
def shortest_path(
    conn: Connection, *, engagement_id: str, start: NodeRef, target: NodeRef,
    max_depth: int = 10,
) -> int | None:
    """Fewest hops from start to target, or None if none within max_depth."""

def paths_within_hops(
    conn: Connection, *, engagement_id: str, start: NodeRef, max_depth: int,
) -> list[NodeRef]:
    """Every node reachable from start within max_depth hops."""
```

Both are thin wrappers around the exact query shape benchmarked in
`scripts/bench/d42_bloodhound_cte_bench.py`'s `BFS_QUERY`, parameterized
by `engagement_id` (relying on RLS via the ordinary `engagement_scope()`
connection — not a manual `WHERE engagement_id = ...`, since the whole
point of I4/RLS is that the query does not have to get that right by hand).

**Binding implementation gate (requirement #2): a query shape is not
merged into this module until its own D42-2-style benchmark exists.**
`shortest_path` ships with the benchmark this deliverable already produced
(`docs/D42_2_CTE_BENCHMARK.md`). `paths_within_hops` needs its own —
enumerating a bounded-hop neighborhood is a different cost profile (the
result set itself can be large, where `shortest_path` returns one number),
and D42-2's numbers say nothing about it. No third shape (e.g. "all users
with a path to any Tier-0 asset," mentioned as a candidate in the ADR) is
in scope for this deliverable at all; adding one later means adding its own
benchmark first, not assuming either existing one generalizes.

### 2.7 Structural tests (requirement #1)

Three tests, in a new `tests/test_graph_queries_structure.py`, modeled
directly on `tests/test_capability_broker.py`'s `_broker_code()` pattern
(AST-parse, strip docstrings, check the actual code rather than prose that
mentions the forbidden thing):

**(a) One module owns every recursive graph query.**

```python
def test_only_one_module_defines_security_graph_recursive_queries():
    """WITH RECURSIVE over the Security Graph lives in exactly one place.

    Scoped deliberately: provenance/graph.py's why() also uses WITH
    RECURSIVE, predates this rule, and queries a structurally different,
    near-tree-shaped graph (a bounded backward walk from one known node) --
    it is not touched by, or exempted by exception-list, this rule. This
    test greps only files that import or reference the new
    security_graph_* tables.
    """
    offenders = [
        path for path in _files_referencing_security_graph_tables()
        if "WITH RECURSIVE" in _source_stripped_of_strings(path)
        and path != "control_plane/graph/queries.py"
    ]
    assert not offenders, f"recursive query outside the sanctioned module: {offenders}"
```

**(b) The sanctioned module uses the dedup formulation, not the naive one.**

```python
def test_graph_queries_use_dedup_union_not_union_all():
    """Every WITH RECURSIVE in queries.py dedups on (node, depth) via UNION.

    D42-2 measured the alternative: a per-path visited-array with UNION ALL
    is up to ~280x slower at 6k nodes and times out on 7/10 samples at 19k
    nodes (docs/D42_2_CTE_BENCHMARK.md). This is the one line that number
    depends on, checked directly rather than trusted to review.
    """
    code = _source_stripped_of_strings("control_plane/graph/queries.py")
    for recursive_block in _extract_recursive_cte_blocks(code):
        assert "UNION ALL" not in recursive_block, (
            "found UNION ALL in a Security Graph recursive query -- "
            "must be UNION (see D42-2)"
        )
```

**(c) A mutation-style behavioral guard, on an adversarial hub fixture.**

```python
def test_graph_queries_stay_fast_on_a_hub_fixture(hub_graph_fixture):
    """Regression guard: reverting to per-path dedup must fail this test.

    hub_graph_fixture is the same diamond/converging-structure generator
    used in scripts/bench/d42_bloodhound_cte_bench.py's naive-vs-BFS
    comparison, scaled down to a few hundred nodes so the test suite stays
    fast. The naive formulation blew past a 20s cap on 7/10 samples at
    19k nodes (D42-2); this fixture is sized to reproduce the same failure
    inside a much smaller, CI-appropriate time budget.
    """
    with time_budget(seconds=2):
        result = shortest_path(
            hub_graph_fixture.conn, engagement_id=hub_graph_fixture.engagement_id,
            start=hub_graph_fixture.a_deep_node, target=hub_graph_fixture.target,
            max_depth=10,
        )
    assert result is not None
```

`hub_graph_fixture` reuses `scripts/bench/d42_bloodhound_cte_bench.py`'s
`generate_graph` at a small scale (shared as an importable fixture rather
than copied) — the same generator, not a second implementation of it, so
the two never drift apart the way D33/D34 already found two schema copies
doing.

### 2.8 Review path: a new distinction, not an existing invariant

A proposal whose action is `ad.collect` is reviewed as "should this
collection run against this domain" — the Reviewer's prompt for an
`ad.collect` proposal is framed around collection scope and duration, not
around a specific target's classification, since collection touches no
single classified resource. This is new prompt-construction work in
`agents/llm/reviewer_base.py` (a conditional framing keyed on the action
namespace, the same way the Worker's own prompt already varies by what
`TARGET_TYPES`/actions are offered) — not a reuse of `network.scan`'s
review framing, and not a claim that an existing invariant already
describes this (§0's correction).

---

## 3. Requirement #3: concurrency risk, drafted as a DEFERRED item

Format matches `ACCEPTANCE_MVP_KERNEL.md` §5.2 / `ACCEPTANCE_MVP1_AGENTS.md`'s
running DEFERRED list exactly. Ready to insert as **5.23** (continuing after
5.20-5.22, added at D39-D41) when D42-1/D42-6 are actually implemented —
not inserted now, since the items it describes do not exist yet:

> ### 5.23 BloodHound query/collection performance under concurrent load — untested, D42-2
>
> `scripts/bench/d42_bloodhound_cte_bench.py`, `control_plane/graph/queries.py`
>
> D42-2's benchmark measured `shortest_path` at two realistic scales (6.2k
> and 19k nodes) and found it comfortably fast — under 275ms worst case —
> but **every query ran sequentially, on a single connection, with nothing
> else touching the database.** Real usage is neither: a Supervisor driving
> an audit sweep issues many queries in a short window, other engagements'
> traffic shares the same Postgres instance, and an `ad.collect` bulk write
> (§2.4-§2.5) may be landing tens of thousands of rows at the same time a
> query against an *older* run's data is in flight.
>
> *Why not now:* D42-2 was scoped to answer one question — is a correctly-
> formulated recursive CTE fast enough at all, which gated the D42-5
> Neo4j-vs-Postgres decision. Concurrency is a different, real question
> that does not change that decision (nothing about it favors Neo4j, whose
> own access-control story, per D42-3's findings, has no equivalent of
> Postgres's per-connection RLS GUC) and would have delayed answering the
> one D42-5 was actually waiting on.
>
> *Binding constraints:* (1) measured against a Postgres instance under a
> representative concurrent write load (an `ad.collect` batch insert
> in flight), not read-only concurrency alone — the write path is the one
> this report never exercised at all; (2) measured with RLS active and
> multiple engagements' data present, not the single-engagement throwaway
> database D42-2 used, since RLS's per-query filter is exactly the
> mechanism concurrency could interact with; (3) if the numbers regress
> materially from D42-2's single-connection figures, that is new
> information for D42-5, not a reason to quietly retune the query and
> move on without recording what changed and why.

---

## 4. Open calls for your sign-off before implementation starts

Everything above follows directly from the decisions already made in the
ADR and the benchmark. Three smaller calls this document made a specific
choice on, named explicitly in case any should go differently:

1. **Collector tool**: `bloodhound-python` (Impacket-based), not SharpHound
   (.NET) — chosen because it runs in the existing Linux sandbox with no
   new base image or Windows host. If there is a reason to want SharpHound
   specifically (e.g. collection-method parity with the reference tool),
   say so now — it changes §2.1's sandbox image story materially.
2. **`security_graph.recorded` as a new audit event**, rather than folding
   the node/edge counts into the existing `tool_run.succeeded` payload.
   Chosen so a reader can filter "how much graph data has this engagement
   produced" without parsing every tool run's payload by tool type — but
   it is one more event name to maintain.
3. **No credential parameter anywhere in this design** (§2.1). `ad.collect`
   is fully buildable, testable (against fixture output), and reviewable
   under this design, but cannot run against a real domain until the
   Credential Vault deliverable lands. If that sequencing is wrong — if
   `ad.collect` should not be considered "done" until it can actually run
   — say so, since that would pull the Credential Vault work forward
   rather than leaving it as an independent candidate.
