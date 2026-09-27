"""Security Graph tables and the ad_domain collection-only constraint (D42-1/D42-6).

Revision ID: 0011
Revises: 0010

Two independent additions, both decided in docs/ADR_BLOODHOUND_NEO4J.md and
detailed in docs/D42_1_D42_6_DESIGN.md:

**ad_domain scope objects may only ever grant ad.collect (D42-1 Option C).**
``scope_registry.type`` has accepted ``'ad_domain'`` since migration 0001 with
nothing behind it. The rule this migration enforces -- an ad_domain scope
authorizes *collection*, never a downstream *action* against what it
discovers -- is put directly on the schema rather than left to whoever calls
``register_scope_object`` to get right, the same shape as
``emergency_overlay_can_only_tighten`` (migration 0001): the invariant that
matters is enforced by the table, and the application-level guard in
``register_scope_object`` exists only to turn a constraint violation into a
message that names the actual mistake.

**The Security Graph (D42-6, D42-3 Option A).** ``security_graph_nodes`` /
``security_graph_edges`` hold whatever a bulk collection run (``ad.collect``)
discovers -- opaque identities and edges only. Neither table carries a
classification column of any kind. That is D42-3's "Neo4j/here holds only
opaque identity, Postgres's Metadata Registry stays the sole classification
authority" decided the other way: there is no second graph store in this
design (D42-5: Postgres only), so the same discipline applies to these two
tables directly. A discovered entity that needs classifying goes through
``register_metadata`` like any other resource -- these tables are never
consulted for, and never assert, a resource_class or data_class.

Append-only, engagement-scoped, and indexed on ``security_graph_edges`` --
**two** indexes, not the one the benchmarks ran against, and the second one
is a real fix, not a redundant addition. Found during D42-6's own
implementation: D42-2/D42-6's benchmarks ran against a throwaway database
with no RLS and a single-column index (``bh_edges_src_idx`` on ``src``
alone). On the real, RLS-enabled, engagement-scoped ``security_graph_edges``
with only the composite ``(engagement_id, src_node_id)`` index, the same
query at the same "mid" scale (5,000 users / 800 computers / 400 groups)
took **28.9 seconds**, not the tens of milliseconds the benchmark reported —
the planner chose a plan that scanned the composite index on
``engagement_id`` alone, materialized the result, and then filtered
``src_node_id`` with a row-by-row join filter (25 million rows discarded
that way) instead of using ``src_node_id`` as part of the index condition.
Adding a **second, plain, single-column index on ``src_node_id`` alone**
(mirroring the benchmark's own index shape exactly) changed the planner's
choice back to a parameterized index scan using both columns, and the same
query dropped to 57ms. Both indexes are kept: the composite one supports
any query that also wants to scan by engagement_id without a specific
source node, the single-column one is what actually make the recursive
join in ``control_plane/graph/queries.py`` fast. This is recorded here
rather than silently added, because it means the benchmark reports'
numbers were not reproduced on the real schema without this fix — see the
addendum in both docs/D42_2_CTE_BENCHMARK.md and
docs/D42_6_PATHS_WITHIN_HOPS_BENCHMARK.md.
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # D42-1: ad_domain scope objects authorize collection only.
    # ------------------------------------------------------------------
    op.execute("""
ALTER TABLE scope_registry ADD CONSTRAINT ad_domain_collection_only CHECK (
    type <> 'ad_domain' OR allowed_actions <@ ARRAY['ad.collect']::TEXT[]
);
""")

    # ------------------------------------------------------------------
    # D42-6: Security Graph.
    # ------------------------------------------------------------------
    op.execute("""
CREATE TABLE security_graph_nodes (
    node_id           TEXT PRIMARY KEY,
    engagement_id     TEXT NOT NULL REFERENCES engagements(engagement_id),
    first_seen_run_id TEXT NOT NULL REFERENCES tool_runs(run_id),
    identity_type     TEXT NOT NULL,
    identity_value    TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('user', 'computer', 'group')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- UNIQUE, not a plain index: a node is one identity, however many collection
-- runs re-observe it. Without this, a second ad.collect run against the same
-- domain would mint a second node row for the same computer, and edges from
-- the two runs would never connect -- silently fragmenting the graph exactly
-- where an incremental re-collection is the realistic case, not the
-- exception. record_batch() (control_plane/graph/store.py) inserts nodes
-- ON CONFLICT (engagement_id, identity_type, identity_value) DO NOTHING and
-- reuses the existing node_id; first_seen_run_id is informational and is
-- never updated on a later rediscovery (this table has no UPDATE grant at
-- all -- see below).
CREATE UNIQUE INDEX security_graph_nodes_identity ON security_graph_nodes
    (engagement_id, identity_type, identity_value);
""")
    op.execute("""
CREATE TABLE security_graph_edges (
    id             BIGSERIAL PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
    run_id         TEXT NOT NULL REFERENCES tool_runs(run_id),
    src_node_id    TEXT NOT NULL REFERENCES security_graph_nodes(node_id),
    dst_node_id    TEXT NOT NULL REFERENCES security_graph_nodes(node_id),
    edge_type      TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_graph_edges_src ON security_graph_edges
    (engagement_id, src_node_id);
-- A second, single-column index on src_node_id alone. Not redundant with
-- the composite one above: see this migration's module docstring for the
-- 28.9s-vs-57ms finding this fixes. Both are kept -- the composite index
-- still serves any query that scans by engagement_id without a specific
-- source node.
CREATE INDEX security_graph_edges_src_only ON security_graph_edges (src_node_id);
""")

    # RLS, identical shape to migration 0001's ENGAGEMENT_SCOPED loop --
    # written out here rather than re-imported, since 0001's loop is local to
    # its own upgrade() and this table did not exist when it ran.
    for table in ("security_graph_nodes", "security_graph_edges"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
CREATE POLICY engagement_isolation ON {table}
    FOR ALL TO PUBLIC
    USING (engagement_id = cyberorch_current_engagement())
    WITH CHECK (engagement_id = cyberorch_current_engagement());
""")
        # Append-only, same treatment as evidence/audit_log/provenance_edges
        # (migration 0001's APPEND_ONLY list): a discovered fact is never
        # updated in place, a later collection run just adds more rows.
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM cyberorch_app;")
        op.execute(f"GRANT INSERT, SELECT ON {table} TO cyberorch_app;")

    # security_graph_edges.id is BIGSERIAL -- migration 0001's blanket
    # "ALL SEQUENCES IN SCHEMA public" grant only covered sequences that
    # existed when it ran, the same way its table grant did, so a sequence
    # created here needs its own explicit grant or every INSERT fails with
    # InsufficientPrivilege on the sequence rather than the table.
    op.execute("GRANT USAGE, SELECT ON security_graph_edges_id_seq TO cyberorch_app;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS security_graph_edges CASCADE;")
    op.execute("DROP TABLE IF EXISTS security_graph_nodes CASCADE;")
    op.execute("ALTER TABLE scope_registry DROP CONSTRAINT IF EXISTS ad_domain_collection_only;")
