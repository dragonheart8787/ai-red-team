"""Global-scope audit attribution (D11-7, DEFERRED_MVP0.md 11.2).

Revision ID: 0007
Revises: 0006

The D11 live run hit this: a policy layer published globally
(``scoped_to_engagement=False``, so ``policy_layers.engagement_id IS NULL``)
leaves a globally-visible effect and an audit record scoped to whichever
engagement the publisher happened to be in. From inside any engagement you can
see that a global layer constrains you and cannot see where it came from —
``published by: unknown``. Both halves were individually correct (global layers
must be globally visible; one engagement's audit must not leak into another),
and the gap was between them: a globally-scoped operation had no globally-scoped
record.

This gives ``audit_log`` a ``scope`` and lets a global operation carry
``engagement_id IS NULL``, enforced by a CHECK so the two fields cannot disagree
by anyone's oversight. A globally-visible record needs a reader that is not any
one engagement's, so a new ``global_auditor`` role gets a SELECT-only RLS policy
over exactly the global rows — added *on top of* the per-engagement policy, which
is untouched. Existing roles gain no way to read global audit, and the new role
gains no way to read anything else or to write.
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. scope column (default keeps every existing row engagement-scoped), and
    #    engagement_id becomes nullable so a global row can carry NULL.
    op.execute("""
        ALTER TABLE audit_log
            ADD COLUMN scope TEXT NOT NULL DEFAULT 'engagement'
                CHECK (scope IN ('global', 'engagement'))
    """)
    op.execute("ALTER TABLE audit_log ALTER COLUMN engagement_id DROP NOT NULL")

    # 2. The two fields cannot disagree. Structural, not a matter of code
    #    discipline: a global row has no engagement, an engagement row has one.
    op.execute("""
        ALTER TABLE audit_log
            ADD CONSTRAINT audit_scope_consistent CHECK (
                (scope = 'global' AND engagement_id IS NULL)
                OR (scope = 'engagement' AND engagement_id IS NOT NULL)
            )
    """)
    op.execute("""
        COMMENT ON COLUMN audit_log.scope IS
'global | engagement (D11-7). A global row records a globally-scoped operation
(e.g. a global policy overlay) and carries engagement_id IS NULL; only
global_auditor can read it. An engagement row is the ordinary case and stays
confined to its engagement by RLS. The CHECK audit_scope_consistent keeps the
two fields from disagreeing.';
    """)
    op.execute(
        "CREATE INDEX audit_log_global_ts ON audit_log (ts) WHERE scope = 'global'"
    )

    # 3. Writing a global row. record_audit runs as cyberorch_app, whose FOR ALL
    #    engagement_isolation WITH CHECK requires engagement_id = the connection's
    #    engagement — which a global (NULL) row cannot satisfy. This permissive
    #    INSERT policy is OR'd with it, so a global row can be written while an
    #    engagement row still must match its engagement. It does not grant any
    #    read.
    op.execute("""
CREATE POLICY audit_global_insert ON audit_log
    FOR INSERT TO PUBLIC
    WITH CHECK (scope = 'global' AND engagement_id IS NULL);
""")

    # 4. Reading global rows: global_auditor only. Added on top of the
    #    per-engagement engagement_isolation policy (untouched), and OR'd with
    #    it. The current_user condition is what confines global reads to this one
    #    role; removing it would widen global audit to every role, which an
    #    isolation test asserts against.
    op.execute("""
CREATE POLICY audit_global_read ON audit_log
    FOR SELECT TO PUBLIC
    USING (scope = 'global' AND current_user = 'global_auditor');
""")

    # 5. global_auditor: SELECT on audit_log and nothing else. USAGE on the
    #    schema, EXECUTE on the engagement helper (the per-engagement policy that
    #    also applies to this table references it, so evaluating a SELECT needs
    #    it). No grant on any other table, no sequence, no INSERT anywhere.
    op.execute("GRANT USAGE ON SCHEMA public TO global_auditor;")
    op.execute("GRANT SELECT ON audit_log TO global_auditor;")
    op.execute("GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() TO global_auditor;")


def downgrade() -> None:
    op.execute("REVOKE ALL ON audit_log FROM global_auditor;")
    op.execute("REVOKE EXECUTE ON FUNCTION cyberorch_current_engagement() FROM global_auditor;")
    op.execute("REVOKE USAGE ON SCHEMA public FROM global_auditor;")
    op.execute("DROP POLICY IF EXISTS audit_global_read ON audit_log;")
    op.execute("DROP POLICY IF EXISTS audit_global_insert ON audit_log;")
    op.execute("DROP INDEX IF EXISTS audit_log_global_ts;")
    op.execute("ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_scope_consistent;")
    # Only safe if no global rows exist; downgrade is a developer operation.
    op.execute("ALTER TABLE audit_log ALTER COLUMN engagement_id SET NOT NULL")
    op.execute("ALTER TABLE audit_log DROP COLUMN IF EXISTS scope")
