"""engagement_ca — per-engagement TLS signing material for the egress proxy (D35).

D35 gives the egress proxy a certificate to terminate TLS with. The signing CA
is per engagement, never global (§8.3 / I4): a single global CA would be one
key whose leak lets an attacker impersonate any host in any engagement, sitting
above the very boundary the rest of the schema enforces.

This is the most sensitive table in the system — it holds private keys — and it
is protected exactly like ``credentials``, which is the standard the D35 brief
named:

* **FORCE ROW LEVEL SECURITY under the same engagement_isolation policy.** A
  connection bound to one engagement can read only that engagement's CA. The
  control plane signs a leaf while scoped to the engagement, so it never sees
  another's key.
* **Granted to cyberorch_app alone.** The secondary roles — ui_reader,
  registry_admin, global_auditor — grant SELECT only on the specific tables
  they name, none of which is this one, so a new table is invisible to them by
  construction. The CA key is therefore as unreachable to the web console as
  ``credentials`` is. The in-container egress proxy has no database role at all
  (5.12), so it cannot reach this even in principle; it is handed a pre-signed
  leaf and never the CA key.

There is no UPDATE grant: a CA is written once per engagement and then only
read. Rewriting it would invalidate leaves already handed to running proxies.
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE engagement_ca (
    engagement_id  TEXT PRIMARY KEY REFERENCES engagements(engagement_id),
    ca_cert_pem    TEXT NOT NULL,
    ca_key_pem     TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
""")
    op.execute("COMMENT ON TABLE engagement_ca IS "
               "'D35: per-engagement TLS CA for the egress proxy. Private key. "
               "Protected like credentials: RLS + cyberorch_app only.';")

    # Same isolation as every engagement-scoped table, and FORCE so the table
    # owner does not bypass it (§8.6). Without FORCE the tests would pass while
    # production leaked, which is the exact half-done case §8.6 exists for.
    op.execute("ALTER TABLE engagement_ca ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE engagement_ca FORCE ROW LEVEL SECURITY;")
    op.execute("""
CREATE POLICY engagement_isolation ON engagement_ca
    FOR ALL TO PUBLIC
    USING (engagement_id = cyberorch_current_engagement())
    WITH CHECK (engagement_id = cyberorch_current_engagement());
""")

    # SELECT and INSERT only, to the runtime role only. No UPDATE (a CA is
    # written once), no DELETE, and nothing to any read role.
    op.execute("GRANT SELECT, INSERT ON engagement_ca TO cyberorch_app;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS engagement_ca CASCADE;")
