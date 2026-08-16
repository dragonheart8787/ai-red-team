"""Split registry write access into its own role (ARCHITECTURE.md §5).

Revision ID: 0002
Revises: 0001

§5 calls the Scope Registry and the Authoritative Metadata Registry the highest
value attack surface in the system: whoever can write them can grant themselves
authorization, or reclassify a PII database as a static site. Until this
migration, cyberorch_app -- the role every component connects as -- could do
both. The guarantee that the resolvers only trust AUTHORITATIVE classifications
rested entirely on application code choosing not to write them.

After this migration the runtime role can read the registries and nothing else.
Writes require registry_admin, which the Engagement Manager alone connects as.
An application-layer bug, or a component taken over and talking to the database
directly, no longer reaches the tables that decide what is authorized.

registry_admin is not privileged in any other respect: same RLS, same
engagement boundary, no BYPASSRLS. It is cyberorch_app plus two writable tables.
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

REGISTRY_TABLES = ["scope_registry", "metadata_registry"]


def upgrade() -> None:
    for table in REGISTRY_TABLES:
        # The runtime role keeps SELECT: the resolvers read these tables on
        # every decision. It loses every way of changing them.
        op.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON {table} FROM cyberorch_app;")
        op.execute(f"GRANT SELECT ON {table} TO cyberorch_app;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {table} TO registry_admin;")
        # DELETE stays revoked for both. Scope objects and classifications are
        # retired by setting active = FALSE, so history survives and an audit
        # trail has something to point at.
        op.execute(f"REVOKE DELETE, TRUNCATE ON {table} FROM registry_admin;")

    op.execute("GRANT USAGE ON SCHEMA public TO registry_admin;")

    # §5 requires every registry write to be audited, and record_audit runs in
    # the same transaction as the write it describes. Without INSERT here the
    # audit and the change could not be atomic, and a write that failed to log
    # would still land.
    op.execute("GRANT INSERT, SELECT ON audit_log TO registry_admin;")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE audit_log_audit_id_seq TO registry_admin;")

    # Reading engagements is needed to validate an engagement exists before
    # registering scope against it. Still filtered by RLS.
    op.execute("GRANT SELECT ON engagements TO registry_admin;")
    op.execute("GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() TO registry_admin;")


def downgrade() -> None:
    for table in REGISTRY_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM registry_admin;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO cyberorch_app;")
    op.execute("REVOKE ALL ON audit_log FROM registry_admin;")
    op.execute("REVOKE ALL ON engagements FROM registry_admin;")
