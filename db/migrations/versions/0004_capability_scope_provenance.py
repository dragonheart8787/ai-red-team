"""Record which scope object authorized each capability.

Revision ID: 0004
Revises: 0003

Found by the D9 stateful test, not by design review, and it had been there
since D5. The shortest failing sequence Hypothesis shrank to was three steps:

    issue(octet=1)      # scope object live, resolver authorizes, capability issued
    deactivate_scope()  # the scope object is retired
    -> I1 violated      # the capability is still live and still renewable

Retiring a scope object revoked nothing, and ``check_preconditions`` had no way
to notice: a capability recorded the policy version, the approval and the
credential it depended on, but not the scope object that authorized it. The
dependency existed and was simply unrepresented, so nothing could re-check it.

That is I8 (Authorization Provenance) as much as I1: a capability that cannot
name the scope object it came from cannot prove it was ever authorized, and
cannot be asked whether it still is.

Nullable, because it has to be. Capabilities predating this column have no
answer, and inventing one — defaulting to some scope object they may never have
been issued against — would manufacture provenance rather than record it. A
NULL means "unknown", and :func:`check_preconditions` treats it as nothing to
check rather than as permission.
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE capabilities ADD COLUMN scope_object_id text")
    op.execute("""
COMMENT ON COLUMN capabilities.scope_object_id IS
'The scope object that authorized this capability (ARCHITECTURE.md §4.1, I8).
Recorded so renewal can re-check that the authorization still holds -- the
Capability Broker looks this row up by id to confirm it is still active and
still permits the action. Deliberately no foreign key: scope_registry rows are
soft-deleted rather than removed, and a capability must remain able to name the
scope object it came from even after that object is retired, which is precisely
the case the column exists to detect. NULL means the capability predates this
column; it is treated as unknown, never as authorized.';
""")
    # Renewal filters live capabilities by scope object on every heartbeat.
    op.execute("""
        CREATE INDEX ix_capabilities_scope_object
        ON capabilities (engagement_id, scope_object_id)
        WHERE revoked IS FALSE
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_capabilities_scope_object")
    op.execute("ALTER TABLE capabilities DROP COLUMN IF EXISTS scope_object_id")
