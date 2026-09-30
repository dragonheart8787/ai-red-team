"""Narrow the runtime role's write access to policy_layers and engagements (ACCEPTANCE 5.36, D54).

Revision ID: 0013
Revises: 0012

Migration 0001 gave ``cyberorch_app`` SELECT, INSERT, UPDATE and DELETE on every table. D5
narrowed the registries, D39 (migration 0010) took INSERT and DELETE off ``engagements``, and the
append-only tables lost UPDATE and DELETE at the start. Nothing narrowed ``policy_layers`` at all,
and ``engagements`` kept UPDATE on every column. Checked at D54 by executing the statements as the
role: ``UPDATE policy_layers SET document = '{}'`` and ``DELETE FROM policy_layers`` both
succeeded, so the policy history the freeze in §4.5 would read from was mutable by the same role
every Worker and Reviewer call runs as.

What production code needs, read from every writer in the tree:

* ``policy_layers`` -- ``publish_policy_layer`` INSERTs; ``deactivate_policy_layer`` sets
  ``active = FALSE``. Nothing updates any other column and nothing deletes. So: INSERT and
  SELECT stay, UPDATE narrows to the ``active`` column, DELETE goes.
* ``engagements`` -- the four lifecycle operations (pause, resume, kill, complete) write
  ``status``, ``kill_switch_engaged`` and ``updated_at`` and nothing else. So: SELECT stays,
  UPDATE narrows to those three columns. ``customer_id`` (which decides which customer-scoped
  policy applies, 5.35) and ``policy_snapshot_version`` (the pointer 5.20's freeze would read)
  are no longer writable by the runtime role.

``active`` is deliberately kept writable rather than moved to another role: it is how a layer is
retired, ``deactivate_policy_layer`` runs on this connection, and moving it is a design question
of its own (5.37: an engagement's connection can retire a *global* layer). This migration removes
what nothing uses; it does not decide who may retire a layer.

Table-level REVOKE first, then the column grants: revoking UPDATE at table level also clears
any column-level UPDATE, so the order matters.
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("REVOKE UPDATE, DELETE ON policy_layers FROM cyberorch_app;")
    op.execute("GRANT UPDATE (active) ON policy_layers TO cyberorch_app;")
    op.execute("REVOKE UPDATE ON engagements FROM cyberorch_app;")
    op.execute(
        "GRANT UPDATE (status, kill_switch_engaged, updated_at) "
        "ON engagements TO cyberorch_app;"
    )


def downgrade() -> None:
    op.execute("REVOKE UPDATE (active) ON policy_layers FROM cyberorch_app;")
    op.execute("GRANT UPDATE, DELETE ON policy_layers TO cyberorch_app;")
    op.execute("REVOKE UPDATE (status, kill_switch_engaged, updated_at) "
               "ON engagements FROM cyberorch_app;")
    op.execute("GRANT UPDATE ON engagements TO cyberorch_app;")
