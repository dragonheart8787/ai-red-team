"""A role of its own for global policy layers (ACCEPTANCE 5.37, D54).

Revision ID: 0014
Revises: 0013

``policy_layers`` rows with ``engagement_id IS NULL`` apply to every engagement: the baseline,
the emergency overlay and a global customer layer. Row-level security lets a global row be
written from *any* engagement's connection (its ``engagement_isolation`` policy admits
``engagement_id IS NULL`` on both sides), so until this migration the runtime role -- the one
every Worker, Reviewer and Supervisor call runs as -- could publish a global baseline, which can
*widen* every open engagement, and retire a global emergency overlay, which is a relaxation.
Executed at D54: a connection scoped to an engagement id that does not exist deactivated two
global layers other engagements had published. Migration 0013 narrowed which columns the runtime
role may write; it did not narrow *whose* rows.

This is the D5 / D39 / D44 pattern -- a new duty gets a new role -- and D11-7 / D21's
global_auditor is the closest precedent: a role for exactly the rows that belong to no
engagement.

* ``global_policy_admin`` -- SELECT and INSERT on ``policy_layers``, and UPDATE of ``active``
  alone (the same columns 0013 left the runtime role), the sequence for the id it inserts,
  and the engagement helper the table's policy calls. A **restrictive** policy confines every
  command to ``engagement_id IS NULL``: it cannot see an engagement-scoped row, cannot insert
  one and cannot retire one, whatever engagement setting its session carries. It holds nothing
  on any other table; its audit record is written by the ordinary audit path.
* ``cyberorch_app`` -- keeps everything 0013 left it on *engagement-scoped* rows and may still
  read every row (global layers must stay visible to the merge). Two restrictive policies
  remove the rest: an INSERT must carry an engagement, and an UPDATE may only leave a row with
  an engagement. A refusal is an error (SQLSTATE 42501, ``InsufficientPrivilege``), not a
  silent zero-row update, which is why the UPDATE policy is a ``WITH CHECK``: a ``USING``
  clause would merely hide the global row and let the statement report success.

Restrictive policies are AND-ed with the existing permissive ``engagement_isolation`` policy,
which is untouched; nothing here widens what any role could do before.
"""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("GRANT USAGE ON SCHEMA public TO global_policy_admin;")
    op.execute("GRANT SELECT, INSERT ON policy_layers TO global_policy_admin;")
    op.execute("GRANT UPDATE (active) ON policy_layers TO global_policy_admin;")
    op.execute("GRANT USAGE ON SEQUENCE policy_layers_id_seq TO global_policy_admin;")
    op.execute(
        "GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() TO global_policy_admin;"
    )

    op.execute("""
CREATE POLICY global_policy_admin_global_rows_only ON policy_layers
    AS RESTRICTIVE FOR ALL TO global_policy_admin
    USING (engagement_id IS NULL)
    WITH CHECK (engagement_id IS NULL);
""")
    op.execute("""
CREATE POLICY runtime_role_inserts_engagement_rows_only ON policy_layers
    AS RESTRICTIVE FOR INSERT TO cyberorch_app
    WITH CHECK (engagement_id IS NOT NULL);
""")
    op.execute("""
CREATE POLICY runtime_role_updates_engagement_rows_only ON policy_layers
    AS RESTRICTIVE FOR UPDATE TO cyberorch_app
    USING (true)
    WITH CHECK (engagement_id IS NOT NULL);
""")


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS runtime_role_updates_engagement_rows_only ON policy_layers;")
    op.execute("DROP POLICY IF EXISTS runtime_role_inserts_engagement_rows_only ON policy_layers;")
    op.execute("DROP POLICY IF EXISTS global_policy_admin_global_rows_only ON policy_layers;")
    op.execute(
        "REVOKE EXECUTE ON FUNCTION cyberorch_current_engagement() FROM global_policy_admin;"
    )
    op.execute("REVOKE USAGE ON SEQUENCE policy_layers_id_seq FROM global_policy_admin;")
    op.execute("REVOKE ALL ON policy_layers FROM global_policy_admin;")
    op.execute("REVOKE USAGE ON SCHEMA public FROM global_policy_admin;")
