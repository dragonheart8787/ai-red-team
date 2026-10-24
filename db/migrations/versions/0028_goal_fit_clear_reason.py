"""A class is let back in for a reason (D68 DP-15 follow-up).

Revision ID: 0028
Revises: 0027

**Why.** Re-including a suspended class is the one act that puts Q1 back in front of a person's
approvals for a class the control plane took out because it failed. ``cleared_by`` said who;
nothing said why. A clearing now carries ``cleared_reason`` -- short free text written by the
operator -- and the database refuses a clearing without one, the same way it refuses one without a
name:

* ``cleared_reason`` is set in the same statement as ``cleared_at`` and ``cleared_by`` (a table
  CHECK ties the three together: all NULL while the suspension is live, all set once cleared);
* it is not empty and not longer than 500 characters;
* ``global_policy_admin`` gets ``UPDATE (cleared_reason)`` beside the other two columns, and nothing
  else; the guard trigger of 0027 already freezes a row once it is cleared, so a reason cannot be
  edited afterwards.

A suspension cleared before this migration (only on a database where someone ran the operator
script during development) is given the reason ``(cleared before reasons were recorded)``, with the
guard trigger off for that one statement; no live suspension is touched.

**Downgrade** drops the column (and its checks with it).
"""

from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE goal_fit_suspensions ADD COLUMN cleared_reason TEXT;")
    op.execute("ALTER TABLE goal_fit_suspensions DISABLE TRIGGER goal_fit_suspensions_guard;")
    op.execute("ALTER TABLE goal_fit_suspensions NO FORCE ROW LEVEL SECURITY;")
    op.execute("UPDATE goal_fit_suspensions SET cleared_reason = "
               "'(cleared before reasons were recorded)' WHERE cleared_at IS NOT NULL;")
    op.execute("ALTER TABLE goal_fit_suspensions FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE goal_fit_suspensions ENABLE TRIGGER goal_fit_suspensions_guard;")
    op.execute("ALTER TABLE goal_fit_suspensions ADD CONSTRAINT "
               "goal_fit_suspensions_reason_shape CHECK (cleared_reason IS NULL OR "
               "(cleared_reason <> '' AND length(cleared_reason) <= 500));")
    op.execute("ALTER TABLE goal_fit_suspensions ADD CONSTRAINT "
               "goal_fit_suspensions_reason_with_clearing CHECK "
               "((cleared_at IS NULL) = (cleared_reason IS NULL));")
    op.execute("GRANT UPDATE (cleared_reason) ON goal_fit_suspensions TO global_policy_admin;")


def downgrade() -> None:
    op.execute("ALTER TABLE goal_fit_suspensions DROP CONSTRAINT IF EXISTS "
               "goal_fit_suspensions_reason_with_clearing;")
    op.execute("ALTER TABLE goal_fit_suspensions DROP CONSTRAINT IF EXISTS "
               "goal_fit_suspensions_reason_shape;")
    op.execute("ALTER TABLE goal_fit_suspensions DROP COLUMN IF EXISTS cleared_reason;")
