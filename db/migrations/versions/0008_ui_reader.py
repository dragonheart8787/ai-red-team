"""ui_reader — the web console's read-only connection (D29).

The console (control_plane/web) shows engagement state, findings, evidence, the
pending-approval queue and task decision histories. All of that is reading, and
a browser-facing process holding a connection that can also INSERT, UPDATE or
DELETE is a wider blast radius than the job needs: any defect in a read path
becomes a write primitive.

So the reads get their own role. It is deliberately *not* a new capability —
every row it can reach, ``cyberorch_app`` could already reach. What changes is
what a read endpoint can do if something goes wrong with it: nothing.

Three properties, each enforced by the database rather than by the application:

* **SELECT only.** No INSERT anywhere, and that includes ``audit_log``. The
  console's approve and deny actions are not served by this role at all — they
  run through the existing D24 ``grant_approval`` / ``deny_approval`` on the
  ``cyberorch_app`` connection, so there is exactly one write path and one audit
  path, shared with the CLI (D29 constraint 5).
* **Same RLS, same engagement boundary (I4).** ``engagement_isolation`` is
  ``FOR ALL TO PUBLIC``, so it already applies to this role; ``NOBYPASSRLS`` and
  owning nothing are what keep that true. With no engagement bound the policy
  matches nothing, so the connection fails closed rather than opening a
  cross-engagement view.
* **Only the tables the dashboard shows.** ``credentials``,
  ``metadata_registry``, ``provenance_edges`` and ``policy_layers`` are left
  out: the console does not display them, and a grant that covers "everything,
  read-only" would have to be re-justified every time a table is added.
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

# Exactly what the console reads, and nothing else. Kept as a list so the
# revoke in downgrade() cannot drift from the grant in upgrade().
UI_READABLE = [
    "engagements",
    "scope_registry",
    "tasks",
    "action_proposals",
    "approvals",
    "capabilities",
    "tool_runs",
    "evidence",
    "findings",
    "audit_log",
]


def upgrade() -> None:
    op.execute("GRANT USAGE ON SCHEMA public TO ui_reader;")
    for table in UI_READABLE:
        op.execute(f"GRANT SELECT ON {table} TO ui_reader;")
    # RLS reads the engagement GUC through this function, so the role that is
    # subject to the policy has to be able to call it.
    op.execute("GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() TO ui_reader;")


def downgrade() -> None:
    op.execute("REVOKE EXECUTE ON FUNCTION cyberorch_current_engagement() FROM ui_reader;")
    for table in UI_READABLE:
        op.execute(f"REVOKE SELECT ON {table} FROM ui_reader;")
    op.execute("REVOKE USAGE ON SCHEMA public FROM ui_reader;")
