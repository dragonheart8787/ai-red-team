"""Every look at the admission report is recorded (D68 DP-15).

Revision ID: 0030
Revises: 0029

**Why.** The admission recommendation is read from a rolling window, so the more often it is read
the more likely a class is to be seen in a good stretch (``docs/D68_DP15_ADMISSION_LOOKS.md``). The
rule cannot stop anyone from looking, but it can make looking visible: each run of
``scripts/manage_goal_fit_classes.py report`` writes one row per class -- when, the window's ``n``,
its failures and upper bound, and who ran it -- and the report shows how many times a class has
been looked at and what ``n`` it had the first time.

A row is a record about reading, never an input: nothing in the control plane reads this table,
and the report prints whether or not it could write. Append-only; the runtime role (the one the
tool already uses to write an audit event) may insert and read, nobody else has any grant.
``viewer`` is the name the tool found for the person (the kernel's login uid where it has one) and
``identity_unverified`` says when it had to take the environment's word.

**Downgrade** drops the table.
"""

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

ACTION_RE = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE goal_fit_report_views (
            view_id              BIGSERIAL PRIMARY KEY,
            viewed_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
            action               TEXT NOT NULL CHECK (action ~ '{ACTION_RE}'),
            window_n             INTEGER NOT NULL CHECK (window_n >= 0),
            window_failed        INTEGER NOT NULL
                                 CHECK (window_failed >= 0 AND window_failed <= window_n),
            upper95              DOUBLE PRECISION NOT NULL CHECK (upper95 >= 0 AND upper95 <= 1),
            viewer               TEXT NOT NULL CHECK (viewer <> ''),
            identity_unverified  BOOLEAN NOT NULL
        );
    """)
    op.execute("CREATE INDEX goal_fit_report_views_action ON goal_fit_report_views "
               "(action, view_id);")
    op.execute("ALTER TABLE goal_fit_report_views ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE goal_fit_report_views FORCE ROW LEVEL SECURITY;")
    op.execute("CREATE POLICY runtime_read ON goal_fit_report_views FOR SELECT "
               "TO cyberorch_app USING (true);")
    op.execute("CREATE POLICY runtime_insert ON goal_fit_report_views FOR INSERT "
               "TO cyberorch_app WITH CHECK (true);")
    op.execute("GRANT SELECT, INSERT ON goal_fit_report_views TO cyberorch_app;")
    op.execute("GRANT USAGE ON SEQUENCE goal_fit_report_views_view_id_seq TO cyberorch_app;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS goal_fit_report_views;")
