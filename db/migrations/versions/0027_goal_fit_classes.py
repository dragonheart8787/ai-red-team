"""Q1 per action class: the calls the control plane has made, and the classes it has taken out (D68
DP-15).

Revision ID: 0027
Revises: 0026

**Why.** Q1's failure rate depends on the class of action a goal is about (the safety classifier
stops Active-Directory and reconnaissance wording much more often than a secrets scan), and a failed
check is a person. DP-15 lets Q1 be asked only about the classes an operator has let in, and takes a
class out on its own when its recent calls fail too often. Both need a memory that is **not** an
engagement's: the last fifty calls of a class are calls of every engagement, and the runtime role
cannot read another engagement's rows. Two small global tables, closed vocabulary, no free text.

* ``goal_fit_calls`` -- one row per call the validator was actually asked: the action class, the
  outcome (``answered`` / ``failed``) and the time. Append-only: the runtime role may insert and
  read, and has no grant to change or delete. It holds **no engagement, no target, no goal and no
  answer** -- nothing that could say what was asked.
* ``goal_fit_suspensions`` -- a class taken out. The runtime role may **insert** one (the control
  plane suspending a class) and read them; it cannot clear one. ``global_policy_admin`` -- the
  operator's role, the one that publishes global policy -- may clear it (``cleared_at`` and
  ``cleared_by``, once), and nothing else about a row can change. At most one live suspension per
  class. Re-inclusion is therefore a person's act, in the database and not only in the code.

Neither table references an engagement, so neither is isolated per engagement; row-level security is
written per role, as for ``scheduler_enrollment`` (0019): enabled and forced, one policy for each
role that has a grant. No other role has any.

**Downgrade** drops both tables and the guard function; nothing else is touched.
"""

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

ACTION_RE = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE goal_fit_calls (
            call_id    BIGSERIAL PRIMARY KEY,
            action     TEXT NOT NULL CHECK (action ~ '{ACTION_RE}'),
            outcome    TEXT NOT NULL CHECK (outcome IN ('answered', 'failed')),
            called_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """)
    op.execute("CREATE INDEX goal_fit_calls_recent ON goal_fit_calls (action, call_id DESC);")
    op.execute("ALTER TABLE goal_fit_calls ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE goal_fit_calls FORCE ROW LEVEL SECURITY;")
    op.execute("CREATE POLICY runtime_read ON goal_fit_calls FOR SELECT TO cyberorch_app "
               "USING (true);")
    op.execute("CREATE POLICY runtime_insert ON goal_fit_calls FOR INSERT TO cyberorch_app "
               "WITH CHECK (true);")
    op.execute("CREATE POLICY operator_read ON goal_fit_calls FOR SELECT TO global_policy_admin "
               "USING (true);")
    op.execute("GRANT SELECT, INSERT ON goal_fit_calls TO cyberorch_app;")
    op.execute("GRANT USAGE ON SEQUENCE goal_fit_calls_call_id_seq TO cyberorch_app;")
    op.execute("GRANT SELECT ON goal_fit_calls TO global_policy_admin;")

    op.execute(f"""
        CREATE TABLE goal_fit_suspensions (
            suspension_id  BIGSERIAL PRIMARY KEY,
            action         TEXT NOT NULL CHECK (action ~ '{ACTION_RE}'),
            suspended_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            window_n       INTEGER NOT NULL CHECK (window_n >= 0),
            window_failed  INTEGER NOT NULL
                           CHECK (window_failed >= 0 AND window_failed <= window_n),
            cleared_at     TIMESTAMPTZ,
            cleared_by     TEXT CHECK (cleared_by <> ''),
            CHECK ((cleared_at IS NULL) = (cleared_by IS NULL))
        );
    """)
    op.execute("CREATE UNIQUE INDEX goal_fit_suspensions_live ON goal_fit_suspensions (action) "
               "WHERE cleared_at IS NULL;")
    op.execute("ALTER TABLE goal_fit_suspensions ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE goal_fit_suspensions FORCE ROW LEVEL SECURITY;")
    op.execute("CREATE POLICY runtime_read ON goal_fit_suspensions FOR SELECT TO cyberorch_app "
               "USING (true);")
    op.execute("CREATE POLICY runtime_insert ON goal_fit_suspensions FOR INSERT TO cyberorch_app "
               "WITH CHECK (cleared_at IS NULL);")
    op.execute("CREATE POLICY operator_read ON goal_fit_suspensions FOR SELECT "
               "TO global_policy_admin USING (true);")
    op.execute("CREATE POLICY operator_clear ON goal_fit_suspensions FOR UPDATE "
               "TO global_policy_admin USING (cleared_at IS NULL) WITH CHECK (true);")
    op.execute("""
        CREATE FUNCTION goal_fit_suspensions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.suspension_id IS DISTINCT FROM OLD.suspension_id
               OR NEW.action IS DISTINCT FROM OLD.action
               OR NEW.suspended_at IS DISTINCT FROM OLD.suspended_at
               OR NEW.window_n IS DISTINCT FROM OLD.window_n
               OR NEW.window_failed IS DISTINCT FROM OLD.window_failed THEN
                RAISE EXCEPTION 'a suspension is fixed when it is written (id %)',
                    OLD.suspension_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            IF OLD.cleared_at IS NOT NULL THEN
                RAISE EXCEPTION 'a cleared suspension stays cleared (id %)', OLD.suspension_id
                    USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END $$;
    """)
    op.execute("CREATE TRIGGER goal_fit_suspensions_guard BEFORE UPDATE ON goal_fit_suspensions "
               "FOR EACH ROW EXECUTE FUNCTION goal_fit_suspensions_guard();")
    op.execute("GRANT SELECT, INSERT ON goal_fit_suspensions TO cyberorch_app;")
    op.execute("GRANT USAGE ON SEQUENCE goal_fit_suspensions_suspension_id_seq TO cyberorch_app;")
    op.execute("GRANT SELECT ON goal_fit_suspensions TO global_policy_admin;")
    op.execute("GRANT UPDATE (cleared_at, cleared_by) ON goal_fit_suspensions "
               "TO global_policy_admin;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS goal_fit_suspensions;")
    op.execute("DROP FUNCTION IF EXISTS goal_fit_suspensions_guard();")
    op.execute("DROP TABLE IF EXISTS goal_fit_calls;")
