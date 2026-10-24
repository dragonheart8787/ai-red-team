"""A failed Q1 call has a kind, and a suspected outage of the validator is recorded (D68 DP-15).

Revision ID: 0029
Revises: 0028

**Why.** The per-class exit rule (0027) counted every failed call. A failed call is one of three
things: the service's safety classifier stopped the turn (``refusal``), the call never got an answer
for a reason that says nothing about the question -- a timeout, a connection error, a 5xx, an
authentication or usage error (``transport``) -- or anything else (``unclassified``). Only the
first and the last are about the class. An outage of the validator service must not suspend every
class that has traffic, so the rule now ignores ``transport`` calls; the check still fails closed
for them, exactly as before (that is the control plane's, not the database's).

**What changes.**

* ``goal_fit_calls.failure_kind`` -- ``refusal`` / ``transport`` / ``unclassified`` for a failed
  call, ``NULL`` for an answered one; a table CHECK ties the two columns together
  (``outcome = 'failed'`` exactly when a kind is present). Closed vocabulary, no text. **Existing
  failed rows are given ``unclassified``**, which is what the rule has always done with them
  (counted), so no class's history changes; the data statement runs with FORCE ROW LEVEL SECURITY
  off for that one table.
* ``goal_fit_outage_suspicions`` -- one row each time the share of ``transport`` failures among the
  last 30 calls (of any class) rises above 50%: when, and how many of the 30. Append-only; the
  runtime role may insert and read, ``global_policy_admin`` may read. It suspends nothing. It exists
  so that the reports can show the period's suspected outages: the matching audit event is
  global-scope, which neither the runtime role nor the operator role can read.

**Downgrade** drops the table, the column and its checks; a ``transport`` row simply becomes a
failed row again, and counts.
"""

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE goal_fit_calls ADD COLUMN failure_kind TEXT;")
    op.execute("ALTER TABLE goal_fit_calls NO FORCE ROW LEVEL SECURITY;")
    op.execute("UPDATE goal_fit_calls SET failure_kind = 'unclassified' WHERE outcome = 'failed';")
    op.execute("ALTER TABLE goal_fit_calls FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE goal_fit_calls ADD CONSTRAINT goal_fit_calls_kind_vocabulary CHECK "
               "(failure_kind IS NULL OR failure_kind IN ('refusal', 'transport', "
               "'unclassified'));")
    op.execute("ALTER TABLE goal_fit_calls ADD CONSTRAINT goal_fit_calls_kind_with_failure CHECK "
               "((outcome = 'failed') = (failure_kind IS NOT NULL));")
    op.execute("CREATE INDEX goal_fit_calls_all_recent ON goal_fit_calls (call_id DESC);")

    op.execute("""
        CREATE TABLE goal_fit_outage_suspicions (
            suspicion_id      BIGSERIAL PRIMARY KEY,
            detected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            window_n          INTEGER NOT NULL CHECK (window_n > 0),
            window_transport  INTEGER NOT NULL
                              CHECK (window_transport >= 0 AND window_transport <= window_n)
        );
    """)
    op.execute("ALTER TABLE goal_fit_outage_suspicions ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE goal_fit_outage_suspicions FORCE ROW LEVEL SECURITY;")
    op.execute("CREATE POLICY runtime_read ON goal_fit_outage_suspicions FOR SELECT "
               "TO cyberorch_app USING (true);")
    op.execute("CREATE POLICY runtime_insert ON goal_fit_outage_suspicions FOR INSERT "
               "TO cyberorch_app WITH CHECK (true);")
    op.execute("CREATE POLICY operator_read ON goal_fit_outage_suspicions FOR SELECT "
               "TO global_policy_admin USING (true);")
    op.execute("GRANT SELECT, INSERT ON goal_fit_outage_suspicions TO cyberorch_app;")
    op.execute("GRANT USAGE ON SEQUENCE goal_fit_outage_suspicions_suspicion_id_seq "
               "TO cyberorch_app;")
    op.execute("GRANT SELECT ON goal_fit_outage_suspicions TO global_policy_admin;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS goal_fit_outage_suspicions;")
    op.execute("DROP INDEX IF EXISTS goal_fit_calls_all_recent;")
    op.execute("ALTER TABLE goal_fit_calls DROP CONSTRAINT IF EXISTS "
               "goal_fit_calls_kind_with_failure;")
    op.execute("ALTER TABLE goal_fit_calls DROP CONSTRAINT IF EXISTS "
               "goal_fit_calls_kind_vocabulary;")
    op.execute("ALTER TABLE goal_fit_calls DROP COLUMN IF EXISTS failure_kind;")
