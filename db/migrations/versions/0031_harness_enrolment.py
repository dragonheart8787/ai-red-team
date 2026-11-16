"""The harness's enrolment list: which engagements the production harness may work on (D69 H5b).

Revision ID: 0031
Revises: 0030

``harness_enrolment`` is the list a person writes before the harness's loop may touch an
engagement. It is the harness's own list, not the scheduler's: the scheduler dispatches what a
person approved, the harness proposes, and neither list decides the other's. It follows
``scheduler_enrollment`` (0019) closely and differs where the harness's job differs:

* **No new role.** ``cyberorch_app`` -- the role the harness already connects as -- reads and writes
  it, and **no other role has any privilege on it**: not ``scheduler_admin`` or
  ``scheduler_reader``, not the reconciler, the UI, the registry, the credential vault or the
  auditor. ``cyberorch_app``
  gets ``SELECT`` and ``INSERT``, ``UPDATE`` on the two withdrawal columns only, and no ``DELETE``:
  a registration is history, and ending one is a withdrawal.
* **Global, so per-role row security.** There is no engagement bound on the connection that reads
  the list (the reader has to list ids to know which engagement to open), so the policies are
  written for the role and not for an engagement: ``FORCE ROW LEVEL SECURITY`` binds the table's
  owner too, and the policies name ``cyberorch_app`` and nobody else.
* **``engagement_id`` references ``engagements``,** as in 0019: a referential-integrity check
  bypasses row security, so an id that does not exist is refused by the database whoever asks, and
  ``engagements`` cannot lose a row (``cyberorch_app`` has no ``DELETE`` on it since 0010).
* **``purpose``** is ``NOT NULL`` with no default, and its ``CHECK`` allows ``'harness_lab'`` only.
  It is an operator's statement of what the registration is for, not a control: nothing in
  ``engagements`` tells a laboratory engagement from a real one (its columns are the id, a free-text
  ``customer_id``, a status, the kill switch, the policy snapshot version, the baseline freeze
  position and two timestamps), so the label can be wrong. It stops a mistaken registration and a
  later purpose being picked up by a reader that does not ask for it; it does not stop a person who
  means to lie. The reader (``harness/enrolment_db.py``) returns only the rows whose purpose is
  ``harness_lab``.
* **History is append-only.** A trigger forbids everything but withdrawing a live registration: no
  column of a written row changes, and a withdrawn row stays withdrawn. A withdrawn engagement can
  be registered again -- the unique index covers the live rows only.
"""

from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE harness_enrolment (
            enrolment_id   BIGSERIAL PRIMARY KEY,
            engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
            purpose        TEXT NOT NULL
                           CONSTRAINT harness_enrolment_purpose_check
                           CHECK (purpose IN ('harness_lab')),
            enrolled_by    TEXT NOT NULL CHECK (enrolled_by <> ''),
            enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            withdrawn_by   TEXT,
            withdrawn_at   TIMESTAMPTZ,
            CONSTRAINT harness_enrolment_withdrawn_pair
                CHECK ((withdrawn_at IS NULL) = (withdrawn_by IS NULL))
        );
    """)
    op.execute("CREATE UNIQUE INDEX harness_enrolment_live ON harness_enrolment "
               "(engagement_id) WHERE withdrawn_at IS NULL;")
    op.execute("ALTER TABLE harness_enrolment ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE harness_enrolment FORCE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY runtime_read ON harness_enrolment
            FOR SELECT TO cyberorch_app USING (true);
    """)
    op.execute("""
        CREATE POLICY runtime_insert ON harness_enrolment
            FOR INSERT TO cyberorch_app WITH CHECK (true);
    """)
    op.execute("""
        CREATE POLICY runtime_withdraw ON harness_enrolment
            FOR UPDATE TO cyberorch_app USING (true) WITH CHECK (true);
    """)
    op.execute("""
        CREATE FUNCTION harness_enrolment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.enrolment_id IS DISTINCT FROM OLD.enrolment_id
               OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
               OR NEW.purpose       IS DISTINCT FROM OLD.purpose
               OR NEW.enrolled_by   IS DISTINCT FROM OLD.enrolled_by
               OR NEW.enrolled_at   IS DISTINCT FROM OLD.enrolled_at THEN
                RAISE EXCEPTION 'an enrolment is fixed when it is written (id %)',
                    OLD.enrolment_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            IF OLD.withdrawn_at IS NOT NULL
               AND (NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at
                    OR NEW.withdrawn_by IS DISTINCT FROM OLD.withdrawn_by) THEN
                RAISE EXCEPTION 'a withdrawn enrolment stays withdrawn (id %)',
                    OLD.enrolment_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END $$;
    """)
    op.execute("CREATE TRIGGER harness_enrolment_guard BEFORE UPDATE ON harness_enrolment "
               "FOR EACH ROW EXECUTE FUNCTION harness_enrolment_guard();")
    op.execute("GRANT SELECT, INSERT ON harness_enrolment TO cyberorch_app;")
    op.execute("GRANT UPDATE (withdrawn_by, withdrawn_at) ON harness_enrolment TO cyberorch_app;")
    op.execute("GRANT USAGE ON SEQUENCE harness_enrolment_enrolment_id_seq TO cyberorch_app;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS harness_enrolment;")
    op.execute("DROP FUNCTION IF EXISTS harness_enrolment_guard();")
