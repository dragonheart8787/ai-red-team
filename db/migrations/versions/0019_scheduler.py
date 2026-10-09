"""The scheduler's tables, view and grants (D62, D58-1/2/3/4).

Revision ID: 0019
Revises: 0018

Three roles (created by ``db/roles.sql``), each with one job and a short grant list:

* ``scheduler_admin`` -- writes ``scheduler_enrollment``, the list of engagements the scheduler
  may touch (D58-1/A). Used by an operator's CLI, never by the service. Reads nothing else.
* ``scheduler_reader`` -- reads the scheduling decision's inputs, and **only** those: the
  enrollment list; ``engagements.engagement_id/status/kill_switch_engaged``; the view
  ``scheduler_proposals``; ``scheduler_state``. It has **no grant** on ``action_proposals``
  itself, on ``audit_log``, ``tasks``, ``capabilities``, ``tool_runs``, ``approvals``,
  ``evidence`` or ``credential_material``.
* ``scheduler_state_writer`` -- writes ``scheduler_state``, and nothing else.

``cyberorch_app`` gets **no** grant on either new table: the pipeline's own role cannot read or
write the enrollment list or the scheduler's state.

* ``scheduler_enrollment`` -- global (no engagement GUC: the reader must list ids to know which
  engagement to open), so its row-level security is written per role rather than per
  engagement. ``engagement_id`` references ``engagements`` -- referential-integrity checks
  bypass row security, so a nonexistent id is refused by the database. Append-only history; a
  trigger forbids everything but withdrawing a live enrollment.
* ``scheduler_state`` -- the scheduler's memory between ticks, as **closed vocabulary**: every
  column is an id, a timestamp or a ``CHECK``-constrained code, so no column can hold free
  text (an ``audit_log.payload`` grant could not give the same guarantee). Engagement-isolated
  like every other engagement table.
* ``scheduler_proposals`` -- a view over ``action_proposals`` exposing five columns. ``action``
  is free text written by the agent before any registry check, so the view maps any name that
  is not a registered action to ``'other'``: the database itself makes ``action_class`` a
  closed vocabulary. The registered names are listed here; ``tests/test_scheduler_roles.py``
  fails if they drift from ``tool_gateway.registry.ADAPTERS``. It is a definer view --
  ``FORCE ROW LEVEL SECURITY`` applies to its owner, whose policy reads the same engagement
  setting, so it shows one engagement at a time (verified by execution, and tested).
"""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

#: ``tool_gateway.registry.ADAPTERS`` at the time of writing. A new adapter needs a migration that
#: replaces this view; the test that compares the two is what makes that visible.
REGISTERED_ACTIONS = (
    "network.scan", "network.recon", "web.get", "web.post", "web.render",
    "ad.collect", "code.scan", "code.secrets",
)

SKIP_CODES = (
    "action_not_supported_v0", "scope_type_has_no_network_range",
    "scope_narrower_than_sandbox_minimum", "no_usable_block_for_address",
    "target_is_reserved_address", "ipv6_not_supported_v0",
)
DEFER_CODES = ("engagement_paused", "engagement_killed", "engagement_not_active")


def _in(values) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    # ------------------------------------------------------------------ enrollment
    op.execute("""
        CREATE TABLE scheduler_enrollment (
            enrollment_id  BIGSERIAL PRIMARY KEY,
            engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
            enrolled_by    TEXT NOT NULL CHECK (enrolled_by <> ''),
            enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            withdrawn_by   TEXT,
            withdrawn_at   TIMESTAMPTZ,
            CHECK ((withdrawn_at IS NULL) = (withdrawn_by IS NULL))
        );
    """)
    op.execute("CREATE UNIQUE INDEX scheduler_enrollment_live ON scheduler_enrollment "
               "(engagement_id) WHERE withdrawn_at IS NULL;")
    op.execute("ALTER TABLE scheduler_enrollment ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scheduler_enrollment FORCE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY scheduler_admin_all ON scheduler_enrollment
            FOR ALL TO scheduler_admin USING (true) WITH CHECK (true);
    """)
    op.execute("""
        CREATE POLICY scheduler_reader_select ON scheduler_enrollment
            FOR SELECT TO scheduler_reader USING (true);
    """)
    op.execute("""
        CREATE FUNCTION scheduler_enrollment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.enrollment_id IS DISTINCT FROM OLD.enrollment_id
               OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
               OR NEW.enrolled_by   IS DISTINCT FROM OLD.enrolled_by
               OR NEW.enrolled_at   IS DISTINCT FROM OLD.enrolled_at THEN
                RAISE EXCEPTION 'an enrollment is fixed when it is written (id %)',
                    OLD.enrollment_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            IF OLD.withdrawn_at IS NOT NULL
               AND (NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at
                    OR NEW.withdrawn_by IS DISTINCT FROM OLD.withdrawn_by) THEN
                RAISE EXCEPTION 'a withdrawn enrollment stays withdrawn (id %)',
                    OLD.enrollment_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END $$;
    """)
    op.execute("CREATE TRIGGER scheduler_enrollment_guard BEFORE UPDATE ON scheduler_enrollment "
               "FOR EACH ROW EXECUTE FUNCTION scheduler_enrollment_guard();")
    op.execute("GRANT USAGE ON SCHEMA public TO scheduler_admin, scheduler_reader, "
               "scheduler_state_writer;")
    op.execute("GRANT SELECT, INSERT ON scheduler_enrollment TO scheduler_admin;")
    op.execute("GRANT UPDATE (withdrawn_by, withdrawn_at) ON scheduler_enrollment "
               "TO scheduler_admin;")
    op.execute("GRANT USAGE ON SEQUENCE scheduler_enrollment_enrollment_id_seq "
               "TO scheduler_admin;")
    op.execute("GRANT SELECT ON scheduler_enrollment TO scheduler_reader;")

    # ------------------------------------------------------------------ state
    op.execute("""
        ALTER TABLE action_proposals
            ADD CONSTRAINT action_proposals_id_engagement UNIQUE (proposal_id, engagement_id);
    """)
    codes = _in(SKIP_CODES + DEFER_CODES + ("approved_and_idle",))
    op.execute(f"""
        CREATE TABLE scheduler_state (
            engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
            proposal_id    TEXT,
            kind           TEXT NOT NULL CHECK (kind IN ('engagement', 'proposal')),
            disposition    TEXT NOT NULL CHECK (disposition IN
                               ('served', 'deferred', 'skipped', 'dispatch_decided')),
            reason_code    TEXT CHECK (reason_code IN ({codes})),
            since          TIMESTAMPTZ NOT NULL DEFAULT now(),
            FOREIGN KEY (proposal_id, engagement_id)
                REFERENCES action_proposals (proposal_id, engagement_id),
            CHECK ((kind = 'engagement' AND proposal_id IS NULL
                        AND disposition IN ('served', 'deferred'))
                OR (kind = 'proposal' AND proposal_id IS NOT NULL
                        AND disposition IN ('skipped', 'dispatch_decided'))),
            -- A NULL makes `reason_code IN (...)` NULL, and a CHECK passes on NULL: each branch
            -- that needs a code says so explicitly, or "skipped, no reason" would be accepted.
            CHECK ((disposition = 'served'           AND reason_code IS NULL)
                OR (disposition = 'deferred'         AND reason_code IS NOT NULL
                        AND reason_code IN ({_in(DEFER_CODES)}))
                OR (disposition = 'skipped'          AND reason_code IS NOT NULL
                        AND reason_code IN ({_in(SKIP_CODES)}))
                OR (disposition = 'dispatch_decided' AND reason_code IS NOT NULL
                        AND reason_code = 'approved_and_idle'))
        );
    """)
    op.execute("CREATE UNIQUE INDEX scheduler_state_key ON scheduler_state "
               "(engagement_id, COALESCE(proposal_id, ''));")
    op.execute("ALTER TABLE scheduler_state ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scheduler_state FORCE ROW LEVEL SECURITY;")
    op.execute("""
        CREATE POLICY engagement_isolation ON scheduler_state
            FOR ALL TO PUBLIC
            USING (engagement_id = cyberorch_current_engagement())
            WITH CHECK (engagement_id = cyberorch_current_engagement());
    """)
    op.execute("GRANT SELECT ON scheduler_state TO scheduler_reader;")
    op.execute("GRANT SELECT, INSERT ON scheduler_state TO scheduler_state_writer;")
    op.execute("GRANT UPDATE (disposition, reason_code, since) ON scheduler_state "
               "TO scheduler_state_writer;")
    op.execute("GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() "
               "TO scheduler_reader, scheduler_state_writer;")

    # ------------------------------------------------------------------ reader's other inputs
    op.execute("GRANT SELECT (engagement_id, status, kill_switch_engaged) ON engagements "
               "TO scheduler_reader;")
    op.execute(f"""
        CREATE VIEW scheduler_proposals WITH (security_barrier = true) AS
        SELECT proposal_id, engagement_id, pipeline_stage, stage_updated_at,
               CASE WHEN action IN ({_in(REGISTERED_ACTIONS)}) THEN action
                    ELSE 'other' END AS action_class
        FROM action_proposals;
    """)
    op.execute("GRANT SELECT ON scheduler_proposals TO scheduler_reader;")


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS scheduler_proposals;")
    op.execute("REVOKE SELECT (engagement_id, status, kill_switch_engaged) ON engagements "
               "FROM scheduler_reader;")
    op.execute("DROP TABLE IF EXISTS scheduler_state;")
    op.execute("ALTER TABLE action_proposals DROP CONSTRAINT IF EXISTS "
               "action_proposals_id_engagement;")
    op.execute("DROP TABLE IF EXISTS scheduler_enrollment;")
    op.execute("DROP FUNCTION IF EXISTS scheduler_enrollment_guard();")
    op.execute("REVOKE EXECUTE ON FUNCTION cyberorch_current_engagement() "
               "FROM scheduler_reader, scheduler_state_writer;")
    op.execute("REVOKE USAGE ON SCHEMA public FROM scheduler_admin, scheduler_reader, "
               "scheduler_state_writer;")
