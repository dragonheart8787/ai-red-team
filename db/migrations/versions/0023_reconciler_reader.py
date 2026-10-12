"""The reconciler's read side: two SECURITY DEFINER functions, nothing else (ACCEPTANCE 5.80).

Revision ID: 0023
Revises: 0022

The reconciler's plan side has to see stuck work in **every** engagement, and every table it needs
is under FORCE ROW LEVEL SECURITY keyed on a per-connection GUC (D64 §2.3). The narrowest way
to cross that is a function: ``reconciler_reader`` (login) holds ``EXECUTE`` on two functions and
no privilege on any table; the functions are owned by ``reconciler_fn_owner`` (NOLOGIN,
NOSUPERUSER, NOBYPASSRLS), whose own row policies and column grants decide what they can read.
Both roles are created in
``db/roles.sql`` (a migration cannot ``CREATE ROLE``); this migration creates the functions, the
policies and the grants.

A ``SECURITY DEFINER`` function **does not bypass row-level security**; it runs under the owner's
policies. Four mistakes were measured on the way to this text (D64 §2.3 S2-S5, experiment E20), and
each is closed here and has a structural test and a mutation (``tests/test_reconciler_reader.py``):

* **S2 -- the stage filter.** The existing ``engagement_isolation`` policy is ``TO PUBLIC``, so it
  applies to the owner too and policies are OR-ed: a caller that sets the GUC widens what the owner
  sees to that whole engagement. Both functions therefore filter ``pipeline_stage`` themselves.
* **S3 -- EXECUTE.** It defaults to PUBLIC. ``REVOKE ALL ... FROM PUBLIC``, then ``GRANT EXECUTE``
  to ``reconciler_reader`` alone.
* **S4 -- search_path.** An unpinned function resolved ``action_proposals`` to a TEMP table the
  caller had made. ``SET search_path = pg_catalog, <schema>, pg_temp`` and every relation is
  schema-qualified. As a second line the database-level ``TEMP`` privilege is taken from PUBLIC and
  from the reader (nothing in the repository creates a temporary table).
* **S5 -- the cast.** ``(budget->>'max_duration_seconds')::int`` on ``"abc"`` raises for the whole
  call, so one bad row blinds the reconciler, and the error echoes the value. The cast is guarded:
  the value must be a JSON *number* matching ``^[1-9][0-9]{0,8}$``, else NULL (the plan reports
  ``budget_unreadable``).

**What the functions return** -- ids, the closed ``pipeline_stage`` / engagement-status /
run-status vocabularies (each CHECK-bound in its table), integers (epoch microseconds, seconds), and
booleans. Never a target, a decision, a reason, a budget document, an array, or free text. Time is
the *database's* clock (``db_now_us`` is returned with each row), so the plan never compares two
clocks.

``reconciler_stuck_proposals()`` -- one row per proposal in ``received``, ``decided``, ``approved``,
``capability_issued`` or ``dispatching`` (``awaiting_approval`` is a person's, not a fault), oldest
first, at most ``LIMIT_ROWS`` of them; the rest are returned on later passes as the oldest are
resolved. With the latest capability, approval and run of that proposal, the engagement's status,
kill flag and whether the scheduler serves it.

``reconciler_run_states(text[])`` -- the status of the given run ids, for the orphan-container and
orphan-proxy judgement. A run id the database does not know is **absent** from the result, which the
plan reads as "orphan"; so the function refuses (a fixed-text error, no content) a NULL argument and
more than ``MAX_RUN_IDS`` ids instead of silently returning less.

**Downgrade** drops the functions, the policies, the column grants and the four read indexes, and
puts ``TEMP`` back on PUBLIC, which is what the database had before. The two roles stay: they are
cluster-global and belong to ``roles.sql``.
"""

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

OWNER = "reconciler_fn_owner"
READER = "reconciler_reader"
POLICY = "reconciler_owner_select"

#: The stages the reconciler looks at. ``awaiting_approval`` is a person's, not a fault.
STUCK_STAGES = ("received", "decided", "approved", "capability_issued", "dispatching")
LIMIT_ROWS = 5000
MAX_RUN_IDS = 2000

#: owner's column-level SELECT: exactly the columns the functions read, nothing wider.
OWNER_COLUMNS = {
    "action_proposals": ("engagement_id", "proposal_id", "pipeline_stage", "stage_updated_at"),
    "capabilities": ("capability_id", "engagement_id", "proposal_id", "budget",
                     "lease_expires_at", "revoked", "issued_at"),
    "approvals": ("approval_id", "engagement_id", "proposal_id", "valid_until", "revoked"),
    "engagements": ("engagement_id", "status", "kill_switch_engaged"),
    "scheduler_enrollment": ("engagement_id", "withdrawn_at"),
    "tool_runs": ("run_id", "engagement_id", "proposal_id", "status", "created_at"),
}

#: The indexes the stuck-proposals read needs. Without them the function took 18 s on the
#: development database (25k proposals, 22k capabilities: a sequential scan of each per stuck row);
#: with them 0.15 s (D64 experiment E21). The partial index carries the function's own stage list
#: and ordering.
INDEXES = {
    "capabilities_by_proposal": "capabilities (proposal_id, issued_at)",
    "approvals_by_proposal": "approvals (proposal_id)",
    "tool_runs_by_proposal": "tool_runs (proposal_id, created_at)",
    "action_proposals_reconciler_stuck":
        "action_proposals (stage_updated_at, proposal_id) WHERE pipeline_stage IN ({stages})",
}

COMMENT_STUCK = (
    "D64 0023: stuck proposals across engagements for the reconciler's plan. SECURITY DEFINER, "
    "owner reconciler_fn_owner (NOLOGIN, NOBYPASSRLS), pinned search_path, EXECUTE for "
    "reconciler_reader only. Returns ids, closed-vocabulary enums and integers; never a target, a "
    "decision or a budget document."
)
COMMENT_RUNS = (
    "D64 0023: the status of the given run ids, for orphan-container and orphan-proxy judgement. "
    "SECURITY DEFINER, same owner and grants as reconciler_stuck_proposals. Refuses NULL and more "
    "than 2000 ids with a fixed error text, because an absent id means orphan."
)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _stages() -> str:
    return ", ".join(f"'{s}'" for s in STUCK_STAGES)


def _us(expression: str) -> str:
    """Epoch microseconds of a timestamptz: an integer, whatever the session's time zone."""
    return f"(extract(epoch FROM {expression}) * 1000000)::bigint"


def _schema() -> str:
    """The schema the migration runs in: ``public`` in production, a scratch schema in the
    round-trip test (which rewrites the literal ``SCHEMA public`` in these files, not a computed
    name)."""
    return op.get_bind().exec_driver_sql("SELECT quote_ident(current_schema())").scalar_one()


def _stuck_function(s: str) -> str:
    return f"""
        CREATE FUNCTION {s}.reconciler_stuck_proposals()
        RETURNS TABLE (
            engagement_id         text,
            proposal_id           text,
            pipeline_stage        text,
            stage_updated_us      bigint,
            db_now_us             bigint,
            engagement_status     text,
            kill_switch_engaged   boolean,
            enrolled              boolean,
            capability_id         text,
            max_duration_s        integer,
            lease_expires_us      bigint,
            capability_revoked    boolean,
            approval_id           text,
            approval_valid_until_us bigint,
            approval_revoked      boolean,
            run_id                text,
            run_status            text
        )
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, {s}, pg_temp
        AS $fn$
            SELECT p.engagement_id,
                   p.proposal_id,
                   p.pipeline_stage,
                   {_us("p.stage_updated_at")},
                   {_us("now()")},
                   e.status,
                   e.kill_switch_engaged,
                   EXISTS (SELECT 1 FROM {s}.scheduler_enrollment se
                           WHERE se.engagement_id = p.engagement_id AND se.withdrawn_at IS NULL),
                   c.capability_id,
                   CASE WHEN jsonb_typeof(c.budget -> 'max_duration_seconds') = 'number'
                         AND (c.budget ->> 'max_duration_seconds') ~ '^[1-9][0-9]{{0,8}}$'
                        THEN (c.budget ->> 'max_duration_seconds')::integer END,
                   {_us("c.lease_expires_at")},
                   c.revoked,
                   a.approval_id,
                   {_us("a.valid_until")},
                   a.revoked,
                   r.run_id,
                   r.status
            FROM {s}.action_proposals p
            LEFT JOIN {s}.engagements e ON e.engagement_id = p.engagement_id
            LEFT JOIN LATERAL (
                SELECT c0.capability_id, c0.budget, c0.lease_expires_at, c0.revoked
                FROM {s}.capabilities c0
                WHERE c0.proposal_id = p.proposal_id AND c0.engagement_id = p.engagement_id
                ORDER BY c0.issued_at DESC, c0.capability_id DESC LIMIT 1) c ON true
            LEFT JOIN LATERAL (
                SELECT a0.approval_id, a0.valid_until, a0.revoked
                FROM {s}.approvals a0
                WHERE a0.proposal_id = p.proposal_id AND a0.engagement_id = p.engagement_id
                ORDER BY a0.valid_until DESC, a0.approval_id DESC LIMIT 1) a ON true
            LEFT JOIN LATERAL (
                SELECT r0.run_id, r0.status
                FROM {s}.tool_runs r0
                WHERE r0.proposal_id = p.proposal_id AND r0.engagement_id = p.engagement_id
                ORDER BY r0.created_at DESC, r0.run_id DESC LIMIT 1) r ON true
            WHERE p.pipeline_stage IN ({_stages()})
            ORDER BY p.stage_updated_at, p.proposal_id
            LIMIT {LIMIT_ROWS}
        $fn$;
    """


def _runs_function(s: str) -> str:
    return f"""
        CREATE FUNCTION {s}.reconciler_run_states(p_run_ids text[])
        RETURNS TABLE (run_id text, status text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, {s}, pg_temp
        AS $fn$
        BEGIN
            IF p_run_ids IS NULL OR cardinality(p_run_ids) > {MAX_RUN_IDS} THEN
                RAISE EXCEPTION 'reconciler_run_states: argument refused'
                    USING ERRCODE = '22023';
            END IF;
            RETURN QUERY
                SELECT t.run_id, t.status FROM {s}.tool_runs t
                WHERE t.run_id = ANY (p_run_ids)
                ORDER BY t.run_id;
        END
        $fn$;
    """


def _policy_using(table: str, s: str) -> str:
    if table == "action_proposals":
        return f"pipeline_stage IN ({_stages()})"
    if table == "scheduler_enrollment":
        return "withdrawn_at IS NULL"
    if table == "tool_runs":
        # Orphan detection needs terminal runs too; the columns and the function bound what is read.
        return "true"
    if table == "engagements":
        return (f"EXISTS (SELECT 1 FROM {s}.action_proposals p "
                f"WHERE p.engagement_id = engagements.engagement_id)")
    # capabilities, approvals: the proposal they belong to must itself be a visible (stuck) one.
    return (f"EXISTS (SELECT 1 FROM {s}.action_proposals p "
            f"WHERE p.proposal_id = {table}.proposal_id "
            f"AND p.engagement_id = {table}.engagement_id)")


def upgrade() -> None:
    s = _schema()
    # The roles come from roles.sql. Fail with a sentence, not an obscure "role does not exist".
    op.execute(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{OWNER}')
               OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{READER}') THEN
                RAISE EXCEPTION 'roles {OWNER} and {READER} come from db/roles.sql; run it first';
            END IF;
        END $$;
    """)

    op.execute(f"GRANT USAGE ON SCHEMA {s} TO {OWNER}, {READER};")
    op.execute(f"GRANT EXECUTE ON FUNCTION {s}.cyberorch_current_engagement() TO {OWNER};")
    for table, columns in OWNER_COLUMNS.items():
        op.execute(f"GRANT SELECT ({', '.join(columns)}) ON {s}.{table} TO {OWNER};")
        op.execute(f"""
            CREATE POLICY {POLICY} ON {s}.{table} FOR SELECT TO {OWNER}
                USING ({_policy_using(table, s)});
        """)

    for name, definition in INDEXES.items():
        table, rest = definition.split(" ", 1)
        op.execute(f"CREATE INDEX {name} ON {s}.{table} {rest.format(stages=_stages())};")

    op.execute(_stuck_function(s))
    op.execute(_runs_function(s))
    # Everything that needs the function's owner is done while migration_owner still is one: the
    # hand-over comes last, because migration_owner is a member of reconciler_fn_owner WITHOUT
    # inheriting it (db/roles.sql) and so cannot touch the functions afterwards. ALTER ... OWNER
    # needs the new owner to hold CREATE on the schema for the length of the statement; it is
    # granted and taken back in the same transaction.
    for signature, comment in (("reconciler_stuck_proposals()", COMMENT_STUCK),
                               ("reconciler_run_states(text[])", COMMENT_RUNS)):
        op.execute(f"REVOKE ALL ON FUNCTION {s}.{signature} FROM PUBLIC;")
        op.execute(f"GRANT EXECUTE ON FUNCTION {s}.{signature} TO {READER};")
        op.execute(f"COMMENT ON FUNCTION {s}.{signature} IS {_literal(comment)};")
    op.execute(f"GRANT CREATE ON SCHEMA {s} TO {OWNER};")
    for signature in ("reconciler_stuck_proposals()", "reconciler_run_states(text[])"):
        op.execute(f"ALTER FUNCTION {s}.{signature} OWNER TO {OWNER};")
    op.execute(f"REVOKE CREATE ON SCHEMA {s} FROM {OWNER};")

    # Second line against S4: no TEMP table can be made by the reader (who holds it only through
    # PUBLIC), or by anyone else without a grant. Nothing in the repository creates one. (Dynamic
    # SQL: the database's name is not known to the migration.)
    op.execute("""
        DO $$
        BEGIN
            EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
        END $$;
    """)


def downgrade() -> None:
    s = _schema()
    op.execute("""
        DO $$
        BEGIN
            EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO PUBLIC', current_database());
        END $$;
    """)
    for name in INDEXES:
        op.execute(f"DROP INDEX {s}.{name};")
    op.execute(f"DROP FUNCTION {s}.reconciler_run_states(text[]);")
    op.execute(f"DROP FUNCTION {s}.reconciler_stuck_proposals();")
    for table, columns in OWNER_COLUMNS.items():
        op.execute(f"DROP POLICY {POLICY} ON {s}.{table};")
        op.execute(f"REVOKE SELECT ({', '.join(columns)}) ON {s}.{table} FROM {OWNER};")
    op.execute(f"REVOKE EXECUTE ON FUNCTION {s}.cyberorch_current_engagement() FROM {OWNER};")
    op.execute(f"REVOKE USAGE ON SCHEMA {s} FROM {OWNER}, {READER};")
