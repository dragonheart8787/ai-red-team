"""The reconciler reads past its first page: ``reconciler_stuck_proposals_after`` (ACCEPTANCE 5.88).

Revision ID: 0024
Revises: 0023

``reconciler_stuck_proposals()`` returns the oldest ``LIMIT_ROWS`` stuck proposals and nothing
more. When more than that are stuck -- and a development database collects about 600 of them per
full run of the suite -- the proposals past the page are never seen, and if the oldest 5,000 are
ones the reconciler leaves alone (an ``approved`` proposal with no approval row is *reported*, not
acted on) a proposal that does need closing sits behind them for ever (D64 pre-deletion item 6,
experiment E23).

This adds the next page: the same rows, the same order, the same columns, the same owner, the same
policies, starting strictly after a keyset cursor ``(p_after_us, p_after_id)`` -- the
``stage_updated_us`` and ``proposal_id`` of the last row of the page before. A keyset, not an
``OFFSET``: the partial index on ``(stage_updated_at, proposal_id)`` serves it as a range scan, and
rows that leave the stuck set between two pages cannot make the next one skip.

What the function does with a cursor that is not whole: **nothing** -- no row is returned for a
``NULL`` in either half. (This is stated in the ``WHERE`` and not left to the row comparison: SQL
compares rows left to right, so ``ROW(a, b) > ROW(x, NULL)`` is *true* whenever ``a > x`` and the
missing half is never looked at -- found by calling it with ``(5, NULL)``, which returned every
row.) The caller only ever passes the pair it was given, and treats a page that does not advance as
an error; an empty page for a bad cursor is the fail-closed answer, not a silent restart.

Everything else is 0023's, for the same reasons (S2-S5 there): ``SECURITY DEFINER``, owner
``reconciler_fn_owner``, ``search_path`` pinned with ``pg_temp`` last, schema-qualified relations,
the stage filter in the function, ``REVOKE ALL FROM PUBLIC`` then ``EXECUTE`` for the reader alone,
the guarded cast, scalar columns only. The zero-argument function is untouched: it is the first
page.
"""

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

OWNER = "reconciler_fn_owner"
READER = "reconciler_reader"
STUCK_STAGES = ("received", "decided", "approved", "capability_issued", "dispatching")
LIMIT_ROWS = 5000
SIGNATURE = "reconciler_stuck_proposals_after(bigint, text)"

COMMENT = (
    "D64 0024: the next page of reconciler_stuck_proposals(): the same rows and columns, strictly "
    "after the keyset cursor (stage_updated_us, proposal_id) of the last row of the page before. A "
    "cursor with a NULL half returns nothing. SECURITY DEFINER, owner reconciler_fn_owner, EXECUTE "
    "for reconciler_reader only."
)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _stages() -> str:
    return ", ".join(f"'{s}'" for s in STUCK_STAGES)


def _us(expression: str) -> str:
    return f"(extract(epoch FROM {expression}) * 1000000)::bigint"


def _schema() -> str:
    return op.get_bind().exec_driver_sql("SELECT quote_ident(current_schema())").scalar_one()


def _function(s: str) -> str:
    return f"""
        CREATE FUNCTION {s}.reconciler_stuck_proposals_after(p_after_us bigint, p_after_id text)
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
              AND p_after_us IS NOT NULL AND p_after_id IS NOT NULL
              AND ROW(p.stage_updated_at, p.proposal_id)
                  > ROW(timestamptz 'epoch' + p_after_us * interval '1 microsecond', p_after_id)
            ORDER BY p.stage_updated_at, p.proposal_id
            LIMIT {LIMIT_ROWS}
        $fn$;
    """


def upgrade() -> None:
    s = _schema()
    op.execute(_function(s))
    op.execute(f"REVOKE ALL ON FUNCTION {s}.{SIGNATURE} FROM PUBLIC;")
    op.execute(f"GRANT EXECUTE ON FUNCTION {s}.{SIGNATURE} TO {READER};")
    op.execute(f"COMMENT ON FUNCTION {s}.{SIGNATURE} IS {_literal(COMMENT)};")
    # The hand-over comes last (0023): migration_owner is a member of the owner WITHOUT inheriting
    # it, so it cannot touch the function afterwards.
    op.execute(f"GRANT CREATE ON SCHEMA {s} TO {OWNER};")
    op.execute(f"ALTER FUNCTION {s}.{SIGNATURE} OWNER TO {OWNER};")
    op.execute(f"REVOKE CREATE ON SCHEMA {s} FROM {OWNER};")


def downgrade() -> None:
    s = _schema()
    op.execute(f"DROP FUNCTION {s}.{SIGNATURE};")
