"""A refused run records why, as state: ``tool_runs.refusal_code`` and the network-conflict read
(D64-N1, option B; ACCEPTANCE 5.85, 5.90).

Revision ID: 0025
Revises: 0024

**The decision (D64-N1).** The network-conflict trigger (D64 pre-deletion §3) needs one fact the
database already holds only as a log line: *this run was refused because its range overlaps a
network Docker already has*. The log line is a ``tool_run.refused`` row in ``audit_log`` whose
``reasons`` carry the code. Reading it would give the reader's function owner ``SELECT`` on the
most sensitive table in the schema, and turn a log into an input. Instead the fact becomes
**state**: a closed-vocabulary column on the run, written by the statement that already marks the
run failed -- the same statement, the same transaction, as the stage take that decides the run's
fate.

``tool_runs.refusal_code`` -- ``NULL`` for every run that was not refused before it started (all
existing rows, and every run that ran). Not ``NULL`` only for a run the sandbox declined while
nothing of it existed (``NotStarted`` and its subclasses). Two CHECKs, each tested from both sides:

* the **vocabulary**: the code is one of the closed list below (every ``reason`` a ``NotStarted``
  subclass carries, and every ``deadline_helper_*`` code). A value outside it is refused by the
  database, not by a Python ``if`` that a later change could drop. (``dispatch`` maps an unknown
  reason to ``sandbox_not_started`` before it writes, so a new subclass can never make the refusal
  itself fail.)
* the **NULL rule**: a code means the run **never ran** -- ``status = 'failed'`` and ``exit_code IS
  NULL``. A run that succeeded, timed out (it has an exit code, even -1) or is of unknown outcome
  cannot carry one, and a late result that rewrites a run's status cannot leave a stale code behind
  on a row that now says something else.

**The read.** ``reconciler_network_conflicts(p_window_s integer)`` -- ``SECURITY DEFINER``, owner
``reconciler_fn_owner``, the same pinned ``search_path``, ``REVOKE ALL FROM PUBLIC``, ``EXECUTE``
for ``reconciler_reader`` alone. **Every column it returns is an integer.** A range is never
returned
(a CIDR is the one thing that must not cross to the plan side, D64 §3.2): the blocking network is
named by the *number* its name suffix spells -- the first 12 hex digits of
``sha256("|".join(sorted(allowlist)))``, i.e. 48 bits, as a ``bigint`` -- which is exactly the
suffix of ``cyberorch-allow-<h>`` (``DockerSandbox.network_name``; measured identical in E22-1).
One row per blocking network in the window:

``(blocking_hash_n, conflicts_n, last_conflict_us, last_used_us, live_runs_n, db_now_us)``

and, if some refusals in the window have **no** blocker among the allowlists this database has run
(a lab's network, or another deployment on the same daemon), one more row with
``blocking_hash_n = -1`` and ``conflicts_n`` = how many: the "foreign" signal, as a number.

The aggregate over ``tool_runs`` runs **only if the window holds at least one refusal** (the cost of
the aggregate on 2,000,000 rows is 0.8 s, E22-5; with no refusal the function costs one index
lookup). Overlap is ``inet && inet`` and an element that is not a valid ``inet`` is *skipped*, not
raised on (``pg_input_is_valid``, PostgreSQL 16): one malformed historical allowlist must not blind
the reconciler (S5 of 0023).

The function's owner gets column-level ``SELECT`` on three more ``tool_runs`` columns
(``network_allowlist``, ``refusal_code``, ``finished_at``) and nothing else; the ``audit_log`` stays
unreadable by every function.

**Downgrade** drops the function, the index, the grants, the two CHECKs and the column. Rows lose
their codes -- the information lives in ``audit_log`` too, which is why this is a column and not the
only copy.
"""

from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None

OWNER = "reconciler_fn_owner"
READER = "reconciler_reader"
SIGNATURE = "reconciler_network_conflicts(integer)"

#: Every code a refused run can carry: the ``reason`` of each ``NotStarted`` subclass in
#: ``tool_gateway/sandbox.py`` and each ``deadline_helper_*`` code. ``tests/test_refusal_code.py``
#: compares this list with the code, so a new reason cannot be added in one place only.
REFUSAL_CODES = (
    "sandbox_not_started",
    "docker_unreachable",
    "tool_image_missing",
    "container_start_refused",
    "network_unavailable",
    "network_in_use_by_another_engagement",
    "network_range_conflicts_with_another_network",
    "tool_command_not_executable",
    "deadline_helper_unavailable",
    "deadline_helper_unsupported_architecture",
    "deadline_helper_unpinned",
    "deadline_helper_unreadable",
    "deadline_helper_missing",
    "deadline_helper_hash_mismatch",
    "deadline_helper_not_executable",
    "deadline_helper_path_in_use",
)
CONFLICT_CODE = "network_range_conflicts_with_another_network"
MAX_WINDOW_S = 31 * 86400
VOCAB_CHECK = "tool_runs_refusal_code_vocabulary"
NULL_RULE_CHECK = "tool_runs_refusal_code_means_never_ran"
INDEX = "tool_runs_refused"
NEW_OWNER_COLUMNS = ("network_allowlist", "refusal_code", "finished_at")

COMMENT_COLUMN = (
    "D64 0025: why the sandbox declined to start this run (a closed vocabulary), NULL for every "
    "run that was not refused before it started. Written in the statement that marks the run "
    "failed."
)
COMMENT_FUNCTION = (
    "D64 0025: the sandbox networks that blocked a refused run (window in seconds): one row per "
    "blocking network named by the number its name suffix spells, plus -1 for refusals with no "
    "blocker among the allowlists run here. Integers only; no range is returned. SECURITY DEFINER, "
    "owner reconciler_fn_owner, EXECUTE for reconciler_reader only."
)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _schema() -> str:
    return op.get_bind().exec_driver_sql("SELECT quote_ident(current_schema())").scalar_one()


def _codes() -> str:
    return ", ".join(_literal(c) for c in REFUSAL_CODES)


def _us(expression: str) -> str:
    return f"(extract(epoch FROM {expression}) * 1000000)::bigint"


def _hash(array: str) -> str:
    """The 48-bit number the network's name suffix spells, from an allowlist array."""
    return (
        "(('x' || substr(encode(sha256(convert_to((SELECT string_agg(e, '|' ORDER BY e COLLATE "
        f"\"C\") FROM unnest({array}) AS e), 'UTF8')), 'hex'), 1, 12))::bit(48)::bigint)"
    )


def _function(s: str) -> str:
    return f"""
        CREATE FUNCTION {s}.reconciler_network_conflicts(p_window_s integer)
        RETURNS TABLE (
            blocking_hash_n   bigint,
            conflicts_n       integer,
            last_conflict_us  bigint,
            last_used_us      bigint,
            live_runs_n       integer,
            db_now_us         bigint
        )
        LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, {s}, pg_temp
        AS $fn$
        BEGIN
            IF p_window_s IS NULL OR p_window_s < 1 OR p_window_s > {MAX_WINDOW_S} THEN
                RAISE EXCEPTION 'reconciler_network_conflicts: argument refused'
                    USING ERRCODE = '22023';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM {s}.tool_runs t
                           WHERE t.refusal_code = {_literal(CONFLICT_CODE)}
                             AND t.finished_at >= now() - make_interval(secs => p_window_s)) THEN
                RETURN;
            END IF;
            RETURN QUERY
            WITH refused AS (
                SELECT t.network_allowlist AS al, count(*) AS n, max(t.finished_at) AS last_at
                FROM {s}.tool_runs t
                WHERE t.refusal_code = {_literal(CONFLICT_CODE)}
                  AND t.finished_at >= now() - make_interval(secs => p_window_s)
                GROUP BY t.network_allowlist
            ),
            history AS (
                SELECT t.network_allowlist AS al,
                       max(t.created_at) AS last_used,
                       count(*) FILTER (WHERE t.status IN ('queued', 'dispatching', 'running'))
                           AS live
                FROM {s}.tool_runs t
                WHERE t.refusal_code IS NULL AND cardinality(t.network_allowlist) > 0
                GROUP BY t.network_allowlist
            ),
            refused_h AS (SELECT r.*, {_hash("r.al")} AS h FROM refused r),
            history_h AS (SELECT x.*, {_hash("x.al")} AS h FROM history x),
            pairs AS (
                SELECT hh.h AS blocker, rr.h AS refused_hash, rr.n, rr.last_at,
                       hh.last_used, hh.live
                FROM refused_h rr JOIN history_h hh ON hh.h <> rr.h AND EXISTS (
                    SELECT 1 FROM unnest(hh.al) a, unnest(rr.al) b
                    WHERE pg_input_is_valid(a, 'inet') AND pg_input_is_valid(b, 'inet')
                      AND a::inet && b::inet)
            ),
            blockers AS (
                SELECT p.blocker AS bh,
                       least(sum(p.n), 2147483647)::integer AS cn,
                       {_us("max(p.last_at)")} AS lc,
                       {_us("max(p.last_used)")} AS lu,
                       least(sum(p.live), 2147483647)::integer AS lv
                FROM pairs p GROUP BY p.blocker
            ),
            unblocked AS (
                -- (LEAST ignores NULL: with nothing to sum, least(NULL, max) is max, so the empty
                -- case is cut off by HAVING, not by a NULL test on the result)
                SELECT least(sum(rr.n), 2147483647)::integer AS cn,
                       {_us("max(rr.last_at)")} AS lc
                FROM refused_h rr
                WHERE NOT EXISTS (SELECT 1 FROM pairs p WHERE p.refused_hash = rr.h)
                HAVING count(*) > 0
            )
            SELECT b.bh, b.cn, b.lc, b.lu, b.lv, {_us("now()")} FROM blockers b
            UNION ALL
            SELECT -1::bigint, u.cn, u.lc, 0::bigint, 0, {_us("now()")}
            FROM unblocked u
            ORDER BY 1;
        END
        $fn$;
    """


def upgrade() -> None:
    s = _schema()
    op.execute(f"ALTER TABLE {s}.tool_runs ADD COLUMN refusal_code TEXT;")
    op.execute(f"COMMENT ON COLUMN {s}.tool_runs.refusal_code IS {_literal(COMMENT_COLUMN)};")
    op.execute(f"""
        ALTER TABLE {s}.tool_runs ADD CONSTRAINT {VOCAB_CHECK}
            CHECK (refusal_code IS NULL OR refusal_code IN ({_codes()}));
    """)
    op.execute(f"""
        ALTER TABLE {s}.tool_runs ADD CONSTRAINT {NULL_RULE_CHECK}
            CHECK (refusal_code IS NULL OR (status = 'failed' AND exit_code IS NULL));
    """)
    op.execute(f"CREATE INDEX {INDEX} ON {s}.tool_runs (finished_at) "
               "WHERE refusal_code IS NOT NULL;")
    op.execute(f"GRANT SELECT ({', '.join(NEW_OWNER_COLUMNS)}) ON {s}.tool_runs TO {OWNER};")

    op.execute(_function(s))
    op.execute(f"REVOKE ALL ON FUNCTION {s}.{SIGNATURE} FROM PUBLIC;")
    op.execute(f"GRANT EXECUTE ON FUNCTION {s}.{SIGNATURE} TO {READER};")
    op.execute(f"COMMENT ON FUNCTION {s}.{SIGNATURE} IS {_literal(COMMENT_FUNCTION)};")
    # The hand-over comes last (0023): migration_owner is a member of the owner WITHOUT inheriting
    # it, so it cannot touch the function afterwards.
    op.execute(f"GRANT CREATE ON SCHEMA {s} TO {OWNER};")
    op.execute(f"ALTER FUNCTION {s}.{SIGNATURE} OWNER TO {OWNER};")
    op.execute(f"REVOKE CREATE ON SCHEMA {s} FROM {OWNER};")


def downgrade() -> None:
    s = _schema()
    op.execute(f"DROP FUNCTION {s}.{SIGNATURE};")
    op.execute(f"REVOKE SELECT ({', '.join(NEW_OWNER_COLUMNS)}) ON {s}.tool_runs FROM {OWNER};")
    op.execute(f"DROP INDEX {s}.{INDEX};")
    op.execute(f"ALTER TABLE {s}.tool_runs DROP CONSTRAINT {NULL_RULE_CHECK};")
    op.execute(f"ALTER TABLE {s}.tool_runs DROP CONSTRAINT {VOCAB_CHECK};")
    op.execute(f"ALTER TABLE {s}.tool_runs DROP COLUMN refusal_code;")
