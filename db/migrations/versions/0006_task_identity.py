"""Persist a task's structure so two tasks can be compared (§11.3, ADR task identity).

Revision ID: 0006
Revises: 0005

D17 showed ``create_task`` dropped everything about a task except its goal text:
``ProposedTask`` carries ``action``, ``target`` and ``scope_object_id`` and the
write path kept none of them, so the only thing a duplicate check could have
compared was prose. This adds the columns a structural comparison needs.

Option 1 of ADR_TASK_IDENTITY.md, accepted: the identity is target-level —
``(action, canonical_target)`` at host/network granularity, the same
``work_key`` the D17 harness measured. ``canonical_target`` is the target after
the real Target Canonicalizer, so a spelling difference does not read as
different work. ``identity_key`` is the stored, indexed form the write path
matches on and ``query_tasks`` reads back; it is deliberately *not* the §7
execution fingerprint — the execution layer keys on ports and this layer does
not, which is exactly why two scans of the same host on different ports are one
task-level identity here and two executions there (they are told apart at
dispatch, not here).

``scope_object_id`` is persisted for provenance but is intentionally absent from
``identity_key``: the same host scanned under two valid scope objects is the same
work, and scope is an authorization fact rather than a work-identity one.

All columns are nullable. A task whose target will not canonicalize stores NULL
``canonical_target``/``identity_key`` and therefore matches nothing — a task
nobody can reduce must never silently match, which would be a fail-open drop.
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE tasks
            ADD COLUMN action           TEXT,
            ADD COLUMN canonical_target TEXT,
            ADD COLUMN scope_object_id  TEXT,
            ADD COLUMN identity_key     TEXT
    """)
    op.execute("""
        COMMENT ON COLUMN tasks.identity_key IS
'The task-level work identity (action + canonical target), ADR_TASK_IDENTITY.md
Option 1. Written by create_task, read by query_tasks and by the overlap check.
NULL when the target will not canonicalize, so such a task matches nothing.
Not the §7 execution fingerprint: this layer has no ports.';
    """)
    # The overlap check and query_tasks both look up live tasks in one
    # engagement by identity_key. Without this index that is a sequential scan
    # on every create_task, and dedup that is slow is dedup people switch off.
    op.execute("""
        CREATE INDEX tasks_identity ON tasks (engagement_id, identity_key, status)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS tasks_identity")
    op.execute("""
        ALTER TABLE tasks
            DROP COLUMN IF EXISTS action,
            DROP COLUMN IF EXISTS canonical_target,
            DROP COLUMN IF EXISTS scope_object_id,
            DROP COLUMN IF EXISTS identity_key
    """)
