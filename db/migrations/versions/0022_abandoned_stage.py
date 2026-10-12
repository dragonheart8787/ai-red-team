"""The terminal stage ``abandoned`` (D64, ACCEPTANCE 5.78).

Revision ID: 0022
Revises: 0021

Migration 0021 made every stage past ``received`` require a decision. A proposal stuck at
``received`` -- the caller died between "the row is committed" and "the decision is committed" --
has none, and ``closed`` would say a decision was made. ``abandoned`` is the terminal stage for
exactly that case: **never decided, and past a grace period**. It is written only by the reconciler
(not built yet; this migration only makes the stage legal and keeps it honest).

The properties the database itself enforces (D64 §1.8, A1-A9; the rest are the reconciler's and
the structural tests'):

* A4 -- ``abandoned`` has **no decision** (``decision IS NULL``);
* A5 -- ``abandoned`` has **exactly one reason**, ``stage_detail = 'undecided_past_grace'``, and
  the CHECK says ``stage_detail IS NOT NULL`` explicitly. Written without it
  (``... AND stage_detail = '...'``) the CHECK passes on a NULL detail -- ACCEPTANCE 5.69 -- and an
  abandoned row with no reason was accepted when this was tried;
* ``decision_past_received`` (0021) grows from ``{received}`` to ``{received, abandoned}``: those
  are the two stages in which a NULL decision is legal. ``closed`` still cannot be undecided.

What else changes: the partial index ``action_proposals_open_stage`` stops listing abandoned rows
as open (they are terminal), and the COMMENT on ``pipeline_stage`` names the new stage.

**Upgrade** only relaxes and adds, so it needs no pre-check and cannot fail on existing rows.

**Downgrade** must move the rows first: the old stage CHECK cannot be added while a row says
``abandoned``. Row-level security binds the table owner, which is the role migrations run as, so
the repair ``UPDATE`` runs between ``NO FORCE ROW LEVEL SECURITY`` and ``FORCE ROW LEVEL SECURITY``
(ACCEPTANCE 5.75), in the same transaction -- a failure between them rolls both back. An abandoned
proposal becomes ``received`` with no detail again, i.e. *resumable by its idempotency key*: that
is what it was before it was abandoned, and the semantics are stated here because a migration
cannot write the audit record that says so. Dropping and re-adding a constraint loses its COMMENT,
so the downgrade restores the 0021 text and the 0016 column comment byte for byte
(``tests/test_migrations_roundtrip.py`` compares them with ``snapshot_schema()``).
"""

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

STAGE_CHECK = "action_proposals_pipeline_stage_check"
DECISION_CHECK = "action_proposals_decision_past_received"
ABANDONED_CHECK = "action_proposals_abandoned_is_undecided"

OLD_STAGES = ("received", "decided", "awaiting_approval", "approved", "capability_issued",
              "dispatching", "recorded", "closed")
NEW_STAGES = (*OLD_STAGES, "abandoned")

COMMENT_DECISION_0021 = (
    "NULL decision is the state of a proposal that has been received and not decided. "
    "Every later stage has a decision (D63, ACCEPTANCE 5.69)."
)
COMMENT_DECISION_0022 = (
    "NULL decision is legal at `received` (not decided yet) and at `abandoned` (never decided, "
    "past the grace period) and at no other stage (D63 5.69, D64 0022)."
)
COMMENT_ABANDONED = (
    "An abandoned proposal was never decided and says why: no decision, and the one reason "
    "`undecided_past_grace`. Both are tested NULL-exactly (D64 0022, ACCEPTANCE 5.69)."
)
# The text 0016 gave the column, including its line break and indentation: the downgrade puts the
# same bytes back.
COMMENT_STAGE_0016 = (
    "D58-5/D60: the pipeline stage this proposal has reached and COMMITTED. Moves only by a\n"
    "        conditional UPDATE in the transaction that does the stage's work, so a stage runs once."  # noqa: E501
)
COMMENT_STAGE_0022 = (
    "D58-5/D60: the pipeline stage this proposal has reached and COMMITTED. Moves only by a "
    "conditional UPDATE in the transaction that does the stage's work, so a stage runs once. "
    "D64 0022 adds `abandoned`: terminal, never decided, written only by the reconciler."
)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _stage_list(stages: tuple[str, ...]) -> str:
    return ", ".join(f"'{s}'" for s in stages)


def upgrade() -> None:
    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {STAGE_CHECK};")
    op.execute(f"""
        ALTER TABLE action_proposals ADD CONSTRAINT {STAGE_CHECK}
            CHECK (pipeline_stage IN ({_stage_list(NEW_STAGES)}));
    """)
    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {DECISION_CHECK};")
    op.execute(f"""
        ALTER TABLE action_proposals ADD CONSTRAINT {DECISION_CHECK}
            CHECK (decision IS NOT NULL OR pipeline_stage IN ('received', 'abandoned'));
    """)
    op.execute(f"COMMENT ON CONSTRAINT {DECISION_CHECK} ON action_proposals "
               f"IS {_literal(COMMENT_DECISION_0022)};")
    op.execute(f"""
        ALTER TABLE action_proposals ADD CONSTRAINT {ABANDONED_CHECK}
            CHECK (pipeline_stage <> 'abandoned'
                   OR (decision IS NULL
                       AND stage_detail IS NOT NULL
                       AND stage_detail = 'undecided_past_grace'));
    """)
    op.execute(f"COMMENT ON CONSTRAINT {ABANDONED_CHECK} ON action_proposals "
               f"IS {_literal(COMMENT_ABANDONED)};")
    op.execute("DROP INDEX action_proposals_open_stage;")
    op.execute("""
        CREATE INDEX action_proposals_open_stage
            ON action_proposals (engagement_id, pipeline_stage, stage_updated_at)
            WHERE pipeline_stage NOT IN ('recorded', 'closed', 'abandoned')
               OR provenance_complete IS FALSE;
    """)
    op.execute(f"COMMENT ON COLUMN action_proposals.pipeline_stage "
               f"IS {_literal(COMMENT_STAGE_0022)};")


def downgrade() -> None:
    # FORCE ROW LEVEL SECURITY binds the owner: with no engagement bound the UPDATE below would see
    # no row and move nothing, and the old stage CHECK could then not be added (ACCEPTANCE 5.75).
    op.execute("ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY;")
    op.execute("""
        UPDATE action_proposals
        SET pipeline_stage = 'received', stage_detail = NULL, stage_updated_at = now()
        WHERE pipeline_stage = 'abandoned';
    """)
    op.execute("ALTER TABLE action_proposals FORCE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {ABANDONED_CHECK};")
    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {DECISION_CHECK};")
    op.execute(f"""
        ALTER TABLE action_proposals ADD CONSTRAINT {DECISION_CHECK}
            CHECK (decision IS NOT NULL OR pipeline_stage = 'received');
    """)
    op.execute(f"COMMENT ON CONSTRAINT {DECISION_CHECK} ON action_proposals "
               f"IS {_literal(COMMENT_DECISION_0021)};")
    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {STAGE_CHECK};")
    op.execute(f"""
        ALTER TABLE action_proposals ADD CONSTRAINT {STAGE_CHECK}
            CHECK (pipeline_stage IN ({_stage_list(OLD_STAGES)}));
    """)
    op.execute("DROP INDEX action_proposals_open_stage;")
    op.execute("""
        CREATE INDEX action_proposals_open_stage
            ON action_proposals (engagement_id, pipeline_stage, stage_updated_at)
            WHERE pipeline_stage NOT IN ('recorded', 'closed')
               OR provenance_complete IS FALSE;
    """)
    op.execute(f"COMMENT ON COLUMN action_proposals.pipeline_stage "
               f"IS {_literal(COMMENT_STAGE_0016)};")
