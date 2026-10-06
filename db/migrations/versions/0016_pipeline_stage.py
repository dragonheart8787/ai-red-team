"""Where a proposal is in the pipeline, as committed state (D58-5, D60).

Revision ID: 0016
Revises: 0015

``propose_action`` used to be one database transaction from canonicalization to the last
provenance edge. A crash, a Postgres restart or a kill switch in the middle rolled every state
row back and left only the audit trail to say anything had started (docs/ADR_PRODUCTION_
ORCHESTRATOR.md §3.1). D60 splits it into stages that each commit on their own; this migration
adds what that needs to be *observable* and *resumable*:

* ``pipeline_stage`` -- the stage the proposal has reached and committed. Each stage transition is
  one conditional UPDATE (``... WHERE pipeline_stage = <expected>``) taken inside the transaction
  that does the stage's work, so a stage is performed at most once: a second driver (a retry, a
  restarted service) finds the stage already advanced and does not repeat it.

      received -> decided -> capability_issued -> dispatching -> recorded
                    \\-> closed        \\-> closed        \\-> closed

  ``closed`` = finished without a tool run (DENY / HUMAN_APPROVAL, capability refused, the
  dispatch refused before a run row existed, a dedup hit); ``recorded`` = a tool run happened (or
  may have: ``unknown_outcome``) and its outcome is committed. ``stage_detail`` says why.
* ``stage_updated_at`` -- when it last moved; what a reconciler ages a stuck proposal by.
* ``authorized_scope_object_id`` / ``classified_asset_id`` -- the two facts the decision stage
  established, kept on the proposal so every provenance edge can be *derived* from committed rows
  afterwards instead of written in the same transaction as a result.
* ``provenance_complete`` -- whether those edges have been written. False on a terminal proposal
  means "re-run the derivation", not "something is wrong with the result".

No back-fill. A proposal that pre-dates this migration reads as ``received`` with no detail, which
is true to the extent anyone knows: its stage was never recorded, and nothing drives old proposals.
The role grants are the table-level ones 0001 gave ``cyberorch_app``; the new columns need none.
"""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE action_proposals
            ADD COLUMN pipeline_stage TEXT NOT NULL DEFAULT 'received',
            ADD COLUMN stage_detail TEXT,
            ADD COLUMN stage_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            ADD COLUMN authorized_scope_object_id TEXT,
            ADD COLUMN classified_asset_id TEXT,
            ADD COLUMN provenance_complete BOOLEAN NOT NULL DEFAULT FALSE;
    """)
    op.execute("""
        ALTER TABLE action_proposals ADD CONSTRAINT action_proposals_pipeline_stage_check
            CHECK (pipeline_stage IN
                   ('received', 'decided', 'capability_issued', 'dispatching',
                    'recorded', 'closed'));
    """)
    op.execute("""
        CREATE INDEX action_proposals_open_stage
            ON action_proposals (engagement_id, pipeline_stage, stage_updated_at)
            WHERE pipeline_stage NOT IN ('recorded', 'closed')
               OR provenance_complete IS FALSE;
    """)
    op.execute("""
        COMMENT ON COLUMN action_proposals.pipeline_stage IS
        'D58-5/D60: the pipeline stage this proposal has reached and COMMITTED. Moves only by a
        conditional UPDATE in the transaction that does the stage''s work, so a stage runs once.';
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS action_proposals_open_stage;")
    op.execute("ALTER TABLE action_proposals "
               "DROP CONSTRAINT IF EXISTS action_proposals_pipeline_stage_check;")
    op.execute("""
        ALTER TABLE action_proposals
            DROP COLUMN provenance_complete,
            DROP COLUMN classified_asset_id,
            DROP COLUMN authorized_scope_object_id,
            DROP COLUMN stage_updated_at,
            DROP COLUMN stage_detail,
            DROP COLUMN pipeline_stage;
    """)
