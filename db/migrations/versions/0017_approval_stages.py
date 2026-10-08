"""Approval is a stage, and a capability is issued when the tool runs (D58-8, D61).

Revision ID: 0017
Revises: 0016

``grant_approval`` used to write the ``approvals`` row *and* issue a 60-second capability, then
return -- and nothing in ``control_plane/`` or ``agents/`` ever dispatched it. A capability's lease
is anchored to the transaction that issues it (D58), so issuing at grant time meant the capability
was already ageing while the human was still reading the next proposal, and no dispatcher was
there to use it. The fix moves issuance to the moment of use (``dispatch_approved``), which needs
two stages the D60 vocabulary lacked:

* ``awaiting_approval`` -- the decision was HUMAN_APPROVAL; a human has not yet answered. (A
  HUMAN_APPROVAL used to close the proposal outright, which was true of the *run* and false of the
  *request*: it was still waiting.)
* ``approved`` -- a human approved it (an ``approvals`` row exists). **Awaiting dispatch.** No
  capability exists yet. This is the state a reconciler (D58-9) finds when an approved proposal is
  stuck: ``stage_updated_at`` says since when.

      decided --> capability_issued --> dispatching --> recorded
         |
         +--> awaiting_approval --> approved --> capability_issued --> ...
         |            |
         +--> closed <+   (deny: detail ``approval_denied``)

``decided_policy_version`` is the policy version in force when the decision was made. The JIT issue
passes it to the broker, which refuses if the policy has moved since (I9): an approval is a human
saying yes to *that* decision, not to whatever the policy has become.

Back-fill: a HUMAN_APPROVAL proposal that pre-dates this migration is ``closed``/
``decision_HUMAN_APPROVAL``. If no live approval exists and it was not denied, it becomes
``awaiting_approval`` (it was always pending). An already-approved or denied one stays closed: the
old path issued (or did not) at grant time, and re-opening it would let a month-old approval be
dispatched. No old approval is resurrected.
"""

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE action_proposals
            DROP CONSTRAINT action_proposals_pipeline_stage_check;
    """)
    op.execute("""
        ALTER TABLE action_proposals ADD CONSTRAINT action_proposals_pipeline_stage_check
            CHECK (pipeline_stage IN
                   ('received', 'decided', 'awaiting_approval', 'approved',
                    'capability_issued', 'dispatching', 'recorded', 'closed'));
    """)
    op.execute("ALTER TABLE action_proposals ADD COLUMN decided_policy_version BIGINT;")
    op.execute("""
        UPDATE action_proposals p
        SET pipeline_stage = 'awaiting_approval', stage_detail = NULL,
            stage_updated_at = now()
        WHERE p.decision = 'HUMAN_APPROVAL'
          AND p.pipeline_stage = 'closed'
          AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.proposal_id = p.proposal_id)
          AND NOT EXISTS (SELECT 1 FROM audit_log l
                          WHERE l.subject_id = p.proposal_id
                            AND l.event_type = 'approval.denied');
    """)
    op.execute("""
        UPDATE action_proposals p
        SET stage_detail = 'approval_denied'
        WHERE p.decision = 'HUMAN_APPROVAL' AND p.pipeline_stage = 'closed'
          AND EXISTS (SELECT 1 FROM audit_log l
                      WHERE l.subject_id = p.proposal_id AND l.event_type = 'approval.denied');
    """)
    op.execute("""
        DROP INDEX IF EXISTS action_proposals_open_stage;
        CREATE INDEX action_proposals_open_stage
            ON action_proposals (engagement_id, pipeline_stage, stage_updated_at)
            WHERE pipeline_stage NOT IN ('recorded', 'closed')
               OR provenance_complete IS FALSE;
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE action_proposals SET pipeline_stage = 'closed',
            stage_detail = 'decision_HUMAN_APPROVAL', stage_updated_at = now()
        WHERE pipeline_stage IN ('awaiting_approval', 'approved');
    """)
    op.execute("ALTER TABLE action_proposals DROP COLUMN decided_policy_version;")
    op.execute("""
        ALTER TABLE action_proposals
            DROP CONSTRAINT action_proposals_pipeline_stage_check;
    """)
    op.execute("""
        ALTER TABLE action_proposals ADD CONSTRAINT action_proposals_pipeline_stage_check
            CHECK (pipeline_stage IN
                   ('received', 'decided', 'capability_issued', 'dispatching',
                    'recorded', 'closed'));
    """)
