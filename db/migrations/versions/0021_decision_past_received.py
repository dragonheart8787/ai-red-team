"""A proposal past ``received`` has a decision (D63).

Revision ID: 0021
Revises: 0020

``action_proposals.decision`` is a closed vocabulary (``ALLOW`` / ``DENY`` / ``HUMAN_APPROVAL``) on
a nullable column, and a CHECK passes on NULL. NULL is a real state -- a proposal that has been
received and not yet decided -- but nothing said that it is the *only* stage in which it is one: a
proposal could be moved to ``recorded`` with no decision and the database accepted it (found at
D63, ACCEPTANCE 5.69, executed in a rolled-back transaction).

The stages in which NULL is legal were listed from the code, not assumed:

* ``received``           -- yes. The row is committed, nothing is decided (``_decide`` has not run).
* ``decided`` / ``awaiting_approval`` / ``approved`` / ``capability_issued`` -- no. Each is defined
  as "after the decision" and is reached only by ``_decide``, which now writes the decision in the
  same statement that moves the stage.
* ``dispatching`` / ``recorded`` / ``closed`` -- no, in the pipeline. The only way to reach them
  with NULL was a proposal built by hand and dispatched directly (``BEFORE_DISPATCH`` includes
  ``received``): nine test files did, nothing in ``control_plane``, ``agents``, ``scripts`` or
  ``tool_gateway`` does. That route is closed here too -- a tool run for a proposal nobody decided
  is not a state the database should be able to hold.

So the constraint is: ``decision IS NOT NULL OR pipeline_stage = 'received'``.

**Rows already in the table.** Adding the constraint validates every row. A database holding a
proposal past ``received`` with no decision (hand-built ones from a test run are the only way to get
one) refuses the migration with "check constraint ... is violated by some row"; the table is under
``FORCE ROW LEVEL SECURITY``, so look for the rows as a superuser::

    SELECT proposal_id, pipeline_stage FROM action_proposals
    WHERE decision IS NULL AND pipeline_stage <> 'received';

They are not repaired automatically: inventing a decision for a run that happened without one would
write a fact nobody established.
"""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

NAME = "action_proposals_decision_past_received"


def upgrade() -> None:
    op.execute(f"""
        ALTER TABLE action_proposals ADD CONSTRAINT {NAME}
            CHECK (decision IS NOT NULL OR pipeline_stage = 'received');
    """)
    op.execute(f"""
        COMMENT ON CONSTRAINT {NAME} ON action_proposals IS
            'NULL decision is the state of a proposal that has been received and not decided. '
            'Every later stage has a decision (D63, ACCEPTANCE 5.69).';
    """)


def downgrade() -> None:
    op.execute(f"ALTER TABLE action_proposals DROP CONSTRAINT {NAME};")
