"""An approval is bound to one proposal and to what the approver saw (D58-8, D61 closeout).

Revision ID: 0018
Revises: 0017

D61 moved capability issuance to the moment of dispatch. That left the link between *the approval
and what is dispatched* resting on the proposal's ``stage_detail`` and on the broker's validity
checks -- which ask "is this approval alive?", not "is this the world the approver approved?". This
closes that gap, as part of D58-8 (it is the part of the JIT design the first pass did not cover):

* ``approvals.snapshot`` -- what the approver saw when approving: the normalized target, the
  action, the authorization the registry gave it, the classification it resolved to, and the
  reasons OPA gave for asking a human. ``dispatch_approved`` re-derives all of it from the
  registries and OPA at dispatch and refuses if anything differs; an approval can narrow what
  runs, never widen it, and never revive an operation that is no longer permitted.
* ``action_proposals.reviewer_hints`` -- the reviewer's advisory hints at the decision. They are
  *inputs* to OPA (they can only add caution), recorded so the policy can be re-run on the same
  inputs without calling a model again.
* A trigger on ``approvals`` that fixes everything the approver decided: ``proposal_id`` and the
  rest of the record cannot be changed after the row is written. Two things may still move, both
  only toward less authority: ``valid_until`` may be brought earlier, and ``revoked`` may go
  false -> true.

``approvals.proposal_id`` already existed (nullable, from 0001) and ``grant_approval`` has always
written it; the trigger is what makes "written at grant, never altered" a property of the database
rather than of the code that happens to be there. It stays nullable because the broker's own tests
and the stateful model create approvals that belong to no proposal; ``dispatch_approved`` requires
it to be present and to match.
"""

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE approvals ADD COLUMN snapshot JSONB;")
    op.execute("ALTER TABLE action_proposals ADD COLUMN reviewer_hints JSONB;")
    op.execute("""
        CREATE FUNCTION approvals_guard_update() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.approval_id    IS DISTINCT FROM OLD.approval_id
               OR NEW.engagement_id  IS DISTINCT FROM OLD.engagement_id
               OR NEW.proposal_id    IS DISTINCT FROM OLD.proposal_id
               OR NEW.action_class   IS DISTINCT FROM OLD.action_class
               OR NEW.resource       IS DISTINCT FROM OLD.resource
               OR NEW.constraints    IS DISTINCT FROM OLD.constraints
               OR NEW.approved_by    IS DISTINCT FROM OLD.approved_by
               OR NEW.approved_scope IS DISTINCT FROM OLD.approved_scope
               OR NEW.snapshot       IS DISTINCT FROM OLD.snapshot
               OR NEW.created_at     IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'an approval is fixed when it is granted (approval %)',
                    OLD.approval_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            IF NEW.valid_until > OLD.valid_until THEN
                RAISE EXCEPTION 'an approval can only be shortened, never extended (approval %)',
                    OLD.approval_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            IF OLD.revoked AND NOT NEW.revoked THEN
                RAISE EXCEPTION 'a revoked approval stays revoked (approval %)',
                    OLD.approval_id USING ERRCODE = 'integrity_constraint_violation';
            END IF;
            RETURN NEW;
        END
        $$;
    """)
    op.execute("""
        CREATE TRIGGER approvals_guard_update BEFORE UPDATE ON approvals
        FOR EACH ROW EXECUTE FUNCTION approvals_guard_update();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS approvals_guard_update ON approvals;")
    op.execute("DROP FUNCTION IF EXISTS approvals_guard_update();")
    op.execute("ALTER TABLE action_proposals DROP COLUMN IF EXISTS reviewer_hints;")
    op.execute("ALTER TABLE approvals DROP COLUMN IF EXISTS snapshot;")
