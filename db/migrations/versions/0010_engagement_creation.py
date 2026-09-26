"""Engagement creation moves to registry_admin (D11-9, D39).

Revision ID: 0010
Revises: 0009

Until this migration nothing created an engagement: every caller — test
fixtures, the stateful machine, five live-run scripts — wrote the row with a
raw INSERT on the ``cyberorch_app`` connection, because migration 0001's
blanket grant (``GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES``) was
never narrowed for ``engagements`` the way it was for ``scope_registry`` /
``metadata_registry`` at D5 (migration 0002). That is the same "guarantee
rests on application code choosing not to" gap D5 closed for the registries,
just never noticed for this table: the role every Worker/Reviewer/Supervisor
call runs as has always held raw INSERT and DELETE on ``engagements``, and the
only reason neither has happened is that no code path called it.

This migration and ``create_engagement()`` (control_plane/orchestrator/
engagement.py) close it the same way §5 closed the registries: the write moves
to ``registry_admin`` — the Engagement Manager role, already the one that
registers scope and classification — and ``cyberorch_app`` loses the two
privileges it never legitimately used. It keeps SELECT and UPDATE, which is
all ``pause_engagement`` / ``resume_engagement`` / ``engage_kill_switch`` /
``complete_engagement`` have ever needed.

``registry_admin`` also gains SELECT on ``policy_layers``, which it has never
had, so ``create_engagement`` can compute a real ``policy_snapshot_version``
via the broker's existing ``current_policy_version`` rather than a second
implementation of "what version is this."
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("GRANT INSERT ON engagements TO registry_admin;")
    op.execute("GRANT SELECT ON policy_layers TO registry_admin;")
    # cyberorch_app has held these since migration 0001's blanket grant and has
    # never had a legitimate caller for either: every existing write to this
    # table is an UPDATE (status, kill_switch_engaged), never an INSERT or a
    # DELETE (rows are retired by status, not removed).
    op.execute("REVOKE INSERT, DELETE ON engagements FROM cyberorch_app;")


def downgrade() -> None:
    op.execute("GRANT INSERT, DELETE ON engagements TO cyberorch_app;")
    op.execute("REVOKE SELECT ON policy_layers FROM registry_admin;")
    op.execute("REVOKE INSERT ON engagements FROM registry_admin;")
