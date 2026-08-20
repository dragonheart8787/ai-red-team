"""Record which columns exist for Phase 1 and are inert today.

Revision ID: 0005
Revises: 0004

Found by the pre-merge sweep: three columns are declared, defaulted, and read by
nothing. Each looked like an oversight and none is, but "looks like an oversight"
is exactly what gets a column dropped by a later tidying commit, or -- worse --
wired up by someone who assumes the absent behaviour was a bug rather than a
stage boundary.

Documented in the schema rather than only in a commit message, because the
schema is what the next reader opens.
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
COMMENT ON COLUMN findings.state IS
'Phase 1 (ARCHITECTURE.md §8.10, I5 finding verification). MVP-Kernel produces
evidence but never promotes it to a finding, so nothing writes or reads this
column yet. Kept because the verification workflow it belongs to is designed;
only its implementation is out of scope for this stage.';
""")
    op.execute("""
COMMENT ON COLUMN findings.verification_conflict IS
'Phase 1 (ARCHITECTURE.md §8.10). Set when two verification passes disagree
about the same claim, which is the I10 fail-closed case for findings. Inert in
MVP-Kernel: no verification pass exists to disagree.';
""")
    op.execute("""
COMMENT ON COLUMN capabilities.heartbeat_required IS
'Declared per ARCHITECTURE.md §4.6 and not yet enforced. A capability whose
heartbeats stop currently lapses when its lease expires rather than being
revoked as an anomaly. Enforcement needs a scheduler (MVP-Kernel has none --
reconcile_stale_dispatches is called by tests) and a real agent heartbeat
interval to measure staleness against. See the DEFERRED section in
control_plane/capability/broker.py.';
""")


def downgrade() -> None:
    op.execute("COMMENT ON COLUMN findings.state IS NULL;")
    op.execute("COMMENT ON COLUMN findings.verification_conflict IS NULL;")
    op.execute("COMMENT ON COLUMN capabilities.heartbeat_required IS NULL;")
