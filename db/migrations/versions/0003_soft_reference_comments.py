"""Record why audit_log and provenance_edges carry no foreign keys.

Revision ID: 0003
Revises: 0002

Neither table references the entities it describes, and both look like
oversights to anyone reading the schema. They are not, and a later "tidying up"
commit adding the missing constraints would break behaviour the design depends
on. The reasoning belongs where a schema reader will find it, so it goes in
COMMENT ON TABLE rather than only in a commit message nobody will re-read.

audit_log
    Records commit on their own connection and are deliberately allowed to
    outlive — or precede — the row they describe (§4.4). A foreign key would
    make the audit write fail in exactly the case the independent commit exists
    to cover: the state write rolling back. That is the D5 bug reintroduced at
    the database layer, where it would be harder to see. subject_id is also
    polymorphic (interpreted through subject_type), so no single referenced
    table exists; and engagement_id carries no constraint either, so an event
    can still be recorded about an engagement that has since been removed.

provenance_edges
    from_id and to_id are polymorphic too, naming rows in whichever table each
    step of the chain lives in (§8.10). engagement_id keeps its foreign key
    because every edge belongs to exactly one engagement.
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
COMMENT ON TABLE audit_log IS
'Append-only decision record (ARCHITECTURE.md §4.4). Intentionally has NO
foreign keys, including on engagement_id. Records are written on an
independent connection and commit immediately, so one may outlive or precede
the row it describes; a foreign key would make the audit write fail precisely
when the state write rolled back, which is the failure this design exists to
prevent. subject_id is polymorphic, interpreted via subject_type. Do not add
referential constraints here.';
""")
    op.execute("""
COMMENT ON COLUMN audit_log.subject_id IS
'Polymorphic reference, interpreted through subject_type. No foreign key by
design -- see the table comment.';
""")
    op.execute("""
COMMENT ON TABLE provenance_edges IS
'Provenance Graph edges (ARCHITECTURE.md §8.10) -- "why do we believe this".
from_id and to_id are polymorphic, naming rows in whichever table each step of
the chain lives in, so no foreign key is possible on them by design. Only
engagement_id is constrained. Append-only: rewriting how a belief was formed
would defeat the purpose.';
""")


def downgrade() -> None:
    op.execute("COMMENT ON TABLE audit_log IS NULL;")
    op.execute("COMMENT ON COLUMN audit_log.subject_id IS NULL;")
    op.execute("COMMENT ON TABLE provenance_edges IS NULL;")
