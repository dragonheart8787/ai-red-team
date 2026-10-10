"""Narrow the scheduler's skip vocabulary: ``no_usable_block_for_address`` is gone (D62).

Revision ID: 0020
Revises: 0019

Migration 0019 is already applied elsewhere, so it is not edited. It listed six skip codes; one of
them, ``no_usable_block_for_address``, existed only for the derivation that widened a single-IP
(``ip``) scope into a /29-/27 block. That derivation was removed: an ``ip`` scope is now always
skipped as ``scope_narrower_than_sandbox_minimum``, so the code has no use and an operator must not
be told it can occur. The two CHECK constraints that list the codes are replaced by the five-code
versions.

Rows already holding the retired code are rewritten to the code the scheduler would now give them
first -- otherwise the new constraint could not be added. ``scheduler_state`` is under ``FORCE ROW
LEVEL SECURITY``, which binds its owner too, so the rewrite switches ``FORCE`` off for that one
statement and back on; the table's policy and grants are untouched.
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

OLD_SKIP = (
    "action_not_supported_v0", "scope_type_has_no_network_range",
    "scope_narrower_than_sandbox_minimum", "no_usable_block_for_address",
    "target_is_reserved_address", "ipv6_not_supported_v0",
)
NEW_SKIP = tuple(c for c in OLD_SKIP if c != "no_usable_block_for_address")
DEFER = ("engagement_paused", "engagement_killed", "engagement_not_active")


def _in(values) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _replace_constraints(skip: tuple[str, ...]) -> None:
    op.execute("ALTER TABLE scheduler_state DROP CONSTRAINT scheduler_state_reason_code_check;")
    op.execute("ALTER TABLE scheduler_state DROP CONSTRAINT scheduler_state_check1;")
    codes = _in(skip + DEFER + ("approved_and_idle",))
    op.execute(f"""
        ALTER TABLE scheduler_state ADD CONSTRAINT scheduler_state_reason_code_check
            CHECK (reason_code IN ({codes}));
        ALTER TABLE scheduler_state ADD CONSTRAINT scheduler_state_check1
            CHECK ((disposition = 'served'           AND reason_code IS NULL)
                OR (disposition = 'deferred'         AND reason_code IS NOT NULL
                        AND reason_code IN ({_in(DEFER)}))
                OR (disposition = 'skipped'          AND reason_code IS NOT NULL
                        AND reason_code IN ({_in(skip)}))
                OR (disposition = 'dispatch_decided' AND reason_code IS NOT NULL
                        AND reason_code = 'approved_and_idle'));
    """)


def upgrade() -> None:
    op.execute("ALTER TABLE scheduler_state DROP CONSTRAINT scheduler_state_reason_code_check;")
    op.execute("ALTER TABLE scheduler_state DROP CONSTRAINT scheduler_state_check1;")
    op.execute("ALTER TABLE scheduler_state NO FORCE ROW LEVEL SECURITY;")
    op.execute("UPDATE scheduler_state SET reason_code = 'scope_narrower_than_sandbox_minimum' "
               "WHERE reason_code = 'no_usable_block_for_address';")
    op.execute("ALTER TABLE scheduler_state FORCE ROW LEVEL SECURITY;")
    codes = _in(NEW_SKIP + DEFER + ("approved_and_idle",))
    op.execute(f"""
        ALTER TABLE scheduler_state ADD CONSTRAINT scheduler_state_reason_code_check
            CHECK (reason_code IN ({codes}));
        ALTER TABLE scheduler_state ADD CONSTRAINT scheduler_state_check1
            CHECK ((disposition = 'served'           AND reason_code IS NULL)
                OR (disposition = 'deferred'         AND reason_code IS NOT NULL
                        AND reason_code IN ({_in(DEFER)}))
                OR (disposition = 'skipped'          AND reason_code IS NOT NULL
                        AND reason_code IN ({_in(NEW_SKIP)}))
                OR (disposition = 'dispatch_decided' AND reason_code IS NOT NULL
                        AND reason_code = 'approved_and_idle'));
    """)


def downgrade() -> None:
    _replace_constraints(OLD_SKIP)
