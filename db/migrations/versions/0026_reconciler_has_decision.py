"""The reconciler can tell a proposal that has a decision from one that has none: ``has_decision``
(D64 completion 4, item 4; ACCEPTANCE 5.98).

Revision ID: 0026
Revises: 0025

**Why.** ``reconciler_stuck_proposals()`` did not return whether a proposal has a decision, so the
plan could not tell a ``received`` proposal that is undecided -- which it abandons -- from a
``received`` proposal that **has** a decision, which the database refuses to abandon (the CHECK
``action_proposals_abandoned_is_undecided``, 0022). Through the pipeline such a row cannot arise
(a decision is written together with ``decided``); a hand-made one did, in the development database
(436 and 467 of them in the two ``state-only`` runs of completion 3), and the plan asked for an
action the database then refused on every pass. The refusal was the right outcome and the plan's
ignorance was the defect (``docs/D64_PREDELETION_COMPLETION.md`` §9.1, point 2).

**What changes.** Both read functions (``reconciler_stuck_proposals()`` and
``reconciler_stuck_proposals_after(bigint, text)``) return one more column, ``has_decision
boolean`` -- ``decision IS NOT NULL`` and nothing else: **never the decision itself** (the value,
the reason, the rule that decided stay out of the reader's sight, as 0023 promised). A function's
result type cannot be changed in place, so each is dropped and created again from the text of 0023
and 0024 with the one column added; owner, ``search_path``, grants, comments and the ownership
hand-over are repeated exactly. The function owner gets column-level ``SELECT`` on
``action_proposals.decision`` and on nothing else new; the row policy that limits it to the stuck
stages is unchanged.

**Downgrade** drops both functions, creates the 0023 and 0024 definitions again, and takes the
column grant back. No row of any table is touched in either direction.
"""

import importlib.util
from pathlib import Path

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

OWNER = "reconciler_fn_owner"
READER = "reconciler_reader"
FIRST = "reconciler_stuck_proposals()"
NEXT = "reconciler_stuck_proposals_after(bigint, text)"
NEW_OWNER_COLUMNS = {"action_proposals": ("decision",)}

COMMENT_FIRST = (
    "D64 0023/0026: stuck proposals across engagements for the reconciler's plan. SECURITY "
    "DEFINER, owner reconciler_fn_owner (NOLOGIN, NOBYPASSRLS), pinned search_path, EXECUTE for "
    "reconciler_reader only. Returns ids, closed-vocabulary enums, integers and booleans "
    "(has_decision says whether a decision exists, never what it is); never a target, a decision "
    "or a budget document."
)
COMMENT_NEXT = (
    "D64 0024/0026: the next page of reconciler_stuck_proposals(): the same rows and columns, "
    "strictly after the keyset cursor (stage_updated_us, proposal_id) of the last row of the page "
    "before. A cursor with a NULL half returns nothing. SECURITY DEFINER, owner "
    "reconciler_fn_owner, EXECUTE for reconciler_reader only."
)

_OLD_COLUMN = "            run_status            text\n        )"
_NEW_COLUMN = ("            run_status            text,\n"
               "            has_decision          boolean\n        )")
_OLD_SELECT = "                   r.status\n            FROM"
_NEW_SELECT = ("                   r.status,\n"
               "                   p.decision IS NOT NULL\n            FROM")


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _schema() -> str:
    return op.get_bind().exec_driver_sql("SELECT quote_ident(current_schema())").scalar_one()


def _earlier(filename: str):
    """An earlier migration's module, loaded from its file next to this one (their names start
    with digits, so they cannot be imported by name)."""
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(f"earlier_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _with_has_decision(definition: str) -> str:
    """0023's / 0024's function text with ``has_decision`` added as the last column. Each edit
    must find exactly one place, or the migration refuses to run (a changed 0023 is not silently
    patched)."""
    for old, new in ((_OLD_COLUMN, _NEW_COLUMN), (_OLD_SELECT, _NEW_SELECT)):
        if definition.count(old) != 1:
            raise RuntimeError("an earlier definition is not the text 0026 was written against")
        definition = definition.replace(old, new)
    return definition


def _install(s: str, signature: str, definition: str, comment: str) -> None:
    op.execute(definition)
    op.execute(f"REVOKE ALL ON FUNCTION {s}.{signature} FROM PUBLIC;")
    op.execute(f"GRANT EXECUTE ON FUNCTION {s}.{signature} TO {READER};")
    op.execute(f"COMMENT ON FUNCTION {s}.{signature} IS {_literal(comment)};")
    # The hand-over comes last (0023): migration_owner is a member of the owner WITHOUT inheriting
    # it, so it cannot touch the function afterwards.
    op.execute(f"GRANT CREATE ON SCHEMA {s} TO {OWNER};")
    op.execute(f"ALTER FUNCTION {s}.{signature} OWNER TO {OWNER};")
    op.execute(f"REVOKE CREATE ON SCHEMA {s} FROM {OWNER};")


def upgrade() -> None:
    s = _schema()
    m23, m24 = _earlier("0023_reconciler_reader.py"), _earlier("0024_reconciler_paging.py")
    op.execute(f"GRANT SELECT (decision) ON {s}.action_proposals TO {OWNER};")
    op.execute(f"DROP FUNCTION {s}.{FIRST};")
    op.execute(f"DROP FUNCTION {s}.{NEXT};")
    _install(s, FIRST, _with_has_decision(m23._stuck_function(s)), COMMENT_FIRST)
    _install(s, NEXT, _with_has_decision(m24._function(s)), COMMENT_NEXT)


def downgrade() -> None:
    s = _schema()
    m23, m24 = _earlier("0023_reconciler_reader.py"), _earlier("0024_reconciler_paging.py")
    op.execute(f"DROP FUNCTION {s}.{FIRST};")
    op.execute(f"DROP FUNCTION {s}.{NEXT};")
    _install(s, FIRST, m23._stuck_function(s), m23.COMMENT_STUCK)
    _install(s, NEXT, m24._function(s), m24.COMMENT)
    op.execute(f"REVOKE SELECT (decision) ON {s}.action_proposals FROM {OWNER};")
