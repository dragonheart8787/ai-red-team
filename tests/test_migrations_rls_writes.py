"""A migration's data statement runs with FORCE ROW LEVEL SECURITY off for what it touches (5.75).

Every engagement-scoped table is ``FORCE ROW LEVEL SECURITY``, which binds the owner -- the role
migrations run as -- and with no ``cyberorch.engagement_id`` the owner sees no rows. A data
statement in a migration therefore reads and writes nothing, silently. D64 found it twice: the
downgrade of 0017 failed on a database that had rows (the repair UPDATE moved none, so the old
CHECK could not be re-added), and the upgrade back-fill of 0017 did the wrong thing (its
``NOT EXISTS`` over ``approvals`` and ``audit_log`` was true for every row, which re-opens
approvals that were granted or denied). 0020 had done it right, for one table.

This reads every migration with ``ast``, takes each SQL string the ``upgrade``/``downgrade``
functions execute, finds the data statements (``UPDATE``, ``INSERT INTO``, ``DELETE FROM``,
``TRUNCATE``) and every table they read or write, and requires, for each table under FORCE RLS: an
``ALTER TABLE <t> NO FORCE ROW LEVEL SECURITY`` earlier in the same function, and
``ALTER TABLE <t> FORCE ROW LEVEL SECURITY`` after the statement. Tables created earlier in the
same function have no rows to hide and are exempt. A new data statement fails the registry below
until someone reads this docstring and lists it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.state.db import get_engine

VERSIONS = Path(__file__).resolve().parents[1] / "db" / "migrations" / "versions"

DATA_STATEMENT = re.compile(
    r"\b(?:UPDATE\s+(?P<u>\w+)\s+(?:\w+\s+)?SET|INSERT\s+INTO\s+(?P<i>\w+)|"
    r"DELETE\s+FROM\s+(?P<d>\w+)|TRUNCATE\s+(?:TABLE\s+)?(?P<t>\w+))\b", re.I)
READS = re.compile(r"\b(?:FROM|JOIN)\s+(?P<table>\w+)", re.I)
NO_FORCE = re.compile(r"ALTER\s+TABLE\s+(?P<t>\w+)\s+NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY", re.I)
FORCE = re.compile(r"ALTER\s+TABLE\s+(?P<t>\w+)\s+FORCE\s+ROW\s+LEVEL\s+SECURITY", re.I)
CREATE = re.compile(r"CREATE\s+TABLE\s+(?P<t>\w+)", re.I)

#: (migration file, function) -> the tables its data statements touch. A new entry means a new data
#: statement in a migration; adding one is a review of the rule above.
EXPECTED = {
    ("0017_approval_stages.py", "upgrade"): {"action_proposals", "approvals", "audit_log"},
    ("0017_approval_stages.py", "downgrade"): {"action_proposals"},
    ("0020_scheduler_state_narrow.py", "upgrade"): {"scheduler_state"},
}


def _executed_strings(fn: ast.FunctionDef) -> list[tuple[int, str]]:
    """The SQL string constants of a function, in source order."""
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append((node.lineno, node.col_offset, node.value))
    return [(line, value) for line, _col, value in sorted(found)]


def _statements() -> dict[tuple[str, str], list[tuple[int, str]]]:
    out = {}
    for path in sorted(VERSIONS.glob("0*.py")):
        tree = ast.parse(path.read_text())
        for fn in tree.body:
            if isinstance(fn, ast.FunctionDef) and fn.name in ("upgrade", "downgrade"):
                out[(path.name, fn.name)] = _executed_strings(fn)
    return out


def _force_tables() -> set[str]:
    with get_engine().connect() as conn:
        return {r[0] for r in conn.execute(text(
            "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
            "AND relkind = 'r' AND relforcerowsecurity"))}


def _is_data_write(statement: str) -> re.Match | None:
    """A real data statement, not a ``GRANT UPDATE``, a ``FOR UPDATE`` or a word in a docstring."""
    for m in DATA_STATEMENT.finditer(statement):
        before = statement[max(0, m.start() - 20):m.start()].upper()
        if "GRANT" in before or "REVOKE" in before or "FOR " in before[-5:]:
            continue
        if statement.lstrip().upper().startswith(("GRANT", "REVOKE", "COMMENT")):
            continue
        return m
    return None


def _data_statements(strings):
    return [(i, line, s) for i, (line, s) in enumerate(strings) if _is_data_write(s)
            and not s.lstrip().startswith(('"', "'")) and len(s) < 4000]


def _tables_touched(statement: str, rls_tables: set[str]) -> set[str]:
    named = {g for m in DATA_STATEMENT.finditer(statement) for g in m.groupdict().values() if g}
    named |= {m.group("table") for m in READS.finditer(statement)}
    return {t for t in named if t in rls_tables}


def test_every_data_statement_in_a_migration_is_known(db_available):
    rls = _force_tables()
    found: dict[tuple[str, str], set[str]] = {}
    for key, strings in _statements().items():
        touched: set[str] = set()
        created = {m.group("t") for _l, s in strings for m in CREATE.finditer(s)}
        for _i, _line, statement in _data_statements(strings):
            touched |= _tables_touched(statement, rls) - created
        if touched:
            found[key] = touched
    assert found == EXPECTED, (
        f"data statements in migrations differ from the registry.\n  found: {found}\n  "
        f"expected: {EXPECTED}\nRead this module's docstring before listing a new one.")


@pytest.mark.parametrize("key", sorted(EXPECTED), ids=lambda k: f"{k[0]}:{k[1]}")
def test_each_data_statement_runs_with_force_off_for_every_table_it_touches(db_available, key):
    rls = _force_tables()
    strings = _statements()[key]
    created = {m.group("t") for _l, s in strings for m in CREATE.finditer(s)}
    checked = 0
    for index, line, statement in _data_statements(strings):
        needed = _tables_touched(statement, rls) - created
        before = "\n".join(s for _l, s in strings[:index])
        after = "\n".join(s for _l, s in strings[index + 1:])
        for table in sorted(needed):
            off = [m for m in NO_FORCE.finditer(before) if m.group("t") == table]
            on = [m for m in FORCE.finditer(after) if m.group("t") == table]
            assert off, (f"{key}: the statement at line {line} touches {table}, which is "
                         f"FORCE ROW LEVEL SECURITY, with no earlier NO FORCE for it -- the "
                         f"owner sees no rows (ACCEPTANCE 5.75)")
            assert on, (f"{key}: line {line}: {table} is switched to NO FORCE and never back to "
                        f"FORCE after the statement")
            checked += 1
    assert checked, f"no data statement found in {key}: the registry is stale"


def test_the_scan_sees_what_it_should_in_a_known_bad_migration():
    """A positive control: the same rule, run on text that breaks it, finds it."""
    strings = [(1, "UPDATE action_proposals p SET stage_detail = 'x' WHERE NOT EXISTS "
                   "(SELECT 1 FROM approvals a WHERE a.proposal_id = p.proposal_id)"),
               (2, "ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY"),
               (3, "ALTER TABLE action_proposals FORCE ROW LEVEL SECURITY")]
    index, _line, statement = _data_statements(strings)[0]
    needed = _tables_touched(statement, {"action_proposals", "approvals"})
    assert needed == {"action_proposals", "approvals"}
    before = "\n".join(s for _l, s in strings[:index])
    assert not NO_FORCE.search(before), "the update comes first: FORCE was never switched off"
