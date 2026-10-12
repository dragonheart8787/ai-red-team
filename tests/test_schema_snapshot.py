"""``snapshot_schema()`` sees what it claims to see (D64 step 5, ACCEPTANCE 5.78).

A comparison is only worth something if it can fail. For each kind of schema fact the snapshot
covers, a scratch schema is built, one fact is changed inside a transaction that is rolled back, and
the snapshot must differ -- and name the object. The first case is the one that mattered: a
constraint dropped and re-added with the same definition *loses its COMMENT*, which a comparison of
definitions does not see (the development database lost the 0021 comment that way).
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text

from control_plane.state.schema_snapshot import diff, snapshot_schema


@pytest.fixture
def schema(db_available):
    url = os.environ.get("MIGRATION_DATABASE_URL")
    assert url, "MIGRATION_DATABASE_URL is not set"
    engine = create_engine(url, future=True)
    name = f"snaptest_{uuid.uuid4().hex[:10]}"
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {name}"))
        for statement in (
            f"CREATE TABLE {name}.t (id int PRIMARY KEY, kind text, note text, "
            f"CONSTRAINT kind_ok CHECK (kind IN ('a', 'b')))",
            f"COMMENT ON CONSTRAINT kind_ok ON {name}.t IS 'only a or b'",
            f"COMMENT ON COLUMN {name}.t.note IS 'free text'",
            f"COMMENT ON TABLE {name}.t IS 'the table'",
            f"CREATE INDEX t_kind ON {name}.t (kind) WHERE kind = 'a'",
            f"ALTER TABLE {name}.t ENABLE ROW LEVEL SECURITY",
            f"CREATE POLICY p ON {name}.t USING (true)",
            f"CREATE FUNCTION {name}.f() RETURNS int LANGUAGE sql SECURITY DEFINER "
            f"SET search_path = {name}, pg_temp AS 'SELECT 1'",
            f"CREATE FUNCTION {name}.trg() RETURNS trigger LANGUAGE plpgsql AS "
            f"'BEGIN RETURN NEW; END'",
            f"CREATE TRIGGER tr BEFORE INSERT ON {name}.t FOR EACH ROW EXECUTE FUNCTION "
            f"{name}.trg()",
            f"CREATE VIEW {name}.v AS SELECT id FROM {name}.t",
        ):
            conn.execute(text(statement))
    try:
        yield name, engine
    finally:
        with engine.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {name} CASCADE"))
        engine.dispose()


def _changed(schema, change: str) -> list[str]:
    name, engine = schema
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            before = snapshot_schema(conn, name)
            for statement in change.format(s=name).split(";"):
                if statement.strip():
                    conn.execute(text(statement))
            return diff(before, snapshot_schema(conn, name))
        finally:
            trans.rollback()


CASES = {
    "a constraint dropped and re-added loses its COMMENT": (
        "ALTER TABLE {s}.t DROP CONSTRAINT kind_ok; "
        "ALTER TABLE {s}.t ADD CONSTRAINT kind_ok CHECK (kind IN ('a', 'b'))",
        "constraint:t.kind_ok"),
    "a constraint's COMMENT changes": (
        "COMMENT ON CONSTRAINT kind_ok ON {s}.t IS 'something else'", "constraint:t.kind_ok"),
    "a column's COMMENT is removed": (
        "COMMENT ON COLUMN {s}.t.note IS NULL", "column:t.note"),
    "a table's COMMENT changes": ("COMMENT ON TABLE {s}.t IS 'x'", "relation:t"),
    "a constraint's definition changes": (
        "ALTER TABLE {s}.t DROP CONSTRAINT kind_ok; "
        "ALTER TABLE {s}.t ADD CONSTRAINT kind_ok CHECK (kind IN ('a', 'b', 'c')); "
        "COMMENT ON CONSTRAINT kind_ok ON {s}.t IS 'only a or b'", "constraint:t.kind_ok"),
    "an index predicate changes": (
        "DROP INDEX {s}.t_kind; CREATE INDEX t_kind ON {s}.t (kind) WHERE kind = 'b'",
        "index:t_kind"),
    "FORCE ROW LEVEL SECURITY is switched on": (
        "ALTER TABLE {s}.t FORCE ROW LEVEL SECURITY", "relation:t"),
    "row level security is switched off": (
        "ALTER TABLE {s}.t DISABLE ROW LEVEL SECURITY", "relation:t"),
    "a policy changes": (
        "DROP POLICY p ON {s}.t; CREATE POLICY p ON {s}.t USING (false)", "policy:t.p"),
    "a table privilege is granted": ("GRANT SELECT ON {s}.t TO PUBLIC", "relation:t"),
    "a column privilege is granted": ("GRANT SELECT (note) ON {s}.t TO PUBLIC", "column:t.note"),
    "a function loses SECURITY DEFINER": (
        "ALTER FUNCTION {s}.f() SECURITY INVOKER", "function:f()"),
    "a function's search_path changes": (
        "ALTER FUNCTION {s}.f() SET search_path = pg_temp", "function:f()"),
    "a function's COMMENT is set": ("COMMENT ON FUNCTION {s}.f() IS 'x'", "function:f()"),
    "a trigger is disabled": ("ALTER TABLE {s}.t DISABLE TRIGGER tr", "trigger:t.tr"),
    "a view definition changes": (
        "CREATE OR REPLACE VIEW {s}.v AS SELECT id, kind FROM {s}.t", "view:v"),
    "a column's default changes": ("ALTER TABLE {s}.t ALTER COLUMN kind SET DEFAULT 'a'",
                                   "column:t.kind"),
    "a column becomes NOT NULL": ("ALTER TABLE {s}.t ALTER COLUMN note SET NOT NULL",
                                  "column:t.note"),
}


@pytest.mark.parametrize("what", sorted(CASES))
def test_the_snapshot_notices(schema, what):
    change, key = CASES[what]
    lines = _changed(schema, change)
    assert lines, f"{what}: the snapshot did not change"
    assert any(key in line for line in lines), (what, lines)


def test_an_unchanged_schema_has_an_empty_diff_and_the_snapshot_is_stable(schema):
    name, engine = schema
    with engine.connect() as conn:
        first = snapshot_schema(conn, name)
        assert diff(first, snapshot_schema(conn, name)) == []
    assert any(k.startswith("constraint:t.kind_ok") and "comment=only a or b" in v
               for k, v in first.items())


def test_the_schemas_own_name_does_not_appear_so_two_schemas_compare(schema):
    name, engine = schema
    with engine.connect() as conn:
        snap = snapshot_schema(conn, name)
    assert not any(name in k or name in v for k, v in snap.items())
    assert "function:f()" in snap and "<schema>" in snap["function:f()"]


def test_the_shared_schema_can_be_snapshotted_and_has_the_stage_checks_with_their_comments(
    db_available,
):
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    with engine.connect() as conn:
        snap = snapshot_schema(conn)
    engine.dispose()
    value = snap["constraint:action_proposals.action_proposals_decision_past_received"]
    assert "comment=NULL decision is legal at `received`" in value
    assert snap["alembic:version"]
