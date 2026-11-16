"""D69 H5b: the reader of the enrolment list (``harness/enrolment_db.py``) against the table.

T1 -- the filter on the purpose. The table's ``CHECK`` lets one purpose in, so a test cannot insert
a row with another purpose; it takes the ``CHECK`` away for the length of one transaction, puts a
row with purpose ``other`` in, reads through the reader **on that same connection** (a second
connection would wait for the lock the ``ALTER TABLE`` holds, and would not see the uncommitted
row), and rolls everything back. It then shows that the ``CHECK`` is back and the rows are gone.
T5 -- withdrawal. The registrations are written with the CLI's own functions
(``scripts/manage_harness_enrolment.py``), not through a subprocess.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.state.db import get_engine
from harness.enrolment import EnrolmentReader
from harness.enrolment_db import EnrolledFromDatabase, read_only_connection

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import manage_harness_enrolment as cli  # noqa: E402
from tests.test_harness_h5b_support import (  # noqa: E402
    PURPOSE_CHECK,
    owner_transaction,
    same_connection,
)


def _reader(conn) -> EnrolledFromDatabase:
    return EnrolledFromDatabase(connect=same_connection(conn))


# -- T1: only purpose harness_lab ---------------------------------------------------------------


def test_the_reader_returns_only_the_harness_lab_rows_whatever_else_is_in_the_table(
        engagement_factory):
    engagement_a, _ = engagement_factory()
    engagement_b, _ = engagement_factory()
    with owner_transaction() as conn:
        assert cli.register(conn, engagement_a, "harness_lab", "alice") is None
        conn.execute(text(f"ALTER TABLE harness_enrolment DROP CONSTRAINT {PURPOSE_CHECK}"))
        conn.execute(text("INSERT INTO harness_enrolment (engagement_id, purpose, enrolled_by) "
                          "VALUES (:e, 'other', 'mallory')"), {"e": engagement_b})
        assert conn.execute(text("SELECT count(*) FROM harness_enrolment WHERE purpose = 'other'")
                            ).scalar() == 1                    # the row is really there

        assert _reader(conn).enrolled() == (engagement_a,)

    # everything of it was rolled back: the CHECK is there again and neither row is
    with owner_transaction() as conn:
        definition = conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = :n AND conrelid = 'public.harness_enrolment'::regclass"),
            {"n": PURPOSE_CHECK}).scalar_one()
    assert "harness_lab" in definition
    with get_engine().begin() as conn:
        left = conn.execute(text("SELECT engagement_id FROM harness_enrolment "
                                 "WHERE engagement_id = ANY(:ids)"),
                            {"ids": [engagement_a, engagement_b]}).all()
    assert left == []


def test_the_reader_returns_nothing_for_an_empty_table_and_a_tuple_of_strings_otherwise(
        engagement_id):
    with owner_transaction() as conn:
        conn.execute(text("DELETE FROM harness_enrolment"))
        assert _reader(conn).enrolled() == ()
        assert cli.register(conn, engagement_id, "harness_lab", "alice") is None
        got = _reader(conn).enrolled()
        assert got == (engagement_id,)
        assert isinstance(got, tuple) and all(isinstance(e, str) for e in got)


def test_the_order_is_by_registration_and_then_by_engagement_id_and_the_same_every_time(
        engagement_factory):
    first, _ = engagement_factory()
    second, _ = engagement_factory()
    third, _ = engagement_factory()
    with owner_transaction() as conn:
        conn.execute(text("DELETE FROM harness_enrolment"))
        # same moment for the first two (one statement), a later one for the third
        conn.execute(text("INSERT INTO harness_enrolment (engagement_id, purpose, enrolled_by, "
                          "enrolled_at) VALUES (:b, 'harness_lab', 'a', TIMESTAMPTZ '2030-01-01'), "
                          "(:a, 'harness_lab', 'a', TIMESTAMPTZ '2030-01-01'), "
                          "(:c, 'harness_lab', 'a', TIMESTAMPTZ '2029-01-01')"),
                     {"a": first, "b": second, "c": third})
        expected = (third, *sorted((first, second)))
        assert _reader(conn).enrolled() == expected
        assert _reader(conn).enrolled() == expected


# -- T5: withdrawal -------------------------------------------------------------------------------


def test_a_withdrawn_engagement_leaves_the_list_and_can_be_registered_again(engagement_id):
    with owner_transaction() as conn:
        conn.execute(text("DELETE FROM harness_enrolment"))
        reader = _reader(conn)

        assert cli.register(conn, engagement_id, "harness_lab", "alice") is None
        assert reader.enrolled() == (engagement_id,)

        assert cli.withdraw(conn, engagement_id, "alice") is None
        assert reader.enrolled() == ()

        # the unique index covers the live rows only: the same engagement can be registered again
        assert cli.register(conn, engagement_id, "harness_lab", "bob") is None
        assert reader.enrolled() == (engagement_id,)
        history = conn.execute(text(
            "SELECT enrolled_by, withdrawn_by IS NULL FROM harness_enrolment "
            "WHERE engagement_id = :e ORDER BY enrolment_id"), {"e": engagement_id}).all()
        assert [tuple(r) for r in history] == [("alice", False), ("bob", True)]


def test_a_withdrawn_row_cannot_be_made_live_again_through_the_cli_functions(engagement_id):
    with owner_transaction() as conn:
        assert cli.register(conn, engagement_id, "harness_lab", "alice") is None
        assert cli.withdraw(conn, engagement_id, "alice") is None
        with pytest.raises(DBAPIError), conn.begin_nested():
            conn.execute(text("UPDATE harness_enrolment SET withdrawn_at = NULL, "
                              "withdrawn_by = NULL WHERE engagement_id = :e"),
                         {"e": engagement_id})
        assert _reader(conn).enrolled() == ()
        # and withdrawing what is not live is refused, not repeated
        assert cli.withdraw(conn, engagement_id, "alice") == "not currently registered"


# -- the reader's own shape -----------------------------------------------------------------------


def test_the_reader_is_an_enrolment_reader_and_reads_in_a_read_only_transaction(db_available):
    reader: EnrolmentReader = EnrolledFromDatabase()
    assert callable(reader.enrolled)
    with read_only_connection() as conn:
        assert conn.execute(text("SHOW transaction_read_only")).scalar() == "on"
        with pytest.raises(Exception) as caught, conn.begin_nested():
            conn.execute(text("INSERT INTO harness_enrolment (engagement_id, purpose, "
                              "enrolled_by) VALUES ('X', 'harness_lab', 'a')"))
        assert getattr(caught.value.orig, "sqlstate", "") == "25006"   # read_only_sql_transaction


def test_the_default_reader_reads_the_real_table_as_cyberorch_app(db_available):
    assert isinstance(EnrolledFromDatabase().enrolled(), tuple)
