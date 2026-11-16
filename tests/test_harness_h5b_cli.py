"""D69 H5b: the operator's CLI (``scripts/manage_harness_enrolment.py``) -- T6.

Almost everything here runs ``main`` with a ``connect`` that hands out the connection of an
always-rolled-back owner transaction (``tests/test_harness_h5b_support.py``), so no test of a
refusal can write a row, whatever the CLI does. One test runs the CLI for real, as
``cyberorch_app``, and removes what it wrote.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import manage_harness_enrolment as cli  # noqa: E402
from tests.test_harness_h5b_support import owner_transaction, read_only_flag_spy  # noqa: E402


def _count(conn, engagement_id: str) -> int:
    return conn.execute(text("SELECT count(*) FROM harness_enrolment WHERE engagement_id = :e"),
                        {"e": engagement_id}).scalar()


def _register_args(engagement_id: str, *extra: str) -> list[str]:
    return ["register", "--engagement", engagement_id, "--actor", "alice", "--yes", *extra]


# -- --purpose: required, no default, one value -------------------------------------------------


def test_a_registration_without_purpose_is_an_error_and_writes_nothing(engagement_id, capsys):
    with owner_transaction() as conn:
        seen: list[bool] = []
        with pytest.raises(SystemExit) as caught:
            cli.main(_register_args(engagement_id), connect=read_only_flag_spy(conn, seen))
        assert caught.value.code == 2
        assert "--purpose" in capsys.readouterr().err
        assert _count(conn, engagement_id) == 0
        assert seen == []                                     # the database was never asked for


@pytest.mark.parametrize("purpose", ["other", "harness_prod", "HARNESS_LAB", "", "harness_lab "])
def test_a_purpose_that_is_not_harness_lab_is_refused_before_the_database(
        engagement_id, purpose, capsys):
    with owner_transaction() as conn:
        seen: list[bool] = []
        code = cli.main(_register_args(engagement_id, "--purpose", purpose),
                        connect=read_only_flag_spy(conn, seen))
        assert code == 1
        assert "--purpose" in capsys.readouterr().err
        assert _count(conn, engagement_id) == 0
        assert seen == []


def test_there_is_no_default_purpose_anywhere_in_the_cli():
    parser = cli.build_parser()
    subparsers = next(a for a in parser._actions if a.dest == "command")
    options = [a for a in subparsers.choices["register"]._actions
               if a.option_strings == ["--purpose"]]
    assert len(options) == 1
    assert options[0].required is True
    assert options[0].default is None
    assert options[0].const is None


def test_a_registration_with_purpose_harness_lab_is_written(engagement_id, capsys):
    with owner_transaction() as conn:
        code = cli.main(_register_args(engagement_id, "--purpose", "harness_lab"),
                        connect=read_only_flag_spy(conn, []))
        assert code == 0
        assert f"registered {engagement_id}" in capsys.readouterr().out
        row = conn.execute(text("SELECT purpose, enrolled_by, withdrawn_at FROM harness_enrolment "
                                "WHERE engagement_id = :e"), {"e": engagement_id}).one()
        assert tuple(row) == ("harness_lab", "alice", None)


# -- refusals ------------------------------------------------------------------------------------


def test_a_second_registration_of_a_live_engagement_is_refused(engagement_id, capsys):
    with owner_transaction() as conn:
        connect = read_only_flag_spy(conn, [])
        assert cli.main(_register_args(engagement_id, "--purpose", "harness_lab"),
                        connect=connect) == 0
        capsys.readouterr()
        code = cli.main(_register_args(engagement_id, "--purpose", "harness_lab"),
                        connect=connect)
        assert code == 1
        assert "already registered" in capsys.readouterr().err
        assert _count(conn, engagement_id) == 1


def test_an_engagement_that_does_not_exist_is_refused(db_available, capsys):
    with owner_transaction() as conn:
        code = cli.main(_register_args("ENG-NOBODY-MADE-THIS", "--purpose", "harness_lab"),
                        connect=read_only_flag_spy(conn, []))
        assert code == 1
        assert "no such engagement" in capsys.readouterr().err


@pytest.mark.parametrize("what", ["engagement", "actor"])
@pytest.mark.parametrize("value", ["", "a b", "x;DROP TABLE", "_leading", "é", "a" * 129, "x\ny"])
def test_an_id_or_an_actor_that_is_not_a_plain_identifier_is_refused_before_anything_else(
        what, value, capsys):
    seen: list[bool] = []
    argv = ["register", "--engagement", "ENG-OK", "--purpose", "harness_lab", "--actor", "alice",
            "--yes"]
    argv[argv.index("--engagement" if what == "engagement" else "--actor") + 1] = value
    code = cli.main(argv, connect=read_only_flag_spy(None, seen))
    assert code == 1
    assert "plain identifier" in capsys.readouterr().err
    assert seen == []


def test_without_yes_and_without_a_terminal_nothing_is_written(engagement_id, capsys):
    with owner_transaction() as conn:
        seen: list[bool] = []
        code = cli.main(["register", "--engagement", engagement_id, "--purpose", "harness_lab",
                         "--actor", "alice"], connect=read_only_flag_spy(conn, seen))
        assert code == 2
        assert "no terminal" in capsys.readouterr().err
        assert _count(conn, engagement_id) == 0
        assert seen == []


# -- withdraw ------------------------------------------------------------------------------------


def test_withdrawing_a_registered_engagement_works_and_withdrawing_it_twice_is_refused(
        engagement_id, capsys):
    with owner_transaction() as conn:
        connect = read_only_flag_spy(conn, [])
        assert cli.main(_register_args(engagement_id, "--purpose", "harness_lab"),
                        connect=connect) == 0
        capsys.readouterr()
        withdraw = ["withdraw", "--engagement", engagement_id, "--actor", "bob", "--yes"]
        assert cli.main(withdraw, connect=connect) == 0
        assert f"withdrawn {engagement_id}" in capsys.readouterr().out
        assert cli.main(withdraw, connect=connect) == 1
        assert "not currently registered" in capsys.readouterr().err
        who = conn.execute(text("SELECT withdrawn_by FROM harness_enrolment "
                                "WHERE engagement_id = :e"), {"e": engagement_id}).scalar()
        assert who == "bob"


# -- list: read only -----------------------------------------------------------------------------


def test_list_asks_for_a_read_only_transaction_and_writes_nothing(engagement_id, capsys):
    with owner_transaction() as conn:
        write_seen: list[bool] = []
        assert cli.main(_register_args(engagement_id, "--purpose", "harness_lab"),
                        connect=read_only_flag_spy(conn, write_seen)) == 0
        capsys.readouterr()
        before = conn.execute(text("SELECT count(*), max(enrolment_id) FROM harness_enrolment")
                              ).one()
        seen: list[bool] = []

        assert cli.main(["list"], connect=read_only_flag_spy(conn, seen)) == 0

        assert write_seen == [False] and seen == [True]
        out = capsys.readouterr().out
        assert engagement_id in out and "purpose=harness_lab" in out and "[live]" in out
        after = conn.execute(text("SELECT count(*), max(enrolment_id) FROM harness_enrolment")
                             ).one()
        assert tuple(before) == tuple(after)


def test_the_real_read_only_connection_of_the_cli_cannot_write(db_available):
    with cli._connect(True) as conn:
        assert conn.execute(text("SHOW transaction_read_only")).scalar() == "on"
        with pytest.raises(DBAPIError) as caught, conn.begin_nested():
            conn.execute(text("INSERT INTO harness_enrolment (engagement_id, purpose, enrolled_by)"
                              " VALUES ('X', 'harness_lab', 'a')"))
        assert getattr(caught.value.orig, "sqlstate", "") == "25006"


def test_list_prints_a_line_for_a_registration_and_says_so_when_there_is_none(
        db_available, capsys):
    with owner_transaction() as conn:
        conn.execute(text("DELETE FROM harness_enrolment"))
        assert cli.main(["list"], connect=read_only_flag_spy(conn, [])) == 0
        assert "no registrations" in capsys.readouterr().out


# -- the whole thing as the real role ------------------------------------------------------------


def test_the_cli_works_end_to_end_as_cyberorch_app_and_the_row_is_removed_afterwards(
        engagement_id, capsys):
    registered = ["register", "--engagement", engagement_id, "--purpose", "harness_lab",
                  "--actor", "e2e", "--yes"]
    try:
        assert cli.main(registered) == 0
        assert cli.main(registered) == 1                     # as the real role: the index refuses
        assert cli.main(["list"]) == 0
        assert engagement_id in capsys.readouterr().out
        assert cli.main(["withdraw", "--engagement", engagement_id, "--actor", "e2e", "--yes"]) == 0
        assert cli.main(["withdraw", "--engagement", engagement_id, "--actor", "e2e", "--yes"]) == 1
    finally:
        # cyberorch_app cannot delete (that is the point); the owner removes the test's own rows
        engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
        try:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE harness_enrolment NO FORCE ROW LEVEL SECURITY"))
                conn.execute(text("DELETE FROM harness_enrolment WHERE engagement_id = :e"),
                             {"e": engagement_id})
                conn.execute(text("ALTER TABLE harness_enrolment FORCE ROW LEVEL SECURITY"))
        finally:
            engine.dispose()
