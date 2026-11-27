"""Plan item 159: the name of ``--record`` and the entries of the records directory.

A record is a regular ``*.jsonl`` file directly in ``REGISTERED_RECORDS_DIR``, not hidden and not
the ledger's name, because the acknowledgement check and the analysis read exactly those files: a
record anywhere else would be seen by neither (fail open, found by the implementer in item 157).
So ``scripts/run_shadow.py`` refuses a ``--record`` in a subdirectory, with another suffix or a
hidden name (``record_name_not_allowed``, after ``record_outside_registered_dir``), and both it
(step 2a, after the history) and ``scripts/analyse_shadow.py`` (step b, before the records are
read) refuse a directory holding anything else (``records_dir_unexpected_entry``, by name).

Git is real, in a repository under pytest's ``tmp_path`` (``Checkout`` of
``tests/test_shadow_record_history.py``). No model, no container, no network; a start that passes
is stopped at the hand-over by the ``through`` spy, before the database.
"""

from __future__ import annotations

import pytest

from scripts import analyse_shadow, run_shadow
from tests.test_shadow_record_history import (  # noqa: F401 - fixtures
    MARK,
    RECDIR,
    co,
    look,
    start,
)
from tests.test_shadow_runner_guard import _codes, _subscription_only, through  # noqa: F401

REFUSED = run_shadow.EXIT_STARTUP_REFUSED


# == the name of --record =========================================================================


@pytest.mark.parametrize("record,said", [
    ("sub/run.jsonl", "is in a subdirectory"),
    ("run.json", "does not end with .jsonl"),
    ("run.txt", "does not end with .jsonl"),
    (".run.jsonl", "is a hidden name"),
])
def test_a_record_name_that_is_not_a_record_s_is_refused(record, said, co, through, capsys):  # noqa: F811
    code, lock = start(co, record=record)
    err = capsys.readouterr().err
    with capsys.disabled():
        print(f"\nSTDERR (--record {record})\n{err}")
    assert code == REFUSED
    assert _codes(err) == [run_shadow.RECORD_NAME_NOT_ALLOWED] and said in err
    assert lock.asked == 0 and through == []
    assert not (co.path / RECDIR / record).exists()


def test_the_ledger_s_name_is_refused_by_the_earlier_check(co, through, capsys):  # noqa: F811
    """``looks.jsonl`` is refused before the name check, as ``record_outside_registered_dir`` (plan
    item 156; its test is ``test_the_ledger_s_name_is_not_a_record``); the name rule names it
    too."""
    code, _ = start(co, record=run_shadow.LEDGER_NAME)
    assert code == REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.RECORD_OUTSIDE_REGISTERED_DIR]
    directory = co.path / RECDIR
    assert run_shadow.record_name_problem(directory / run_shadow.LEDGER_NAME, directory) == \
        f"is the ledger's name, {run_shadow.LEDGER_NAME}"
    assert run_shadow.record_name_problem(directory / "run.jsonl", directory) is None


def test_a_record_outside_the_directory_is_still_the_earlier_code(co, through, capsys):  # noqa: F811
    code, _ = start(co, record="../outside.jsonl")
    assert code == REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.RECORD_OUTSIDE_REGISTERED_DIR]


# == the entries of the records directory =========================================================


def _subdirectory(checkout):
    (checkout.path / RECDIR / "sub").mkdir()
    checkout.record("sub/x.jsonl")


def _text_file(checkout):
    (checkout.path / RECDIR / "notes.txt").write_text("not a record\n")


def _symbolic_link(checkout):
    checkout.record("a.jsonl")
    (checkout.path / RECDIR / "b.jsonl").symlink_to("a.jsonl")


def _hidden_file(checkout):
    checkout.record(".hidden.jsonl")


@pytest.mark.parametrize("entry,name,said", [
    (_subdirectory, "sub", "is a subdirectory"),
    (_text_file, "notes.txt", "is not a *.jsonl file"),
    (_symbolic_link, "b.jsonl", "is a symbolic link"),
    (_hidden_file, ".hidden.jsonl", "is a hidden name"),
])
def test_an_unexpected_entry_in_the_records_directory_refuses_the_start_and_the_look(
        entry, name, said, co, through, capsys):  # noqa: F811
    co.record("r.jsonl")
    entry(co)
    co.commit_all("a record, and an entry that is not one")
    code, lock = start(co)
    err = capsys.readouterr().err
    with capsys.disabled():
        print(f"\nSTDERR (start, {entry.__name__})\n{err}")
    assert code == REFUSED
    assert _codes(err) == [run_shadow.RECORDS_DIR_UNEXPECTED_ENTRY]
    assert f"{name} {said}" in err and MARK not in err
    assert lock.asked == 0 and through == [] and not (co.path / RECDIR / "run.jsonl").exists()
    assert look(co) == REFUSED
    err = capsys.readouterr().err
    assert _codes(err) == [run_shadow.RECORDS_DIR_UNEXPECTED_ENTRY]
    assert f"{name} {said}" in err and MARK not in err
    assert not (co.path / RECDIR / run_shadow.LEDGER_NAME).exists()


def test_records_and_the_ledger_alone_let_the_start_and_the_look_through(co, through, capsys):  # noqa: F811
    co.record("a.jsonl")
    co.record("b.jsonl")
    co.commit_all("two records")
    assert look(co) == run_shadow.EXIT_OK
    co.commit_all("look 1: the ledger")
    code, lock = start(co)
    assert lock.asked == 1 and len(through) == 1          # through every check, to the hand-over
    capsys.readouterr()
    assert look(co, "--reason", "a second look, for the test") == REFUSED     # the new record
    assert _codes(capsys.readouterr().err) == [run_shadow.TREE_NOT_CLEAN]


def test_a_records_directory_that_is_a_symbolic_link_is_refused(co, through, capsys):  # noqa: F811
    (co.path / "docs" / "real").mkdir()
    (co.path / RECDIR).rmdir()
    (co.path / RECDIR).symlink_to("real")
    co.commit_all("the records directory is a link")
    code, _ = start(co)
    err = capsys.readouterr().err
    assert code == REFUSED and "symbolic link" in err
    # git, asked about a path beyond a symbolic link, cannot answer either (git_unavailable)
    assert run_shadow.RECORDS_DIR_UNEXPECTED_ENTRY in _codes(err)
    assert set(_codes(err)) <= {run_shadow.RECORDS_DIR_UNEXPECTED_ENTRY, run_shadow.GIT_UNAVAILABLE}


def test_a_records_directory_that_does_not_exist_keeps_the_earlier_handling(co, through, capsys):  # noqa: F811
    """Not refused by the entry check: the runner cannot create the record
    (``record_unwritable``), and the analysis finds no record (``no_records``)."""
    (co.path / RECDIR).rmdir()                           # git keeps no empty directory
    assert run_shadow.records_dir_entry_problems(co.path / RECDIR) == []
    code, lock = start(co)
    assert code == REFUSED and lock.asked == 0
    assert _codes(capsys.readouterr().err) == [run_shadow.RECORD_UNWRITABLE]
    assert look(co) == REFUSED
    assert _codes(capsys.readouterr().err) == [analyse_shadow.NO_RECORDS]
