"""S6 (shadow runner plan 2g, g3; plan item 156): ``scripts/analyse_shadow.py look`` and its ledger
of looks, ``looks.jsonl`` in the records directory.

A first look needs no reason and writes the ledger; a later one needs ``--reason``; a look with the
ledger (or anything else) uncommitted is refused by the clean tree; a record added or changed since
the previous look is noted; a record of another registration is not read; the ledger is only ever
appended to; the reading is a registered function, and one that fails writes nothing.

Git is real, in a repository under pytest's ``tmp_path`` (``Checkout`` of
``tests/test_shadow_record_history.py``). The readings are functions of this file. No model, no
container, no network, no database.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from scripts import analyse_shadow, run_shadow
from tests.test_shadow_record_history import (  # noqa: F401 - fixtures
    MARK,
    RECDIR,
    Checkout,
    _git_run,
    co,
    look,
)
from tests.test_shadow_runner_guard import _codes, _subscription_only  # noqa: F401 - fixtures

LEDGER = f"{RECDIR}/{run_shadow.LEDGER_NAME}"
REFUSED = run_shadow.EXIT_STARTUP_REFUSED


def count_reading(records):
    """A reading for the tests: how many records and lines."""
    return f"{len(records)} record(s), {sum(len(r.lines) for r in records)} line(s)"


def failing_reading(records):
    raise RuntimeError(MARK)


def two_lines_reading(records):
    return "one line\nand another"


def writing_reading(records):
    """A reading that tries to change what it was given."""
    records[0].header["registered_commit"] = "changed"
    return "changed"


def _ledger(checkout):
    path = checkout.path / LEDGER
    return path.read_bytes() if path.exists() else None


def _entries(checkout):
    return [json.loads(line) for line in _ledger(checkout).decode().splitlines()]


def _looked(checkout, *args, **kwargs):
    lines = []
    code = look(checkout, *args, out=lines.append, **kwargs)
    return code, lines


@pytest.fixture
def one(co):  # noqa: F811
    """A checkout with one record of the registration, committed."""
    co.record("a.jsonl")
    co.commit_all("record a")
    return co


# == the first look, the second, the third =========================================================


def test_the_first_look_needs_no_reason_and_writes_the_ledger(one, capsys):
    code, lines = _looked(one)
    assert code == run_shadow.EXIT_OK, capsys.readouterr().err
    sha = run_shadow.hashlib.sha256((one.path / RECDIR / "a.jsonl").read_bytes()).hexdigest()
    assert _entries(one) == [{"look": 1, "at": "2026-11-27T01:02:03Z",
                              "records": [{"file": "a.jsonl", "sha256": sha}],
                              "verdict": "1 record(s), 3 line(s)", "reason": None}]
    assert lines[0] == f"look 1 of 1 record(s) of {one.commit[:7]}"
    assert "verdict: 1 record(s), 3 line(s)" in lines and not any("NOTE" in x for x in lines)


def test_a_second_look_without_a_reason_is_refused_and_one_with_a_reason_is_kept(one, capsys):
    assert _looked(one)[0] == run_shadow.EXIT_OK
    one.commit_all("look 1")
    before = _ledger(one)
    for reason in ([], ["--reason", "   "]):
        code, lines = _looked(one, *reason)
        err = capsys.readouterr().err
        assert code == REFUSED and lines == []
        assert _codes(err) == [analyse_shadow.REASON_REQUIRED]
        assert "1 time(s)" in err and "first on 2026-11-27T01:02:03Z" in err
        assert _ledger(one) == before
    code, lines = _looked(one, "--reason", "the window closed")
    assert code == run_shadow.EXIT_OK
    assert [e["look"] for e in _entries(one)] == [1, 2]
    assert _entries(one)[1]["reason"] == "the window closed"
    assert lines[0].endswith("(reason: the window closed)")


def test_a_look_with_the_ledger_uncommitted_is_refused_by_the_clean_tree(one, capsys):
    assert _looked(one)[0] == run_shadow.EXIT_OK
    one.commit_all("look 1")
    assert _looked(one, "--reason", "two")[0] == run_shadow.EXIT_OK      # look 2, not committed
    before = _ledger(one)
    code, lines = _looked(one, "--reason", "three")
    err = capsys.readouterr().err
    assert code == REFUSED and lines == []
    assert _codes(err) == [run_shadow.TREE_NOT_CLEAN] and run_shadow.LEDGER_NAME in err
    assert _ledger(one) == before


def test_an_untracked_file_anywhere_refuses_the_look(one, capsys):
    """D69-SR-G2's test: the clean tree counts untracked files."""
    (one.path / "notes.txt").write_text("not committed\n")
    code, _ = _looked(one)
    assert code == REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.TREE_NOT_CLEAN]
    assert _ledger(one) is None


def test_the_two_looks_ledger_notes_an_added_record_and_leaves_out_another_registration(
        one, capsys):
    code, first = _looked(one)
    assert code == run_shadow.EXIT_OK
    one.commit_all("look 1")
    one.record("b.jsonl")
    one.record("c.jsonl", commit="d" * 40)              # another registration's record
    one.commit_all("record b, and another registration's c")
    code, second = _looked(one, "--reason", "a record was added")
    assert code == run_shadow.EXIT_OK, capsys.readouterr().err
    with capsys.disabled():
        print("\nSTDOUT (look 1)\n" + "\n".join(first))
        print("STDOUT (look 2)\n" + "\n".join(second))
        print(f"LEDGER ({LEDGER})\n" + _ledger(one).decode())
    b = run_shadow.hashlib.sha256((one.path / RECDIR / "b.jsonl").read_bytes()).hexdigest()
    assert "NOTE: the records differ from look 1's:" in second
    assert f"  added: b.jsonl (sha256 {b})" in second
    assert not any("c.jsonl" in line for line in first + second)
    assert [r["file"] for r in _entries(one)[1]["records"]] == ["a.jsonl", "b.jsonl"]
    assert "verdict: 2 record(s), 6 line(s)" in second


def test_the_note_also_lists_a_changed_and_a_missing_record(one):
    """In a checkout, a record changed or gone since the previous look is refused by the history
    check (step b) before the note could show it; the note itself lists both."""
    assert analyse_shadow.changes(
        {"look": 1, "records": [{"file": "a.jsonl", "sha256": "1"}, {"file": "z.jsonl",
                                                                       "sha256": "2"}]},
        [analyse_shadow.ShadowRecord("a.jsonl", "3", {}, ())]) == [
        "NOTE: the records differ from look 1's:", "  changed: a.jsonl (sha256 1 -> 3)",
        "  missing: z.jsonl (sha256 2)"]


def test_no_record_of_the_registration_is_refused(co, capsys):  # noqa: F811
    co.record("c.jsonl", commit="d" * 40)
    co.commit_all("another registration's record")
    assert _looked(co)[0] == REFUSED
    assert _codes(capsys.readouterr().err) == [analyse_shadow.NO_RECORDS]
    assert _ledger(co) is None


def test_a_record_whose_header_names_no_commit_is_refused(one, capsys):
    (one.path / RECDIR / "x.jsonl").write_text("{ not a header\n")
    one.commit_all("a record with no header")
    assert _looked(one)[0] == REFUSED
    assert _codes(capsys.readouterr().err) == [analyse_shadow.RECORD_UNREADABLE]


# == the ledger is only appended to ================================================================


def _commit_ledger(checkout, text):
    (checkout.path / LEDGER).write_text(text)
    checkout.commit_all("the ledger, by hand")


def _entry(number, *, verdict="v"):
    return json.dumps({"look": number, "at": "2026-11-27T00:00:00Z",
                       "records": [{"file": "a.jsonl", "sha256": "0" * 64}], "verdict": verdict,
                       "reason": None if number == 1 else "r"}) + "\n"


def test_a_ledger_rewritten_in_a_commit_is_refused(one, capsys):
    assert _looked(one)[0] == run_shadow.EXIT_OK
    one.commit_all("look 1")
    first = _ledger(one).decode()
    _commit_ledger(one, first.replace('"verdict": "1 record(s), 3 line(s)"', '"verdict": "met"'))
    code, lines = _looked(one, "--reason", "after a rewrite")
    err = capsys.readouterr().err
    assert code == REFUSED and lines == []
    assert _codes(err) == [analyse_shadow.LEDGER_REWRITTEN] and one.head()[:7] in err


def test_a_ledger_changed_on_disk_with_git_told_to_look_away_is_refused(one, capsys):
    assert _looked(one)[0] == run_shadow.EXIT_OK
    one.commit_all("look 1")
    _git_run(one.path, "update-index", "--assume-unchanged", LEDGER)
    (one.path / LEDGER).write_text(_entry(1, verdict="met"))
    code, _ = _looked(one, "--reason", "after a rewrite on disk")
    assert code == REFUSED
    assert _codes(capsys.readouterr().err) == [analyse_shadow.LEDGER_REWRITTEN]


@pytest.mark.parametrize("text,said", [
    (_entry(1) + "not json\n", "line 2 is not a look"),
    (_entry(1) + _entry(3), "line 2 is look 3, not 2"),
    (_entry(2), "line 1 is look 2, not 1"),
    (_entry(1).rstrip("\n"), "its last line is not ended"),
])
def test_a_ledger_that_cannot_be_read_or_skips_a_number_is_corrupt(text, said, one, capsys):
    _commit_ledger(one, text)
    code, lines = _looked(one, "--reason", "any")
    err = capsys.readouterr().err
    assert code == REFUSED and lines == []
    assert _codes(err) == [analyse_shadow.LEDGER_CORRUPT] and said in err
    assert _ledger(one) == text.encode()


# == the reading ===================================================================================


def test_the_product_reading_is_empty_and_every_look_is_refused(one, capsys):
    assert analyse_shadow.REGISTERED_READING is None
    code = analyse_shadow.main(["look"], registration=run_shadow.Registration(
        commit=one.commit, files=None, digests=None), records_root=one.path, git=one.git)
    assert code == REFUSED
    assert set(_codes(capsys.readouterr().err)) == {run_shadow.NOT_REGISTERED,
                                                    analyse_shadow.READING_UNREGISTERED}


@pytest.mark.parametrize("reading", ["", "no-colon", ":f", "m:"])
def test_an_empty_or_malformed_reading_is_refused_before_git(reading, one, capsys):
    one.calls.clear()
    assert _looked(one, reading=reading)[0] == REFUSED
    assert _codes(capsys.readouterr().err) == [analyse_shadow.READING_UNREGISTERED]
    assert one.calls == [] and _ledger(one) is None


@pytest.mark.parametrize("reading", ["failing_reading", "two_lines_reading", "writing_reading",
                                     "no_such_reading"])
def test_a_reading_that_fails_writes_no_ledger(reading, one, capsys):
    code, lines = _looked(one, reading=f"tests.test_shadow_ledger:{reading}")
    err = capsys.readouterr().err
    assert code == REFUSED and lines == []
    assert _codes(err) == [analyse_shadow.READING_FAILED] and MARK not in err
    assert _ledger(one) is None


def test_a_reading_that_fails_after_a_look_leaves_the_ledger_as_it_was(one, capsys):
    assert _looked(one)[0] == run_shadow.EXIT_OK
    one.commit_all("look 1")
    before = _ledger(one)
    code, _ = _looked(one, "--reason", "r", reading="tests.test_shadow_ledger:failing_reading")
    assert code == REFUSED and _ledger(one) == before
    assert _codes(capsys.readouterr().err) == [analyse_shadow.READING_FAILED]


def test_a_ledger_that_cannot_be_written_shows_no_result(one, monkeypatch, capsys):
    real_open = analyse_shadow.Path.open

    def no_append(self, mode="r", *args, **kwargs):
        if self.name == run_shadow.LEDGER_NAME and "a" in mode:
            raise PermissionError("read-only")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(analyse_shadow.Path, "open", no_append)
    code, lines = _looked(one)
    assert code == REFUSED and lines == []
    assert _codes(capsys.readouterr().err) == [analyse_shadow.LEDGER_UNWRITABLE]


def test_the_ledger_history_git_cannot_answer_is_refused(one, capsys):
    def git(repo, *args):
        if args[0] == "log" and "--format=%H %P" in args:
            return subprocess.CompletedProcess(args, 128, b"", b"fatal")
        return one.git(repo, *args)

    assert _looked(one, git=git)[0] == REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.GIT_UNAVAILABLE]


def test_the_analysis_runs_only_git():
    """No database, no network, no model: the script imports none of their clients and runs no
    process but git."""
    source = (run_shadow.REPO_ROOT / "scripts" / "analyse_shadow.py").read_text()
    for name in ("sqlalchemy", "psycopg", "engagement_scope", "urllib", "requests", "socket",
                 "http", "subprocess", "claude"):
        assert f"import {name}" not in source and f"from {name}" not in source, name
