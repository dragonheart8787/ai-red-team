"""S6 (shadow runner plan 2g, 2b; plan item 156): the records directory is inside the repository,
not ignored by git, and no committed record in it is deleted, renamed or modified after the
registered commit; ``scripts/run_shadow.py`` (step 2a) and ``scripts/analyse_shadow.py`` (step b)
both refuse otherwise.

Git is real: a repository under pytest's ``tmp_path`` (``Checkout``), its registered commit holding
a copy of the compliant roles' module, which is the registered file. The code under test is handed
``repo=`` the project's own checkout -- the role classes' module is read from there, and its bytes
are the copy's -- and a git function that runs git in the temporary repository, whose root is the
records root. No model, no container, no network; the database is not read (a start that passes is
stopped at the hand-over by the ``through`` spy).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import analyse_shadow, run_shadow
from tests.test_shadow_runner_guard import (  # noqa: F401 - fixtures
    ROOT,
    SUPPORT,
    _argv,
    _codes,
    _Git,
    _Lock,
    _registration,
    _subscription_only,
    through,
)

RECDIR = "docs/D69_SHADOW_RECORDS"
CLEAN = {"PATH": "/usr/bin:/bin", "HOME": "/home/shadow"}
#: A value written in every record; no refusal may print it (a refusal names files, not content).
MARK = "RECORD-CONTENT-5b2e"
READING = "tests.test_shadow_record_history:count_reading"


def count_reading(records):
    """A reading for the tests: how many records and lines."""
    return f"{len(records)} record(s), {sum(len(r.lines) for r in records)} line(s)"


def _git_run(path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=path,
                          capture_output=True, timeout=30, check=True)


class Checkout:
    """A git repository under ``tmp_path``: the registered commit, then whatever a test commits."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir()
        _git_run(path, "init", "-q", "-b", "main")
        _git_run(path, "config", "user.email", "shadow@test.invalid")
        _git_run(path, "config", "user.name", "Shadow Test")
        (path / SUPPORT).parent.mkdir(parents=True)
        shutil.copyfile(ROOT / SUPPORT, path / SUPPORT)
        (path / RECDIR).mkdir(parents=True)
        self.commit = self.commit_all("the registered commit")
        self.calls: list[tuple[str, ...]] = []

    def commit_all(self, message: str) -> str:
        _git_run(self.path, "add", "-A")
        _git_run(self.path, "commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def head(self, short: bool = False) -> str:
        args = ("rev-parse", "--short", "HEAD") if short else ("rev-parse", "HEAD")
        return _git_run(self.path, *args).stdout.decode().strip()

    def git(self, _repo, *args):
        """The git the code under test is handed: real git, in this repository."""
        self.calls.append(args)
        return run_shadow._git(self.path, *args)

    def record(self, name: str, *, commit: str | None = None, code: int = 0) -> Path:
        """A record of a run that ended normally (no acknowledgement needed)."""
        lines = [{"line": "header", "registered_commit": commit or self.commit, "note": MARK,
                  "run": name},
                 {"line": "round", "round": 1}, {"line": "footer", "exit_code": code}]
        path = self.path / RECDIR / name
        path.write_text("".join(json.dumps(x) + "\n" for x in lines))
        return path


@pytest.fixture
def co(tmp_path):
    return Checkout(tmp_path / "repo")


def _reg(co, **override):
    return _registration(commit=co.commit, records_dir=RECDIR, **override)


def start(co, record="run.jsonl", git=None, **override):
    lock = _Lock(True)
    code = run_shadow.main(_argv(record=co.path / RECDIR / record),
                           registration=_reg(co, **override), git=git or co.git, lock=lock,
                           environ=CLEAN, settings_files=(), records_root=co.path)
    return code, lock


def look(co, *args, git=None, reading=READING, out=None):
    return analyse_shadow.main(["look", *args], registration=_reg(co), reading=reading,
                               records_root=co.path, git=git or co.git,
                               out=(out if out is not None else (lambda line: None)),
                               now=lambda: "2026-11-27T01:02:03Z")


# == the records directory: inside the repository, relative to it (step 1) =========================


@pytest.mark.parametrize("name,why", [
    ("/abs/records", "is an absolute path"),
    ("docs/../../records", "contains '..'"),
    (".", "names the repository itself"),
    ("link/records", "resolves outside the repository"),
])
def test_a_records_dir_that_is_not_inside_the_repository_is_refused_at_step_1(
        name, why, tmp_path, through, capsys):  # noqa: F811
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "elsewhere").mkdir()
    (root / "link").symlink_to(tmp_path / "elsewhere")
    git, lock = _Git(), _Lock(True)
    code = run_shadow.main(_argv(record=root / "x.jsonl"),
                           registration=_registration(records_dir=name), git=git, lock=lock,
                           records_root=root)
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.RECORDS_DIR_OUTSIDE_REPOSITORY] and why in err
    assert git.calls == [] and lock.asked == 0 and through == []


def test_the_suggested_records_dir_is_inside_the_repository():
    assert run_shadow.records_dir_outside(RECDIR, ROOT) is None
    assert run_shadow.REGISTERED_RECORDS_DIR is None        # nothing is registered


# == the records directory: not ignored by git (step 2a) ===========================================


@pytest.mark.parametrize("rule,present,look_code", [
    ("docs/D69_SHADOW_RECORDS/", None, 10),      # the directory
    ("*.jsonl", None, 10),                       # every record
    ("looks.jsonl", None, 10),                   # the ledger alone
    ("run.jsonl", None, 0),                      # the new record's name: the start's alone
    ("old-*.jsonl", "old-1.jsonl", 10),          # a record already there, which git does not see
])
def test_a_records_dir_git_ignores_is_refused_by_the_start_and_by_the_look(
        rule, present, look_code, co, through, capsys):  # noqa: F811
    (co.path / ".gitignore").write_text(rule + "\n")
    co.record("a.jsonl")
    co.commit_all("an ignore rule and a record")
    if present:
        co.record(present)
    code, lock = start(co)
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert set(_codes(err)) == {run_shadow.RECORDS_DIR_IGNORED}, err
    assert lock.asked == 0 and through == [] and MARK not in err
    assert look(co) == look_code
    assert set(_codes(capsys.readouterr().err)) == (
        {run_shadow.RECORDS_DIR_IGNORED} if look_code else set())


def test_an_exclude_rule_outside_gitignore_is_seen_too(co, through, capsys):  # noqa: F811
    (co.path / ".git" / "info" / "exclude").write_text("docs/D69_SHADOW_RECORDS/\n")
    code, _ = start(co)
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert set(_codes(capsys.readouterr().err)) == {run_shadow.RECORDS_DIR_IGNORED}


def test_the_ledger_s_name_is_not_a_record(co, through, capsys):  # noqa: F811
    code, lock = start(co, record=run_shadow.LEDGER_NAME)
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.RECORD_OUTSIDE_REGISTERED_DIR] and "ledger" in err
    assert lock.asked == 0 and not (co.path / RECDIR / run_shadow.LEDGER_NAME).exists()


# == the history of the records: deleted, renamed, modified (step 2a, step b) ======================


def _delete(co):
    _git_run(co.path, "rm", "-q", f"{RECDIR}/a.jsonl")


def _rename(co):
    _git_run(co.path, "mv", f"{RECDIR}/a.jsonl", f"{RECDIR}/b.jsonl")


def _rename_with_renames_off(co):
    _git_run(co.path, "config", "diff.renames", "false")
    _rename(co)


def _modify(co):
    with (co.path / RECDIR / "a.jsonl").open("a") as handle:
        handle.write(json.dumps({"line": "round", "round": 2}) + "\n")


@pytest.mark.parametrize("change,code,said", [
    (_delete, run_shadow.RECORD_REMOVED, "was deleted in commit"),
    (_rename, run_shadow.RECORD_REMOVED, f"was renamed to {RECDIR}/b.jsonl in commit"),
    (_rename_with_renames_off, run_shadow.RECORD_REMOVED, "was renamed to"),
    (_modify, run_shadow.RECORD_MODIFIED, "was modified in commit"),
])
def test_a_committed_record_changed_by_a_later_commit_refuses_the_next_start_and_look(
        change, code, said, co, through, capsys):  # noqa: F811
    co.record("a.jsonl")
    co.commit_all("a record, committed after its run")
    change(co)
    co.commit_all("a later commit")
    short = co.head(short=True)
    started, lock = start(co)
    err = capsys.readouterr().err
    with capsys.disabled():
        print(f"\nSTDERR (start, {change.__name__})\n{err}")
    assert started == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [code]
    assert f"{RECDIR}/a.jsonl {said}" in err and short in err and MARK not in err
    assert lock.asked == 0 and through == [] and not (co.path / RECDIR / "run.jsonl").exists()
    assert look(co) == run_shadow.EXIT_STARTUP_REFUSED
    err = capsys.readouterr().err
    with capsys.disabled():
        print(f"STDERR (look, {change.__name__})\n{err}")
    assert _codes(err) == [code] and short in err and MARK not in err
    assert not (co.path / RECDIR / run_shadow.LEDGER_NAME).exists()


def test_records_no_commit_touched_let_the_start_and_the_look_through(co, through, capsys):  # noqa: F811
    co.record("a.jsonl")
    co.commit_all("a record")
    co.record("b.jsonl")
    co.commit_all("another record")
    assert look(co) == run_shadow.EXIT_OK
    co.commit_all("the look, committed")
    code, lock = start(co)
    assert lock.asked == 1 and len(through) == 1          # through every check, to the hand-over
    assert any(args[0] == "log" for args in co.calls)


def test_the_ledger_appended_to_and_committed_is_not_a_modified_record(co, through, capsys):  # noqa: F811
    co.record("a.jsonl")
    co.commit_all("a record")
    assert look(co) == run_shadow.EXIT_OK
    co.commit_all("look 1")
    assert look(co, "--reason", "a second look, for the test") == run_shadow.EXIT_OK
    co.commit_all("look 2: the ledger modified, by appending")
    code, lock = start(co)
    assert lock.asked == 1 and len(through) == 1          # through every check, to the hand-over


def test_a_deleted_ledger_is_a_removed_record(co, through, capsys):  # noqa: F811
    co.record("a.jsonl")
    co.commit_all("a record")
    assert look(co) == run_shadow.EXIT_OK
    co.commit_all("look 1")
    _git_run(co.path, "rm", "-q", f"{RECDIR}/{run_shadow.LEDGER_NAME}")
    co.commit_all("the ledger deleted")
    code, _ = start(co)
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.RECORD_REMOVED] and run_shadow.LEDGER_NAME in err


class _NoLog:
    """The checkout's git, except that ``log`` cannot answer: raising, or failing."""

    def __init__(self, co, *, raises):
        self.co, self.raises = co, raises

    def __call__(self, repo, *args):
        if args[0] == "log":
            if self.raises:
                raise OSError("git cannot be run")
            return subprocess.CompletedProcess(args, 128, b"", b"fatal")
        return self.co.git(repo, *args)


@pytest.mark.parametrize("raises", [True, False])
def test_a_history_git_cannot_answer_refuses_the_start_and_the_look(
        raises, co, through, capsys):  # noqa: F811
    co.record("a.jsonl")
    co.commit_all("a record")
    code, lock = start(co, git=_NoLog(co, raises=raises))
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.GIT_UNAVAILABLE] and lock.asked == 0 and through == []
    assert look(co, git=_NoLog(co, raises=raises)) == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.GIT_UNAVAILABLE]


def test_a_history_answer_that_cannot_be_read_is_refused(co):
    def git(repo, *args):
        return subprocess.CompletedProcess(args, 0, b"commit abc1234\nnot a status line\n", b"")
    assert run_shadow.record_history_problems(co.path, RECDIR, co.commit, git) == [
        (run_shadow.GIT_UNAVAILABLE, f"git's history of {RECDIR} cannot be read")]


def test_a_record_written_and_not_committed_is_refused_by_the_integrity_guard(
        co, through, capsys):  # noqa: F811
    """No new code: the clean tree of step 2 counts untracked files (plan item 156 (a))."""
    co.record("a.jsonl")                                 # a run's record, not committed
    code, lock = start(co)
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.TREE_NOT_CLEAN] and "a.jsonl" in err
    assert lock.asked == 0 and through == []


def test_a_change_before_the_registered_commit_is_not_in_the_range(tmp_path, through, capsys):  # noqa: F811
    """The history is read from the registered commit on: a record deleted before it is not seen
    (plan item 157's known limit)."""
    co = Checkout(tmp_path / "repo")
    co.record("old.jsonl")
    co.commit_all("an old record")
    _git_run(co.path, "rm", "-q", f"{RECDIR}/old.jsonl")
    co.commit = co.commit_all("deleted, then registered")
    (co.path / RECDIR).mkdir(parents=True, exist_ok=True)    # git keeps no empty directory
    code, lock = start(co)
    assert lock.asked == 1 and len(through) == 1
