"""A mutation sweep that is stopped, or killed, puts back what it changed (ACCEPTANCE 5.102).

``scripts/mutation_check.py`` edits source files and, for some mutations, the database. On
2026-10-14 a sweep was interrupted while a migration round-trip test was running; the test was
killed in the middle, and a scratch schema and the database's ``TEMPORARY`` grant to PUBLIC were
left (the next full run found the grant gone -- by luck -- and the schema had to be dropped by
hand). Each way that can happen is made to happen here, and the runner and the session-end check
(``tests/db_hygiene.py``, ``tests/residue.py``) are shown to see and put right what is left.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from scripts import mutation_check as mc
from tests import db_hygiene, residue


@pytest.fixture
def owner(db_available):
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    yield engine
    engine.dispose()


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """A repository root of its own, so a journal and 'source files' can be written freely."""
    monkeypatch.setattr(mc, "ROOT", tmp_path)
    monkeypatch.setattr(mc, "JOURNAL", tmp_path / ".mutation-journal.json")
    return tmp_path


def _database(engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("SELECT quote_ident(current_database())")).scalar_one()


@pytest.fixture
def temporary_is_put_back(owner):
    """Whatever a test does to the ``TEMPORARY`` grant, the database ends as the migrations leave it
    (revoked) -- a failing test must not be the thing this module is about."""
    yield
    with owner.begin() as conn:
        conn.execute(text(f"REVOKE TEMPORARY ON DATABASE {_database(owner)} FROM PUBLIC"))


@pytest.fixture
def scratch_schema(owner):
    name = f"{db_hygiene.SCRATCH_PREFIX}{uuid.uuid4().hex[:8]}"
    yield name
    with owner.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{name}" CASCADE'))


# --- the database state a killed round trip leaves ---------------------------------------------

def test_a_scratch_schema_of_a_round_trip_is_a_problem(owner, scratch_schema):
    with owner.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{scratch_schema}"'))
    with owner.connect() as conn:
        assert scratch_schema in db_hygiene.scratch_schemas(conn)
    assert any(scratch_schema in line for line in db_hygiene.current_problems())


def test_temporary_held_by_public_is_a_problem_once_0023_is_applied(
        owner, temporary_is_put_back):
    with owner.connect() as conn:
        assert db_hygiene.migration_number(conn) >= db_hygiene.REVOKES_TEMPORARY_FROM
        assert not db_hygiene.public_holds_temporary(conn)
        assert db_hygiene.problems(conn) == []
    with owner.begin() as conn:
        conn.execute(text(f"GRANT TEMPORARY ON DATABASE {_database(owner)} TO PUBLIC"))
    with owner.connect() as conn:
        assert db_hygiene.public_holds_temporary(conn)
    assert any("TEMPORARY" in line for line in db_hygiene.current_problems())


def test_the_session_end_check_fails_the_run_on_either(owner, scratch_schema,
                                                       temporary_is_put_back):
    before = residue.snapshot()
    assert residue.leftovers(before).database == []
    with owner.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{scratch_schema}"'))
        conn.execute(text(f"GRANT TEMPORARY ON DATABASE {_database(owner)} TO PUBLIC"))
    found = residue.leftovers(before)
    failures = " | ".join(found.failures())
    assert scratch_schema in failures and "TEMPORARY" in failures, failures


def test_the_runner_drops_the_schema_and_revokes_the_grant_and_says_so(
        owner, scratch_schema, temporary_is_put_back):
    with owner.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{scratch_schema}"'))
        conn.execute(text(f"GRANT TEMPORARY ON DATABASE {_database(owner)} TO PUBLIC"))
    # (the superuser path of the runner is `su postgres`; the owner can do the same here)
    original = mc._superuser_sql
    mc._superuser_sql = lambda statement: mc._owner_sql(statement.replace(" cyberorch ", " "
                                                        f"{_database(owner)} "))
    try:
        said = mc.hygiene()
    finally:
        mc._superuser_sql = original
    assert any(line.startswith("CLEANED") and scratch_schema in line for line in said), said
    assert any(line.startswith("CLEANED") and "TEMPORARY" in line for line in said), said
    assert not any(line.startswith("STILL WRONG") for line in said), said
    assert db_hygiene.current_problems() == []
    assert mc.hygiene() == []                         # and nothing to say the second time


# --- the journal -------------------------------------------------------------------------------

def test_a_killed_run_s_files_are_put_back_at_the_next_start(sandbox):
    source = sandbox / "pkg" / "code.py"
    source.parent.mkdir()
    source.write_bytes(b"original = 1\n")
    mc._journal_write({source: b"original = 1\n"}, (), (), False)
    source.write_bytes(b"original = 2  # the mutation\n")        # the run dies here
    said = mc.recover()
    assert source.read_bytes() == b"original = 1\n"
    assert any("RECOVERED pkg/code.py" in line for line in said), said
    assert not mc.JOURNAL.exists()
    assert mc.recover() == []                                    # nothing the second time


def test_a_file_that_is_already_right_is_not_touched_and_not_reported(sandbox):
    source = sandbox / "code.py"
    source.write_bytes(b"x = 1\n")
    mc._journal_write({source: b"x = 1\n"}, (), (), False)
    assert mc.recover() == []
    assert not mc.JOURNAL.exists()


def test_the_database_change_of_a_killed_run_is_undone_once(sandbox, monkeypatch):
    ran = []
    monkeypatch.setattr(mc, "_owner_sql", lambda *statements: ran.extend(statements))
    monkeypatch.setattr(mc, "_superuser_sql", lambda statement: ran.append(("su", statement)))
    mc._journal_write({}, ("DROP TRIGGER mutated", "SELECT 2"), ("DELETE FROM t",), True)
    said = mc.recover()
    assert ran == [("su", "DELETE FROM t"), "DROP TRIGGER mutated", "SELECT 2"]
    assert any("database change" in line for line in said), said
    assert mc.recover() == [] and len(ran) == 3


def test_a_change_that_was_never_applied_is_not_undone(sandbox, monkeypatch):
    ran = []
    monkeypatch.setattr(mc, "_owner_sql", lambda *statements: ran.extend(statements))
    mc._journal_write({}, ("DROP TRIGGER mutated",), (), False)   # killed before the SQL went in
    mc.recover()
    assert ran == []


def test_when_the_database_cannot_be_put_back_the_journal_stays_and_it_is_said(
        sandbox, monkeypatch):
    def broken(*statements):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(mc, "_owner_sql", broken)
    mc._journal_write({}, ("DROP TRIGGER mutated",), (), True)
    said = mc.recover()
    assert any("FAILED" in line and "connection refused" in line for line in said), said
    assert mc.JOURNAL.exists()                                     # nothing is lost


def test_the_journal_is_written_whole_or_not_at_all(sandbox):
    a = sandbox / "a.py"
    a.write_bytes(b"\x00\xff binary \n")
    mc._journal_write({a: a.read_bytes()}, ("X",), ("Y",), True)
    payload = json.loads(mc.JOURNAL.read_text())
    assert set(payload) == {"files", "sql_down", "cleanup_sql"}
    assert payload["sql_down"] == ["X"] and payload["cleanup_sql"] == ["Y"]
    assert not list(sandbox.glob("*.tmp"))                         # the temp file was renamed


def test_the_journal_is_never_committed():
    ignored = subprocess.run(["git", "check-ignore", ".mutation-journal.json"],
                             cwd=mc.ROOT, capture_output=True, text=True)
    assert ignored.returncode == 0


# --- the interrupt -----------------------------------------------------------------------------

_CHILD = textwrap.dedent("""
    import signal, sys, time
    marker = sys.argv[1]
    if sys.argv[2] == "polite":
        def stop(signum, frame):
            open(marker, "w").write("teardown ran")
            sys.exit(2)
        signal.signal(signal.SIGINT, stop)
    else:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    open(marker + ".pid", "w").write(str(__import__("os").getpid()))
    time.sleep(30)
""")


def _interrupt_in(seconds: float):
    def raise_it(signum, frame):
        raise KeyboardInterrupt
    old = signal.signal(signal.SIGALRM, raise_it)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    return old


def _forget(pid: int) -> None:
    """A test must not leave the process it started, whatever the code under test did."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_and_interrupt(tmp_path: Path, mode: str, stop_wait_s: float):
    marker = tmp_path / "marker"
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    raised: BaseException | None = None
    old = _interrupt_in(1.5)
    try:
        try:
            mc._run_group([sys.executable, str(script), str(marker), mode],
                          stop_wait_s=stop_wait_s)
        except BaseException as exc:  # noqa: BLE001 -- what comes out is what is asserted
            raised = exc
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    pid = int((tmp_path / "marker.pid").read_text())
    return marker, pid, raised


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return not Path(f"/proc/{pid}/stat").read_text().split(") ")[1].startswith("Z")


def test_an_interrupted_test_run_is_asked_to_stop_so_its_fixtures_run(tmp_path):
    marker, pid, raised = _run_and_interrupt(tmp_path, "polite", stop_wait_s=20)
    try:
        assert isinstance(raised, KeyboardInterrupt), raised   # and the interrupt goes on
        assert marker.exists(), "SIGINT did not reach the test run: its teardown did not run"
        assert marker.read_text() == "teardown ran"
        assert not _alive(pid)
    finally:
        _forget(pid)


def test_one_that_does_not_stop_is_killed_after_the_wait_and_the_interrupt_still_propagates(
        tmp_path):
    started = time.monotonic()
    marker, pid, raised = _run_and_interrupt(tmp_path, "stubborn", stop_wait_s=1)
    try:
        assert isinstance(raised, KeyboardInterrupt), raised
        assert not marker.exists()
        assert not _alive(pid), "a test run that ignored SIGINT was left running"
        assert time.monotonic() - started < 20
    finally:
        _forget(pid)


def test_a_run_that_ends_normally_returns_its_output(tmp_path):
    done = mc._run_group([sys.executable, "-c", "print('out'); import sys; "
                          "print('err', file=sys.stderr); sys.exit(3)"])
    assert (done.returncode, done.stdout.strip(), done.stderr.strip()) == (3, "out", "err")


def test_the_children_of_the_test_run_are_in_the_group_that_is_stopped(tmp_path):
    """pytest starts helpers (the sandbox, the services); a stopped run must not leave them."""
    grandchild = tmp_path / "grandchild.pid"
    code = ("import subprocess, sys, time; "
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']); "
            f"open({str(grandchild)!r}, 'w').write(str(p.pid)); time.sleep(30)")
    raised: BaseException | None = None
    old = _interrupt_in(1.5)
    try:
        try:
            mc._run_group([sys.executable, "-c", code], stop_wait_s=1)
        except BaseException as exc:  # noqa: BLE001
            raised = exc
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    pid = int(grandchild.read_text())
    try:
        time.sleep(0.5)
        assert isinstance(raised, KeyboardInterrupt), raised
        assert not _alive(pid), "a helper of the stopped test run was left running"
    finally:
        _forget(pid)


# --- the run of one mutation ---------------------------------------------------------------------

GREEN = ("<testsuites><testsuite><testcase classname='tests.t' name='test_x'/></testsuite>"
         "</testsuites>")
RED = ("<testsuites><testsuite><testcase classname='tests.t' name='test_x'>"
       "<failure message='assert 1 == 2'/></testcase></testsuite></testsuites>")


@pytest.fixture
def one_mutation(sandbox, monkeypatch, db_available):
    monkeypatch.setattr(sys, "path", list(sys.path))
    source = sandbox / "pkg" / "code.py"
    source.parent.mkdir()
    source.write_bytes(b"VALUE = 1\n")
    mutation = mc.Mutation("T-1", "VALUE is changed", ("tests/t.py",),
                           edits=(mc.Edit("pkg/code.py", "VALUE = 1", "VALUE = 2"),),
                           targets=("test_x",))
    return source, mutation


def test_the_journal_exists_and_the_file_is_changed_while_the_tests_run_and_both_are_undone(
        one_mutation, monkeypatch):
    source, mutation = one_mutation
    seen = []

    def fake(tests, env=None):
        mutated = source.read_bytes() != b"VALUE = 1\n"
        seen.append((mutated, mc.JOURNAL.exists()))
        return mc.ET.fromstring(RED if mutated else GREEN), 0

    monkeypatch.setattr(mc, "_pytest", fake)
    result = mc.run(mutation, {})
    assert seen == [(False, False), (True, True)]      # the journal is written before the edit
    assert result.verdict == "valid", result.problems
    assert source.read_bytes() == b"VALUE = 1\n" and not mc.JOURNAL.exists()


def test_the_journal_is_on_disk_before_the_first_byte_of_a_file_is_changed(
        one_mutation, monkeypatch):
    source, mutation = one_mutation
    at_write = []
    real = mc.Path.write_text

    def watching(self, data, *args, **kwargs):
        if self == source:
            at_write.append(mc.JOURNAL.exists() and "VALUE = 1" in
                            __import__("base64").b64decode(
                                json.loads(mc.JOURNAL.read_text())["files"]["pkg/code.py"]).decode())
        return real(self, data, *args, **kwargs)

    monkeypatch.setattr(mc.Path, "write_text", watching)
    monkeypatch.setattr(mc, "_pytest", lambda tests, env=None: (
        mc.ET.fromstring(RED if source.read_bytes() != b"VALUE = 1\n" else GREEN), 0))
    mc.run(mutation, {})
    assert at_write == [True]


def test_a_run_killed_while_the_tests_run_is_put_back_from_the_journal_alone(
        one_mutation, monkeypatch):
    """What ``kill -9`` leaves is the mutated file and the journal; the next start's ``recover``
    must be enough. (The fake test run calls ``recover`` at the moment a ``kill -9`` would have
    stopped everything: the mutated file in place, the journal on disk, no ``finally`` run yet.)"""
    source, mutation = one_mutation
    state = {}

    def fake(tests, env=None):
        if source.read_bytes() == b"VALUE = 1\n":
            return mc.ET.fromstring(GREEN), 0
        state["after_kill"] = (source.read_bytes(), mc.JOURNAL.exists())
        state["recovered"] = mc.recover()
        state["after_recover"] = (source.read_bytes(), mc.JOURNAL.exists())
        return mc.ET.fromstring(RED), 0

    monkeypatch.setattr(mc, "_pytest", fake)
    mc.run(mutation, {})
    assert state["after_kill"] == (b"VALUE = 2\n", True)
    assert state["after_recover"] == (b"VALUE = 1\n", False)
    assert any("RECOVERED pkg/code.py" in line for line in state["recovered"])


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_an_interrupt_while_the_tests_run_puts_the_file_back_and_still_propagates(
        one_mutation, monkeypatch, interrupt):
    source, mutation = one_mutation

    def fake(tests, env=None):
        if source.read_bytes() == b"VALUE = 1\n":
            return mc.ET.fromstring(GREEN), 0
        raise interrupt

    monkeypatch.setattr(mc, "_pytest", fake)
    with pytest.raises(interrupt):
        mc.run(mutation, {})
    assert source.read_bytes() == b"VALUE = 1\n" and not mc.JOURNAL.exists()


def test_a_restore_that_fails_keeps_the_journal_and_makes_the_mutation_invalid(
        one_mutation, monkeypatch):
    source, mutation = one_mutation
    mutation.sql_up, mutation.sql_down = ("SELECT 1",), ("SELECT 2",)
    calls = []

    def owner_sql(*statements):
        calls.append(statements)
        if statements == ("SELECT 2",):
            raise RuntimeError("database went away")

    monkeypatch.setattr(mc, "_owner_sql", owner_sql)
    monkeypatch.setattr(mc, "_pytest", lambda tests, env=None: (
        mc.ET.fromstring(RED if source.read_bytes() != b"VALUE = 1\n" else GREEN), 0))
    result = mc.run(mutation, {})
    assert result.verdict == "INVALID"
    assert any("RESTORE FAILED" in p for p in result.problems), result.problems
    assert mc.JOURNAL.exists()                         # the next start undoes it
    assert source.read_bytes() == b"VALUE = 1\n"


def test_a_mutation_that_leaves_a_scratch_schema_behind_is_not_valid_and_is_cleaned(
        one_mutation, monkeypatch, owner, scratch_schema):
    source, mutation = one_mutation

    def fake(tests, env=None):
        if source.read_bytes() != b"VALUE = 1\n":
            with owner.begin() as conn:                # the test that was killed in the middle
                conn.execute(text(f'CREATE SCHEMA "{scratch_schema}"'))
            return mc.ET.fromstring(RED), 0
        return mc.ET.fromstring(GREEN), 0

    monkeypatch.setattr(mc, "_pytest", fake)
    result = mc.run(mutation, {})
    assert result.verdict == "INVALID"
    assert any(line.startswith("CLEANED") and scratch_schema in line
               for line in result.problems), result.problems
    assert db_hygiene.current_problems() == []
