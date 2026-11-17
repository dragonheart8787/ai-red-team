"""D69 H5c2 (C): the entry script (``scripts/run_harness.py``), run in this process with its lock
and its signal registration handed in, against the test database and scripted roles.

Every bound is required and has no default; the script builds no real role; the banner is printed
before the loop starts; the handlers are installed through ``harness.signals.install``; the exit
status is the loop's, except that a lost lock is 6.
"""

from __future__ import annotations

import ast
import signal
from pathlib import Path

import pytest

from harness.banner import REQUIRED_FIELDS
from harness.exit_codes import EXIT_CAP_REACHED, EXIT_OK, EXIT_STARTUP_REFUSED, EXIT_UNEXPECTED
from harness.lock import HarnessLock
from scripts import run_harness
from tests.test_harness_h5c1_support import make_world, proposal_rows, queued_task, task_rows
from tests.test_harness_h5c2_support import enrolled

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_OPTIONS = ("--role-factory", "--objective", "--window-limit", "--max-rounds",
                    "--max-model-calls", "--no-progress-limit", "--live-task-limit")


@pytest.fixture
def world(engagement_id, registry, monkeypatch):
    made = make_world(engagement_id, registry)
    monkeypatch.setenv("H5C2_SCOPE_ID", made.scope_id)
    return made


def _argv(**override) -> list[str]:
    args = {"--role-factory": "tests.harness_h5c2_roles:build", "--objective": "o",
            "--window-limit": "25", "--max-rounds": "1", "--max-model-calls": "100",
            "--no-progress-limit": "5", "--live-task-limit": "200", **override}
    return ["run", *(part for pair in args.items() if pair[1] is not None for part in pair)]


class _NoLock:
    """A lock that must not be touched: used where the arguments are refused first. If it is, it
    says it is held elsewhere, so that the run ends with code 2 instead of the usage error the
    test expects."""

    def acquire(self):
        return False


def _run(argv, **kwargs):
    kwargs.setdefault("lock", HarnessLock())
    kwargs.setdefault("register", lambda *a: None)
    return run_harness.main(argv, **kwargs)


# -- the bounds are required ------------------------------------------------------------------


def test_every_bound_is_required_and_has_no_default():
    parser = run_harness.build_parser()
    run = next(a for a in parser._actions if a.dest == "command").choices["run"]
    options = {o: a for a in run._actions for o in a.option_strings}
    for name in REQUIRED_OPTIONS:
        assert options[name].required is True, name
        assert options[name].default is None, name
    residue = next(a for a in parser._actions if a.dest == "command").choices["residue"]
    limit = next(a for a in residue._actions if a.option_strings == ["--live-task-limit"])
    assert limit.required is True and limit.default is None
    assert options["--once"].default is False


@pytest.mark.parametrize("missing", REQUIRED_OPTIONS)
def test_an_argument_that_is_left_out_is_a_usage_error_before_the_lock_is_taken(
        missing, capsys):
    argv = _argv(**{missing: None})
    with pytest.raises(SystemExit) as caught:
        run_harness.main(argv, lock=_NoLock(), register=lambda *a: None)
    assert caught.value.code == 2
    assert missing in capsys.readouterr().err


@pytest.mark.parametrize("name", ["--window-limit", "--max-rounds", "--max-model-calls",
                                  "--no-progress-limit", "--live-task-limit"])
@pytest.mark.parametrize("bad", ["0", "-1", "x", "1.5"])
def test_a_bound_that_is_not_a_positive_integer_is_refused_before_the_lock(name, bad):
    with pytest.raises(SystemExit) as caught:
        run_harness.main(_argv(**{name: bad}), lock=_NoLock(), register=lambda *a: None)
    assert caught.value.code == 2


def test_the_script_builds_no_real_role_and_no_real_sandbox():
    tree = ast.parse((ROOT / "scripts" / "run_harness.py").read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert not roots & {"agents", "tool_gateway", "anthropic", "openai", "docker", "requests"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"DockerSandbox", "LocalReviewer", "AnthropicWorker", "AnthropicSupervisor"}


# -- a run ------------------------------------------------------------------------------------


def test_a_run_with_once_exits_0_after_one_round_and_prints_the_banner(world, capsys):
    with enrolled(world.engagement_id):
        code = _run(_argv() + ["--once"])

    out = capsys.readouterr()
    assert code == EXIT_OK == 0
    assert [line.split(":", 1)[0] for line in out.out.splitlines()] == list(REQUIRED_FIELDS)
    assert f"engagements: {world.engagement_id}" in out.out
    assert "lock_key: 0x0D69_5C4E_D000_0001" in out.out
    assert "harness stopped (exit 0)" in out.err
    # the scripted Supervisor planned three tasks and each went through the pipeline (denied here)
    assert [row[1] for row in task_rows(world.engagement_id)] == ["completed"] * 3
    assert len(proposal_rows(world.engagement_id)) == 3


def test_a_run_without_once_stops_at_its_round_cap_with_code_13(world, capsys):
    with enrolled(world.engagement_id):
        code = _run(_argv())
    assert code == EXIT_CAP_REACHED == 13
    assert "reason=cap_reached" in capsys.readouterr().err


def test_the_banner_is_printed_before_the_loop_starts(world, capsys, monkeypatch):
    seen = []
    real = run_harness.run_loop

    def watching(*args, **kwargs):
        seen.append(capsys.readouterr().out)
        return real(*args, **kwargs)

    monkeypatch.setattr(run_harness, "run_loop", watching)
    with enrolled(world.engagement_id):
        _run(_argv())
    (before_the_loop,) = seen
    assert len(before_the_loop.splitlines()) == len(REQUIRED_FIELDS)


def test_the_handlers_of_sigint_and_sigterm_are_installed_and_set_the_flag(world, monkeypatch):
    registered, flags = [], []

    class Flag(run_harness.SignalFlag):
        def __init__(self):
            super().__init__()
            flags.append(self)

    monkeypatch.setattr(run_harness, "SignalFlag", Flag)
    with enrolled(world.engagement_id):
        _run(_argv(), register=lambda number, handler: registered.append((number, handler)))

    assert {number for number, _ in registered} == {signal.SIGINT, signal.SIGTERM}
    (flag,) = flags
    assert flag.is_set() is False
    registered[0][1](signal.SIGTERM, None)                 # what the kernel's call does
    assert flag.is_set() is True


def test_an_engagement_that_holds_a_live_task_is_refused_with_code_10_and_nothing_changes(
        world, capsys):
    queued_task(world, 40)
    before = task_rows(world.engagement_id)
    with enrolled(world.engagement_id):
        code = _run(_argv())
    assert code == EXIT_STARTUP_REFUSED == 10
    assert task_rows(world.engagement_id) == before
    assert proposal_rows(world.engagement_id) == []


def test_no_enrolled_engagement_is_a_refusal_with_code_10_and_no_banner(db_available, capsys):
    from harness.enrolment_db import EnrolledFromDatabase
    assert EnrolledFromDatabase().enrolled() == (), "the test database has an enrolment"
    code = _run(_argv())
    out = capsys.readouterr()
    assert code == 10 and out.out == "" and "refused: switches" in out.err


def test_a_role_factory_that_fails_is_exit_1_and_its_text_is_not_printed(
        db_available, capsys, monkeypatch):
    def failing(spec):
        raise ValueError("SECRET-TEXT-OF-THE-FACTORY")

    monkeypatch.setattr(run_harness, "_roles", failing)
    code = _run(_argv())
    err = capsys.readouterr().err
    assert code == EXIT_UNEXPECTED == 1
    assert "ValueError" in err and "SECRET-TEXT-OF-THE-FACTORY" not in err


def test_the_lock_is_released_on_every_way_out(world):
    with enrolled(world.engagement_id):
        _run(_argv())
    again = HarnessLock()
    try:
        assert again.acquire() is True
    finally:
        again.close()


def test_a_database_that_cannot_be_reached_is_exit_4_and_the_driver_text_is_not_printed(capsys):
    def unreachable():
        raise ConnectionError("SECRET-DRIVER-TEXT password=hunter2")

    code = run_harness.main(_argv(), lock=HarnessLock(connect=unreachable),
                            register=lambda *a: None)
    err = capsys.readouterr().err
    assert code == 4
    assert "ConnectionError" in err and "SECRET-DRIVER-TEXT" not in err and "hunter2" not in err
