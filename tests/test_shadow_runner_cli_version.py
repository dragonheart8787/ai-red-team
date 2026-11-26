"""The CLI's version lock (plan item 148): the name lists were reviewed on one version.

``agents.llm.auth_guard`` holds ``REVIEWED_CLI_VERSION`` ("2.1.330", the CLI the names of plan items
145 and 147 were read out of) and ``query_cli_version``, which runs ``claude --version`` with
the stripped environment and a 30-second limit and parses the version; a failure, a timeout or a
reply that is not a version raises, and the message never holds what was printed.
``scripts/run_shadow.py`` asks it at step 1c, after the login (1b) and before the integrity guard
(2), and refuses another version, or one that cannot be read, as ``cli_version_unreviewed`` with
exit 10; the record's header has the version as ``claude_cli_version`` (plan item 150: the
banner's ``cli_version`` is the project's version). The query is always handed in or run on a fake
runner: no test runs the CLI. Records are written under pytest's ``tmp_path``.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from agents.llm import auth_guard
from harness.exit_codes import EXIT_STARTUP_REFUSED
from scripts import run_shadow
from tests import shadow_compliant_roles as compliant
from tests.test_shadow_runner_guard import (  # noqa: F401 - fixtures
    SUBSCRIPTION_LOGIN,
    _argv,
    _codes,
    _Git,
    _Lock,
    _registration,
    _subscription_only,
    through,
)

#: A value no refusal line and no exception message may contain.
MARK = "MARKED-VALUE-7c1e"
#: The real query, taken before the autouse fixture of the guard's tests replaces it.
QUERY_CLI_VERSION = auth_guard.query_cli_version
CLEAN = {"PATH": "/usr/bin:/bin", "HOME": "/home/shadow"}


def test_the_reviewed_version_is_the_one_the_lists_were_read_from():
    assert auth_guard.REVIEWED_CLI_VERSION == "2.1.330"
    assert run_shadow.CLI_VERSION_UNREVIEWED in run_shadow.REASONS
    assert len(set(run_shadow.REASONS)) == len(run_shadow.REASONS) == 29    # 19 + S4's 6 + S6's 4


def _start(tmp_path, *, version=None, query=None, login_query=None):
    """A start with the version query handed in; a run it lets through is stopped by ``through``'s
    spy after the hand-over and leaves a header in ``tmp_path``."""
    git, lock = _Git(), _Lock(True)
    record = tmp_path / "run.jsonl"
    if query is None:
        query = lambda: "2.1.330" if version is None else version  # noqa: E731
    code = run_shadow.main(_argv(record=record), registration=_registration(), git=git, lock=lock,
                           environ=CLEAN, settings_files=(), login_query=login_query,
                           version_query=query)
    return code, git, lock, record


def test_the_reviewed_version_passes_and_is_in_the_header(tmp_path, through):  # noqa: F811
    code, git, lock, record = _start(tmp_path)
    assert lock.asked == 1 and len(through) == 1 and git.calls
    header = json.loads(record.read_text().splitlines()[0])
    assert header["claude_cli_version"] == "2.1.330"


@pytest.mark.parametrize("version", ["2.1.331", "2.1.33", "2.1.3300", "3.0.0", "2.1.329", "",
                                     " 2.1.330", "2.1.330 (Claude Code)"])
def test_a_cli_version_that_is_not_the_reviewed_one_is_refused(
        version, tmp_path, through, capsys):  # noqa: F811
    code, git, lock, record = _start(tmp_path, version=version)
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED, version
    assert _codes(err) == [run_shadow.CLI_VERSION_UNREVIEWED], version
    assert "2.1.330" in err
    # refused before the integrity guard: no git, no factory, no lock, no record
    assert git.calls == [] and compliant.BUILT == [] and lock.asked == 0 and through == []
    assert not record.exists()


@pytest.mark.parametrize("failure", [auth_guard.VersionQueryFailed("exit 1"), OSError(MARK),
                                     subprocess.TimeoutExpired("claude", 30), ValueError(MARK)])
def test_a_cli_version_that_cannot_be_read_is_refused(failure, tmp_path, through, capsys):  # noqa: F811
    def query():
        raise failure

    code, git, lock, record = _start(tmp_path, query=query)
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.CLI_VERSION_UNREVIEWED]
    assert "the CLI's version cannot be read" in err and MARK not in err
    assert git.calls == [] and lock.asked == 0 and through == [] and not record.exists()


def test_the_login_is_checked_before_the_version_is_asked(tmp_path, through, capsys):  # noqa: F811
    asked = []
    code, _, _, _ = _start(tmp_path, login_query=lambda: {**SUBSCRIPTION_LOGIN, "loggedIn": False},
                           query=lambda: asked.append(1) or "2.1.330")
    assert code == EXIT_STARTUP_REFUSED and asked == []
    assert set(_codes(capsys.readouterr().err)) == {run_shadow.LOGIN_NOT_SUBSCRIPTION}


def test_by_default_the_runner_asks_the_guards_query(tmp_path, through, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(auth_guard, "query_cli_version", lambda **kwargs: "9.9.9")
    git, lock = _Git(), _Lock(True)
    code = run_shadow.main(_argv(record=tmp_path / "run.jsonl"), registration=_registration(),
                           git=git, lock=lock, environ=CLEAN, settings_files=())
    assert code == EXIT_STARTUP_REFUSED and git.calls == [] and lock.asked == 0
    assert _codes(capsys.readouterr().err) == [run_shadow.CLI_VERSION_UNREVIEWED]


# -- the query itself, on a fake runner -----------------------------------------------------------


def _runner(seen, *, returncode=0, stdout="", raises=None):
    def run(command, **kwargs):
        seen.append((command, kwargs))
        if raises is not None:
            raise raises
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
    return run


@pytest.mark.parametrize("reply", ["2.1.330 (Claude Code)\n", "2.1.330\n", "2.1.330"])
def test_the_query_runs_version_with_the_stripped_environment_and_parses_it(reply):
    seen = []
    version = QUERY_CLI_VERSION(runner=_runner(seen, stdout=reply),
                                environ={**CLEAN, "ANTHROPIC_BASE_URL": MARK,
                                         "ANTHROPIC_API_KEY": MARK})
    assert version == "2.1.330"
    ((command, kwargs),) = seen
    assert command == ["claude", "--version"]
    assert kwargs["env"] == CLEAN and kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["timeout"] == auth_guard.VERSION_QUERY_TIMEOUT_SECONDS == 30.0
    assert kwargs["check"] is False


@pytest.mark.parametrize("runner", [
    dict(returncode=1, stdout="2.1.330 (Claude Code)"),
    dict(stdout=f"{MARK} 2.1.330"),
    dict(stdout=f"2.1.330 (Claude Code) {MARK}"),
    dict(stdout=f"version {MARK}"),
    dict(stdout=""),
    dict(stdout=None),
    dict(raises=subprocess.TimeoutExpired("claude", 30)),
    dict(raises=FileNotFoundError(MARK)),
])
def test_a_query_that_fails_raises_and_never_carries_what_was_printed(runner):
    with pytest.raises(auth_guard.VersionQueryFailed) as failed:
        QUERY_CLI_VERSION(runner=_runner([], **runner), environ=CLEAN)
    assert MARK not in str(failed.value)
