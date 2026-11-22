"""Subscription login only (the owner's decision of 2026-11-22; plan items 141 c and 143).

``scripts/run_shadow.py`` refuses, right after the registration check and before the integrity
guard, the factory, the lock and the database, when a variable of
``agents.llm.auth_guard.BILLING_VARIABLES`` has a value or a Claude Code settings file sets
``apiKeyHelper``; the refusal names the variable or the setting, never its value. And
``agents/llm/headless.py`` starts the CLI with an environment from which those variables are
removed and in which every other variable is kept. The environment and the settings files are
handed in; settings files are written under pytest's ``tmp_path``. No model, no process, no
database.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.base_agent import ProposedAction
from agents.llm import auth_guard, headless
from agents.llm.claude_code_headless_reviewer import ClaudeCodeHeadlessReviewer
from agents.llm.claude_code_headless_supervisor import ClaudeCodeHeadlessSupervisor
from agents.llm.claude_code_headless_worker import ClaudeCodeHeadlessWorker
from agents.llm.supervisor_base import StateSummary
from control_plane.canonicalizer.target import normalize_target
from harness.exit_codes import EXIT_STARTUP_REFUSED
from scripts import run_shadow
from tests import shadow_compliant_roles as compliant
from tests.test_shadow_runner_guard import (  # noqa: F401 - fixtures
    _argv,
    _codes,
    _Git,
    _Lock,
    _registration,
    _subscription_only,
    through,
)
from tests.test_shadow_runner_pins import CANDIDATES, SCOPE, TASK

#: A value no refusal line and no record may contain.
MARK = "MARKED-VALUE-c41d"
#: The list as this test expects it, written out, so that a name dropped from the module's list is
#: a failure here rather than a test that silently stops being made.
EXPECTED = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "ANTHROPIC_AWS_API_KEY", "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "ANTHROPIC_IDENTITY_TOKEN", "ANTHROPIC_IDENTITY_TOKEN_FILE", "AWS_BEARER_TOKEN_BEDROCK",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_GATEWAY",
    "CLAUDE_CODE_USE_MANTLE",
)
CLEAN = {"PATH": "/usr/bin:/bin", "HOME": "/home/shadow", "CLAUDE_CODE_OAUTH_TOKEN": "login"}


def test_the_list_is_the_expected_one_and_keeps_the_subscription_login_out():
    assert auth_guard.BILLING_VARIABLES == EXPECTED
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in auth_guard.BILLING_VARIABLES
    assert auth_guard.SETTINGS_KEYS == ("apiKeyHelper",)


def _start(environ, settings_files=(), record=None):
    """A start with the environment and settings files handed in. A run the guard lets through
    needs ``record`` (under ``tmp_path``): the spy of ``through`` stops it after the hand-over."""
    git, lock = _Git(), _Lock(True)
    argv = _argv() if record is None else _argv(record=record)
    code = run_shadow.main(argv, registration=_registration(), git=git, lock=lock,
                           environ=environ, settings_files=settings_files)
    return code, git, lock


@pytest.mark.parametrize("name", EXPECTED)
def test_each_billing_variable_is_refused_before_the_lock_and_the_database(name, through, capsys):  # noqa: F811
    code, git, lock = _start({**CLEAN, name: MARK})
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.API_BILLING_AUTH_PRESENT]
    assert name in err and MARK not in err
    # nothing after the registration check ran: no git, no factory, no lock, no database read
    assert git.calls == [] and compliant.BUILT == [] and lock.asked == 0 and through == []


def test_an_empty_value_is_not_present_and_the_run_is_handed_over(through, capsys, tmp_path):  # noqa: F811
    code, _, lock = _start({**CLEAN, "ANTHROPIC_API_KEY": ""}, record=tmp_path / "run.jsonl")
    assert code == EXIT_STARTUP_REFUSED and lock.asked == 1 and len(through) == 1
    assert "stopped by the test after the hand-over" in capsys.readouterr().err


def test_every_present_variable_is_named_on_its_own_line(through, capsys):  # noqa: F811
    code, _, _ = _start({**CLEAN, "ANTHROPIC_API_KEY": MARK, "CLAUDE_CODE_USE_VERTEX": "1"})
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and through == []
    lines = [x for x in err.splitlines() if x.startswith("refused: ")]
    assert len(lines) == 2 and "ANTHROPIC_API_KEY" in lines[0]
    assert "CLAUDE_CODE_USE_VERTEX" in lines[1] and MARK not in err


def _settings(tmp_path: Path, content) -> Path:
    path = tmp_path / "settings.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


def test_an_api_key_helper_in_a_settings_file_is_refused(tmp_path, through, capsys):  # noqa: F811
    path = _settings(tmp_path, {"apiKeyHelper": f"/usr/local/bin/key {MARK}", "model": "opus"})
    code, git, lock = _start(CLEAN, (path,))
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.API_BILLING_AUTH_PRESENT]
    assert "apiKeyHelper" in err and str(path) in err and MARK not in err
    assert git.calls == [] and lock.asked == 0 and through == []


def test_a_settings_file_without_the_helper_passes_and_one_that_cannot_be_read_does_not(
        tmp_path, through, capsys):  # noqa: F811
    plain = _settings(tmp_path, {"model": "opus", "apiKeyHelper": ""})
    assert _start(CLEAN, (plain, tmp_path / "absent.json"), tmp_path / "run.jsonl")[2].asked == 1
    capsys.readouterr()
    broken = _settings(tmp_path, "{ not json")
    code, _, lock = _start(CLEAN, (broken,))
    assert code == EXIT_STARTUP_REFUSED and lock.asked == 0
    assert _codes(capsys.readouterr().err) == [run_shadow.API_BILLING_AUTH_PRESENT]


def test_the_settings_files_are_the_users_the_projects_two_and_the_managed_one(tmp_path):
    files = auth_guard.settings_files(environ={}, home=Path("/home/u"), project=Path("/repo"))
    assert files == (Path("/home/u/.claude/settings.json"), Path("/repo/.claude/settings.json"),
                     Path("/repo/.claude/settings.local.json"), auth_guard.MANAGED_SETTINGS)
    moved = auth_guard.settings_files(environ={"CLAUDE_CONFIG_DIR": "/cfg"}, home=Path("/home/u"),
                                      project=Path("/repo"))
    assert moved[0] == Path("/cfg/settings.json")


def test_by_default_the_check_reads_the_process_environment(through, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", MARK)
    code = run_shadow.main(_argv(), registration=_registration(), git=_Git(), lock=_Lock(True))
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and "ANTHROPIC_AUTH_TOKEN" in err and MARK not in err


def test_a_refused_start_writes_no_record(tmp_path, through, capsys):  # noqa: F811
    record = tmp_path / "run.jsonl"
    argv = _argv(record=record)
    code = run_shadow.main(argv, registration=_registration(), git=_Git(), lock=_Lock(True),
                           environ={**CLEAN, "ANTHROPIC_API_KEY": MARK}, settings_files=())
    assert code == EXIT_STARTUP_REFUSED and not record.exists()


# -- the CLI's own environment ---------------------------------------------------------------------


@pytest.fixture
def started(monkeypatch):
    """Every variable of the list set to the mark, and a runner that keeps what it was given."""
    monkeypatch.setattr(headless.tempfile, "mkdtemp",
                        lambda prefix="": "/nonexistent/cyberorch-headless-auth")
    for name in EXPECTED:
        monkeypatch.setenv(name, MARK)
    for name, value in CLEAN.items():
        monkeypatch.setenv(name, value)
    seen = []

    def runner(command, **kwargs):
        seen.append(kwargs)
        envelope = {"result": {"risk_hint": "low"}, "usage": {"input_tokens": 1}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")
    return runner, seen


def _each_adapter(runner):
    ClaudeCodeHeadlessWorker(runner=runner).propose(task=TASK, candidates=CANDIDATES)
    ClaudeCodeHeadlessSupervisor(runner=runner).plan(
        state=StateSummary(engagement_id="ENG-AUTH", objective="o"), candidates=CANDIDATES)
    proposal = ProposedAction(
        action="network.scan", target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": SCOPE},
        discovery={"source": "explicit_scope"}, task_id="TASK-AUTH")
    ClaudeCodeHeadlessReviewer(runner=runner).review(
        proposal=proposal, canonical_target=normalize_target(proposal.target))


def test_the_cli_of_each_role_starts_without_the_billing_variables(started):
    runner, seen = started
    _each_adapter(runner)
    assert len(seen) == 3
    # compared so that a failure prints names and booleans, never a value of this environment
    expected = {k: v for k, v in os.environ.items() if k not in EXPECTED}
    for kwargs in seen:
        env = kwargs["env"]
        assert sorted(set(EXPECTED) & set(env)) == []
        assert [k for k, v in env.items() if v == MARK] == []
        assert sorted(set(env) ^ set(expected)) == []          # every other variable is kept ...
        assert [k for k in expected if env[k] != expected[k]] == []   # ... with its value
        assert env["PATH"] == CLEAN["PATH"] and env["HOME"] == CLEAN["HOME"]
        assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "login"       # the subscription login is kept
    assert [n for n in EXPECTED if os.environ[n] != MARK] == []    # the process's own is untouched
