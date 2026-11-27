"""The billing guard's follow-up (plan item 145): the reviewed names, a settings file's ``env``, and
the login itself.

``agents.llm.auth_guard`` refuses the names the first search found and left out unless there is
evidence to keep them (``REVIEWED_REFUSE`` and ``REVIEWED_KEEP``); refuses a settings file whose
``"env"`` object sets a billing variable, or whose ``"env"`` is not an object; and asks
``claude auth status --json`` what the login is. ``scripts/run_shadow.py`` refuses, before git,
the lock and the database, a login that is not the subscription's or that cannot be read
(``login_not_subscription``). The query is always handed in: no test runs the CLI. Settings files
and records are written under pytest's ``tmp_path``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.llm import auth_guard
from harness.exit_codes import EXIT_STARTUP_REFUSED
from scripts import run_shadow
from tests import shadow_compliant_roles as compliant
from tests.test_shadow_runner_guard import (  # noqa: F401 - fixtures
    RECORDS,
    SUBSCRIPTION_LOGIN,
    _argv,
    _codes,
    _Git,
    _Lock,
    _registration,
    _subscription_only,
    through,
)
from tests.test_shadow_runner_names_b3 import B3_FOUND, B3_REFUSE

#: A value no refusal line and no record may contain.
MARK = "MARKED-VALUE-4b0e"
#: The real query, taken before the autouse fixture of the guard's tests replaces it.
QUERY_LOGIN = auth_guard.query_login
CLEAN = {"PATH": "/usr/bin:/bin", "HOME": "/home/shadow"}
#: Every name the first search found in the CLI outside the first sixteen (plan item 145, B4).
FOUND_OUTSIDE_THE_FIRST_LIST = {
    "ANTHROPIC_BASE_URL", "ANTHROPIC_ENVIRONMENT_KEY", "CLAUDE_CODE_SESSIONS_OAUTH_TOKEN",
    "CLAUDE_CODE_LAUNCHER_RUNS_API_KEY_HELPER", "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_CODE_MCP_SERVE_AUTH_TOKEN",
    "ANTHROPIC_WEBHOOK_SIGNING_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_CCR_V2",
    "CLAUDE_CODE_USE_COWORK_PLUGINS", "CLAUDE_CODE_USE_NATIVE_FILE_SEARCH",
    "CLAUDE_CODE_USE_POWERSHELL_TOOL",
}


def _start(tmp_path, *, environ=CLEAN, settings=(), login=None, query=None):
    """A start with everything the guard reads handed in; a run it lets through is stopped by
    ``through``'s spy after the hand-over and leaves a header in ``tmp_path``."""
    git, lock = _Git(), _Lock(True)
    record = tmp_path / "run.jsonl"
    if query is None:
        query = lambda: dict(SUBSCRIPTION_LOGIN if login is None else login)  # noqa: E731
    code = run_shadow.main(_argv(record=record), registration=_registration(), git=git, lock=lock,
                           environ=environ, settings_files=tuple(settings), login_query=query)
    return code, git, lock, record


# -- the reviewed names ---------------------------------------------------------------------------


def test_the_reviewed_lists_are_disjoint_and_cover_every_name_found():
    refused, kept = set(auth_guard.REVIEWED_REFUSE), set(auth_guard.REVIEWED_KEEP)
    refused |= set(B3_REFUSE)                    # plan item 147: the second review, B3
    assert not refused & kept
    assert refused | kept == FOUND_OUTSIDE_THE_FIRST_LIST | B3_FOUND
    assert refused <= set(auth_guard.BILLING_VARIABLES)
    assert not kept & set(auth_guard.BILLING_VARIABLES)
    assert "ANTHROPIC_BASE_URL" in auth_guard.BILLING_VARIABLES
    for name, reason in auth_guard.REVIEWED_KEEP.items():
        assert reason.strip() and "\n" not in reason, name


def test_a_base_url_is_refused_and_not_passed_to_the_cli(tmp_path, through, capsys):  # noqa: F811
    code, git, lock, _ = _start(tmp_path, environ={**CLEAN, "ANTHROPIC_BASE_URL": MARK})
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and _codes(err) == [run_shadow.API_BILLING_AUTH_PRESENT]
    assert "ANTHROPIC_BASE_URL" in err and MARK not in err
    assert git.calls == [] and lock.asked == 0 and through == []
    env = auth_guard.subprocess_environment({**CLEAN, "ANTHROPIC_BASE_URL": MARK})
    assert "ANTHROPIC_BASE_URL" not in env and env["PATH"] == CLEAN["PATH"]


# -- a settings file's env ------------------------------------------------------------------------


def _settings(tmp_path, content):
    path = Path(RECORDS["settings"]) / "settings.json"     # not in the records directory (item 159)
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


@pytest.mark.parametrize("name", ["ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"])
def test_a_billing_variable_in_a_settings_env_is_refused(name, tmp_path, through, capsys):  # noqa: F811
    path = _settings(tmp_path, {"env": {name: MARK, "TZ": "UTC"}})
    code, git, lock, _ = _start(tmp_path, settings=[path])
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and _codes(err) == [run_shadow.API_BILLING_AUTH_PRESENT]
    assert str(path) in err and f"env.{name}" in err and MARK not in err
    assert git.calls == [] and lock.asked == 0 and through == []


def test_a_settings_env_with_unrelated_names_only_passes(tmp_path, through, capsys):  # noqa: F811
    path = _settings(tmp_path, {"env": {"TZ": "UTC", "ANTHROPIC_API_KEY": ""}})
    code, _, lock, _ = _start(tmp_path, settings=[path])
    assert lock.asked == 1 and len(through) == 1
    assert "refused: api_billing_auth_present" not in capsys.readouterr().err


def test_a_settings_env_that_is_not_an_object_is_refused(tmp_path, through, capsys):  # noqa: F811
    path = _settings(tmp_path, {"env": f"ANTHROPIC_API_KEY={MARK}"})
    code, _, lock, _ = _start(tmp_path, settings=[path])
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and _codes(err) == [run_shadow.API_BILLING_AUTH_PRESENT]
    assert "env" in err and MARK not in err and lock.asked == 0


# -- the login ------------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["claude.ai", "oauth_token"])
def test_a_subscription_login_passes_and_its_kind_is_in_the_header(
        method, tmp_path, through, capsys):  # noqa: F811
    login = {**SUBSCRIPTION_LOGIN, "authMethod": method, "email": MARK, "orgName": MARK}
    code, _, lock, record = _start(tmp_path, login=login)
    assert lock.asked == 1 and len(through) == 1
    header = json.loads(record.read_text().splitlines()[0])
    assert header["auth_guard"] == "passed"
    assert header["login"] == {"auth_method": method, "api_provider": "firstParty"}
    assert MARK not in record.read_text() and MARK not in capsys.readouterr().err


#: Logins that are not the subscription's, each as ``claude auth status --json`` could say it.
NOT_SUBSCRIPTION = {
    "console_api_key": {**SUBSCRIPTION_LOGIN, "authMethod": "api_key"},
    "api_key_helper": {**SUBSCRIPTION_LOGIN, "authMethod": "api_key_helper"},
    "third_party": {**SUBSCRIPTION_LOGIN, "authMethod": "third_party", "apiProvider": "bedrock"},
    "not_logged_in": {"loggedIn": False, "authMethod": "none", "apiProvider": "firstParty"},
    "gateway": {**SUBSCRIPTION_LOGIN, "apiProvider": "gateway"},
    "key_beside_the_login": {**SUBSCRIPTION_LOGIN, "apiKeySource": "ANTHROPIC_API_KEY"},
    "no_fields": {},
    "not_an_object": ["claude.ai"],
}


@pytest.mark.parametrize("case", list(NOT_SUBSCRIPTION))
def test_a_login_that_is_not_the_subscriptions_is_refused_before_the_lock(
        case, tmp_path, through, capsys):  # noqa: F811
    code, git, lock, record = _start(tmp_path, query=lambda: NOT_SUBSCRIPTION[case])
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED, case
    assert set(_codes(err)) == {run_shadow.LOGIN_NOT_SUBSCRIPTION}, case
    assert git.calls == [] and compliant.BUILT == [] and lock.asked == 0 and through == []
    assert not record.exists()


@pytest.mark.parametrize("failure", [auth_guard.LoginQueryFailed("exit 1"), OSError("no claude"),
                                     subprocess.TimeoutExpired("claude", 30)])
def test_a_login_that_cannot_be_read_is_refused(failure, tmp_path, through, capsys):  # noqa: F811
    def query():
        raise failure

    code, git, lock, _ = _start(tmp_path, query=query)
    err = capsys.readouterr().err
    assert code == EXIT_STARTUP_REFUSED and _codes(err) == [run_shadow.LOGIN_NOT_SUBSCRIPTION]
    assert "the login cannot be read" in err and lock.asked == 0 and through == []


def test_the_billing_variables_are_checked_before_the_login_is_asked(tmp_path, through, capsys):  # noqa: F811
    asked = []
    code, _, _, _ = _start(tmp_path, environ={**CLEAN, "ANTHROPIC_API_KEY": MARK},
                           query=lambda: asked.append(1) or dict(SUBSCRIPTION_LOGIN))
    assert code == EXIT_STARTUP_REFUSED and asked == []
    assert _codes(capsys.readouterr().err) == [run_shadow.API_BILLING_AUTH_PRESENT]


# -- the query itself, on a fake runner -----------------------------------------------------------


def _runner(seen, *, returncode=0, stdout="", raises=None):
    def run(command, **kwargs):
        seen.append((command, kwargs))
        if raises is not None:
            raise raises
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
    return run


def test_the_query_asks_auth_status_with_the_stripped_environment():
    seen = []
    status = QUERY_LOGIN(
        runner=_runner(seen, stdout=json.dumps(SUBSCRIPTION_LOGIN)),
        environ={**CLEAN, "ANTHROPIC_BASE_URL": MARK, "ANTHROPIC_API_KEY": MARK})
    assert status == SUBSCRIPTION_LOGIN
    ((command, kwargs),) = seen
    assert command == ["claude", "auth", "status", "--json"]
    assert kwargs["env"] == CLEAN and kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["timeout"] == auth_guard.LOGIN_QUERY_TIMEOUT_SECONDS


@pytest.mark.parametrize("runner", [
    dict(returncode=1, stdout=json.dumps({"email": MARK})),
    dict(stdout=f"Logged in as {MARK}"),
    dict(stdout=json.dumps([MARK])),
    dict(raises=subprocess.TimeoutExpired("claude", 30)),
    dict(raises=FileNotFoundError("claude")),
])
def test_a_query_that_fails_raises_and_never_carries_what_was_printed(runner):
    with pytest.raises(auth_guard.LoginQueryFailed) as failed:
        QUERY_LOGIN(runner=_runner([], **runner), environ=CLEAN)
    assert MARK not in str(failed.value)
