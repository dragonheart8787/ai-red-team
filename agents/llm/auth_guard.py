"""Subscription login only: the shadow runner's guard against API-key billing (items 141 c, 143).

The owner decided on 2026-11-22 that a shadow run may use only the subscription login of the
``claude`` CLI and never API-key billing. This module holds the three pieces that decision needs
and nothing else:

* :data:`BILLING_VARIABLES` -- a closed list of environment variables that make the CLI bill by an
  API key or a token, or send its calls to another provider. The first four are named by the
  owner's decision; the others were found, by name, in the installed CLI (2.1.330), as variables
  of the same kind: an API key, a bearer or identity token, or a switch to a cloud provider.
  ``CLAUDE_CODE_OAUTH_TOKEN`` is **not** in it: it is the subscription login itself.
* :func:`problems` -- what is present: a variable of the list with a non-empty value, or an
  ``apiKeyHelper`` with a non-empty value in a Claude Code settings file. It names variables and
  setting keys, **never a value**.
* :func:`subprocess_environment` -- the caller's environment without the variables of the list,
  every other variable unchanged; ``agents/llm/headless.py`` starts the CLI with it.

What this cannot do: show that a call was in fact served by the subscription. It blocks the known
API-billing paths; the first real call (S8) must confirm and record the login it used.

Added by the follow-up of plan item 145:

* :data:`REVIEWED_REFUSE` -- the names the first search found in the CLI and left out, now refused
  (fail closed: what has no evidence that it may be kept is refused), :data:`ANTHROPIC_BASE_URL`
  among them; and :data:`REVIEWED_KEEP`, the names kept, each with its one-line reason. The two
  are disjoint, and together they are every name that search found outside the first sixteen.
* a settings file's ``"env"`` object: a name of :data:`BILLING_VARIABLES` with a non-empty value
  in it is refused, and so is an ``"env"`` that is not an object (it cannot be ruled out).
* :func:`query_login` and :func:`login_problems` -- ``claude auth status --json``, which reads the
  CLI's own record of its login and calls no model, and the check of what it says: the login
  must be the subscription's (``authMethod`` ``claude.ai`` or ``oauth_token``, ``apiProvider``
  ``firstParty``, logged in, and no ``apiKeySource``); a query that fails or cannot be parsed is
  a refusal too.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

#: Named by the owner's decision (plan item 141 c).
DECIDED = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
           "CLAUDE_CODE_USE_VERTEX")
#: Of the same kind, found by name in the installed CLI (plan item 143, step 1e).
SAME_KIND = (
    "ANTHROPIC_AWS_API_KEY", "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "ANTHROPIC_IDENTITY_TOKEN", "ANTHROPIC_IDENTITY_TOKEN_FILE", "AWS_BEARER_TOKEN_BEDROCK",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_GATEWAY",
    "CLAUDE_CODE_USE_MANTLE",
)
#: Found by the same search and first left out; refused after review (plan item 145, B4).
REVIEWED_REFUSE = (
    "ANTHROPIC_BASE_URL",                       # sends the CLI's calls to another endpoint
    "ANTHROPIC_ENVIRONMENT_KEY",                # a remote worker's environment credential
    "CLAUDE_CODE_SESSIONS_OAUTH_TOKEN",         # a sessions token, not shown to be the login
    "CLAUDE_CODE_LAUNCHER_RUNS_API_KEY_HELPER",  # the API-key helper path
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",        # the API-key helper path
    "CLAUDE_CODE_MCP_SERVE_AUTH_TOKEN",         # no evidence either way: fail closed
    "CLAUDE_CODE_USE_CCR_V2",                   # set by the CLI together with ANTHROPIC_BASE_URL
    "CLAUDE_CODE_USE_NATIVE_FILE_SEARCH",       # no evidence either way: fail closed
)
BILLING_VARIABLES: tuple[str, ...] = DECIDED + SAME_KIND + REVIEWED_REFUSE

#: Found by the same search and kept, each with the evidence for it (plan item 145, B4).
REVIEWED_KEEP: Mapping[str, str] = {
    "CLAUDE_CODE_OAUTH_TOKEN": "the subscription login itself; the login check confirms its kind",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR":
        "the same OAuth token handed on a file descriptor (the CLI names it beside "
        "CLAUDE_CODE_OAUTH_TOKEN); the login check confirms its kind",
    "ANTHROPIC_WEBHOOK_SIGNING_KEY":
        "the SDK client's webhookKey, apart from its apiKey and authToken: it signs webhooks and "
        "authenticates no model call",
    "CLAUDE_CODE_USE_POWERSHELL_TOOL":
        "turns on a tool; the headless call has no tools (--tools \"\")",
    "CLAUDE_CODE_USE_COWORK_PLUGINS":
        "where plugins are read from; the headless call loads none (--safe-mode)",
}

#: The settings object whose names are environment variables the CLI sets for itself.
SETTINGS_ENV = "env"

#: The settings key that has the CLI run a program for an API key.
SETTINGS_KEYS: tuple[str, ...] = ("apiKeyHelper",)

#: The managed settings file on Linux (read whatever ``--setting-sources`` says).
MANAGED_SETTINGS = Path("/etc/claude-code/managed-settings.json")


def settings_files(*, environ: Mapping[str, str], home: Path, project: Path) -> tuple[Path, ...]:
    """The Claude Code settings files that could hold an ``apiKeyHelper``: the user's (under
    ``CLAUDE_CONFIG_DIR`` when it is set, else ``~/.claude``), the project's two, and the managed
    one."""
    user = Path(environ["CLAUDE_CONFIG_DIR"]) if environ.get("CLAUDE_CONFIG_DIR") else (
        home / ".claude")
    return (user / "settings.json", project / ".claude" / "settings.json",
            project / ".claude" / "settings.local.json", MANAGED_SETTINGS)


def present_variables(environ: Mapping[str, str]) -> list[str]:
    """The names of the list whose value is not empty, in the list's order."""
    return [name for name in BILLING_VARIABLES if environ.get(name)]


def _settings_problems(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [f"{path} cannot be read as JSON, so its apiKeyHelper cannot be ruled out"]
    if not isinstance(settings, dict):
        return [f"{path} is not a JSON object, so its apiKeyHelper cannot be ruled out"]
    found = []
    keys = [key for key in SETTINGS_KEYS if settings.get(key)]
    if keys:
        found.append(f"{path} sets {', '.join(keys)}")
    if SETTINGS_ENV in settings:
        env = settings[SETTINGS_ENV]
        if not isinstance(env, dict):
            found.append(f"{path} has an {SETTINGS_ENV} that is not an object, so a billing "
                         "variable in it cannot be ruled out")
        else:
            found += [f"{path} sets {SETTINGS_ENV}.{name}" for name in BILLING_VARIABLES
                      if env.get(name)]
    return found


def problems(environ: Mapping[str, str], paths: Iterable[Path]) -> list[str]:
    """One line per thing present, naming a variable or a settings key and never a value."""
    found = [f"{name} is set" for name in present_variables(environ)]
    for path in paths:
        found += _settings_problems(path)
    return found


def subprocess_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """``environ`` (default ``os.environ``) without the variables of :data:`BILLING_VARIABLES`."""
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if key not in BILLING_VARIABLES}


# -- the login itself (plan item 145, B3) ----------------------------------------------------------

#: ``claude auth status --json``: the CLI's own record of its login, read without a model call.
LOGIN_STATUS_ARGS = ("auth", "status", "--json")
LOGIN_QUERY_TIMEOUT_SECONDS = 30.0
#: The ``authMethod`` values that are the subscription: a claude.ai sign-in, or its OAuth token
#: (``claude setup-token`` "requires Claude subscription"). A Console sign-in is ``api_key``.
SUBSCRIPTION_AUTH_METHODS = ("claude.ai", "oauth_token")
SUBSCRIPTION_API_PROVIDER = "firstParty"


class LoginQueryFailed(RuntimeError):
    """The login could not be read: the command failed, timed out or printed no JSON object."""


def query_login(*, executable: str = "claude", runner: Callable = subprocess.run,
                environ: Mapping[str, str] | None = None) -> dict:
    """What ``claude auth status --json`` says, run with the environment the CLI's model calls
    get (:func:`subprocess_environment`). Raises :class:`LoginQueryFailed`; its message never
    holds what the command printed, which can name the account."""
    try:
        done = runner([executable, *LOGIN_STATUS_ARGS], capture_output=True, text=True,
                      stdin=subprocess.DEVNULL, env=subprocess_environment(environ),
                      timeout=LOGIN_QUERY_TIMEOUT_SECONDS, check=False)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise LoginQueryFailed(type(exc).__name__) from None
    if done.returncode != 0:
        raise LoginQueryFailed(f"exit {done.returncode}")
    try:
        status = json.loads(done.stdout or "")
    except ValueError:
        raise LoginQueryFailed("not JSON") from None
    if not isinstance(status, dict):
        raise LoginQueryFailed("not a JSON object")
    return status


def login_problems(status: Mapping[str, object]) -> list[str]:
    """What makes the login not the subscription's; empty when it is. Names fields and their
    login-type values only (never an e-mail, an organization or a key)."""
    if not isinstance(status, Mapping):
        return ["the login status is not a JSON object"]
    found = []
    if status.get("loggedIn") is not True:
        found.append("the CLI is not logged in")
    method, provider = status.get("authMethod"), status.get("apiProvider")
    if method not in SUBSCRIPTION_AUTH_METHODS:
        found.append(f"authMethod is {method!r}, not one of {list(SUBSCRIPTION_AUTH_METHODS)}"
                     if isinstance(method, str) or method is None else "authMethod is not a string")
    if provider != SUBSCRIPTION_API_PROVIDER:
        found.append(f"apiProvider is {provider!r}, not {SUBSCRIPTION_API_PROVIDER!r}"
                     if isinstance(provider, str) or provider is None
                     else "apiProvider is not a string")
    if "apiKeySource" in status:
        found.append("apiKeySource is present: an API key is available to the CLI")
    return found
