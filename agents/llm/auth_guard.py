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
#: The names of plan item 147's scan (B3) of the installed CLI (2.1.330): every name that starts
#: ANTHROPIC_, CLAUDE_CODE_, CLAUDE_, AWS_BEARER_, CLOUD_ML_ or VERTEX_ and holds TOKEN, KEY, AUTH,
#: CRED, OAUTH, URL, ENDPOINT, BASE, PROVIDER or HOST, and was in neither list before; refused
#: unless the CLI's own text shows it has nothing to do with a credential, a login or where calls
#: go.
REVIEWED_REFUSE_2 = (
    "ANTHROPIC_API_HOST",
    "ANTHROPIC_ASSETS_HOST",
    "ANTHROPIC_AWS_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "ANTHROPIC_GOOGLE_CLOUD_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "CLAUDE_AI_AUTHORIZE_URL",
    "CLAUDE_AI_HOST",
    "CLAUDE_API_KEY",
    "CLAUDE_ARTIFACT_HOST_GRANT",
    "CLAUDE_BG_AUTH_SNAPSHOT_PATH",
    "CLAUDE_BG_CLAIM_AUTH",
    "CLAUDE_BG_PTY_AUTH",
    "CLAUDE_BG_RV_AUTH",
    "CLAUDE_BG_SESSION_CREDENTIAL",
    "CLAUDE_BG_SOCKET_TOKENS_PATH",
    "CLAUDE_BRIDGE_BASE_URL",
    "CLAUDE_BRIDGE_OAUTH_TOKEN",
    "CLAUDE_BRIDGE_SESSION_INGRESS_URL",
    "CLAUDE_CODE_AGENT_PROXY_GIT_HOSTS",
    "CLAUDE_CODE_API_BASE_URL",
    "CLAUDE_CODE_ARG_KEY_SHAPE",
    "CLAUDE_CODE_ARTIFACTS_API_BASE_URL",
    "CLAUDE_CODE_ARTIFACTS_API_TOKEN",
    "CLAUDE_CODE_ARTIFACT_ASSET_BASE_URL",
    "CLAUDE_CODE_ARTIFACT_LIVE_BASE_URL",
    "CLAUDE_CODE_ARTIFACT_SYNC_BASE_URL",
    "CLAUDE_CODE_ARTIFACT_VIEWER_BASE_URL",
    "CLAUDE_CODE_AUTH_FAIL_EXIT_MS",
    "CLAUDE_CODE_AUTOUPDATER_DISABLED_BY_HOST",
    "CLAUDE_CODE_CCR_AFFINITY_KEY",
    "CLAUDE_CODE_CLIENT_DATA_URL",
    "CLAUDE_CODE_CLIENT_KEY",
    "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
    "CLAUDE_CODE_CUSTOM_OAUTH_URL",
    "CLAUDE_CODE_DESIGN_OAUTH_CLIENT_ID",
    "CLAUDE_CODE_DEV_RAW_CHANGELOG_URL",
    "CLAUDE_CODE_DISABLE_ATTRIBUTION_BASELINE_REUSE",
    "CLAUDE_CODE_DISABLE_AUTH_REFRESH_LOCK",
    "CLAUDE_CODE_DISABLE_EARLY_KEY_GUARD",
    "CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER",
    "CLAUDE_CODE_FORCE_WINDOWS_CREDMAN",
    "CLAUDE_CODE_GATEWAY_TOKEN",
    "CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_GB_BASE_URL",
    "CLAUDE_CODE_HFI_BEARER_TOKEN",
    "CLAUDE_CODE_HOSTED_DESKTOP",
    "CLAUDE_CODE_HOST_ALLOW_RESETS_DENIAL_STREAK",
    "CLAUDE_CODE_HOST_ARTIFACT_TYPE_COMMANDS",
    "CLAUDE_CODE_HOST_AUTH_ASK_AT_START",
    "CLAUDE_CODE_HOST_AUTH_ENV_VAR",
    "CLAUDE_CODE_HOST_AUTH_REFRESH_TIMEOUT_MS",
    "CLAUDE_CODE_HOST_CHECKED_FOLDER",
    "CLAUDE_CODE_HOST_CREDS_FILE",
    "CLAUDE_CODE_HOST_GATEWAY_LINEAGE",
    "CLAUDE_CODE_HOST_GUARDS_ARTIFACTS_MCP",
    "CLAUDE_CODE_HOST_HTTP_PROXY_PORT",
    "CLAUDE_CODE_HOST_HYBRID_ORGANIZATION_UUID",
    "CLAUDE_CODE_HOST_OWNED_CONFIG_DIR",
    "CLAUDE_CODE_HOST_OWNED_SPAWN_ENV",
    "CLAUDE_CODE_HOST_PROMPT_SUPERSEDES_RECORD",
    "CLAUDE_CODE_HOST_READS_NO_BASH_EDIT_DIFF",
    "CLAUDE_CODE_HOST_SCHEDULED_RUN",
    "CLAUDE_CODE_HOST_SESSION_ID",
    "CLAUDE_CODE_HOST_SHOWS_CONNECTION_NOTICE",
    "CLAUDE_CODE_HOST_SOCKS_PROXY_PORT",
    "CLAUDE_CODE_MARKETPLACE_URL",
    "CLAUDE_CODE_MCP_APPS_HOST",
    "CLAUDE_CODE_MCP_SERVER_URL",
    "CLAUDE_CODE_MEMORY_API_BASE_URL",
    "CLAUDE_CODE_MEMORY_API_TOKEN",
    "CLAUDE_CODE_MESSAGING_TOKEN",
    "CLAUDE_CODE_MODEL_CATALOG_URL",
    "CLAUDE_CODE_NOTIFICATIONS_HOST",
    "CLAUDE_CODE_OAUTH_401_WAIT_MS",
    "CLAUDE_CODE_OAUTH_CLIENT_ID",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_SCOPES",
    "CLAUDE_CODE_PLUGIN_ARCHIVE_URL",
    "CLAUDE_CODE_PLUGIN_REMOTE_MCP_REACHABLE_HOSTS_HINT",
    "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
    "CLAUDE_CODE_PROXY_AUTHENTICATE",
    "CLAUDE_CODE_PROXY_AUTH_HELPER_TTL_MS",
    "CLAUDE_CODE_PROXY_HOST",
    "CLAUDE_CODE_PROXY_RESOLVES_HOSTS",
    "CLAUDE_CODE_PROXY_URL",
    "CLAUDE_CODE_RELAUNCH_PROACTIVITY_BASELINE",
    "CLAUDE_CODE_REMOTE_SDK_URL",
    "CLAUDE_CODE_REMOTE_TOOLS_DESKTOP_APP_HOST",
    "CLAUDE_CODE_REMOTE_TOOLS_HOST_ALLOWS_UNATTENDED",
    "CLAUDE_CODE_REMOTE_TOOLS_HOST_IDLE_RELEASE_MINUTES",
    "CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH",
    "CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH",
    "CLAUDE_CODE_SDK_HAS_SESSIONS_OAUTH_REFRESH",
    "CLAUDE_CODE_SESSION_ACCESS_TOKEN",
    "CLAUDE_CODE_SHELL_HANDOVER_KEY",
    "CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH",
    "CLAUDE_CODE_SKIP_ANTHROPIC_GOOGLE_CLOUD_AUTH",
    "CLAUDE_CODE_SKIP_AWS_CRED_CACHE",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
    "CLAUDE_CODE_SKIP_MANTLE_AUTH",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "CLAUDE_CODE_SLACK_TAG_TOKEN",
    "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_PROVIDERS",
    "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
    "CLAUDE_CODE_WORKSPACE_HOST_PATHS",
    "CLAUDE_LOCAL_OAUTH_API_BASE",
    "CLAUDE_LOCAL_OAUTH_APPS_BASE",
    "CLAUDE_LOCAL_OAUTH_CONSOLE_BASE",
    "CLAUDE_PTY_HOST_EXEC",
    "CLAUDE_PTY_HOST_NO_STABLE_PATH",
    "CLAUDE_REMOTE_TOOLS_BRIDGE_URL",
    "CLAUDE_RUNNER_API_BASE_URL",
    "CLAUDE_RUNNER_GIT_MOUNT_URL",
    "CLAUDE_RUNNER_PRIMARY_REPO_URL",
    "CLAUDE_RUNNER_REPO_URL",
    "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
    "CLAUDE_TRUSTED_DEVICE_TOKEN",
    "VERTEX_AUTH_HOSTS",
    "VERTEX_OAUTH_CREDENTIAL_KIND",
)
BILLING_VARIABLES: tuple[str, ...] = (DECIDED + SAME_KIND + REVIEWED_REFUSE
                                       + REVIEWED_REFUSE_2)

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
    # plan item 147, B3: kept on the CLI's own text (none is a credential, a login or an endpoint)
    "CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS":
        "a count of model tokens for a file read; no credential or endpoint",
    "CLAUDE_CODE_IDLE_COMPACT_MIN_TOKENS": "a compaction threshold in model tokens",
    "CLAUDE_CODE_IDLE_TOKEN_THRESHOLD": "an idle threshold in model tokens",
    "CLAUDE_CODE_MAX_CONTEXT_TOKENS": "the model's context window in tokens",
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "an output-token limit",
    "CLAUDE_CODE_RESUME_TOKEN_THRESHOLD": "a resume threshold in model tokens",
    "CLAUDE_CODE_TOTAL_TOKENS_REMINDER": "a switch for a token-count reminder",
    "CLAUDE_CODE_TOTAL_TOKENS_REMINDER_AFTER_USER_TURN": "a switch for a token-count reminder",
    "CLAUDE_CODE_TOTAL_TOKENS_REMINDER_BUDGET": "the starting count of a token-count reminder",
    "CLAUDE_CODE_WORKFLOW_SIZE_WARNING_TOKENS": "a warning threshold in model tokens",
    "CLAUDE_CODE_ENABLE_TOKEN_USAGE_ATTACHMENT": "attaches the token count to the context",
    "CLAUDE_CODE_OVERLOADED_RETRY_BASE_DELAY_MS": "a retry delay in milliseconds",
    "CLAUDE_CODE_BASE_REF": "a git base ref of the checkout",
    "CLAUDE_CODE_BASE_REFS": "git base refs of the checkouts",
    "CLAUDE_BASE": "a worktree baseline file",
    "CLAUDE_CODE_HOST_PLATFORM": "overrides the platform name (win32, darwin or linux)",
    "CLAUDE_CODE_HOST_SHORT_TEMP_DIRS": "how temporary directories are named",
    "CLAUDE_CODE_HOST_WORKTREE": "a fence for file writes; the headless call has no tools",
    "CLAUDE_CODE_HOST_WORKTREE_FENCE": "a fence for file writes; the headless call has no tools",
    "CLAUDE_CODE_HOST_SKILL_CATALOG": "a list of skill folders; the headless call loads no skills",
    "CLAUDE_CODE_IDE_HOST_OVERRIDE": "the address of an IDE connection",
    "CLAUDE_CHROME_TAB_GROUP_KEY": "a browser tab group key",
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
