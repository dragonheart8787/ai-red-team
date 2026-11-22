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
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
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
BILLING_VARIABLES: tuple[str, ...] = DECIDED + SAME_KIND

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


def _settings_problem(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return f"{path} cannot be read as JSON, so its apiKeyHelper cannot be ruled out"
    if not isinstance(settings, dict):
        return f"{path} is not a JSON object, so its apiKeyHelper cannot be ruled out"
    keys = [key for key in SETTINGS_KEYS if settings.get(key)]
    return f"{path} sets {', '.join(keys)}" if keys else None


def problems(environ: Mapping[str, str], paths: Iterable[Path]) -> list[str]:
    """One line per thing present, naming a variable or a settings key and never a value."""
    found = [f"{name} is set" for name in present_variables(environ)]
    found += [problem for problem in map(_settings_problem, paths) if problem]
    return found


def subprocess_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """``environ`` (default ``os.environ``) without the variables of :data:`BILLING_VARIABLES`."""
    source = os.environ if environ is None else environ
    return {key: value for key, value in source.items() if key not in BILLING_VARIABLES}
