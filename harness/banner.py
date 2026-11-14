"""D69 H5a1 (a6): the start-up banner, as a pure formatter of a dict of facts.

The banner states what a run is about to do, so that a person reading the first lines of its output
can tell (plan item 47, choice 3.3: standard output only). This module only *formats*: it reads no
database, no environment and no file, and the caller collects the facts.

The facts are a **closed** set of eleven fields; a missing one and an extra one are both a
``ValueError``. An extra one matters most: a caller that adds ``database_url`` or ``password`` to
the dict must be refused, not printed. The message of a refusal names the field, never a value.

::

    database          host, name, role
    migration_head
    switches          task_relation_enforce, goal_fit_enforce        (booleans)
    action_set        a list of action names
    engagements       a list of engagement ids
    role_models       role -> model
    cli_version
    prompt_digests    supervisor, worker
    window_limit      a positive int
    caps              max_rounds, max_model_calls, no_progress_limit  (a positive int or "not set")
    lock_key          "0x" and hexadecimal digits (underscores between groups allowed)

One line per field, in this order. Lists keep the order they were given; a mapping is printed in
the order of its sorted keys, so the same facts always give the same text. An empty list or
mapping is printed as ``(none)``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

NOT_SET = "not set"
NONE = "(none)"

REQUIRED_FIELDS = (
    "database", "migration_head", "switches", "action_set", "engagements", "role_models",
    "cli_version", "prompt_digests", "window_limit", "caps", "lock_key",
)

_DATABASE_KEYS = ("host", "name", "role")
_SWITCH_KEYS = ("task_relation_enforce", "goal_fit_enforce")
_DIGEST_KEYS = ("supervisor", "worker")
_CAP_KEYS = ("max_rounds", "max_model_calls", "no_progress_limit")
_LOCK_KEY = re.compile(r"0x[0-9a-fA-F]+(_[0-9a-fA-F]+)*")


def _text(field: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is a non-empty string")
    return value


def _exact(field: str, value: object, keys: tuple[str, ...]) -> Mapping:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} is a mapping")
    missing = [k for k in keys if k not in value]
    extra = sorted(str(k) for k in value if k not in keys)
    if missing or extra:
        raise ValueError(f"{field}: missing {missing}, not allowed {extra}")
    return value


def _positive(field: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} is an int of at least 1")
    return value


def _texts(field: str, value: object) -> list[str]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ValueError(f"{field} is a list of strings")
    return [_text(field, item) for item in value]


def _database(value: object) -> str:
    d = _exact("database", value, _DATABASE_KEYS)
    return " ".join(f"{k}={_text('database.' + k, d[k])}" for k in _DATABASE_KEYS)


def _switches(value: object) -> str:
    s = _exact("switches", value, _SWITCH_KEYS)
    parts = []
    for key in _SWITCH_KEYS:
        if not isinstance(s[key], bool):
            raise ValueError(f"switches.{key} is a bool")
        parts.append(f"{key}={'true' if s[key] else 'false'}")
    return " ".join(parts)


def _listed(field: str, value: object) -> str:
    items = _texts(field, value)
    return ", ".join(items) if items else NONE


def _role_models(value: object) -> str:
    if not isinstance(value, Mapping):
        raise ValueError("role_models is a mapping")
    pairs = [f"{_text('role_models', k)}={_text('role_models', value[k])}" for k in sorted(value)]
    return ", ".join(pairs) if pairs else NONE


def _digests(value: object) -> str:
    d = _exact("prompt_digests", value, _DIGEST_KEYS)
    return " ".join(f"{k}={_text('prompt_digests.' + k, d[k])}" for k in _DIGEST_KEYS)


def _caps(value: object) -> str:
    c = _exact("caps", value, _CAP_KEYS)
    parts = []
    for key in _CAP_KEYS:
        v = c[key]
        shown = NOT_SET if isinstance(v, str) and v == NOT_SET else str(_positive("caps." + key, v))
        parts.append(f"{key}={shown}")
    return " ".join(parts)


def _lock_key(value: object) -> str:
    if not isinstance(value, str) or not _LOCK_KEY.fullmatch(value):
        raise ValueError("lock_key is '0x' and hexadecimal digits")
    return value


_RENDER = {
    "database": _database,
    "migration_head": lambda v: _text("migration_head", v),
    "switches": _switches,
    "action_set": lambda v: _listed("action_set", v),
    "engagements": lambda v: _listed("engagements", v),
    "role_models": _role_models,
    "cli_version": lambda v: _text("cli_version", v),
    "prompt_digests": _digests,
    "window_limit": lambda v: str(_positive("window_limit", v)),
    "caps": _caps,
    "lock_key": _lock_key,
}


def format_banner(facts: Mapping) -> str:
    """The banner for ``facts``: one ``<field>: <value>`` line per field, in a fixed order."""
    if not isinstance(facts, Mapping):
        raise ValueError("the facts are a mapping")
    missing = [f for f in REQUIRED_FIELDS if f not in facts]
    extra = sorted(str(f) for f in facts if f not in REQUIRED_FIELDS)
    if missing or extra:
        raise ValueError(f"banner facts: missing {missing}, not allowed {extra}")
    lines = [f"{name}: {_RENDER[name](facts[name])}" for name in REQUIRED_FIELDS]
    return "\n".join(lines)
