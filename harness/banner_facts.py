"""D69 H5c2 (E): the facts of the start-up banner, collected from where they really are.

``harness/banner.py`` only formats a dict of eleven facts (a closed set: a missing one and an extra
one are both refused). This module fills it, and each fact has one source -- none is typed in:

====================  ==============================================================================
database              ``DATABASE_URL`` (the runtime connection): host, database and user. Never the
                      password, and the URL itself is never printed.
migration_head        ``alembic_version`` of that database, read as ``cyberorch_app``.
switches              the effective policy of the **enrolled engagements**
                      (``load_effective_policy``), one value for the run: when the engagements
                      disagree, or none is enrolled, there is no single value to print and
                      :class:`BannerFactsUnavailable` is raised -- the run does not start on a
                      banner that could mislead.
action_set            ``harness.action_allowlist.ALLOWED_ACTIONS``.
engagements           the enrolment reader (``harness_enrolment``), in the order the loop visits.
role_models           ``model`` of the Supervisor, the Worker and the reviewer; ``(not set)`` for a
                      role that names none (a scripted role does not).
cli_version           the project's version, ``[project] version`` of ``pyproject.toml``. There is
                      no version of the command apart from it.
prompt_digests        SHA-256 of the Supervisor's system prompt and its plan schema, and of the
                      Worker's system prompt and its proposal schema. The schemas are built with
                      no scope object and the allowlisted actions (they are closed over what a
                      call may reference, so that is the form that does not depend on a round).
window_limit, caps    the arguments of the run (a cap that is not given is not a banner: the entry
                      script requires them all), and the token and minute caps (plan item 148),
                      which are optional on the entry script: one not given is handed in as
                      ``"not set"``.
lock_key              :data:`harness.lock.KEY`.
====================  ==============================================================================

Nothing here writes. It reads the database as ``cyberorch_app`` and files of the repository.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import make_url

from agents.llm.supervisor_base import plan_schema
from agents.llm.worker_base import WORKER_SYSTEM_PROMPT, proposal_schema
from control_plane.policy.layers import load_effective_policy
from control_plane.state.db import database_url, engagement_scope, get_engine
from harness.action_allowlist import ALLOWED_ACTIONS
from harness.lock import format_key

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
MODEL_NOT_SET = "(not set)"
LOCAL_SOCKET = "(local socket)"


class BannerFactsUnavailable(RuntimeError):
    """A fact cannot be stated truthfully; the message names the fact, never a value."""


def read_migration_head() -> str:
    with get_engine().connect() as conn:
        heads = conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
    if len(heads) != 1:
        raise BannerFactsUnavailable("migration_head: alembic_version does not hold one row")
    return heads[0]


def load_policy_of(engagement_id: str):
    with engagement_scope(engagement_id) as conn:
        return load_effective_policy(conn, engagement_id)


def _database() -> dict[str, str]:
    url = make_url(database_url())
    if not url.database or not url.username:
        raise BannerFactsUnavailable("database: the connection string names no database or user")
    return {"host": url.host or LOCAL_SOCKET, "name": url.database, "role": url.username}


def _switches(engagements: Sequence[str], load_policy: Callable[[str], object]) -> dict[str, bool]:
    if not engagements:
        raise BannerFactsUnavailable("switches: no engagement is enrolled, so no policy applies")
    values: dict[str, set[bool]] = {"task_relation_enforce": set(), "goal_fit_enforce": set()}
    for engagement_id in engagements:
        policy = load_policy(engagement_id)
        for name in values:
            values[name].add(bool(getattr(policy, name)))
    for name, seen in values.items():
        if len(seen) != 1:
            raise BannerFactsUnavailable(f"switches: the enrolled engagements disagree on {name}")
    return {name: next(iter(seen)) for name, seen in values.items()}


def version_of(pyproject_text: str) -> str:
    """``[project] version`` of the text of a ``pyproject.toml``."""
    version = tomllib.loads(pyproject_text).get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise BannerFactsUnavailable("cli_version: pyproject.toml names no project version")
    return version


def cli_version(path: Path = PYPROJECT) -> str:
    return version_of(path.read_text())


def digest(prompt: str, schema: dict) -> str:
    """SHA-256 of the prompt, a newline, and the schema as JSON with sorted keys."""
    h = hashlib.sha256()
    h.update(prompt.encode("utf-8"))
    h.update(b"\n")
    h.update(json.dumps(schema, sort_keys=True, ensure_ascii=True).encode("ascii"))
    return h.hexdigest()


def prompt_digests(supervisor: object) -> dict[str, str]:
    actions = tuple(ALLOWED_ACTIONS)
    return {
        "supervisor": digest(supervisor.system_prompt,
                             plan_schema(scope_object_ids=(), actions=actions)),
        "worker": digest(WORKER_SYSTEM_PROMPT,
                         proposal_schema(scope_object_ids=(), actions=actions)),
    }


def _model(role: object) -> str:
    return str(getattr(role, "model", "") or MODEL_NOT_SET)


def collect_banner_facts(
    *,
    engagements: Sequence[str],
    supervisor: object,
    worker: object,
    reviewer: object,
    window_limit: int,
    max_rounds: int,
    max_model_calls: int,
    no_progress_limit: int,
    max_tokens: int | str,
    max_minutes: int | str,
    load_policy: Callable[[str], object] = load_policy_of,
    migration_head: Callable[[], str] = read_migration_head,
) -> dict:
    """The eleven facts of ``harness.banner.format_banner``, read from their sources."""
    engagements = list(engagements)
    return {
        "database": _database(),
        "migration_head": migration_head(),
        "switches": _switches(engagements, load_policy),
        "action_set": list(ALLOWED_ACTIONS),
        "engagements": engagements,
        "role_models": {"supervisor": _model(supervisor), "worker": _model(worker),
                        "reviewer": _model(reviewer)},
        "cli_version": cli_version(),
        "prompt_digests": prompt_digests(supervisor),
        "window_limit": window_limit,
        "caps": {"max_rounds": max_rounds, "max_model_calls": max_model_calls,
                 "no_progress_limit": no_progress_limit, "max_tokens": max_tokens,
                 "max_minutes": max_minutes},
        "lock_key": format_key(),
    }
