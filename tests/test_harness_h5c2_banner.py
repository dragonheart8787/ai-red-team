"""D69 H5c2 (E): the banner's eleven facts, collected from their sources (banner_facts.py).

The real facts are read from the test database and the repository and compared with what those say
when asked another way. What the test database cannot show -- a switch that is ON -- is shown with a
policy loader handed to the collector, because no switch is set on any engagement here.
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from agents.llm.supervisor_base import SUPERVISOR_SYSTEM_PROMPT, BaseSupervisor, plan_schema
from agents.llm.worker_base import WORKER_SYSTEM_PROMPT, proposal_schema
from control_plane.policy.layers import load_effective_policy
from control_plane.state.db import engagement_scope, get_engine
from harness.action_allowlist import ALLOWED_ACTIONS
from harness.banner import REQUIRED_FIELDS, format_banner
from harness.banner_facts import (
    BannerFactsUnavailable,
    cli_version,
    collect_banner_facts,
    digest,
    version_of,
)
from harness.enrolment_db import EnrolledFromDatabase
from tests.harness_h5c2_roles import build
from tests.test_harness_h5c1_support import make_world
from tests.test_harness_h5c2_support import enrolled

ROOT = Path(__file__).resolve().parents[1]
CAPS = {"max_rounds": 3, "max_model_calls": 40, "no_progress_limit": 2, "max_tokens": 9000,
        "max_minutes": 20}


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _collect(engagements, roles=None, **override):
    roles = roles or build()
    args = dict(engagements=engagements, supervisor=roles.supervisor, worker=roles.worker,
                reviewer=roles.reviewer, window_limit=25, **CAPS)
    args.update(override)
    return collect_banner_facts(**args)


def _digest(prompt, schema):
    body = json.dumps(schema, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(prompt.encode() + b"\n" + body.encode()).hexdigest()


def test_the_facts_are_the_ones_the_database_and_the_repository_give(world):
    with enrolled(world.engagement_id):
        engagements = list(EnrolledFromDatabase().enrolled())
        facts = _collect(engagements)

    assert sorted(facts) == sorted(REQUIRED_FIELDS)
    # database: the runtime role, asked of the server itself
    with get_engine().connect() as conn:
        user, name = conn.execute(text("SELECT current_user, current_database()")).one()
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    url = make_url(os.environ["DATABASE_URL"])
    assert facts["database"] == {"host": url.host, "name": name, "role": user}
    assert facts["migration_head"] == head
    # engagements: the real list, the one the loop would visit, in its order
    assert facts["engagements"] == engagements and world.engagement_id in engagements
    # switches: what the control plane's loader says for each enrolled engagement
    for engagement_id in engagements:
        with engagement_scope(engagement_id) as conn:
            policy = load_effective_policy(conn, engagement_id)
        assert facts["switches"] == {"task_relation_enforce": policy.task_relation_enforce,
                                     "goal_fit_enforce": policy.goal_fit_enforce}
    assert facts["action_set"] == list(ALLOWED_ACTIONS)
    assert facts["role_models"] == {"supervisor": "scripted-supervisor",
                                    "worker": "scripted-worker", "reviewer": "(not set)"}
    assert facts["cli_version"] == tomllib.loads((ROOT / "pyproject.toml").read_text())[
        "project"]["version"]
    actions = tuple(ALLOWED_ACTIONS)
    assert facts["prompt_digests"] == {
        "supervisor": _digest(SUPERVISOR_SYSTEM_PROMPT,
                              plan_schema(scope_object_ids=(), actions=actions)),
        "worker": _digest(WORKER_SYSTEM_PROMPT,
                          proposal_schema(scope_object_ids=(), actions=actions)),
    }
    assert facts["window_limit"] == 25 and facts["caps"] == CAPS
    assert facts["lock_key"] == "0x0D69_5C4E_D000_0001"


def test_the_banner_prints_every_field_in_order_and_never_the_password(world):
    with enrolled(world.engagement_id):
        facts = _collect(list(EnrolledFromDatabase().enrolled()))
    assert set(facts["database"]) == {"host", "name", "role"}
    banner = format_banner(facts)

    assert [line.split(":", 1)[0] for line in banner.splitlines()] == list(REQUIRED_FIELDS)
    password = make_url(os.environ["DATABASE_URL"]).password
    assert password and password not in banner and password not in str(facts)
    assert os.environ["DATABASE_URL"] not in banner


def test_the_switches_are_read_from_the_policy_of_the_enrolled_engagements():
    on = SimpleNamespace(task_relation_enforce=True, goal_fit_enforce=False)
    facts = _collect(["ENG-A", "ENG-B"], load_policy=lambda engagement_id: on,
                     migration_head=lambda: "0031")
    assert facts["switches"] == {"task_relation_enforce": True, "goal_fit_enforce": False}
    both = SimpleNamespace(task_relation_enforce=True, goal_fit_enforce=True)
    facts = _collect(["ENG-A"], load_policy=lambda engagement_id: both,
                     migration_head=lambda: "0031")
    assert facts["switches"] == {"task_relation_enforce": True, "goal_fit_enforce": True}


def test_engagements_that_disagree_on_a_switch_give_no_banner():
    policies = {"ENG-A": SimpleNamespace(task_relation_enforce=True, goal_fit_enforce=False),
                "ENG-B": SimpleNamespace(task_relation_enforce=False, goal_fit_enforce=False)}
    with pytest.raises(BannerFactsUnavailable) as caught:
        _collect(["ENG-A", "ENG-B"], load_policy=policies.__getitem__,
                 migration_head=lambda: "0031")
    assert "task_relation_enforce" in str(caught.value)


def test_no_enrolled_engagement_gives_no_banner():
    with pytest.raises(BannerFactsUnavailable) as caught:
        _collect([], migration_head=lambda: "0031")
    assert "switches" in str(caught.value)


def test_a_prompt_or_a_schema_that_changes_changes_its_digest():
    assert digest("a", {"x": 1}) != digest("b", {"x": 1})
    assert digest("a", {"x": 1}) != digest("a", {"x": 2})
    assert digest("a", {"x": 1, "y": 2}) == digest("a", {"y": 2, "x": 1})        # key order is not


def test_the_supervisor_arm_with_the_duplicate_warning_has_another_digest():
    plain = _collect(["E"], load_policy=lambda e: SimpleNamespace(
        task_relation_enforce=False, goal_fit_enforce=False), migration_head=lambda: "0031")
    warned_roles = build()
    warned_roles.supervisor = type("Warned", (BaseSupervisor,), {
        "agent_id": "w", "model": "m", "plan": lambda self, **k: []})(
        warn_about_duplicates=True)
    warned = _collect(["E"], roles=warned_roles, load_policy=lambda e: SimpleNamespace(
        task_relation_enforce=False, goal_fit_enforce=False), migration_head=lambda: "0031")
    assert warned["prompt_digests"]["supervisor"] != plain["prompt_digests"]["supervisor"]
    assert warned["prompt_digests"]["worker"] == plain["prompt_digests"]["worker"]


def test_the_cli_version_is_the_projects_and_a_missing_one_is_refused():
    assert cli_version() == tomllib.loads((ROOT / "pyproject.toml").read_text())[
        "project"]["version"]
    assert version_of("[project]\nversion = '1.2.3'\n") == "1.2.3"
    for text_without in ("[project]\nname = 'x'\n", "[tool]\nversion = '1'\n",
                         "[project]\nversion = ''\n"):
        with pytest.raises(BannerFactsUnavailable):
            version_of(text_without)
