"""The duration ceiling: one number, the policy that enforces it, and what it does not touch (D64).

``max_duration_seconds`` was bounded by nothing: whoever built the ``Budget`` chose it, and a day
was legal. ``authz.rego`` now denies a request above ``MAX_DURATION_CEILING_SECONDS`` (and one that
is below 1 or not a number), at the one decision point, so no capability is minted for it. The Rego
unit tests pin the boundary; here are the parts that need Python and a database.
"""

from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.api import approvals
from control_plane.capability.broker import Budget, issue_capability
from control_plane.policy.ceiling import MAX_DURATION_CEILING_SECONDS
from control_plane.state.db import engagement_scope
from tests.test_pipeline_stages import CIDR, FakeSandbox, go, only, snapshot

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def test_the_python_constant_and_the_rego_ceiling_are_one_number():
    rego = (REPO / "control_plane" / "policy" / "rego" / "authz.rego").read_text()
    found = re.findall(r"^max_duration_ceiling_seconds\s*:=\s*(\d+)\s*$", rego, re.M)
    assert found == [str(MAX_DURATION_CEILING_SECONDS)], (
        f"authz.rego says {found}, control_plane/policy/ceiling.py says "
        f"{MAX_DURATION_CEILING_SECONDS}")


def test_no_budget_the_code_builds_is_one_the_policy_would_refuse():
    """Every ``Budget(max_duration_seconds=N)`` and every default the code relies on is at or under
    the ceiling -- so the ceiling is a bound on what callers *could* ask, not a new way for the
    existing paths to be denied."""
    assert Budget().max_duration_seconds <= MAX_DURATION_CEILING_SECONDS
    assert approvals._APPROVED_BUDGET_SECONDS <= MAX_DURATION_CEILING_SECONDS
    over = []
    for root in ("control_plane", "tool_gateway", "agents"):
        for path in (REPO / root).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.keyword) and node.arg == "max_duration_seconds" and \
                        isinstance(node.value, ast.Constant) and isinstance(node.value.value, int) \
                        and node.value.value > MAX_DURATION_CEILING_SECONDS:
                    over.append((str(path.relative_to(REPO)), node.value.value))
    assert not over, f"budgets above the ceiling are built in code: {over}"


def test_a_request_above_the_ceiling_is_denied_and_nothing_is_minted_or_run(world):
    sandbox = FakeSandbox()
    outcome = go(world, sandbox=sandbox,
                 budget=Budget(max_duration_seconds=MAX_DURATION_CEILING_SECONDS + 1))

    assert outcome.decision == "DENY"
    assert "budget_duration_exceeds_ceiling" in outcome.deny_reasons
    snap = snapshot(world["engagement_id"])
    assert snap["capabilities"] == 0 and snap["runs"] == [] and sandbox.calls == 0
    assert only(snap)["stage"] == "closed"


def test_a_request_exactly_at_the_ceiling_runs(world):
    sandbox = FakeSandbox()
    outcome = go(world, sandbox=sandbox,
                 budget=Budget(max_duration_seconds=MAX_DURATION_CEILING_SECONDS))
    assert outcome.decision == "ALLOW" and outcome.run_id and sandbox.calls == 1


@pytest.mark.parametrize("seconds", [0, -1])
def test_a_duration_below_one_is_denied(world, seconds):
    outcome = go(world, budget=Budget(max_duration_seconds=seconds))
    assert outcome.decision == "DENY" and "budget_duration_invalid" in outcome.deny_reasons


def test_a_capability_issued_before_the_ceiling_existed_is_not_touched_by_it(world):
    """The policy gates *decisions*. A capability that already exists with a longer budget keeps
    the budget it was issued with and lives until its lease ends -- the lease is the shorter of the
    requested ttl and the budget, so it cannot outlive its own budget. Nothing rewrites it. What
    bounds a dispatch that runs on one is the reconciler's ``min(budget, ceiling)``."""
    eid = world["engagement_id"]
    with engagement_scope(eid) as conn:
        issued = issue_capability(
            conn, engagement_id=eid, capability_id=f"CAP-{uuid.uuid4().hex[:8]}",
            agent_id="a", action="network.scan", actor="test",
            budget=Budget(max_duration_seconds=5000), ttl_seconds=60,
        )
        assert issued.issued
        row = conn.execute(text(
            "SELECT budget ->> 'max_duration_seconds', lease_expires_at - issued_at "
            "FROM capabilities")).one()
    assert row[0] == "5000"                                   # the budget is recorded as issued
    assert row[1].total_seconds() == 60                       # and the lease is the shorter
