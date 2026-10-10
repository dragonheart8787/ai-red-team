"""Every action the scheduler dispatches, driven through a tick (D63 audit, D62 D-0).

The scheduler's v0 action list is explicit -- ``network.scan``, ``network.recon``, ``code.scan``,
``code.secrets`` -- and each routes to a different dispatcher (``dispatch_scan`` for both network
actions, ``dispatch_code_scan`` for both code actions, each with its own tool image). A test of one
proves nothing about the others' routing, so each action gets its own: a human-approved proposal,
a tick, and a **real container** of the right tool, with the run, the evidence and the audit order
checked. The scheduler is given no sandbox, so each dispatch builds the one its tool needs.
"""

from __future__ import annotations

import uuid

import pytest

from agents.base_agent import ProposedAction
from control_plane.orchestrator import stages
from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.scheduler import vocab
from control_plane.state.db import registry_admin_scope
from tests import scheduler_support as sup
from tests.gitleaks_support import history_only_secret_repo
from tests.helpers import committing_scope


def _network_world(registry, engagement_id, action):
    scope_id = sup.register_scope(registry, type="cidr", value="10.96.76.0/24", actions=(action,))
    proposal = sup.proposal_for(scope_id, host="10.96.76.9", action=action)
    return scope_id, proposal


def _code_world(engagement_id, action, tmp_path):
    repo = history_only_secret_repo(tmp_path / "repo", filler_commits=1)
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_id, type="repo",
            value=repo.scope_value, allowed_actions=[action], actor="test-harness")
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=f"ASSET-{uuid.uuid4().hex[:8]}",
            identity_type="repo", identity_value=repo.scope_value, authority="AUTHORITATIVE",
            source="customer_declared", resource_class=["source_code"],
            data_class=["proprietary_source"], actor="test-harness")
    proposal = ProposedAction(
        action=action,
        target={"logical_identity": {"type": "repo", "value": repo.scope_value}},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"}, resources=("source_code",),
        expected_data=("finding",), reason="D63 scheduler per-action routing test",
        requested_capability_ttl_seconds=60)
    return scope_id, proposal


ACTIONS = [
    ("network.scan", "nmap"),
    ("network.recon", "nmap"),
    ("code.scan", "semgrep"),
    ("code.secrets", "gitleaks"),
]


@pytest.mark.parametrize("action,tool", ACTIONS)
def test_a_tick_dispatches_each_supported_action_to_its_own_tool(
    engagement_id, registry, tmp_path, action, tool,
):
    assert action in vocab.SUPPORTED_ACTIONS
    sup.publish_engagement_policy(engagement_id, actions=(action,))
    if action.startswith("network."):
        _, proposal = _network_world(registry, engagement_id, action)
    else:
        _, proposal = _code_world(engagement_id, action, tmp_path)
    pid = sup.escalate(engagement_id, proposal)
    approval = sup.approve(engagement_id, pid)
    sup.enroll(engagement_id)
    try:
        with sup.running() as sched:               # no sandbox: each dispatch builds its own
            report = sched.tick()
    finally:
        sup.withdraw(engagement_id)

    assert report.dispatched == [pid], report
    with committing_scope(engagement_id) as conn:
        assert stages.stage_of(conn, pid) == (stages.RECORDED, "succeeded")

    (run,) = sup.rows(
        engagement_id, "SELECT tool, status, exit_code, capability_id FROM tool_runs")
    assert (run["tool"], run["status"], run["exit_code"]) == (tool, "succeeded", 0)
    (cap,) = sup.rows(engagement_id, "SELECT capability_id, action, approval_id FROM capabilities")
    assert (cap["capability_id"], cap["action"], cap["approval_id"]) == (
        run["capability_id"], action, approval.approval_id)
    assert len(sup.rows(engagement_id, "SELECT 1 FROM evidence")) == 1

    # decided, then issued, then run -- in that order, by the scheduler
    ids = {e["event_type"]: e["audit_id"] for e in sup.audit(engagement_id)
           if e["event_type"] in ("approval.granted", "scheduler.dispatched",
                                  "capability.issued", "tool_run.started", "tool_run.succeeded")}
    assert set(ids) == {"approval.granted", "scheduler.dispatched", "capability.issued",
                        "tool_run.started", "tool_run.succeeded"}, ids
    assert (ids["approval.granted"] < ids["scheduler.dispatched"] < ids["capability.issued"]
            < ids["tool_run.started"] < ids["tool_run.succeeded"])
    (decided,) = sup.audit(engagement_id, "scheduler.dispatched")
    assert decided["payload"] == {"proposal_id": pid, "reason_code": vocab.APPROVED_AND_IDLE}
