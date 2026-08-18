"""Scenario A — the ALLOW path, end to end (§10).

    authorized target
      → Authorization Resolver confirms action ∈ scope_object.allowed_actions
      → Metadata Resolver finds a known, permitted classification
      → OPA ALLOW
      → capability issued
      → tool executes
      → evidence written (raw + derived)
      → state and provenance updated
      → audit trail complete and traceable

Driven entirely through ``propose_action``. The stages are deliberately not
wired together by hand: a test that assembles the pipeline itself verifies the
assembly the test wrote, and MVP-0 will ship the one in function_api.

The scan is real — a container, a live target, and nmap. §10 asks for evidence
written from a tool run, and evidence manufactured by a stub would leave the
one thing this scenario exists to prove untested.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.fake.fake_planner import FakePlanner, scan_task
from agents.fake.fake_worker import FakeWorker
from control_plane.api.function_api import (
    claim_task,
    complete_task,
    create_task,
    propose_action,
    query_evidence,
)
from control_plane.audit.query import engagement_timeline, reconstruct_decision
from control_plane.evidence.store import read_raw_artifact, verify_artifact
from control_plane.provenance import graph
from control_plane.state.db import engagement_scope
from tests.scenarios.conftest import ALLOWED_CIDR, RecordingSandbox, uid


@pytest.fixture
def engagement(engagement_id, registry, scan_target):
    """An engagement whose scope authorizes scanning the live target."""
    scope_object_id = uid("SCOPE")
    registry.scope(
        scope_object_id=scope_object_id, type="cidr", value=ALLOWED_CIDR,
        allowed_actions=["network.recon", "network.scan"],
    )
    registry.metadata(
        asset_id=uid("ASSET"), identity_type="ip", identity_value=scan_target,
        authority="AUTHORITATIVE", source="customer_declared",
        resource_class=["network_host"], data_class=["network_service"],
    )
    return engagement_id, scope_object_id


def _run_scenario_a(engagement, sandbox, effective_policy, scan_target,
                    reviewer=None):
    engagement_id, scope_object_id = engagement
    spy = RecordingSandbox(sandbox)
    planner = FakePlanner([scan_task(target_ip=scan_target,
                                     scope_object_id=scope_object_id)])
    worker = FakeWorker()
    reviewer = reviewer or HonestFakeReviewer(risk_hint="low")

    with engagement_scope(engagement_id) as conn:
        task = planner.plan(engagement_id=engagement_id)[0]
        task_id = create_task(conn, engagement_id=engagement_id, task=task,
                              created_by=planner.agent_id)
        claimed = claim_task(conn, engagement_id=engagement_id,
                             agent_id=worker.agent_id)
        proposal = worker.propose(task=task, task_id=task_id)

        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=reviewer, policy=effective_policy,
            agent_id=worker.agent_id, sandbox=spy,
            network_allowlist=[ALLOWED_CIDR],
            execution_context={"auth_context_id": "AUTHCTX-A"},
        )
        complete_task(conn, engagement_id=engagement_id, task_id=task_id,
                      result_summary=f"scan {outcome.decision}",
                      actor=worker.agent_id)
    return outcome, spy, task_id, claimed


def test_scenario_a_authorized_scan_runs_and_writes_evidence(
    engagement, sandbox, effective_policy, scan_target
):
    """The ALLOW path reaches the tool and produces real evidence."""
    engagement_id, _ = engagement
    outcome, spy, task_id, claimed = _run_scenario_a(
        engagement, sandbox, effective_policy, scan_target
    )

    assert claimed == task_id
    assert outcome.decision == "ALLOW", (outcome.deny_reasons, outcome.approval_reasons)
    assert outcome.deny_reasons == ()
    assert outcome.metadata_authority == "AUTHORITATIVE"

    # The tool actually ran, once.
    assert spy.call_count == 1
    assert outcome.capability_id is not None
    assert outcome.run_id is not None
    assert outcome.evidence_id is not None

    with engagement_scope(engagement_id) as conn:
        run = conn.execute(
            text("SELECT status, tool, tool_version, execution_fingerprint, "
                 "execution_context, network_allowlist FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).mappings().one()
        assert run["status"] == "succeeded"
        assert run["tool"] == "nmap"
        # §7: the fingerprint exists and carries the execution context.
        assert len(run["execution_fingerprint"]) == 64
        assert run["execution_context"] == {"auth_context_id": "AUTHCTX-A"}
        assert run["network_allowlist"] == [ALLOWED_CIDR]

        # §4.4: raw immutable artifact plus a derived, untrusted view.
        evidence = conn.execute(
            text("SELECT raw_artifact_path, raw_sha256, raw_logically_immutable, "
                 "derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id},
        ).mappings().one()
        assert evidence["raw_logically_immutable"] is True
        assert verify_artifact(conn, outcome.evidence_id) is True
        assert evidence["derived_view"]["untrusted_content"] is True
        assert any(
            p["port"] == 8080 and p["state"] == "open"
            for p in evidence["derived_view"]["open_ports"]
        ), evidence["derived_view"]

        raw = read_raw_artifact(evidence["raw_artifact_path"])
        assert scan_target.encode() in raw

        # The agent-facing query returns the derived view and never the raw
        # artifact (§4.4).
        visible = query_evidence(conn, evidence_id=outcome.evidence_id)
        assert "derived_view" in visible
        assert "raw_artifact_path" not in visible


def test_scenario_a_provenance_chain_is_written_and_traversable(
    engagement, sandbox, effective_policy, scan_target
):
    """§8.10: the first end-to-end write to provenance_edges.

    Before this deliverable the table had never been written by any code path.
    A chain that exists only in the design is not a chain, so this walks the
    edges backwards from the evidence to the scope object that authorized
    collecting it.
    """
    engagement_id, scope_object_id = engagement
    outcome, _, task_id, _ = _run_scenario_a(
        engagement, sandbox, effective_policy, scan_target
    )
    assert outcome.evidence_id is not None

    with engagement_scope(engagement_id) as conn:
        chain = graph.why(conn, node_type="evidence", node_id=outcome.evidence_id)

    assert chain, "provenance_edges is empty: nothing recorded the chain"
    relations = {(e.from_type, e.to_type, e.relation) for e in chain}

    # evidence ← tool_run ← capability ← proposal ← scope_object
    assert ("tool_run", "evidence", graph.PRODUCED) in relations
    assert ("capability", "tool_run", graph.EXECUTED) in relations
    assert ("action_proposal", "capability", graph.ISSUED) in relations
    assert ("scope_object", "action_proposal", graph.AUTHORIZED) in relations

    # The authorizing scope object is reachable from the evidence, which is the
    # §8.10 audit question: what permitted collecting this?
    authorizers = {e.from_id for e in chain if e.from_type == "scope_object"}
    assert scope_object_id in authorizers

    # And the classification that was consulted.
    assert any(e.from_type == "asset" for e in chain), (
        "the asset classification is not in the chain"
    )


def test_scenario_a_audit_trail_reconstructs_the_decision(
    engagement, sandbox, effective_policy, scan_target
):
    """§10: who, what classification, why ALLOW, capability, execution.

    Reconstructed from audit_log alone, because that is the artifact an
    investigator has.
    """
    engagement_id, _ = engagement
    outcome, _, task_id, _ = _run_scenario_a(
        engagement, sandbox, effective_policy, scan_target
    )

    with engagement_scope(engagement_id) as conn:
        chain = reconstruct_decision(conn, proposal_id=outcome.proposal_id)
        timeline = engagement_timeline(conn)

    # The chain answers the §10 question directly, without this test having to
    # know how audit_log is laid out.
    assert chain.decision == "ALLOW"
    assert chain.why() == ()
    assert chain.executed is True
    assert outcome.capability_id in chain.capability_ids
    assert outcome.run_id in chain.run_ids
    assert list(chain.by_stage()) == ["proposal", "review", "decision",
                                      "capability", "execution"]

    types = {e.event_type for e in chain.events}
    assert {"proposal.submitted", "policy_reviewer.opinion", "policy.decided",
            "capability.issued", "tool_run.started", "evidence.recorded",
            "tool_run.succeeded"} <= types

    decided = next(e for e in chain.events if e.event_type == "policy.decided")
    # Why: the classification OPA actually saw.
    assert decided.payload["resource_metadata"]["classification"]["authority"] == (
        "AUTHORITATIVE"
    )
    assert decided.payload["authorization"]["authorized"] is True
    assert chain.reviewer_claim()["risk_hint"] == "low"

    started = next(e for e in chain.events if e.event_type == "tool_run.started")
    assert started.payload["network_allowlist"] == [ALLOWED_CIDR]
    assert "/usr/bin/nmap" in started.payload["command"]

    # The task lifecycle sits outside the proposal's chain, so it is checked
    # against the engagement timeline instead.
    engagement_events = {e.event_type for e in timeline}
    assert {"task.created", "task.claimed", "task.completed"} <= engagement_events


def test_scenario_a_reviewer_may_still_escalate(
    engagement, sandbox, effective_policy, scan_target
):
    """The reviewer is not ignored — §5 lets it tighten.

    Without this, a pipeline that discarded the reviewer entirely would pass
    every adversarial test in Scenario B while being wrong about the design.
    """
    engagement_id, _ = engagement
    outcome, spy, _, _ = _run_scenario_a(
        engagement, sandbox, effective_policy, scan_target,
        reviewer=HonestFakeReviewer(risk_hint="high"),
    )

    assert outcome.decision == "HUMAN_APPROVAL"
    assert "high_risk" in outcome.approval_reasons
    # Escalation stops the pipeline too: no capability, no execution.
    assert outcome.capability_id is None
    assert spy.call_count == 0
