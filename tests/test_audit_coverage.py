"""Audit coverage, the query interface, and what happens when auditing fails.

The inventory below is the D8 coverage audit turned into something that stays
true. A written-once checklist decays the moment someone adds an operation; a
test that exercises every state-changing path and asserts the event appears
fails when the next one is added without a record.

The audit found three real gaps and one missing control:

* ``claim_task`` recorded nothing, so the audit trail attributed every
  downstream event to the orchestrator and the agent that did the work appeared
  nowhere.
* Proposal submission was never attributed to the agent that submitted it.
* Evidence writes were only implied by ``tool_run.succeeded``.
* The engagement kill switch and pause had **no implementation at all** — the
  Capability Broker had checked both since D5, every test set them with raw
  SQL, and no operation existed to audit.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from sqlalchemy import text

from control_plane.audit.logger import AuditWriteError, record_audit
from control_plane.audit.query import (
    audited_event_types,
    engagement_timeline,
    events_for_subject,
    reconstruct_decision,
    reconstruct_task_history,
)
from control_plane.capability.broker import (
    CREDENTIAL_REVOKED,
    SCOPE_OBJECT_DEACTIVATED,
    Budget,
    consume_request,
    get_capability,
    issue_capability,
    renew_capability,
    revoke_capability,
)
from control_plane.orchestrator.engagement import (
    complete_engagement,
    engage_kill_switch,
    get_engagement,
    pause_engagement,
    resume_engagement,
    retire_scope_object,
    revoke_credential,
)
from control_plane.registry.metadata_registry import deactivate_metadata
from control_plane.registry.scope_registry import deactivate_scope_object
from control_plane.state.db import engagement_scope, registry_admin_scope


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Coverage inventory
# ---------------------------------------------------------------------------

def test_registry_operations_are_all_audited(engagement_id, registry):
    """register / reclassify / deactivate, for both registries (§5)."""
    scope_id, ident = _uid("SCOPE"), "audit.customer-a.com"
    registry.scope(scope_object_id=scope_id, type="fqdn", value=ident,
                   allowed_actions=["web.*"])
    registry.scope(scope_object_id=scope_id, type="fqdn", value=ident,
                   allowed_actions=["web.*", "web.post"])

    asset_id = _uid("ASSET")
    registry.metadata(asset_id=asset_id, identity_type="fqdn", identity_value=ident,
                      authority="AUTHORITATIVE", source="customer_declared",
                      data_class=["PII"])
    registry.metadata(asset_id=asset_id, identity_type="fqdn", identity_value=ident,
                      authority="AUTHORITATIVE", source="customer_declared",
                      data_class=["public_marketing"])

    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(conn, engagement_id=engagement_id,
                                scope_object_id=scope_id, actor="em")
        deactivate_metadata(conn, engagement_id=engagement_id, identity_type="fqdn",
                            identity_value=ident, authority="AUTHORITATIVE", actor="em")

    with engagement_scope(engagement_id) as conn:
        recorded = audited_event_types(conn)

    assert {"scope_object.registered", "scope_object.updated",
            "scope_object.deactivated", "metadata.registered",
            "metadata.reclassified", "metadata.deactivated"} <= recorded


def test_capability_lifecycle_is_fully_audited(engagement_id):
    """issue, renew-success, renew-failure, revoke, budget exhaustion (§4.6)."""
    with engagement_scope(engagement_id) as conn:
        good = issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(max_duration_seconds=120), ttl_seconds=60,
        )
        assert good.issued
        renewed = renew_capability(
            conn, engagement_id=engagement_id,
            capability_id=good.capability.capability_id, actor="orchestrator",
        )
        assert renewed.renewed is True

        # Exhaust the request budget: a refusal, therefore a decision.
        for _ in range(3):
            consume_request(conn, capability_id=good.capability.capability_id,
                            max_requests=1, engagement_id=engagement_id)

        revoke_capability(conn, engagement_id=engagement_id,
                          capability_id=good.capability.capability_id,
                          reason="operator_action", actor="operator")

        # A renewal that fails, on a second capability.
        doomed = issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(max_duration_seconds=120), ttl_seconds=60,
        )
        conn.execute(
            text("UPDATE capabilities SET lease_expires_at = now() - interval '1s' "
                 "WHERE capability_id = :c"),
            {"c": doomed.capability.capability_id},
        )
        assert renew_capability(
            conn, engagement_id=engagement_id,
            capability_id=doomed.capability.capability_id, actor="orchestrator",
        ).renewed is False

        # And a refusal to issue at all.
        conn.execute(
            text("UPDATE engagements SET status = 'paused' WHERE engagement_id = :e"),
            {"e": engagement_id},
        )
        refused = issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(), ttl_seconds=60,
        )
        assert refused.issued is False

        recorded = audited_event_types(conn)

    assert {"capability.issued", "capability.renewed", "capability.revoked",
            "capability.revoked_on_renewal", "capability.refused",
            "capability.budget_exhausted"} <= recorded


def test_engagement_lifecycle_is_audited(engagement_id):
    """The control that had no implementation before this deliverable.

    The broker had checked status and kill_switch_engaged since D5. Nothing
    could set them, so nothing could be audited, and "who stopped this
    engagement" had no answer.
    """
    with engagement_scope(engagement_id) as conn:
        issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(), ttl_seconds=60,
        )
        paused = pause_engagement(conn, engagement_id=engagement_id,
                                  actor="operator", reason="customer request")
        assert paused.status == "paused"
        # §1.2(e): pausing stops work in flight rather than letting leases lapse.
        assert len(paused.revoked_capabilities) == 1

        resume_engagement(conn, engagement_id=engagement_id, actor="operator",
                          reason="cleared")
        assert get_engagement(conn, engagement_id).accepts_work is True

        killed = engage_kill_switch(conn, engagement_id=engagement_id,
                                    actor="operator", reason="suspected compromise")
        assert killed.kill_switch_engaged is True

        recorded = audited_event_types(conn)

    assert {"engagement.paused", "engagement.resumed",
            "engagement.kill_switch_engaged"} <= recorded


def test_the_kill_switch_cannot_be_undone(engagement_id):
    """A kill switch that can be flicked back is a pause with a louder name."""
    with engagement_scope(engagement_id) as conn:
        engage_kill_switch(conn, engagement_id=engagement_id, actor="operator",
                           reason="suspected compromise")
        with pytest.raises(ValueError, match="kill switch"):
            resume_engagement(conn, engagement_id=engagement_id, actor="operator",
                              reason="looks fine now")
        # The attempt is on the record.
        assert any(
            e.event_type == "engagement.resume_refused"
            for e in engagement_timeline(conn)
        )


def test_completing_an_engagement_revokes_outstanding_capabilities(engagement_id):
    with engagement_scope(engagement_id) as conn:
        issued = issue_capability(
            conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            budget=Budget(), ttl_seconds=60,
        )
        state = complete_engagement(conn, engagement_id=engagement_id,
                                    actor="operator", summary="report delivered")
        assert issued.capability.capability_id in state.revoked_capabilities
        assert "engagement.completed" in audited_event_types(conn)


def test_task_claim_is_attributed_to_the_agent(engagement_id):
    """One of the gaps this deliverable found."""
    from agents.base_agent import ProposedTask
    from control_plane.api.function_api import claim_task, create_task

    with engagement_scope(engagement_id) as conn:
        task = ProposedTask(goal="scan", target={}, action="network.scan",
                            scope_object_id="SCOPE-1")
        task_id = create_task(conn, engagement_id=engagement_id, task=task,
                              created_by="fake-planner")
        claimed = claim_task(conn, engagement_id=engagement_id,
                             agent_id="fake-worker")
        assert claimed == task_id

        events = events_for_subject(conn, subject_id=task_id)

    kinds = {e.event_type: e for e in events}
    assert "task.claimed" in kinds
    # Attributed to the agent, not the orchestrator.
    assert kinds["task.claimed"].actor == "fake-worker"
    assert kinds["task.created"].actor == "fake-planner"


# ---------------------------------------------------------------------------
# The query interface
# ---------------------------------------------------------------------------

def test_reconstruct_decision_returns_an_ordered_grouped_chain(engagement_id):
    """The logic the scenario tests used to assemble by hand."""
    from agents.base_agent import ProposedAction
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import propose_action
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    policy = merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.81.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": "MISSING"},
        discovery={"source": "explicit_scope"},
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=policy, agent_id="fake-worker",
        )
        chain = reconstruct_decision(conn, proposal_id=outcome.proposal_id)

    assert chain.decision == "DENY"
    assert "target_out_of_scope" in chain.why()
    # Ordered by when they happened, not by however the rows came back.
    assert [e.audit_id for e in chain.events] == sorted(e.audit_id for e in chain.events)
    # Grouped by pipeline stage, in pipeline order.
    stages = list(chain.by_stage())
    assert stages == [s for s in ("proposal", "review", "decision") if s in stages]
    assert chain.executed is False
    assert chain.capability_ids == ()


def test_reconstruct_decision_follows_the_chain_into_capability_and_run(
    engagement_id, registry
):
    """A proposal's chain includes what it caused, not only its own events."""
    from agents.base_agent import ProposedAction
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import propose_action
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    scope_id = _uid("SCOPE")
    registry.scope(scope_object_id=scope_id, type="cidr", value="10.82.0.0/24",
                   allowed_actions=["network.scan"])
    policy = merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
    )

    class FailingSandbox:
        """Stands in for a gateway that cannot run — dispatch is not the point
        here, the shape of the reconstructed chain is."""

        def run(self, **kwargs):
            from tool_gateway.sandbox import SandboxUnavailable

            raise SandboxUnavailable("no docker in this test")

    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=policy, agent_id="fake-worker",
            sandbox=FailingSandbox(), network_allowlist=["10.82.0.0/24"],
        )
        chain = reconstruct_decision(conn, proposal_id=outcome.proposal_id)

    assert chain.decision == "ALLOW"
    assert outcome.capability_id in chain.capability_ids
    assert chain.run_ids, "the run started, so it belongs to the chain"
    types = {e.event_type for e in chain.events}
    assert "capability.issued" in types
    assert "tool_run.started" in types
    assert "tool_run.unknown_outcome" in types
    assert "capability" in chain.by_stage()
    assert "execution" in chain.by_stage()


def test_reconstruct_decision_exposes_the_reviewers_claim_beside_the_truth(
    engagement_id, registry
):
    """What makes an adversarial reviewer provable after the fact.

    Without the pairing, "the AI lied and was ignored" and "the AI was never
    consulted" are the same entry in the log.
    """
    from agents.base_agent import ProposedAction
    from agents.fake.adversarial_fake_reviewer import AdversarialFakeReviewer
    from control_plane.api.function_api import propose_action
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    scope_id = _uid("SCOPE")
    registry.scope(scope_object_id=scope_id, type="cidr", value="10.83.0.0/24",
                   allowed_actions=["network.scan"])
    registry.metadata(asset_id=_uid("ASSET"), identity_type="ip",
                      identity_value="10.83.0.5", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])
    policy = merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.83.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=AdversarialFakeReviewer(), policy=policy,
            agent_id="fake-worker",
        )
        chain = reconstruct_decision(conn, proposal_id=outcome.proposal_id)

    assert chain.decision == "DENY"
    claim = chain.reviewer_claim()
    truth = chain.contradicted_classification()
    assert claim["risk_hint"] == "low"
    assert claim["possible_sensitive_data_hint"] == []
    assert truth["data_class"] == ["PII"]
    assert truth["authority"] == "AUTHORITATIVE"


# ---------------------------------------------------------------------------
# reconstruct_task_history — the task-level view (§5.3)
# ---------------------------------------------------------------------------
# reconstruct_decision answers "what happened to this proposal". A task can
# produce more than one proposal and has a lifecycle of its own that the
# per-proposal view excludes on purpose. These pin the task-level aggregator:
# that it gathers the lifecycle events reconstruct_decision leaves out, that it
# reaches the per-proposal chains *by calling reconstruct_decision* rather than
# a second copy of the trace logic, and that doing so does not alter what
# reconstruct_decision returns.


def _task_with_two_proposals(engagement_id):
    """Create a task, claim it, submit two proposals under it, complete it.

    Both proposals name a scope object that does not exist, so both land on a
    clean DENY before any capability is minted or any sandbox is touched — the
    shape of the aggregated history is the point here, not dispatch.
    """
    from agents.base_agent import ProposedAction, ProposedTask
    from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
    from control_plane.api.function_api import (
        claim_task,
        complete_task,
        create_task,
        propose_action,
    )
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    policy = merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )

    with engagement_scope(engagement_id) as conn:
        task = ProposedTask(goal="scan the two hosts", target={},
                            action="network.scan", scope_object_id="SCOPE-none")
        task_id = create_task(conn, engagement_id=engagement_id, task=task,
                              created_by="fake-planner")
        claim_task(conn, engagement_id=engagement_id, agent_id="fake-worker")

        proposal_ids = []
        for host in ("10.90.0.5", "10.90.0.6"):
            proposal = ProposedAction(
                action="network.scan",
                target={"logical_identity": {"type": "ip", "value": host}},
                authorization={"source": "engagement_scope",
                               "scope_object_id": "MISSING"},
                discovery={"source": "explicit_scope"},
                task_id=task_id,
            )
            outcome = propose_action(
                conn, engagement_id=engagement_id, proposal=proposal,
                reviewer=HonestFakeReviewer(), policy=policy, agent_id="fake-worker",
            )
            proposal_ids.append(outcome.proposal_id)

        complete_task(conn, engagement_id=engagement_id, task_id=task_id,
                      result_summary="both denied", actor="fake-worker")

    return task_id, proposal_ids


def test_reconstruct_task_history_aggregates_lifecycle_and_each_proposal(engagement_id):
    """The task's own lifecycle, plus one reconstructed chain per proposal."""
    task_id, proposal_ids = _task_with_two_proposals(engagement_id)

    with engagement_scope(engagement_id) as conn:
        history = reconstruct_task_history(conn, task_id=task_id)

    # The lifecycle events reconstruct_decision leaves out are present here.
    lifecycle_kinds = {e.event_type for e in history.lifecycle_events}
    assert {"task.created", "task.claimed", "task.completed"} <= lifecycle_kinds
    assert history.completed is True

    # One chain per proposal, each a real DecisionChain. Order is the query's
    # own (created_at, then proposal_id) and is deterministic, but need not
    # equal submission order, so compare as a set.
    assert set(history.proposal_ids) == set(proposal_ids)
    assert len(history.decisions) == 2
    assert all(chain.decision == "DENY" for chain in history.decisions)
    assert history.decision_counts == {"DENY": 2}

    # The merged view is ordered, and the task's own events are not folded into
    # any single proposal's chain — they live only at the task level.
    merged = history.all_events()
    assert [e.audit_id for e in merged] == sorted(e.audit_id for e in merged)
    for chain in history.decisions:
        assert not any(e.event_type.startswith("task.") for e in chain.events)

    # The JSON and human renderings the CLI serves are well-formed on real data.
    from scripts.task_history import render

    doc = history.as_dict()
    assert doc["task_id"] == task_id
    assert doc["completed"] is True
    assert doc["decision_counts"] == {"DENY": 2}
    assert len(doc["proposals"]) == 2
    text_out = render(history)
    assert task_id in text_out
    assert "DENY" in text_out


def test_reconstruct_task_history_delegates_to_reconstruct_decision(
    engagement_id, monkeypatch
):
    """It calls reconstruct_decision once per proposal, not a rewritten trace.

    The D14-style proof that the shared logic is actually shared: spy on
    reconstruct_decision, delegating to the real one, and assert the task
    history reached every proposal through it.
    """
    import control_plane.audit.query as query_mod

    task_id, proposal_ids = _task_with_two_proposals(engagement_id)

    real = query_mod.reconstruct_decision
    seen: list[str] = []

    def spy(conn, *, proposal_id):
        seen.append(proposal_id)
        return real(conn, proposal_id=proposal_id)

    monkeypatch.setattr(query_mod, "reconstruct_decision", spy)

    with engagement_scope(engagement_id) as conn:
        history = query_mod.reconstruct_task_history(conn, task_id=task_id)

    # Every proposal was reconstructed through reconstruct_decision, exactly
    # once each, and the aggregator's own order is the order it delegated in.
    assert sorted(seen) == sorted(proposal_ids)
    assert seen == list(history.proposal_ids)


def test_reconstruct_task_history_does_not_alter_the_per_proposal_chain(engagement_id):
    """An embedded chain is identical to the standalone reconstruct_decision.

    Version A's guarantee: the task view aggregates reconstruct_decision without
    touching it. A DecisionChain is a frozen dataclass, so equality is
    structural — the chain the aggregator carries must equal the one a caller
    gets by asking reconstruct_decision directly, field for field.
    """
    task_id, proposal_ids = _task_with_two_proposals(engagement_id)

    with engagement_scope(engagement_id) as conn:
        history = reconstruct_task_history(conn, task_id=task_id)
        standalone = {
            pid: reconstruct_decision(conn, proposal_id=pid) for pid in proposal_ids
        }

    embedded = {chain.proposal_id: chain for chain in history.decisions}
    for pid in proposal_ids:
        assert embedded[pid] == standalone[pid]


# ---------------------------------------------------------------------------
# When the audit write itself fails
# ---------------------------------------------------------------------------

def test_a_failed_audit_write_raises_rather_than_passing_silently(
    engagement_id, monkeypatch, caplog
):
    """A working control that left no record is indistinguishable from one that
    did not run, and over time equally dangerous. So the write failing is loud."""
    from control_plane.audit import logger as audit_logger

    def broken_scope(_engagement_id):
        from sqlalchemy.exc import OperationalError

        raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    monkeypatch.setattr(audit_logger, "audit_scope", broken_scope)

    with caplog.at_level(logging.CRITICAL, logger="cyberorch.audit"):
        with pytest.raises(AuditWriteError, match="could not write audit record"):
            record_audit(
                engagement_id=engagement_id, actor="operator",
                event_type="test.event", subject_type="test", subject_id="SUBJ-1",
                decision="DENY", reasons=("something_important",),
            )

    # ...and the content is preserved on a channel that does not depend on the
    # database that just failed.
    assert caplog.records, "nothing was written to the application log"
    message = caplog.records[0].getMessage()
    assert "AUDIT WRITE FAILED" in message
    assert "test.event" in message
    assert "something_important" in message
    assert "SUBJ-1" in message


def test_a_failed_audit_write_takes_the_operation_down_with_it(
    engagement_id, monkeypatch
):
    """No unaudited state change survives.

    issue_capability audits after inserting. If the audit fails, the exception
    propagates out of the caller's transaction and the capability is rolled
    back with it — so the system never ends up holding a capability nothing
    recorded issuing.
    """
    from control_plane.audit import logger as audit_logger

    capability_id = _uid("CAP")
    real_scope = audit_logger.audit_scope

    def fail_on_issued(engagement):
        from sqlalchemy.exc import OperationalError

        raise OperationalError("INSERT INTO audit_log", {},
                               Exception("audit backend unavailable"))

    # AuditWriteError, not a bare exception: the failure is typed so a caller
    # cannot mistake it for an ordinary database hiccup and retry past it.
    with pytest.raises(AuditWriteError):
        with engagement_scope(engagement_id) as conn:
            monkeypatch.setattr(audit_logger, "audit_scope", fail_on_issued)
            issue_capability(
                conn, engagement_id=engagement_id, capability_id=capability_id,
                agent_id="fake-worker", action="network.scan", actor="orchestrator",
                budget=Budget(), ttl_seconds=60,
            )

    monkeypatch.setattr(audit_logger, "audit_scope", real_scope)
    with engagement_scope(engagement_id) as conn:
        surviving = conn.execute(
            text("SELECT count(*) FROM capabilities WHERE capability_id = :c"),
            {"c": capability_id},
        ).scalar_one()
    assert surviving == 0, (
        "a capability was issued that no audit record covers"
    )


# ---------------------------------------------------------------------------
# The two controls D9 added (§1.3.2, §4.5, I1, I9)
# ---------------------------------------------------------------------------

def test_revoking_a_credential_cascades_and_is_audited(engagement_id):
    """The cascade that D9 found named in a docstring and nowhere else.

    Before this, ``check_preconditions`` read ``credentials.revoked`` but no
    operation set it, so a pulled credential took effect at the next heartbeat
    if anything happened to heartbeat. The control now exists, it is eager, and
    the operation is on the record.
    """
    credential_id = _uid("CRED")
    capability_id = _uid("CAP")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("INSERT INTO credentials (credential_id, engagement_id, label) "
                 "VALUES (:c, :e, 'leaked')"),
            {"c": credential_id, "e": engagement_id},
        )
        issued = issue_capability(
            conn, engagement_id=engagement_id, capability_id=capability_id,
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            credential_id=credential_id, ttl_seconds=60,
        )
        assert issued.issued is True

        revoked = revoke_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            actor="operator", reason="credential leaked",
        )

    # Eager: revoked now, not at the next heartbeat.
    assert revoked == (capability_id,)
    with engagement_scope(engagement_id) as conn:
        stored = get_capability(conn, capability_id)
        assert stored.revoked is True
        assert CREDENTIAL_REVOKED in stored.revoked_reason
        assert "credential.revoked" in audited_event_types(conn)


def test_revoking_a_credential_leaves_capabilities_holding_another_alone(
    engagement_id
):
    """Precise, like the scope cascade: one credential, not the engagement."""
    pulled, kept = _uid("CRED"), _uid("CRED")
    doomed, bystander = _uid("CAP"), _uid("CAP")
    with engagement_scope(engagement_id) as conn:
        for cid in (pulled, kept):
            conn.execute(
                text("INSERT INTO credentials (credential_id, engagement_id, label) "
                     "VALUES (:c, :e, 'test')"),
                {"c": cid, "e": engagement_id},
            )
        for cap, cred in ((doomed, pulled), (bystander, kept)):
            issue_capability(
                conn, engagement_id=engagement_id, capability_id=cap,
                agent_id="fake-worker", action="network.scan", actor="orchestrator",
                credential_id=cred, ttl_seconds=60,
            )
        revoked = revoke_credential(
            conn, engagement_id=engagement_id, credential_id=pulled,
            actor="operator", reason="rotated",
        )

    assert revoked == (doomed,)
    with engagement_scope(engagement_id) as conn:
        assert get_capability(conn, doomed).revoked is True
        assert get_capability(conn, bystander).revoked is False


def test_retiring_a_scope_object_cascades_and_is_audited(engagement_id):
    """§4.5 + I1, and the operation the stateful test proved was missing."""
    from control_plane.registry.scope_registry import register_scope_object

    scope_object_id = _uid("SCOPE")
    capability_id = _uid("CAP")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="cidr", value="10.30.0.0/24", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
    with engagement_scope(engagement_id) as conn:
        issue_capability(
            conn, engagement_id=engagement_id, capability_id=capability_id,
            agent_id="fake-worker", action="network.scan", actor="orchestrator",
            constraints={"host": "10.30.0.5"}, scope_object_id=scope_object_id,
            ttl_seconds=60,
        )

    revoked = retire_scope_object(
        engagement_id=engagement_id, scope_object_id=scope_object_id,
        actor="engagement-manager", reason="out of scope",
    )

    assert revoked == (capability_id,)
    with engagement_scope(engagement_id) as conn:
        stored = get_capability(conn, capability_id)
        assert stored.revoked is True
        assert SCOPE_OBJECT_DEACTIVATED in stored.revoked_reason

        types = audited_event_types(conn)
        # Both halves are recorded: the registry edit and the cascade it caused.
        assert "scope_object.retired" in types
        assert "scope_object.deactivated" in types
        assert "capability.revoked" in types
