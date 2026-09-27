"""dispatch_collection (D42-6): the ad.collect dispatch path, against fixtures.

No Docker, no real bloodhound-python, no real LDAP bind — deliberately.
§2.1/§4.3 of docs/D42_1_D42_6_DESIGN.md are explicit that this adapter has
no live/production path until the Credential Vault exists: there is no
credential anywhere in this system for a real collection run to authenticate
with, so there is no real domain this suite could collect against even with
Docker available. What is tested here is the control plane's own accounting
around a collection run — the state machine, the two-artifact write
(bounded evidence + the Security Graph batch), and fail-closed behavior —
using ``StubSandbox`` (the same no-Docker pattern ``tests/
test_capability_budget.py`` already uses for the identical reason: "what is
under test here is the control plane's accounting, and a container would
only make the test slower and less able to run anywhere").

**Real LDAP bind and a real bloodhound-python run remain untested, and must
stay that way until the Credential Vault deliverable lands** (docs/
ADR_BLOODHOUND_NEO4J.md §4.3). This file's stub stdout is this adapter's own
documented intermediate JSON shape (``tool_gateway.adapters.ad_collector
.parse_graph``'s docstring), not bloodhound-python's native per-object-type
output — that translation is separately flagged as unverified in the
adapter's own module docstring.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy import text

from control_plane.capability.broker import Budget, issue_capability
from control_plane.orchestrator.dispatch import (
    FAILED,
    SUCCEEDED,
    UNBUILDABLE_PLAN,
    UNKNOWN_OUTCOME,
    UNPARSEABLE_COLLECTION_RESULT,
    dispatch_collection,
)
from control_plane.state.db import engagement_scope
from tool_gateway import registry
from tool_gateway.sandbox import SandboxResult, SandboxUnavailable

TARGET_DOMAIN = "corp.example.com"

FIXTURE_GRAPH = json.dumps({
    "nodes": [
        {"identity_type": "fqdn", "identity_value": "usera@corp.example.com", "kind": "user"},
        {"identity_type": "fqdn", "identity_value": "wkstn1.corp.example.com", "kind": "computer"},
        {"identity_type": "fqdn", "identity_value": "domain admins", "kind": "group"},
    ],
    "edges": [
        {"src": "usera@corp.example.com", "dst": "wkstn1.corp.example.com", "edge_type": "AdminTo"},
        {"src": "wkstn1.corp.example.com", "dst": "domain admins", "edge_type": "MemberOf"},
    ],
})


class StubSandbox:
    """Records what it was asked to run and answers with canned stdout.

    Same shape as test_capability_budget.py's StubSandbox: no Docker, no
    mocked tool behaviour to verify against itself -- what these tests check
    is what dispatch_collection does with whatever the sandbox returns.
    """

    def __init__(self, *, stdout: str = FIXTURE_GRAPH, exit_code: int = 0) -> None:
        self.runs: list[dict] = []
        self.stdout = stdout
        self.exit_code = exit_code

    def run(self, *, command, network_allowlist, max_duration_seconds,
            run_id=None, stdin=None, ca_cert_pem=None, tmpfs=None):
        self.runs.append({"command": list(command), "allowlist": list(network_allowlist)})
        return SandboxResult(
            exit_code=self.exit_code, stdout=self.stdout, stderr="",
            timed_out=False, duration_seconds=0.1,
            network_allowlist=tuple(network_allowlist), image="stub",
        )


class _ExplodingSandbox:
    """Reaching the sandbox at all would mean an unbuildable plan was missed."""

    def run(self, **kwargs):  # pragma: no cover - the assertion is the point
        raise AssertionError(f"the sandbox was reached: {kwargs}")


class _UnavailableSandbox:
    def run(self, **kwargs):
        raise SandboxUnavailable("stub: sandbox could not start")


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _proposal(conn, engagement_id: str, *, action: str = "ad.collect") -> str:
    proposal_id = _uid("PROP")
    conn.execute(
        text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, dispatch_state, action, target,
                "authorization", discovery)
            VALUES (:pid, :eid, 'fake-worker', :key, 'queued', :action,
                    CAST(:target AS jsonb), CAST(:auth AS jsonb),
                    CAST(:disc AS jsonb))
        """),
        {
            "pid": proposal_id, "eid": engagement_id, "key": f"key-{proposal_id}",
            "action": action,
            "target": (
                f'{{"logical_identity": {{"type": "ad_domain", "value": "{TARGET_DOMAIN}"}}}}'
            ),
            "auth": '{"source": "engagement_scope", "scope_object_id": "SCOPE-1"}',
            "disc": '{"source": "explicit_scope"}',
        },
    )
    return proposal_id


def _capability(conn, engagement_id: str, *, action: str = "ad.collect", constraints=None):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action=action, actor="orchestrator",
        constraints=constraints or {"collection_methods": ["Group", "ACL"]},
        budget=Budget(max_duration_seconds=60),
        ttl_seconds=60,
    )
    assert result.issued is True, result.reasons
    return result.capability


def _dispatch(conn, engagement_id, capability, *, sandbox, target=TARGET_DOMAIN):
    return dispatch_collection(
        conn, engagement_id=engagement_id,
        proposal_id=_proposal(conn, engagement_id, action=capability.action),
        capability=capability, target=target, actor="orchestrator",
        sandbox=sandbox, network_allowlist=["10.0.0.0/8"],
        execution_context={"nonce": uuid.uuid4().hex},
    )


def test_normal_path_records_evidence_and_a_security_graph_batch(engagement_id):
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = _dispatch(conn, engagement_id, capability, sandbox=StubSandbox())

        assert outcome.state == SUCCEEDED, outcome.reason
        assert outcome.evidence_id is not None

        node_count = conn.execute(
            text("SELECT COUNT(*) FROM security_graph_nodes WHERE first_seen_run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one()
        edge_count = conn.execute(
            text("SELECT COUNT(*) FROM security_graph_edges WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one()
        assert node_count == 3
        assert edge_count == 2

        audit_rows = conn.execute(
            text("SELECT payload FROM audit_log WHERE subject_id = :r "
                 "AND event_type = 'security_graph.recorded'"),
            {"r": outcome.run_id},
        ).mappings().all()
        assert len(audit_rows) == 1
        assert audit_rows[0]["payload"]["node_count"] == 3
        assert audit_rows[0]["payload"]["edge_count"] == 2

        # The bounded, prompt-facing summary -- never the full graph.
        derived_view = conn.execute(
            text("SELECT derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id},
        ).scalar_one()
        assert derived_view["untrusted_content"] is True
        assert derived_view["computers_seen"] == 1
        assert derived_view["users_seen"] == 1
        assert derived_view["groups_seen"] == 1


def test_wrong_action_on_the_capability_is_refused_before_anything_runs(engagement_id):
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, action="network.scan")
        outcome = dispatch_collection(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, action="network.scan"),
            capability=capability, target=TARGET_DOMAIN, actor="orchestrator",
            sandbox=_ExplodingSandbox(),
        )
        assert outcome.state == FAILED
        assert outcome.reason == registry.UNKNOWN_ACTION


def test_an_invalid_domain_target_is_refused_as_unbuildable(engagement_id):
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = _dispatch(
            conn, engagement_id, capability, sandbox=_ExplodingSandbox(),
            target="",
        )
        assert outcome.state == FAILED
        assert outcome.reason == UNBUILDABLE_PLAN


def test_an_unparseable_collection_result_is_audited_but_does_not_fail_the_run(engagement_id):
    """The tool exited cleanly (status stays SUCCEEDED); the *second* write
    (the graph batch) is what failed, and that is a distinct, separately
    audited fact -- not a re-judgment of whether the tool itself succeeded.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = _dispatch(
            conn, engagement_id, capability,
            sandbox=StubSandbox(stdout="not json at all", exit_code=0),
        )
        assert outcome.state == SUCCEEDED, outcome.reason

        node_count = conn.execute(
            text("SELECT COUNT(*) FROM security_graph_nodes WHERE first_seen_run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one()
        assert node_count == 0

        rows = conn.execute(
            text("SELECT reasons FROM audit_log WHERE subject_id = :r "
                 "AND event_type = 'security_graph.record_failed'"),
            {"r": outcome.run_id},
        ).mappings().all()
        assert len(rows) == 1
        assert UNPARSEABLE_COLLECTION_RESULT in rows[0]["reasons"]


def test_a_failed_tool_run_never_attempts_a_graph_write(engagement_id):
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = _dispatch(
            conn, engagement_id, capability,
            sandbox=StubSandbox(stdout="", exit_code=1),
        )
        assert outcome.state == FAILED

        rows = conn.execute(
            text("SELECT event_type FROM audit_log WHERE subject_id = :r "
                 "AND event_type LIKE 'security_graph%'"),
            {"r": outcome.run_id},
        ).mappings().all()
        assert rows == [], "a failed tool run must not attempt either graph audit event"


def test_sandbox_unavailable_is_unknown_outcome_not_failed(engagement_id):
    """§8.8/I7: the tool may or may not have run. FAILED would invite a retry."""
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = _dispatch(conn, engagement_id, capability, sandbox=_UnavailableSandbox())
        assert outcome.state == UNKNOWN_OUTCOME
