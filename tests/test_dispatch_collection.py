"""dispatch_collection (D42-6): the ad.collect dispatch path, against fixtures.

No Docker, no real bloodhound-python, no real LDAP bind — deliberately.
D44 wires this dispatch path to a real Credential Vault (`control_plane.
vault.vault`), so the credential-shaped gap `docs/ADR_BLOODHOUND_NEO4J.md`
§4.3 named is closed — but a real LDAP bind still cannot happen here, for a
reason that has shifted: there is now a real, encrypted credential this
suite can mint and mount, but there is still no real
``bloodhound-python`` Docker image (no `tool_gateway/images/build_
bloodhound_image.sh` exists), a separate, still-open gap the Vault alone
does not close. `StubSandbox` remains the right tool for the same reason
`tests/test_capability_budget.py`'s own copy is: what is under test here is
the control plane's accounting — the state machine, the two-artifact write,
fail-closed behavior, and now the credential mount/cleanup lifecycle — not
whether a container can run.

D50 F1: every ad.collect capability here is *credentialed* (``_credentialed_
capability``). The real bloodhound-python has no credential-free mode, so
``build_plan`` no longer builds an uncredentialed plan and ``dispatch_collection``
refuses one as ``UNBUILDABLE_PLAN``; until D50 the default capability in this
file was the uncredentialed one, and its "normal path" ran a command no real
container could ever have succeeded with, under a ``StubSandbox`` that never
executed it.

This file's stub stdout is this adapter's own documented intermediate JSON
shape (``tool_gateway.adapters.ad_collector.parse_graph``'s docstring), not
bloodhound-python's native per-object-type output — that translation is
separately flagged as unverified in the adapter's own module docstring.
"""

from __future__ import annotations

import json
import os
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
from control_plane.state.db import credential_admin_scope, engagement_scope
from control_plane.vault.vault import store_credential
from tool_gateway import registry
from tool_gateway.adapters import ad_collector
from tool_gateway.sandbox import SandboxResult, SandboxUnavailable

REAL_DOMAIN_SECRET = "hunter2_real_domain_password"  # noqa: S105 - synthetic test fixture

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
            run_id=None, stdin=None, ca_cert_pem=None, tmpfs=None, source_mounts=None):
        self.runs.append({
            "command": list(command), "allowlist": list(network_allowlist),
            "source_mounts": dict(source_mounts or {}),
        })
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


def _capability(
    conn, engagement_id: str, *, action: str = "ad.collect", constraints=None,
    credential_id: str | None = None,
):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action=action, actor="orchestrator",
        constraints=constraints or {"collection_methods": ["Group", "ACL"]},
        budget=Budget(max_duration_seconds=60),
        ttl_seconds=60, credential_id=credential_id,
    )
    assert result.issued is True, result.reasons
    return result.capability


DEFAULT_CONSTRAINTS = {"collection_methods": ["Group", "ACL"], "domain_username": "svc-account"}


def _credentialed_capability(conn, engagement_id: str, *, action: str = "ad.collect", **extra):
    """An ad.collect capability that can actually be dispatched: it names a bind
    identity in its constraints *and* carries the vault credential behind it.
    ``extra`` adds/overrides constraints (e.g. ``dns_server``).
    """
    return _capability(
        conn, engagement_id, action=action,
        constraints={**DEFAULT_CONSTRAINTS, **extra},
        credential_id=_store_domain_credential(engagement_id),
    )


def _store_domain_credential(engagement_id: str, *, secret: str = REAL_DOMAIN_SECRET) -> str:
    credential_id = _uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label="svc-account", credential_type="ad_domain_bind", secret=secret,
            actor="test-harness",
        )
    return credential_id


def _dispatch(conn, engagement_id, capability, *, sandbox, target=TARGET_DOMAIN):
    return dispatch_collection(
        conn, engagement_id=engagement_id,
        proposal_id=_proposal(conn, engagement_id, action=capability.action),
        capability=capability, target=target, actor="orchestrator",
        sandbox=sandbox, network_allowlist=["10.0.0.0/8"],
        execution_context={"nonce": uuid.uuid4().hex},
    )


def _last_refusal(conn, engagement_id: str):
    return conn.execute(
        text("SELECT reasons, payload FROM audit_log WHERE engagement_id = :e "
             "AND event_type = 'tool_run.refused' ORDER BY ts DESC LIMIT 1"),
        {"e": engagement_id},
    ).mappings().one()


def test_normal_path_records_evidence_and_a_security_graph_batch(engagement_id):
    with engagement_scope(engagement_id) as conn:
        capability = _credentialed_capability(conn, engagement_id)
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
    """Credentialed on purpose: with an uncredentialed capability this would be
    refused too (D50 F1), for the wrong reason, and prove nothing about the
    target check.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _credentialed_capability(conn, engagement_id)
        outcome = _dispatch(
            conn, engagement_id, capability, sandbox=_ExplodingSandbox(),
            target="",
        )
        assert outcome.state == FAILED
        assert outcome.reason == UNBUILDABLE_PLAN
        assert _last_refusal(conn, engagement_id)["payload"]["error"] == "no target"


def test_an_unparseable_collection_result_is_audited_but_does_not_fail_the_run(engagement_id):
    """The tool exited cleanly (status stays SUCCEEDED); the *second* write
    (the graph batch) is what failed, and that is a distinct, separately
    audited fact -- not a re-judgment of whether the tool itself succeeded.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _credentialed_capability(conn, engagement_id)
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
        capability = _credentialed_capability(conn, engagement_id)
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
        capability = _credentialed_capability(conn, engagement_id)
        outcome = _dispatch(conn, engagement_id, capability, sandbox=_UnavailableSandbox())
        assert outcome.state == UNKNOWN_OUTCOME


def test_domain_username_without_a_credential_id_is_refused_as_unbuildable(engagement_id):
    """A capability that declares a bind username but carries no credential_id
    has nothing for mount_for_run to mint -- refused before any sandbox call,
    the same as any other unbuildable plan (D44).
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id,
            constraints={"collection_methods": ["Group"], "domain_username": "svc-account"},
            credential_id=None,
        )
        outcome = _dispatch(conn, engagement_id, capability, sandbox=_ExplodingSandbox())
        assert outcome.state == FAILED
        assert outcome.reason == UNBUILDABLE_PLAN


def test_dns_server_outside_network_allowlist_is_refused_as_unbuildable(engagement_id):
    """D49: a new authorization dimension nothing before it had modeled. A
    dns_server naming an address outside the dispatch's own
    network_allowlist must be refused before any sandbox work, fail-closed,
    the same as domain_username-without-credential_id above.
    """
    with engagement_scope(engagement_id) as conn:
        # Credentialed (D50 F1): otherwise the refusal below would come from
        # the missing bind identity, and this test would keep passing with
        # the dns_server check deleted.
        capability = _credentialed_capability(conn, engagement_id, dns_server="203.0.113.5")
        outcome = _dispatch(conn, engagement_id, capability, sandbox=_ExplodingSandbox())
        assert outcome.state == FAILED
        assert outcome.reason == UNBUILDABLE_PLAN

        refusal = _last_refusal(conn, engagement_id)
        assert UNBUILDABLE_PLAN in refusal["reasons"]
        assert "203.0.113.5" in refusal["payload"]["error"]
        assert "dns_server" in refusal["payload"]["error"]


def test_dns_server_inside_network_allowlist_reaches_the_sandbox(engagement_id):
    """The mirror of the refusal above: an authorized dns_server is passed
    straight through to the real command, unmodified, and the run proceeds
    exactly as any other successful collection would.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _credentialed_capability(conn, engagement_id, dns_server="10.0.0.53")
        sandbox = StubSandbox()
        outcome = _dispatch(conn, engagement_id, capability, sandbox=sandbox)
        assert outcome.state == SUCCEEDED, outcome.reason
        assert len(sandbox.runs) == 1
        command = sandbox.runs[0]["command"]
        # The credentialed command is a shell wrapper: -ns lives inside the
        # script text, the address is its own positional argument ($6).
        assert '-ns "$6"' in command[2]
        assert command[-1] == "10.0.0.53"


def _assert_refused_before_any_run_or_credential_mount(conn, engagement_id: str, outcome):
    assert outcome.state == FAILED
    assert outcome.reason == UNBUILDABLE_PLAN
    assert outcome.run_id is None
    assert conn.execute(
        text("SELECT COUNT(*) FROM tool_runs WHERE engagement_id = :e"),
        {"e": engagement_id},
    ).scalar_one() == 0, "a refused plan must not create a tool_runs row"
    assert conn.execute(
        text("SELECT COUNT(*) FROM audit_log WHERE engagement_id = :e "
             "AND event_type = 'credential.issued_to_run'"),
        {"e": engagement_id},
    ).scalar_one() == 0, "a refused plan must not mint a credential file"


def test_ad_collect_without_a_domain_username_is_refused_as_unbuildable(engagement_id):
    """D50 F1. The real bloodhound-python has no credential-free mode: it prints
    its usage text and exits 1 without a username. Refused before the sandbox
    (``_ExplodingSandbox`` raises if reached), before a tool_runs row, and
    before any credential is minted -- the previous behaviour was to start a
    container that could only fail.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id, constraints={"collection_methods": ["Group", "ACL"]},
        )
        outcome = _dispatch(conn, engagement_id, capability, sandbox=_ExplodingSandbox())

        _assert_refused_before_any_run_or_credential_mount(conn, engagement_id, outcome)
        refusal = _last_refusal(conn, engagement_id)
        assert UNBUILDABLE_PLAN in refusal["reasons"]
        assert "domain_username" in refusal["payload"]["error"]
        assert "credential-free mode" in refusal["payload"]["error"]


def test_a_credential_with_no_domain_username_is_refused_and_never_mounted(engagement_id):
    """The other half of the same gap: a capability that carries a vault
    credential but names no bind identity used to run *uncredentialed*,
    silently ignoring the credential it was issued with. It is refused now, and
    the credential is never minted.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id, constraints={"collection_methods": ["Group"]},
            credential_id=_store_domain_credential(engagement_id),
        )
        outcome = _dispatch(conn, engagement_id, capability, sandbox=_ExplodingSandbox())

        _assert_refused_before_any_run_or_credential_mount(conn, engagement_id, outcome)
        assert "domain_username" in _last_refusal(conn, engagement_id)["payload"]["error"]


def test_a_credentialed_run_mounts_the_secret_and_cleans_it_up(engagement_id):
    credential_id = _store_domain_credential(engagement_id)
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id,
            constraints={"collection_methods": ["Group"], "domain_username": "svc-account"},
            credential_id=credential_id,
        )
        sandbox = StubSandbox()
        outcome = _dispatch(conn, engagement_id, capability, sandbox=sandbox)

        assert outcome.state == SUCCEEDED, outcome.reason
        assert len(sandbox.runs) == 1
        mounts = sandbox.runs[0]["source_mounts"]
        assert list(mounts.values()) == [ad_collector.CONTAINER_CRED_PATH]
        host_path = next(iter(mounts))
        # The dispatch already returned -- cleanup_mount runs in dispatch's
        # own finally block, so by now the file must be gone (D44-5).
        assert not os.path.exists(host_path)

        # The command bloodhound-python actually ran carries no secret --
        # only the fixed container path, never the plaintext.
        rendered = " ".join(sandbox.runs[0]["command"])
        assert REAL_DOMAIN_SECRET not in rendered

        row = conn.execute(
            text("SELECT execution_context FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).mappings().one()
        assert row["execution_context"]["credential_id"] == credential_id


def test_same_credential_same_domain_is_a_dedup_hit(engagement_id):
    credential_id = _store_domain_credential(engagement_id)
    constraints = {"collection_methods": ["Group"], "domain_username": "svc-account"}

    with engagement_scope(engagement_id) as conn:
        cap1 = _capability(
            conn, engagement_id, constraints=constraints, credential_id=credential_id,
        )
        first = dispatch_collection(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, action=cap1.action),
            capability=cap1, target=TARGET_DOMAIN, actor="orchestrator",
            sandbox=StubSandbox(), network_allowlist=["10.0.0.0/8"],
        )
        assert first.state == SUCCEEDED, first.reason

        cap2 = _capability(
            conn, engagement_id, constraints=constraints, credential_id=credential_id,
        )
        second = dispatch_collection(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, action=cap2.action),
            capability=cap2, target=TARGET_DOMAIN, actor="orchestrator",
            sandbox=_ExplodingSandbox(), network_allowlist=["10.0.0.0/8"],
        )
        assert second.reason == "dedup_hit"
        assert second.run_id == first.run_id


def test_a_different_credential_against_the_same_domain_is_not_a_dedup_hit(engagement_id):
    """D11-3's own lesson, applied to a credential rather than a network range
    or a commit: the same target under a different credential is a different
    execution and must not be served from cache.
    """
    constraints = {"collection_methods": ["Group"], "domain_username": "svc-account"}

    with engagement_scope(engagement_id) as conn:
        credential_a = _store_domain_credential(engagement_id, secret="secret-a-value")
        cap1 = _capability(conn, engagement_id, constraints=constraints, credential_id=credential_a)
        first = dispatch_collection(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, action=cap1.action),
            capability=cap1, target=TARGET_DOMAIN, actor="orchestrator",
            sandbox=StubSandbox(), network_allowlist=["10.0.0.0/8"],
        )
        assert first.state == SUCCEEDED, first.reason

        credential_b = _store_domain_credential(engagement_id, secret="secret-b-value")
        cap2 = _capability(conn, engagement_id, constraints=constraints, credential_id=credential_b)
        second = dispatch_collection(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, action=cap2.action),
            capability=cap2, target=TARGET_DOMAIN, actor="orchestrator",
            sandbox=StubSandbox(), network_allowlist=["10.0.0.0/8"],
        )
        assert second.reason != "dedup_hit"
        assert second.state == SUCCEEDED, second.reason
        assert second.run_id != first.run_id


def test_a_credentialed_run_cleans_up_the_secret_even_when_the_tool_fails(engagement_id):
    """D44-5: cleanup is unconditional, not contingent on the run succeeding."""
    credential_id = _store_domain_credential(engagement_id)
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id,
            constraints={"collection_methods": ["Group"], "domain_username": "svc-account"},
            credential_id=credential_id,
        )
        sandbox = StubSandbox(stdout="", exit_code=1)
        outcome = _dispatch(conn, engagement_id, capability, sandbox=sandbox)

        assert outcome.state == FAILED
        host_path = next(iter(sandbox.runs[0]["source_mounts"]))
        assert not os.path.exists(host_path)
