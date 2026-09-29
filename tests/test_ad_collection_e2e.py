"""ad.collect through the real propose_action entry point (D47/D48).

D45 found `propose_action` never routed `ad.collect` to `dispatch_collection`
at all -- every real call ran the generic `dispatch_scan` instead, silently
dropping the Security Graph write `dispatch_collection` exists to perform --
plus three other real bugs alongside it (the wrong `bloodhound-python`
binary path, `execution_constraints` dropping every `ad.collect` field,
`dispatch_collection` never looking up `adapter.IMAGE`). All four were found
only because D45 drove a one-time, real-infrastructure, non-CI live-run
script (`scripts/live_run/d45_ad_collection_e2e.py`) through the real entry
point -- nothing before it, and nothing added afterward until this file,
ever called `propose_action` for `ad.collect` at all. D47's own
merge-readiness audit found that gap explicitly (`docs/
D47_MERGE_READINESS_AUDIT.md` §1) and this file is what closes it: a
permanent, CI-committed regression test, mirroring `test_web_render_e2e.py`'s
own two-tier design (D37) -- a stand-in for the container here, `D45`'s real
Samba AD DC and real bloodhound-python execution as the one-time proof no CI
runner should carry a recurring dependency on.

**Why real Samba stays out of the CI push gate, considered and rejected, not
silently skipped (D48).** D45 already established, independently and twice
over (`ldap3`'s Sicily-only NTLM bind; `impacket`'s Kerberos TGS-REQ never
setting the Authenticator checksum), that `bloodhound-python`'s own
authentication cannot succeed against Samba's AD DC implementation for
reasons in those two libraries, not in this project's adapter -- a fact that
will not change from one CI run to the next. A per-push real-Samba job would
spend real, recurring time re-confirming a static fact it can never get past
to reach the success path this file already covers: `nowsci/samba-domain`
is a third-party, unauthenticated Docker Hub pull (subject to anonymous rate
limiting -- confirmed empirically during D48's own investigation: two
consecutive `docker pull nowsci/samba-domain` attempts from this project's
dev environment both returned `429 Too Many Requests` on the first try, with
no retry needed to reproduce it) on top of real domain provisioning time.
See `docs/D48_AD_COLLECT_CI_E2E_REPORT.md` for the full reasoning and the
recommendation on whether a periodic (not per-push) real-Samba job is worth
the low expected information gain.

**What this file actually drives**: the full, real `propose_action`
pipeline -- Target Canonicalizer -> Authorization Resolver -> Metadata
Resolver -> Policy Reviewer -> OPA -> Capability Broker -> the real
`dispatch_collection` -- with only the container substituted, **at the
class level**, not the instance level. `dispatch_collection` constructs
`DockerSandbox` itself (`DockerSandbox(image=adapter_image) if adapter_image
else DockerSandbox()`) whenever the caller passes `sandbox=None` --
patching the class rather than handing in a pre-built instance is what lets
this test observe *which image `dispatch_collection` chose on its own*
(D45's fourth bug), instead of a caller that already knew the right image
picking it before the fixed code path is ever reached (which is what D45's
own live-run script did, and why it never actually exercised this
particular fallback).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import text

import control_plane.orchestrator.dispatch as dispatch_module
from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.capability.broker import Budget
from control_plane.orchestrator.dispatch import UNBUILDABLE_PLAN
from control_plane.policy.layers import publish_policy_layer
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import (
    credential_admin_scope,
    engagement_scope,
    registry_admin_scope,
)
from control_plane.vault.vault import store_credential
from tool_gateway.adapters import ad_collector
from tool_gateway.sandbox import SandboxResult

ACTOR = "test-harness"
DOMAIN = "corp.example.com"
REAL_DOMAIN_SECRET = "hunter2_e2e_secret"  # noqa: S105 - synthetic test fixture

#: The adapter's own documented intermediate JSON shape
#: (`ad_collector.parse_graph`'s docstring) -- the same fixture
#: `test_dispatch_collection.py` already uses, reused here rather than
#: re-invented so both files agree on what a "successful collection" output
#: actually looks like.
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


class _RecordingDockerSandbox:
    """Stands in for `DockerSandbox` at the class level (see module docstring).

    Every instance records the `image` it was constructed with -- the fact
    under test for D45's fourth bug -- and every `run()` call records the
    real command `dispatch_collection`'s adapter built, so the test can
    assert on the fixed binary path (D45's first bug) without needing a real
    container to execute it in.
    """

    instances: list[_RecordingDockerSandbox] = []

    def __init__(self, *, image: str | None = None) -> None:
        self.image = image
        self.runs: list[dict[str, Any]] = []
        _RecordingDockerSandbox.instances.append(self)

    def run(self, *, command, network_allowlist, max_duration_seconds, run_id=None,
            stdin=None, ca_cert_pem=None, tmpfs=None, source_mounts=None):
        self.runs.append({
            "command": list(command), "network_allowlist": list(network_allowlist),
            "source_mounts": dict(source_mounts or {}),
        })
        return SandboxResult(
            exit_code=0, stdout=FIXTURE_GRAPH, stderr="",
            timed_out=False, duration_seconds=0.05,
            network_allowlist=tuple(network_allowlist), image=self.image or "stub",
        )


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset(), actions={"ad.collect": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _setup(engagement_id: str) -> str:
    """Real ad_domain scope (D42-1 Option C: ad.collect only) against the
    engagement the ``engagement_id`` fixture already created via
    ``create_engagement`` (see tests/conftest.py's ``make_engagement``).
    """
    scope_object_id = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="ad_domain", value=DOMAIN, allowed_actions=["ad.collect"], actor=ACTOR,
        )
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {"ad.collect": "ALLOW"}}, actor=ACTOR,
            scoped_to_engagement=True,
        )
    return scope_object_id


def _store_credential(engagement_id: str) -> str:
    credential_id = _uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label="svc-account", credential_type="ad_domain_bind",
            secret=REAL_DOMAIN_SECRET, actor=ACTOR,
        )
    return credential_id


def _proposal(scope_object_id: str, credential_username: str | None = None) -> ProposedAction:
    target: dict[str, Any] = {
        "logical_identity": {"type": "ad_domain", "value": DOMAIN},
        "collection_methods": ["Group", "ACL"],
    }
    if credential_username is not None:
        target["domain_username"] = credential_username
        target["auth_mode"] = "password"
    return ProposedAction(
        action="ad.collect", target=target,
        authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
        resources=("ad_object",), expected_data=("group_membership", "acl"),
        reason="D47/D48 permanent propose_action regression test",
    )


def test_ad_collect_runs_end_to_end_through_propose_action(engagement_id, monkeypatch):
    """The chain `propose_action` -> OPA -> Capability Broker ->
    `dispatch_collection` -> Security Graph write, driven for real, with
    explicit assertions for each of D45's four bugs -- not just "it ran
    without raising".
    """
    _RecordingDockerSandbox.instances.clear()
    monkeypatch.setattr(dispatch_module, "DockerSandbox", _RecordingDockerSandbox)

    scope_object_id = _setup(engagement_id)
    credential_id = _store_credential(engagement_id)
    proposal = _proposal(scope_object_id, credential_username="svc-account")

    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="test-worker",
            actor=ACTOR, sandbox=None, network_allowlist=["10.0.0.0/8"],
            budget=Budget(max_duration_seconds=90), credential_id=credential_id,
        )

    assert outcome.decision == "ALLOW", outcome.deny_reasons
    assert outcome.capability_id is not None
    assert outcome.run_id is not None

    # Bug 4 (D45): dispatch_collection must resolve adapter.IMAGE itself when
    # handed no sandbox -- not DockerSandbox's own nmap-shaped default.
    assert len(_RecordingDockerSandbox.instances) == 1, (
        "dispatch_collection should construct exactly one sandbox instance"
    )
    sandbox_used = _RecordingDockerSandbox.instances[0]
    assert sandbox_used.image == ad_collector.IMAGE, (
        f"dispatch_collection picked image={sandbox_used.image!r}, "
        f"expected the adapter's own {ad_collector.IMAGE!r}"
    )

    # Bug 1 (D45): the real binary path, not the historical wrong one.
    assert len(sandbox_used.runs) == 1
    rendered_command = " ".join(sandbox_used.runs[0]["command"])
    assert ad_collector.BLOODHOUND_PYTHON_PATH in rendered_command
    assert "/usr/bin/bloodhound-python" not in rendered_command
    # The plaintext secret must never appear in the command dispatch records.
    assert REAL_DOMAIN_SECRET not in rendered_command

    # Bug 3 (D45): execution_constraints must have carried domain_username/
    # auth_mode/collection_methods through onto the issued capability --
    # confirmed by checking the mount actually happened (only reachable if
    # constraints.domain_username survived) and the real params fingerprint.
    with engagement_scope(engagement_id) as conn:
        capability_row = conn.execute(
            text("SELECT constraints FROM capabilities WHERE capability_id = :c"),
            {"c": outcome.capability_id},
        ).mappings().one()
    constraints = capability_row["constraints"]
    assert constraints["domain_username"] == "svc-account"
    assert constraints["auth_mode"] == "password"
    assert constraints["collection_methods"] == ["Group", "ACL"]
    assert list(sandbox_used.runs[0]["source_mounts"].values()) == [
        ad_collector.CONTAINER_CRED_PATH
    ], "a domain_username capability must have triggered a real credential mount"

    # Bug 2 (D45): dispatch_collection, not dispatch_scan, must have been
    # reached -- proven by the Security Graph write dispatch_scan cannot
    # perform, not merely by a tool_runs row existing (dispatch_scan would
    # have made one of those too).
    with engagement_scope(engagement_id) as conn:
        node_count = conn.execute(
            text("SELECT COUNT(*) FROM security_graph_nodes WHERE first_seen_run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one()
        edge_count = conn.execute(
            text("SELECT COUNT(*) FROM security_graph_edges WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one()
        recorded_event = conn.execute(
            text("SELECT payload FROM audit_log WHERE subject_id = :r "
                 "AND event_type = 'security_graph.recorded'"),
            {"r": outcome.run_id},
        ).mappings().one()
    assert node_count == 3
    assert edge_count == 2
    assert recorded_event["payload"]["node_count"] == 3
    assert recorded_event["payload"]["edge_count"] == 2


def test_ad_collect_without_a_credential_is_refused_by_dispatch_collection(
    engagement_id, monkeypatch,
):
    """D50 F1 (this test used to assert the opposite). An ``ad.collect`` proposal
    with no ``domain_username`` is authorized and issued a capability like any
    other -- nothing upstream knows the real tool has no credential-free mode --
    and is then refused by ``dispatch_collection`` itself, through the real
    entry point, before any container is constructed.

    Until D50 this test ran the uncredentialed command through a recording
    sandbox and asserted the run "succeeded" and wrote three graph nodes. That
    was true only because the sandbox never executed the command: the real
    bloodhound-python prints its usage text and exits 1 for it.
    """
    _RecordingDockerSandbox.instances.clear()
    monkeypatch.setattr(dispatch_module, "DockerSandbox", _RecordingDockerSandbox)

    scope_object_id = _setup(engagement_id)
    proposal = _proposal(scope_object_id, credential_username=None)

    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="test-worker",
            actor=ACTOR, sandbox=None, network_allowlist=["10.0.0.0/8"],
            budget=Budget(max_duration_seconds=90),
        )

    # Authorized and issued a capability -- the refusal is dispatch's, not
    # policy's...
    assert outcome.decision == "ALLOW", outcome.deny_reasons
    assert outcome.capability_id is not None
    # ...and it happens before anything runs.
    assert outcome.run_id is None
    assert outcome.failure == UNBUILDABLE_PLAN
    assert _RecordingDockerSandbox.instances == [], (
        "a refused plan must not construct a sandbox at all"
    )

    with engagement_scope(engagement_id) as conn:
        # dispatch_collection (not dispatch_scan) made the refusal: its own
        # adapter's name and its own error text are on the audit row.
        refusal = conn.execute(
            text("SELECT reasons, payload FROM audit_log WHERE engagement_id = :e "
                 "AND event_type = 'tool_run.refused'"),
            {"e": engagement_id},
        ).mappings().one()
        assert UNBUILDABLE_PLAN in refusal["reasons"]
        assert refusal["payload"]["tool"] == ad_collector.TOOL
        assert "domain_username" in refusal["payload"]["error"]
        # Nothing ran, so nothing was recorded.
        assert conn.execute(
            text("SELECT COUNT(*) FROM tool_runs WHERE engagement_id = :e"),
            {"e": engagement_id},
        ).scalar_one() == 0
        assert conn.execute(
            text("SELECT COUNT(*) FROM security_graph_nodes WHERE engagement_id = :e"),
            {"e": engagement_id},
        ).scalar_one() == 0
