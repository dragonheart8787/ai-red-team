"""code.scan through the real propose_action entry point (D47/D48).

D45 found `propose_action` never routed `code.scan` to `dispatch_code_scan`
at all -- every real call ran the generic `dispatch_scan` instead, which
would have started a container with nothing mounted at `CONTAINER_REPO_PATH`
(`dispatch_code_scan`'s own control-plane-side git fetch never runs), plus
`execution_constraints` silently dropping `exclude_paths`. Both were found
only because D45 drove `ad.collect` through the real entry point and then
grepped for the identical shape of gap in `code.scan`'s own wiring; nothing
had ever driven `code.scan` through `propose_action` itself, before or
since, until this file. D47's own merge-readiness audit found that gap
explicitly (`docs/D47_MERGE_READINESS_AUDIT.md` §1) and this file closes it.

Unlike `ad.collect` (see `tests/test_ad_collection_e2e.py`), `code.scan` has
no upstream client-library wall blocking a real success path -- Semgrep
against a real git repository over real HTTP already works reliably
(`tests/test_dispatch_code_scan.py`'s own real-container suite), so this
file needs no stand-in tier at all: it drives the real `propose_action`
against a real Semgrep container and a real git-over-HTTP server, and
asserts a real, successful outcome.

Reuses, rather than re-invents, two pieces of existing real infrastructure:
`private_git_server` (`tests/test_git_fetch_credential.py`'s real, in-process
`git http-backend` behind a real HTTP Basic Auth gate -- no Docker, no
third-party pull, pure Python) and the `sandbox` fixture pattern
`tests/test_dispatch_code_scan.py` already established for a real
`cyberorch/semgrep:local` container.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.capability.broker import Budget
from control_plane.policy.layers import publish_policy_layer
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import credential_admin_scope, engagement_scope, registry_admin_scope
from control_plane.vault.vault import store_credential
from tests.test_git_fetch_credential import REAL_TOKEN, private_git_server  # noqa: F401
from tool_gateway.adapters import semgrep
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

ACTOR = "test-harness"


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox(image=semgrep.IMAGE)
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "code.scan through propose_action is tested against a real "
            "Semgrep run on purpose; build the image with "
            "tool_gateway/images/build_semgrep_image.sh.",
            pytrace=False,
        )
    return box


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset(), actions={"code.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _setup(engagement_id: str, repo_value: str) -> str:
    """Real repo scope, plus the AUTHORITATIVE classification `code.*`
    actions require (`requires_known_classification`, D32/D43) -- both real
    registry writes, not a shortcut around the permission path they enforce.
    """
    scope_object_id = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="repo", value=repo_value, allowed_actions=["code.scan"], actor=ACTOR,
        )
        from control_plane.registry.metadata_registry import register_metadata

        register_metadata(
            conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
            identity_type="repo", identity_value=repo_value,
            authority="AUTHORITATIVE", source="customer_declared",
            resource_class=["source_code"], data_class=["proprietary_source"],
            actor=ACTOR,
        )
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {"code.scan": "ALLOW"}}, actor=ACTOR,
            scoped_to_engagement=True,
        )
    return scope_object_id


def _store_credential(engagement_id: str) -> str:
    credential_id = _uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label="git PAT", credential_type="git_token", secret=REAL_TOKEN, actor=ACTOR,
        )
    return credential_id


def test_code_scan_runs_end_to_end_through_propose_action(
    engagement_id, sandbox, private_git_server,  # noqa: F811 - pytest fixture
):
    """The chain `propose_action` -> OPA -> Capability Broker ->
    `dispatch_code_scan` -> a real git fetch -> a real Semgrep container,
    driven for real, with explicit assertions for D45's two applicable bugs
    (routing; `execution_constraints` dropping `exclude_paths`) -- not just
    "it ran without raising".
    """
    repo_value = f"{private_git_server}#main"
    scope_object_id = _setup(engagement_id, repo_value)
    credential_id = _store_credential(engagement_id)

    proposal = ProposedAction(
        action="code.scan",
        target={
            "logical_identity": {"type": "repo", "value": repo_value},
            "exclude_paths": ["vendor/", "node_modules/"],
        },
        authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
        resources=("source_code",), expected_data=("finding",),
        reason="D47/D48 permanent propose_action regression test",
    )

    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="test-worker",
            actor=ACTOR, sandbox=sandbox, network_allowlist=["10.0.0.0/8"],
            budget=Budget(max_duration_seconds=90), credential_id=credential_id,
        )

    assert outcome.decision == "ALLOW", outcome.deny_reasons
    assert outcome.capability_id is not None
    assert outcome.run_id is not None
    assert outcome.evidence_id is not None

    # Bug (D45): execution_constraints must have carried exclude_paths
    # through onto the issued capability.
    with engagement_scope(engagement_id) as conn:
        capability_row = conn.execute(
            text("SELECT constraints FROM capabilities WHERE capability_id = :c"),
            {"c": outcome.capability_id},
        ).mappings().one()
    assert capability_row["constraints"]["exclude_paths"] == ["vendor/", "node_modules/"]

    # The real command semgrep.build_plan produced actually carries the
    # --exclude flags the constraint was supposed to add -- not merely that
    # the field survived onto the capability row.
    with engagement_scope(engagement_id) as conn:
        run_row = conn.execute(
            text("SELECT execution_context, status FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).mappings().one()
        command = conn.execute(
            text("SELECT payload->'command' FROM audit_log WHERE subject_id = :r "
                 "AND event_type = 'tool_run.started'"),
            {"r": outcome.run_id},
        ).scalar_one()
    rendered_command = " ".join(command)
    assert "--exclude vendor/" in rendered_command
    assert "--exclude node_modules/" in rendered_command

    # Bug (D45): dispatch_code_scan, not dispatch_scan, must have been
    # reached -- proven by the control-plane-side git fetch dispatch_scan
    # cannot perform: a real commit_sha and the real credential_id in
    # execution_context, both populated only by dispatch_code_scan's own
    # fetch_repo call.
    assert run_row["execution_context"]["commit_sha"]
    assert run_row["execution_context"]["credential_id"] == credential_id
    assert run_row["status"] == "succeeded", (
        "the real Semgrep container did not exit cleanly against the real "
        f"fetched repository: {run_row}"
    )

    # credential.stored is this credential's own real Vault audit trail --
    # confirms store_credential really wrote it, not that a stub answered.
    # (material_for()'s git_token delivery mode has no "issued_to_run" event
    # of its own -- that event belongs only to mount_for_run's sandbox-mount
    # mode, D44 §4.1/§4.2 -- so a real commit_sha plus the credential_id
    # already asserted above is this mode's actual, complete proof.)
    with engagement_scope(engagement_id) as conn:
        cred_events = [
            r[0] for r in conn.execute(
                text("SELECT event_type FROM audit_log WHERE subject_id = :c"),
                {"c": credential_id},
            ).all()
        ]
    assert "credential.stored" in cred_events


def test_code_scan_without_a_credential_still_reaches_dispatch_code_scan(
    engagement_id, sandbox,
):
    """A public repo (no credential_id) also has to reach the real
    `dispatch_code_scan` -- both branches of D43-6's original scope are
    exercised through the real entry point, not only the credentialed one.
    """
    import tempfile
    from pathlib import Path

    from tests.test_dispatch_code_scan import _run_git  # reuse the local-repo helper

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "work"
        work.mkdir()
        _run_git("init", "-b", "main", cwd=str(work))
        (work / "app.py").write_text("print('public')\n")
        _run_git("add", "app.py", cwd=str(work))
        _run_git(
            "-c", "user.email=test@example.com", "-c", "user.name=Test",
            "commit", "-m", "initial", cwd=str(work),
        )
        repo_value = f"file://{work}#main"

        scope_object_id = _setup(engagement_id, repo_value)
        proposal = ProposedAction(
            action="code.scan",
            target={"logical_identity": {"type": "repo", "value": repo_value}},
            authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
            discovery={"source": "explicit_scope"},
            resources=("source_code",), expected_data=("finding",),
            reason="D47/D48 permanent propose_action regression test (public repo)",
        )

        with engagement_scope(engagement_id) as conn:
            outcome = propose_action(
                conn, engagement_id=engagement_id, proposal=proposal,
                reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="test-worker",
                actor=ACTOR, sandbox=DockerSandbox(image=semgrep.IMAGE),
                network_allowlist=["10.0.0.0/8"], budget=Budget(max_duration_seconds=90),
            )

        assert outcome.decision == "ALLOW", outcome.deny_reasons
        with engagement_scope(engagement_id) as conn:
            run_row = conn.execute(
                text("SELECT execution_context, status FROM tool_runs WHERE run_id = :r"),
                {"r": outcome.run_id},
            ).mappings().one()
        assert run_row["execution_context"]["commit_sha"]
        assert run_row["status"] == "succeeded"
