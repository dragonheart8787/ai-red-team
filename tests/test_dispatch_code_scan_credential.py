"""dispatch_code_scan's private-repo credential wiring (D44 §4.2).

Reuses ``tests/test_git_fetch_credential.py``'s real HTTP git server (a
real Basic-Auth gate in front of a real ``git http-backend``) rather than
a stub — the fact under test is that a real credential, stored and
retrieved through the real Vault, genuinely lets ``dispatch_code_scan``
clone a repository nothing else here could authenticate to. The sandbox
itself is stubbed (no Docker), because what these tests check is the
credential-resolution step *before* the sandbox ever runs, not Semgrep's
own behavior -- that is ``tests/test_dispatch_code_scan.py``'s job, against
the real image.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text

from control_plane.capability.broker import Budget, issue_capability
from control_plane.orchestrator.dispatch import (
    FAILED,
    REPO_FETCH_FAILED,
    SUCCEEDED,
    UNBUILDABLE_PLAN,
    dispatch_code_scan,
)
from control_plane.state.db import credential_admin_scope, engagement_scope
from control_plane.vault.vault import store_credential
from tests.test_git_fetch_credential import REAL_TOKEN, private_git_server  # noqa: F401
from tool_gateway.sandbox import SandboxResult


class StubSandbox:
    def __init__(self, *, stdout: str = '{"results": []}', exit_code: int = 0) -> None:
        self.runs: list[dict] = []
        self.stdout = stdout
        self.exit_code = exit_code

    def run(self, *, command, network_allowlist, max_duration_seconds,
            run_id=None, tmpfs=None, source_mounts=None):
        self.runs.append({"command": list(command), "source_mounts": dict(source_mounts or {})})
        return SandboxResult(
            exit_code=self.exit_code, stdout=self.stdout, stderr="",
            timed_out=False, duration_seconds=0.1,
            network_allowlist=tuple(network_allowlist), image="stub",
        )


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _proposal(conn, engagement_id: str, *, target: str) -> str:
    proposal_id = _uid("PROP")
    conn.execute(
        text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, dispatch_state, action, target,
                "authorization", discovery)
            VALUES (:pid, :eid, 'fake-worker', :key, 'queued', 'code.scan',
                    CAST(:target AS jsonb), CAST(:auth AS jsonb),
                    CAST(:disc AS jsonb))
        """),
        {
            "pid": proposal_id, "eid": engagement_id, "key": f"key-{proposal_id}",
            "target": f'{{"logical_identity": {{"type": "repo", "value": "{target}"}}}}',
            "auth": '{"source": "engagement_scope", "scope_object_id": "SCOPE-1"}',
            "disc": '{"source": "explicit_scope"}',
        },
    )
    return proposal_id


def _capability(conn, engagement_id: str, *, credential_id: str | None = None):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action="code.scan", actor="orchestrator",
        constraints={}, budget=Budget(max_duration_seconds=60), ttl_seconds=60,
        credential_id=credential_id,
    )
    assert result.issued is True, result.reasons
    return result.capability


def _store_git_token(engagement_id: str, *, secret: str = REAL_TOKEN) -> str:
    credential_id = _uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=credential_id,
            label="git PAT", credential_type="git_token", secret=secret,
            actor="test-harness",
        )
    return credential_id


def test_a_private_repo_without_a_credential_fails_closed(
    private_git_server, engagement_id,  # noqa: F811 - pytest fixture, not a redefinition
):
    target = f"{private_git_server}#main"
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, credential_id=None)
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=target),
            capability=capability, target=target, actor="orchestrator",
            sandbox=StubSandbox(),
        )
        assert outcome.state == FAILED
        assert outcome.reason == REPO_FETCH_FAILED


def test_a_private_repo_with_the_right_credential_clones_and_scans(
    private_git_server, engagement_id,  # noqa: F811 - pytest fixture, not a redefinition
):
    credential_id = _store_git_token(engagement_id)
    target = f"{private_git_server}#main"
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, credential_id=credential_id)
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=target),
            capability=capability, target=target, actor="orchestrator",
            sandbox=StubSandbox(),
        )
        assert outcome.state == SUCCEEDED, outcome.reason

        row = conn.execute(
            text("SELECT execution_context FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).mappings().one()
        assert row["execution_context"]["credential_id"] == credential_id
        assert row["execution_context"]["commit_sha"]


def test_a_credential_of_the_wrong_type_is_refused_as_unbuildable(
    private_git_server, engagement_id,  # noqa: F811 - pytest fixture, not a redefinition
):
    """A code.scan capability carrying an ad_domain_bind credential (the
    wrong shape for this action, D44 §4.3) must be refused, not silently
    treated as if it were a git token.
    """
    wrong_credential_id = _uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        store_credential(
            conn, engagement_id=engagement_id, credential_id=wrong_credential_id,
            label="wrong type", credential_type="ad_domain_bind", secret="not-a-git-token",
            actor="test-harness",
        )
    target = f"{private_git_server}#main"
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, credential_id=wrong_credential_id)
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=target),
            capability=capability, target=target, actor="orchestrator",
            sandbox=StubSandbox(),
        )
        assert outcome.state == FAILED
        assert outcome.reason == UNBUILDABLE_PLAN
