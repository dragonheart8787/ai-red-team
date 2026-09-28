"""dispatch_code_scan (D43), against a real Semgrep container and real git.

The scan itself is real: a container built from ``tool_gateway/images/
semgrep.Dockerfile``, a real local git repository, and Semgrep's actual CLI
running the bundled ruleset — the same D6/D31 standard ``tests/
test_dispatch.py`` holds nmap to ("the scan itself is real... a mocked tool
would verify the mock"). Unlike ``ad_collector.py`` (D42), this action has no
Credential Vault gap to hide behind for the public-repository scope this
phase ships (D43-6): nothing here needs a credential this system does not
have, so there is no reason to settle for a fixture standing in for the
tool.

What this file checks that ``tests/test_dispatch_code_scan_dedup.py`` (real
git, stubbed sandbox) and ``tests/test_semgrep_adapter.py`` (stubbed
everything, adapter functions in isolation) do not: that the whole pipeline
— control-plane git fetch, dual read-only mount, a real cap-dropped
network-less container, real Semgrep JSON, on-disk snippet extraction, and
redaction — produces evidence with genuine findings and no unredacted
secret in it, and that a repository that cannot be fetched fails closed
before any container starts.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid

import pytest
from sqlalchemy import text

from control_plane.capability.broker import Budget, issue_capability
from control_plane.orchestrator.dispatch import (
    FAILED,
    REPO_FETCH_FAILED,
    SUCCEEDED,
    UNBUILDABLE_PLAN,
    dispatch_code_scan,
)
from control_plane.state.db import engagement_scope
from tool_gateway import registry
from tool_gateway.adapters import semgrep
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

AWS_KEY_LITERAL = "AKIAIOSFODNN7EXAMPLE"
PASSWORD_LITERAL = "hunter2_super_secret_real_run"


class _ExplodingSandbox:
    """Reaching the sandbox at all would mean a fail-closed check was missed."""

    def run(self, **kwargs):  # pragma: no cover - the assertion is the point
        raise AssertionError(f"the sandbox was reached: {kwargs}")


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox(image=semgrep.IMAGE)
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "dispatch_code_scan is tested against a real Semgrep run on "
            "purpose; a mocked tool would verify the mock. Build the image "
            "with tool_gateway/images/build_semgrep_image.sh.",
            pytrace=False,
        )
    return box


def _run_git(*args: str, cwd: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _init_vulnerable_repo(path) -> None:
    os.makedirs(path, exist_ok=True)
    _run_git("init", "-b", "main", cwd=str(path))
    with open(os.path.join(path, "vulnerable.py"), "w") as fh:
        fh.write(
            "import subprocess\n"
            f'AWS_KEY = "{AWS_KEY_LITERAL}"\n'
            f'password = "{PASSWORD_LITERAL}"\n'
            "\n"
            "def run(cmd, user_input):\n"
            "    subprocess.run(cmd, shell=True)\n"
            "    eval(user_input)\n"
        )
    _run_git("add", "vulnerable.py", cwd=str(path))
    _run_git(
        "-c", "user.email=test@example.com", "-c", "user.name=Test",
        "commit", "-m", "vulnerable fixture", cwd=str(path),
    )


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _proposal(conn, engagement_id: str, *, target: str, action: str = "code.scan") -> str:
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
            "target": f'{{"logical_identity": {{"type": "repo", "value": "{target}"}}}}',
            "auth": '{"source": "engagement_scope", "scope_object_id": "SCOPE-1"}',
            "disc": '{"source": "explicit_scope"}',
        },
    )
    return proposal_id


def _capability(conn, engagement_id: str, *, action: str = "code.scan"):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action=action, actor="orchestrator",
        constraints={}, budget=Budget(max_duration_seconds=120), ttl_seconds=120,
    )
    assert result.issued is True, result.reasons
    return result.capability


def test_normal_path_produces_real_findings_with_no_unredacted_secret(
    tmp_path, engagement_id, sandbox, monkeypatch,
):
    repo = tmp_path / "repo"
    _init_vulnerable_repo(repo)
    target = f"{repo}#main"

    fetched_paths: list[str] = []
    import control_plane.orchestrator.dispatch as dispatch_module
    real_fetch_repo = dispatch_module.fetch_repo

    def _spy_fetch_repo(*args, **kwargs):
        fetched = real_fetch_repo(*args, **kwargs)
        fetched_paths.append(fetched.local_path)
        return fetched

    monkeypatch.setattr(dispatch_module, "fetch_repo", _spy_fetch_repo)

    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=target),
            capability=capability, target=target, actor="orchestrator",
            sandbox=sandbox,
        )
        assert outcome.state == SUCCEEDED, outcome.reason

        row = conn.execute(
            text("SELECT tool_version, ruleset_version, execution_context "
                 "FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).mappings().one()
        assert row["tool_version"] == semgrep.tool_version()
        assert row["ruleset_version"] == semgrep.ruleset_version()
        assert row["execution_context"]["commit_sha"]
        assert row["execution_context"]["branch"] == "main"

        derived_view = conn.execute(
            text("SELECT derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id},
        ).scalar_one()

        assert derived_view["untrusted_content"] is True
        assert derived_view["first_party_source_content"] is True
        # All three bundled rules (tool_gateway/rulesets/semgrep_default.yml)
        # should have fired against this fixture.
        assert derived_view["finding_count"] >= 3

        rendered = json.dumps(derived_view)
        assert AWS_KEY_LITERAL not in rendered
        assert PASSWORD_LITERAL not in rendered
        # semgrep prefixes each check_id with the mounted config's parent
        # directory name (CONTAINER_RULESET_PATH's "rules", verified against
        # real output) -- not this adapter's own doing, so matched loosely.
        check_ids = {f["check_id"] for f in derived_view["notable_findings"]}
        assert any(cid.endswith("hardcoded-credential-assignment") for cid in check_ids)
        assert any(cid.endswith("shell-injection-via-subprocess") for cid in check_ids)
        assert any(cid.endswith("dangerous-eval-exec") for cid in check_ids)

    # The fetched checkout is cleaned up once dispatch_code_scan returns --
    # nothing left mounted or on disk for a caller to forget about
    # (git_fetch.fetch_repo's own docstring: the caller owns cleanup).
    assert len(fetched_paths) == 1
    assert not os.path.exists(fetched_paths[0])


def test_a_repository_that_cannot_be_fetched_fails_closed_before_any_container(
    tmp_path, engagement_id,
):
    target = f"{tmp_path / 'does-not-exist'}#main"

    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=target),
            capability=capability, target=target, actor="orchestrator",
            sandbox=_ExplodingSandbox(),
        )
        assert outcome.state == FAILED
        assert outcome.reason == REPO_FETCH_FAILED


def test_an_empty_target_is_refused_as_unbuildable_before_any_fetch(engagement_id):
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=""),
            capability=capability, target="", actor="orchestrator",
            sandbox=_ExplodingSandbox(),
        )
        assert outcome.state == FAILED
        assert outcome.reason == UNBUILDABLE_PLAN


def test_wrong_action_on_the_capability_is_refused_before_anything_runs(
    tmp_path, engagement_id,
):
    target = f"{tmp_path}#main"
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, action="network.scan")
        outcome = dispatch_code_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, target=target, action="network.scan"),
            capability=capability, target=target, actor="orchestrator",
            sandbox=_ExplodingSandbox(),
        )
        assert outcome.state == FAILED
        assert outcome.reason == registry.UNKNOWN_ACTION
