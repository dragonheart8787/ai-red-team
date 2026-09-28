"""dispatch_code_scan (D43): ruleset_version and commit SHA really drive dedup.

The D11-3 shape this guards against: a scan confined to a range with no
route to the target succeeded and reported nothing, and the *identical*
proposal under a range that could reach it fingerprinted the same and was
served from the dedup cache instead of running — three open ports went
unreported. §7 v0.3's fix was folding the differentiator into
``execution_context`` rather than trusting a caller to remember it mattered.

Semgrep's own version of that differentiator is the git ref that moved: a
``repo`` scope authorizes a repository *and* a branch (D43-1 Option C), and
a branch is not a fixed point — two proposals naming the same target string
can resolve to two different commits. If the fingerprint only hashed the
branch name, the second commit's scan would dedup_hit against the first and
never run. This file proves, against a **real** local git repository (real
clones, real commits, real ``git rev-parse``) rather than a fixture standing
in for one, that:

* ``tool_runs.ruleset_version`` is actually populated (D11-3's own history
  is a ruleset that was never wired into anything a real caller populated —
  ``ruleset_version`` existed on ``execution_fingerprint``'s signature since
  before D43 and no adapter ever passed it);
* the same commit, same ruleset, is a dedup hit;
* a different commit on the same branch is NOT a dedup hit — the one
  invariant this suite exists to pin down;
* the same commit with a different ruleset is likewise NOT a dedup hit —
  ``ruleset_version`` has to actually move the fingerprint, not merely be a
  column that gets a value nothing reads.

Docker is not needed here: what is under test is the control plane's own
fingerprint/dedup accounting (the same StubSandbox reasoning ``tests/
test_dispatch_collection.py`` and ``tests/test_capability_budget.py`` already
apply), not Semgrep's own findings. The git operations are the one thing
this suite insists be real, because a stubbed commit SHA could not prove
``git_fetch.fetch_repo`` resolves a moved branch to a genuinely different
value.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

from sqlalchemy import text

from control_plane.capability.broker import Budget, issue_capability
from control_plane.orchestrator.dispatch import SUCCEEDED, dispatch_code_scan
from control_plane.state.db import engagement_scope
from tool_gateway.adapters import semgrep
from tool_gateway.sandbox import SandboxResult

EMPTY_RESULTS = '{"results": []}'


class StubSandbox:
    """Records what it was asked to run and answers with canned stdout.

    Same no-Docker pattern as ``tests/test_dispatch_collection.py``'s own
    StubSandbox, extended with the two keyword arguments only this dispatch
    path passes (``tmpfs``, ``source_mounts``) so the call shape matches
    ``dispatch_code_scan``'s real ``sandbox.run(...)`` exactly.
    """

    def __init__(self, *, stdout: str = EMPTY_RESULTS, exit_code: int = 0) -> None:
        self.runs: list[dict] = []
        self.stdout = stdout
        self.exit_code = exit_code

    def run(self, *, command, network_allowlist, max_duration_seconds,
            run_id=None, tmpfs=None, source_mounts=None):
        self.runs.append({
            "command": list(command), "allowlist": list(network_allowlist),
            "source_mounts": dict(source_mounts or {}),
        })
        return SandboxResult(
            exit_code=self.exit_code, stdout=self.stdout, stderr="",
            timed_out=False, duration_seconds=0.1,
            network_allowlist=tuple(network_allowlist), image="stub",
        )


def _run_git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _init_repo(path: Path) -> None:
    _run_git("init", "-b", "main", str(path))
    (path / "app.py").write_text("print('v1')\n")
    _run_git("add", "app.py", cwd=str(path))
    _run_git(
        "-c", "user.email=test@example.com", "-c", "user.name=Test",
        "commit", "-m", "initial commit", cwd=str(path),
    )


def _add_commit(path: Path, *, message: str) -> str:
    """Advance ``main`` one commit and return the new HEAD sha."""
    (path / "app.py").write_text(f"print({uuid.uuid4().hex!r})\n")
    _run_git("add", "app.py", cwd=str(path))
    _run_git(
        "-c", "user.email=test@example.com", "-c", "user.name=Test",
        "commit", "-m", message, cwd=str(path),
    )
    return _run_git("rev-parse", "HEAD", cwd=str(path))


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


def _capability(conn, engagement_id: str):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action="code.scan", actor="orchestrator",
        constraints={}, budget=Budget(max_duration_seconds=60), ttl_seconds=60,
    )
    assert result.issued is True, result.reasons
    return result.capability


def _dispatch(conn, engagement_id, *, target, sandbox, ruleset_path=None):
    capability = _capability(conn, engagement_id)
    return dispatch_code_scan(
        conn, engagement_id=engagement_id,
        proposal_id=_proposal(conn, engagement_id, target=target),
        capability=capability, target=target, actor="orchestrator",
        sandbox=sandbox, ruleset_path=ruleset_path,
    )


def test_ruleset_version_is_populated_on_the_tool_run(tmp_path, engagement_id):
    repo = tmp_path / "repo"
    _init_repo(repo)

    with engagement_scope(engagement_id) as conn:
        outcome = _dispatch(
            conn, engagement_id, target=f"{repo}#main", sandbox=StubSandbox(),
        )
        assert outcome.state == SUCCEEDED, outcome.reason

        stored = conn.execute(
            text("SELECT ruleset_version FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one()

        # Not merely non-null: it is the real, computed content-hash of the
        # bundled ruleset (semgrep.py's own module docstring on why it is a
        # computed property rather than a hand-maintained string) -- the
        # value a genuine caller would independently compute.
        assert stored is not None
        assert stored == semgrep.ruleset_version()

        # And on the evidence row too (record_evidence's own ruleset_version
        # column, populated the same way tool_runs' is).
        evidence_ruleset = conn.execute(
            text("SELECT ruleset_version FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id},
        ).scalar_one()
        assert evidence_ruleset == stored


def test_same_commit_same_ruleset_is_a_dedup_hit(tmp_path, engagement_id):
    repo = tmp_path / "repo"
    _init_repo(repo)
    target = f"{repo}#main"

    with engagement_scope(engagement_id) as conn:
        first = _dispatch(conn, engagement_id, target=target, sandbox=StubSandbox())
        assert first.state == SUCCEEDED, first.reason

        second = _dispatch(conn, engagement_id, target=target, sandbox=StubSandbox())
        assert second.reason == "dedup_hit"
        assert second.dispatched is False
        assert second.run_id == first.run_id


def test_a_different_commit_on_the_same_branch_is_not_a_dedup_hit(tmp_path, engagement_id):
    """The exact D11-3 shape: same target string, real difference underneath.

    ``repo#main`` is the identical scope value in both dispatches -- what
    changed is only what ``main`` currently points at. A fingerprint keyed
    on the branch name alone would treat these as the same execution and
    serve the second scan from cache, exactly as the D11 range confusion
    served a reachable target's scan from a run against an unreachable one.
    """
    repo = tmp_path / "repo"
    _init_repo(repo)
    target = f"{repo}#main"

    with engagement_scope(engagement_id) as conn:
        first = _dispatch(conn, engagement_id, target=target, sandbox=StubSandbox())
        assert first.state == SUCCEEDED, first.reason

        first_commit = conn.execute(
            text("SELECT execution_context->>'commit_sha' FROM tool_runs WHERE run_id = :r"),
            {"r": first.run_id},
        ).scalar_one()

    new_commit = _add_commit(repo, message="second commit")
    assert new_commit != first_commit

    with engagement_scope(engagement_id) as conn:
        second = _dispatch(conn, engagement_id, target=target, sandbox=StubSandbox())

        assert second.reason != "dedup_hit"
        assert second.dispatched is True
        assert second.state == SUCCEEDED, second.reason
        assert second.run_id != first.run_id

        second_commit = conn.execute(
            text("SELECT execution_context->>'commit_sha' FROM tool_runs WHERE run_id = :r"),
            {"r": second.run_id},
        ).scalar_one()
        assert second_commit == new_commit
        assert second_commit != first_commit


def test_same_commit_a_different_ruleset_is_not_a_dedup_hit(tmp_path, engagement_id):
    """ruleset_version has to move the fingerprint, not just sit in a column.

    Same repo, same branch, same commit, both dispatches -- the only thing
    that differs is which ruleset file is passed. If this test passed with
    a NO-OP change to ``ruleset_version`` (e.g. always returning a constant),
    it would be worthless; the two ruleset files below produce two distinct
    hashes, so a fingerprint that genuinely folds ``ruleset_version`` in must
    tell these two runs apart.
    """
    repo = tmp_path / "repo"
    _init_repo(repo)
    target = f"{repo}#main"

    ruleset_a = tmp_path / "ruleset_a.yml"
    ruleset_a.write_text("rules:\n  - id: rule-a\n    pattern: eval(...)\n"
                          "    message: a\n    languages: [python]\n    severity: WARNING\n")
    ruleset_b = tmp_path / "ruleset_b.yml"
    ruleset_b.write_text("rules:\n  - id: rule-b\n    pattern: exec(...)\n"
                          "    message: b\n    languages: [python]\n    severity: WARNING\n")
    assert semgrep.ruleset_version(str(ruleset_a)) != semgrep.ruleset_version(str(ruleset_b))

    with engagement_scope(engagement_id) as conn:
        first = _dispatch(
            conn, engagement_id, target=target, sandbox=StubSandbox(),
            ruleset_path=str(ruleset_a),
        )
        assert first.state == SUCCEEDED, first.reason

        second = _dispatch(
            conn, engagement_id, target=target, sandbox=StubSandbox(),
            ruleset_path=str(ruleset_b),
        )
        assert second.reason != "dedup_hit"
        assert second.dispatched is True
        assert second.run_id != first.run_id
