"""Shared fixtures for the Gitleaks (D55) tests -- real git repositories, a real container.

Not a test module. Three files use it (adapter, injection, end-to-end) and a second
copy of "build a repository whose history holds a secret" would be a second thing
to keep equal to the first.

The canary is assembled from two pieces at import time so that no file in this
repository contains a contiguous GitHub-token-shaped string: a repository that
tests a secret scanner must not itself be a finding for one.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from control_plane.orchestrator.dispatch import NO_EGRESS_ALLOWLIST
from control_plane.orchestrator.git_fetch import cleanup_repo, fetch_repo
from tool_gateway.adapters import gitleaks
from tool_gateway.sandbox import DockerSandbox, SandboxResult, SandboxUnavailable

#: Matches gitleaks' ``github-pat`` rule (``ghp_`` + 36 alphanumerics).
CANARY = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"

_IDENTITY = ("-c", "user.email=dev@example.test", "-c", "user.name=Dev One")


def git(*args: str, cwd: str | Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None, check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def commit(
    repo: Path, message: str, *, author: str | None = None, email: str | None = None,
) -> str:
    """Commit everything staged-or-not in ``repo`` and return the new commit id."""
    git("add", "-A", cwd=repo)
    identity = list(_IDENTITY)
    if author:
        identity[3] = f"user.name={author}"
    if email:
        identity[1] = f"user.email={email}"
    git(*identity, "commit", "-q", "--allow-empty", "-m", message, cwd=repo)
    return git("rev-parse", "HEAD", cwd=repo)


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git("init", "-q", "-b", "main", cwd=path)
    (path / "README").write_text("readme\n")
    commit(path, "base")
    return path


@dataclass(frozen=True)
class HistoryRepo:
    path: Path
    secret_commit: str
    removal_commit: str
    tip: str

    @property
    def location(self) -> str:
        """``file://`` -- git ignores ``--depth`` for a plain path (ADR §7)."""
        return f"file://{self.path}"

    @property
    def scope_value(self) -> str:
        return f"{self.location}#main"


def history_only_secret_repo(path: Path, *, filler_commits: int = 0) -> HistoryRepo:
    """A repository whose secret was committed and then removed.

    The secret exists in **no file at the tip**: a scan of the tree (Semgrep's
    input, or ``gitleaks dir``) cannot see it. That is the case the tool exists for.
    ``filler_commits`` pushes the secret deeper, for the depth tests.
    """
    init_repo(path)
    (path / "config.env").write_text(f"token = {CANARY}\n")
    secret_commit = commit(path, "add config", author="Dev One")
    (path / "config.env").unlink()
    removal_commit = commit(path, "remove the token (it was rotated)")
    tip = removal_commit
    for i in range(filler_commits):
        (path / f"file{i}.txt").write_text(f"filler {i}\n")
        tip = commit(path, f"filler {i}")
    return HistoryRepo(path, secret_commit, removal_commit, tip)


def suppression_repo(path: Path, channel: str) -> Path:
    """A repository holding CANARY that tells the scanner to ignore it, via ``channel``."""
    init_repo(path)
    line = f"token = {CANARY}"
    if channel == "inline":
        line += "  # gitleaks:allow"
    (path / "config.env").write_text(line + "\n")
    secret = commit(path, "add config")
    if channel == "toml":
        (path / ".gitleaks.toml").write_text(
            "[extend]\nuseDefault = true\n[[allowlists]]\nregexes = ['''.*''']\n"
        )
        commit(path, "scanner config")
    elif channel == "ignorefile":
        (path / ".gitleaksignore").write_text(f"{secret}:config.env:github-pat:1\n")
        commit(path, "ignore the known finding")
    return path


def real_sandbox() -> DockerSandbox:
    box = DockerSandbox(image=gitleaks.IMAGE)
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "code.secrets is tested against the real gitleaks binary in its real image on "
            "purpose; build it with tool_gateway/images/build_gitleaks_image.sh.",
            pytrace=False,
        )
    return box


def run_command(
    sandbox: DockerSandbox, command: list[str], repo_dir: str, *,
    config: str | None = gitleaks.DEFAULT_RULESET_HOST_PATH, timeout: int = 90,
    extra_mounts: dict[str, str] | None = None,
) -> SandboxResult:
    """Run ``command`` exactly as ``dispatch_code_scan`` runs one: same mounts, same limits."""
    mounts = {repo_dir: gitleaks.CONTAINER_REPO_PATH}
    if config:
        mounts[config] = gitleaks.CONTAINER_RULESET_PATH
    mounts.update(extra_mounts or {})
    return sandbox.run(
        command=command, network_allowlist=NO_EGRESS_ALLOWLIST,
        max_duration_seconds=timeout, run_id=None, tmpfs=gitleaks.TMPFS,
        source_mounts=mounts, no_network=True,
    )


def scan(
    sandbox: DockerSandbox, location: str, *, bare: bool | None = None, depth: int = 100,
    command: list[str] | None = None, extra_mounts: dict[str, str] | None = None,
) -> tuple[SandboxResult, dict]:
    """Fetch ``location#main`` the way dispatch does and run the real adapter command.

    Returns the raw sandbox result and the derived view. ``command`` overrides the
    adapter's, for the negative controls: each removes *one* thing the adapter puts
    there and nothing else. The view is computed before the checkout is deleted
    because ``history_complete`` reads the clone.

    ``bare`` defaults to what the adapter declares (``FETCH_BARE``), *not* to a
    constant here: a test that hard-codes the defence it claims to verify keeps
    passing when the production wiring loses it (found by mutation at D55).
    Only a negative control passes ``bare=False`` explicitly.
    """
    if bare is None:
        bare = gitleaks.FETCH_BARE
    plan = gitleaks.build_plan(
        constraints={"history_depth": depth},
        budget={"max_duration_seconds": 90}, target=f"{location}#main",
    )
    fetched = fetch_repo(location, "main", depth=plan.fetch_depth, bare=bare)
    try:
        result = run_command(
            sandbox, command or list(plan.command), fetched.local_path,
            extra_mounts=extra_mounts,
        )
        view = gitleaks.derive_view(
            result.stdout, result.stderr, repo_local_path=fetched.local_path,
        )
    finally:
        cleanup_repo(fetched.local_path)
    return result, view
