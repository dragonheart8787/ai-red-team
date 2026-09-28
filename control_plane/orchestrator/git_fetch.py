"""Control-plane-side repository fetch (D43-5 Option B).

Runs entirely outside any sandbox, on whatever credential this step alone
holds — none, for the public-repository-only scope this phase ships
(D43-6). The resulting directory is handed to ``DockerSandbox.run``'s
``source_mount`` as a read-only bind mount; the container that actually
runs Semgrep never has network egress and never holds a git credential.
This is the same trust-minimization shape D34's egress-proxy split and
D35/D36's file-not-network credential delivery already established,
applied one layer up — to the repository's *content* rather than a
credential for reaching it.

Scope object values are ``<location>#<branch>`` (D43-1 Option C: a scope
authorizes a repository *and* a mutable branch name, never a bare
repository or a pinned commit). ``<location>`` is whatever ``git clone``
accepts — an HTTPS URL for a real repository, a filesystem path for a
local fixture in tests. ``#`` rather than the design note's illustrative
``:`` separator: a `:` collides with a port number in a self-hosted git
host's URL (``git.internal.corp:8443/org/repo``); a bare ``#`` does not
appear in either a git remote URL or a valid branch name.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass


class GitFetchError(RuntimeError):
    """The repository could not be fetched, or the scope value is malformed."""


@dataclass(frozen=True)
class FetchedRepo:
    local_path: str
    commit_sha: str
    branch: str


def parse_repo_scope_value(value: str) -> tuple[str, str]:
    """Split a ``repo`` scope object's value into ``(location, branch)``."""
    if "#" not in value:
        raise GitFetchError(
            f"repo scope value {value!r} has no '#<branch>' suffix (D43-1 Option C)"
        )
    location, branch = value.rsplit("#", 1)
    if not location or not branch:
        raise GitFetchError(f"repo scope value {value!r} has an empty location or branch")
    return location, branch


def fetch_repo(location: str, branch: str, *, timeout_seconds: int = 120) -> FetchedRepo:
    """Shallow-clone ``location`` at ``branch`` into a fresh temp directory.

    Shallow (``--depth 1``): Semgrep scans a working tree, not history, and a
    full clone of a large repository costs minutes and gigabytes for no
    benefit here. Shallow does not mean approximate — the resolved commit
    (below) is the exact, real HEAD of that branch at fetch time, which is
    exactly the value D11-3's lesson (docs/ADR_SEMGREP.md §1.2) requires
    enter the execution fingerprint.

    The caller owns cleanup (:func:`cleanup_repo`) — this function does not
    delete on its own success or failure, so a caller inspecting the tree
    after a partial failure still can.
    """
    local_path = tempfile.mkdtemp(prefix="cyberorch-repo-")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, "--single-branch",
             location, local_path],
            check=True, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        cleanup_repo(local_path)
        raise GitFetchError(
            f"git clone failed for {location!r}@{branch!r}: {exc.stderr}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        cleanup_repo(local_path)
        raise GitFetchError(f"git clone timed out for {location!r}@{branch!r}") from exc

    # tempfile.mkdtemp defaults to 0700, and git preserves the cloning
    # user's umask on everything it writes underneath -- fine for every
    # tool before this one, which all run container-side as root (cap-
    # dropped, but still uid 0, so a host-root-owned bind mount is readable
    # regardless of mode). Semgrep is the first tool image that runs as a
    # real non-root container user (``USER semgrep``, uid 10001,
    # semgrep.Dockerfile), with no group overlap with the host process that
    # cloned this tree -- discovered by this test suite's own real-container
    # run failing with "Path '/repo' is not readable", not by inspection.
    # World-read/list, never world-write: this is a read-only bind mount
    # either way, so the extra permission bit does not let the container
    # modify anything, only see it.
    subprocess.run(["chmod", "-R", "a+rX", local_path], check=True)

    try:
        result = subprocess.run(
            ["git", "-C", local_path, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as exc:
        cleanup_repo(local_path)
        raise GitFetchError(f"could not resolve HEAD for {location!r}@{branch!r}") from exc

    return FetchedRepo(local_path=local_path, commit_sha=result.stdout.strip(), branch=branch)


def cleanup_repo(local_path: str) -> None:
    shutil.rmtree(local_path, ignore_errors=True)
