"""Control-plane-side repository fetch (D43-5 Option B).

Runs entirely outside any sandbox, on whatever credential this step alone
holds — none for a public repository (D43-6's original scope), or, as of
D44, a Vault-issued git token for a private one. Either way, the resulting
directory is handed to ``DockerSandbox.run``'s ``source_mount`` as a
read-only bind mount; the container that actually runs Semgrep never has
network egress and never holds a git credential, regardless of whether this
fetch used one. This is the same trust-minimization shape D34's
egress-proxy split and D35/D36's file-not-network credential delivery
already established, applied one layer up — to the repository's *content*
rather than a credential for reaching it.

D44 lands a git token here rather than in the Semgrep sandbox precisely
*because* this function is the trusted control-plane tier
(`docs/ADR_CREDENTIAL_VAULT.md` §4.2: the same tier as
`engagement_ca.mint_leaf_for_host`, not the tool-container tier
`control_plane.vault.vault.mount_for_run` serves) — the caller resolves a
`credential_id` via `vault.material_for()` and passes the decrypted token
in as `auth_token`; this module has no idea what a Vault or a
`credential_id` is, and does not need one.

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

import base64
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


def _basic_auth_header(auth_token: str) -> str:
    """A git ``http.extraHeader`` value for token auth (D44).

    Deliberately not embedded in the clone URL: git echoes the URL verbatim
    into its own stderr on a failed clone (``fatal: unable to access
    'https://...'``), which would smuggle the token into whatever this
    function raises. An extra header never appears in that message at all,
    and :func:`fetch_repo`'s own error path redacts the token from the
    underlying stderr regardless, as a second layer.

    ``x-access-token`` as the username is GitHub's own documented
    convention for token-based Basic auth (works for a classic PAT too,
    which ignores the username) — unverified against a git host that
    expects something else, the same "not independently verified" caveat
    `ad_collector.py`'s flag names already carry for the identical reason:
    nothing in this environment can authenticate to a real private host to
    check.
    """
    encoded = base64.b64encode(f"x-access-token:{auth_token}".encode()).decode()
    return f"Authorization: Basic {encoded}"


def fetch_repo(
    location: str, branch: str, *, timeout_seconds: int = 120,
    auth_token: str | None = None, depth: int = 1, bare: bool = False,
) -> FetchedRepo:
    """Shallow-clone ``location`` at ``branch`` into a fresh temp directory.

    Shallow (``--depth 1`` by default): Semgrep scans a working tree, not
    history, and a full clone of a large repository costs minutes and
    gigabytes for no benefit here. Shallow does not mean approximate — the
    resolved commit (below) is the exact, real HEAD of that branch at fetch
    time, which is exactly the value D11-3's lesson (docs/ADR_SEMGREP.md §1.2)
    requires enter the execution fingerprint.

    ``depth`` and ``bare`` exist for Gitleaks (D55), which reads history. A tip
    commit id names every ancestor of it, so ``(commit_sha, depth)`` still
    determines exactly what was fetched. ``bare`` produces no working tree: a
    scanner that reads its suppressions from the tree it audits (Gitleaks does,
    three ways) has nothing there to read. Note git ignores ``--depth`` for a
    clone from a plain filesystem path (it needs ``file://``); a real remote
    URL honours it.

    ``auth_token``, when given, authenticates the clone (D44) — this is the
    seam `docs/ADR_SEMGREP.md` §3.2 named and this document's own §4.2
    verifies against: a private repository's scope, once the Vault resolves
    its `credential_id` into a token here. The token reaches this process's
    argv (an unavoidable cost of `git`'s own CLI having no "read a header
    value from a file" option — the same honest limit `ad_collector.py`'s
    shell wrapper already carries for the identical reason), but never a
    sandboxed one: this function runs entirely control-plane-side, before
    any container exists for this dispatch.

    The caller owns cleanup (:func:`cleanup_repo`) — this function does not
    delete on its own success or failure, so a caller inspecting the tree
    after a partial failure still can.
    """
    if depth < 1:
        raise GitFetchError(f"clone depth must be at least 1, got {depth}")
    local_path = tempfile.mkdtemp(prefix="cyberorch-repo-")
    command = ["git", "clone", "--depth", str(depth), "--branch", branch, "--single-branch"]
    if bare:
        command.append("--bare")
    if auth_token:
        command += ["-c", f"http.extraHeader={_basic_auth_header(auth_token)}"]
    command += [location, local_path]
    try:
        subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        cleanup_repo(local_path)
        stderr = exc.stderr.replace(auth_token, "***REDACTED***") if auth_token else exc.stderr
        raise GitFetchError(
            f"git clone failed for {location!r}@{branch!r}: {stderr}"
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
