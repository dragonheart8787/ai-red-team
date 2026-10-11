"""Locating and verifying the in-container deadline helper (D65-A).

``tool_gateway/deadline/`` builds a small static program, ``cyberorch-deadline``, that every tool
container runs as PID 1: it starts the tool and ends the container with exit 124 if a deadline
passes, so a tool container does not outlive a control plane that died
(``docs/D65A_CONTAINER_DEADLINE_DESIGN.md``). This module is the control plane's side of that: it
says where the file is, what its sha256 must be, and checks it.

**The check happens before every run, not once.** :func:`verify` reads the file, hashes what it
read and compares that with ``SHA256SUMS`` -- a file that was fine at start-up and replaced since
is refused. It protects against a corrupted file and against a party who can write the file but is
not root; it does not close the window between this check and Docker opening the file for the bind
mount, which only a root-owned, non-writable directory does (the README says so).

Nothing here imports the sandbox: the sandbox turns :class:`HelperProblem` into the
``NotStarted`` error its callers already know how to record.
"""

from __future__ import annotations

import hashlib
import os
import platform
import stat
from dataclasses import dataclass
from pathlib import Path

DEADLINE_DIR = Path(__file__).resolve().parent / "deadline"
SHA256SUMS = DEADLINE_DIR / "SHA256SUMS"
BIN_DIR = DEADLINE_DIR / "bin"

#: Where the helper appears inside the container. Never a path an image or a ``source_mounts``
#: entry may already use; the sandbox refuses a collision.
CONTAINER_PATH = "/cyberorch-deadline"

#: How long the helper waits beyond the run's budget before it ends the container. The control
#: plane's own timeout fires at the budget and its kill took 0.3 s in the measured run, so ten
#: seconds is far longer than the normal path needs and short enough not to matter when the
#: control plane is gone. Chosen, not derived (design §6, D65A-3).
SLACK_SECONDS = 10

#: A container that exits 124 is taken to have hit the helper's deadline only if Docker's own
#: timestamps say it ran at least ``deadline - TOLERANCE_SECONDS``. A tool that exits 124 early
#: does not.
TOLERANCE_SECONDS = 2

#: The helper's exit status for a deadline, and the line it prints when it cannot execute the
#: command (the tool never ran: ``NotStarted``).
EXIT_DEADLINE = 124
EXIT_NOT_EXECUTABLE = 127
NOT_EXECUTABLE_PREFIX = "cyberorch-deadline: cannot execute "

NAME_PREFIX = "cyberorch-deadline-linux-"

_ARCHITECTURES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


class HelperProblem(RuntimeError):
    """The helper cannot be used. ``reason`` is a stable code; the message names no secret."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class VerifiedHelper:
    """A file whose content was just read and equals the pin for its architecture."""

    path: str
    sha256: str
    architecture: str


def architecture() -> str:
    machine = platform.machine().lower()
    try:
        return _ARCHITECTURES[machine]
    except KeyError:
        raise HelperProblem(
            "deadline_helper_unsupported_architecture",
            f"there is no deadline helper for architecture {machine!r}",
        ) from None


def helper_name(arch: str | None = None) -> str:
    return NAME_PREFIX + (arch or architecture())


def default_path(arch: str | None = None) -> str:
    return str(BIN_DIR / helper_name(arch))


def pinned_sha256(arch: str | None = None, *, sums: Path | None = None) -> str:
    """The expected sha256 for ``arch``, from the committed ``SHA256SUMS``."""
    name = helper_name(arch)
    sums = sums or SHA256SUMS
    try:
        lines = sums.read_text().splitlines()
    except OSError as exc:
        raise HelperProblem("deadline_helper_unpinned",
                            f"cannot read the helper's pin file: {exc.strerror or exc}") from exc
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and parts[1] == name:
            digest = parts[0].lower()
            if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                return digest
    raise HelperProblem("deadline_helper_unpinned", f"SHA256SUMS has no valid entry for {name}")


def verify(path: str | os.PathLike[str] | None = None, *, arch: str | None = None,
           sums: Path | None = None) -> VerifiedHelper:
    """Read ``path`` (default: this architecture's built helper) and check it against the pin.

    Raises :class:`HelperProblem` for a missing, unreadable, non-executable or altered file.
    """
    arch = arch or architecture()
    expected = pinned_sha256(arch, sums=sums)
    target = str(path) if path is not None else default_path(arch)
    try:
        with open(target, "rb") as handle:
            mode = os.fstat(handle.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise HelperProblem("deadline_helper_unreadable",
                                    f"{target} is not a regular file")
            content = handle.read()
    except FileNotFoundError:
        raise HelperProblem(
            "deadline_helper_missing",
            f"the deadline helper {target} does not exist; build it with "
            "tool_gateway/deadline/build.sh",
        ) from None
    except OSError as exc:
        raise HelperProblem("deadline_helper_unreadable",
                            f"cannot read the deadline helper {target}: {exc.strerror or exc}",
                            ) from exc
    digest = hashlib.sha256(content).hexdigest()
    if digest != expected:
        raise HelperProblem(
            "deadline_helper_hash_mismatch",
            f"the deadline helper {target} has sha256 {digest}, SHA256SUMS says {expected}",
        )
    # Docker runs it as whatever user the tool image names; "others may execute" is the mode that
    # works for every one of them. A file that is the right bytes but cannot be executed would
    # otherwise surface as a start failure with a less useful message.
    if not mode & stat.S_IXOTH:
        raise HelperProblem("deadline_helper_not_executable",
                            f"the deadline helper {target} is not executable by other users")
    return VerifiedHelper(path=target, sha256=digest, architecture=arch)


def deadline_for(max_duration_seconds: int) -> int:
    """The helper's deadline for a run with this budget: the budget plus the slack."""
    return max(1, int(max_duration_seconds) + SLACK_SECONDS)
