"""Evidence kept before a container whose run ended in ``unknown_outcome`` is removed (D64 §2.4,
ACCEPTANCE 5.97).

A run whose outcome nobody knows is exactly the run somebody may later want to understand, and the
container's ``docker inspect`` and its output are all that is left of it. Before the reconciler
removes such a container it writes both to files and records their SHA-256 in the audit trail:

* ``<container id>.inspect.json`` -- ``container.attrs`` as it was read immediately before;
* ``<container id>.logs``         -- stdout and stderr, with Docker's timestamps.

**Fail closed.** Anything that stops the archive -- no directory, a directory other people can
read or write, a file that cannot be written, synced or read back, a log bigger than
``MAX_LOG_BYTES``, a daemon error while reading the output, a file that already exists with other
content -- raises :class:`EvidenceError`, and the caller does not remove the container and does not
write an intent. The hash is that of the file **read back from disk** after it was synced and moved
into place, not of the bytes that were meant to be written.

The audit trail carries ids and hashes only (``reconciler.evidence_saved``): never a path, never a
line of the output. The files are named by the container's full id, so the path is derivable from
the id and the directory the operator chose.

The files can hold what the container's environment held, which can be a secret. The directory
must therefore belong to the user who runs the reconciler and be closed to everybody else
(``0700``); every file is created ``0600``.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from docker.errors import DockerException

#: refuse to archive more output than this; the container is then left where it is
MAX_LOG_BYTES = 256 * 1024 * 1024
INSPECT_SUFFIX = ".inspect.json"
LOGS_SUFFIX = ".logs"
_CHUNK = 1024 * 1024


class EvidenceError(Exception):
    """The evidence could not be kept. Carries no detail on purpose: the reason is logged by the
    caller as a fixed code, never as text that may hold a path or a line of output."""


@dataclass(frozen=True)
class Saved:
    """What was kept, and what the audit trail will say about it."""

    container_id: str
    inspect_sha256: str
    logs_sha256: str


def check_directory(directory: str | None) -> str:
    """The directory as it must be, or :class:`EvidenceError`: an existing directory (not a link
    to one) that belongs to this user and that nobody else can read, write or enter."""
    if not isinstance(directory, str) or not directory or "\0" in directory:
        raise EvidenceError("no directory")
    try:
        info = os.lstat(directory)
    except OSError as exc:
        raise EvidenceError("directory not readable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise EvidenceError("not a directory")
    if info.st_uid != os.getuid():
        raise EvidenceError("directory belongs to another user")
    if info.st_mode & 0o077:
        raise EvidenceError("directory is open to other users")
    return directory


def _sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _chunks(output: Any) -> Iterable[bytes]:
    if isinstance(output, bytes | bytearray):
        return (bytes(output),)
    return output


def _write(directory: str, name: str, parts: Iterable[bytes], limit: int | None) -> str:
    """Write ``parts`` to ``directory/name`` -- synced, then moved into place without replacing
    anything -- and return the SHA-256 of the file as it is on disk."""
    final = os.path.join(directory, name)
    temporary = os.path.join(directory, f".{name}.{os.getpid()}.partial")
    size = 0
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            for part in parts:
                size += len(part)
                if limit is not None and size > limit:
                    raise EvidenceError("output too large")
                handle.write(part)
            handle.flush()
            os.fsync(handle.fileno())
        written = _sha256_of(temporary)
        try:
            os.link(temporary, final)             # fails if the name is taken: nothing is replaced
        except FileExistsError:
            if _sha256_of(final) != written:
                raise EvidenceError("a file with other content is there") from None
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return _sha256_of(final)
    except EvidenceError:
        raise
    except (OSError, DockerException) as exc:
        raise EvidenceError("could not write") from exc
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def save(container: Any, directory: str | None) -> Saved:
    """Keep ``container``'s inspect output and logs in ``directory``; :class:`EvidenceError` if
    either cannot be kept in full. ``container.attrs`` is read as it is (the caller has just
    reloaded it)."""
    directory = check_directory(directory)
    container_id = str(container.id)
    if len(container_id) != 64 or any(c not in "0123456789abcdef" for c in container_id):
        raise EvidenceError("not a full container id")
    try:
        inspect = json.dumps(container.attrs, sort_keys=True, indent=2, default=str).encode()
        logs = _chunks(container.logs(stdout=True, stderr=True, timestamps=True, stream=True))
        inspect_sha = _write(directory, container_id + INSPECT_SUFFIX, (inspect,), None)
        logs_sha = _write(directory, container_id + LOGS_SUFFIX, logs, MAX_LOG_BYTES)
    except EvidenceError:
        raise
    except (OSError, DockerException, TypeError, ValueError) as exc:
        raise EvidenceError("could not read") from exc
    return Saved(container_id, inspect_sha, logs_sha)
