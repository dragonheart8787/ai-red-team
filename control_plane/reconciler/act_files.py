"""Host files, acted on (D64 §1.5, §1.7, D64-12). Off unless ``Settings.allow_deletions`` says so.

The only module in the package that unlinks anything. Every condition the plan judged is judged
**again** here, on the file as it is now, because a plan is a minute old and ``/tmp`` is shared:

* the name is exactly ``cyberorch-cred-<8>`` or ``cyberorch-tls-<8>.pem``, in the one directory the
  caller configured (the action's own ``directory`` must be that directory);
* it is opened through a **directory fd** and examined with ``lstat``: a regular file, never a
  symlink (the link would be unlinked, not its target, but it is not ours to remove), owned by the
  expected uid, older than ``B_cap + P + Q``;
* no container that could still read it -- ``created``, ``running``, ``paused``, ``restarting`` --
  has it as a mount source, asked of Docker *now*;
* the intent is written (``intend``, D64 item 4) and, if that cannot be done, nothing is unlinked;
* then ``unlink(name, dir_fd=fd)``, and the verification is a second ``lstat`` that must say the
  name is gone (E14-V3).

The temporary directory is sticky: another user cannot replace or remove a file of ours, so the
window between the ``lstat`` and the ``unlink`` is one only the control plane's own uid could use.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable
from typing import Any

from control_plane.reconciler import act_docker, vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import US, Action
from control_plane.reconciler.outcome import (
    CHANGED,
    DONE,
    FAILED,
    FILE_ERROR,
    FOREIGN_OWNER,
    GONE,
    INVALID_ACTION,
    MOUNTED,
    NOT_A_REGULAR_FILE,
    NOT_GONE_AFTER_REMOVAL,
    NOT_OURS,
    TOO_YOUNG,
    Result,
)

#: what ``tempfile.mkstemp`` makes: 8 characters of [a-z0-9_] after the prefix we give it
NAMES = {
    "credential_mount": re.compile(r"cyberorch-cred-[a-z0-9_]{8}"),
    "tls_leaf": re.compile(r"cyberorch-tls-[a-z0-9_]{8}\.pem"),
}


def sweep(action: Action, *, directory: str | None, expected_uid: int | None, th: Thresholds,
           client: Any, wall_clock_us: Callable[[], int],
           intend: Callable[[Action], None] | None = None) -> Result:
    pattern = NAMES.get(action.reason_code)
    if (pattern is None or action.name is None or not pattern.fullmatch(action.name)
            or directory is None or expected_uid is None or client is None
            or action.directory != directory):
        return Result(action, FAILED, INVALID_ACTION)
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return Result(action, FAILED, FILE_ERROR)
    try:
        return _unlink(action, fd, directory, expected_uid, th, client, wall_clock_us, intend)
    except OSError:
        return Result(action, FAILED, FILE_ERROR)
    finally:
        os.close(fd)


def _unlink(action, fd, directory, expected_uid, th, client, wall_clock_us, intend=None) -> Result:
    name = action.name
    try:
        info = os.lstat(name, dir_fd=fd)
    except FileNotFoundError:
        return Result(action, GONE)
    if not stat.S_ISREG(info.st_mode):
        return Result(action, CHANGED, NOT_A_REGULAR_FILE)
    if info.st_uid != expected_uid:
        return Result(action, CHANGED, FOREIGN_OWNER)
    if wall_clock_us() - info.st_mtime_ns // 1000 < th.file_age_s() * US:
        return Result(action, CHANGED, TOO_YOUNG)
    if os.path.join(directory, name) in act_docker.live_mount_sources(client):
        return Result(action, CHANGED, MOUNTED)
    if action.reason_code not in vocab.REASONS[vocab.UNLINK_FILE]:
        return Result(action, CHANGED, NOT_OURS)
    if (blocked := act_docker.declared(action, intend)) is not None:
        return blocked
    os.unlink(name, dir_fd=fd)
    try:
        os.lstat(name, dir_fd=fd)
    except FileNotFoundError:
        return Result(action, DONE)
    return Result(action, FAILED, NOT_GONE_AFTER_REMOVAL)
