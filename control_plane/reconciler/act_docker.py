"""Docker, acted on (D64 §1.5, §1.7, §2.4). Off unless the category is in ``Settings.enabled``.

The only module in the package that kills or removes a Docker object. Four rules, each tested on
real Docker and, where Docker cannot be made to misbehave, on a fake that does:

1. **By full id, never by name.** A name can be taken by another container between the plan and the
   act (E13-D3: removal by name deleted the newcomer). The action's id must be 64 hex characters or
   it is refused; the object fetched must report that same id.
2. **Re-inspect immediately before.** The run label, the owner label and the kind of object (tool
   container, proxy, network) must still be what the plan saw, and its state must still allow the
   act: a container that has started since is no longer "at rest", a network that has a container
   attached is no longer idle. Otherwise ``changed_since_plan`` and nothing is touched.
3. **Docker's refusal is respected, not worked around.** A running container is not removed
   without ``force`` unless the plan asked for a proxy or a kill; a network with an endpoint stays.
4. **Say what is about to happen, then do it.** After the last check that can decline and right
   before the irreversible call, ``intend(action)`` is called; the service writes
   ``reconciler.action_intended`` and commits it. If that cannot be written, no call is made
   (``failed / audit_failed``). A declined action (``changed_since_plan``, ``already_gone``) leaves
   no intent, so an intent always means "the call was about to be made".
5. **Keep the evidence of a run nobody can explain.** A container whose run ended in
   ``unknown_outcome`` (reason ``run_unknown_outcome``) is removed only after its inspect output and
   its logs were written to files and read back, and their SHA-256 given to ``saved`` (the audit
   trail). If they cannot be kept in full, the container stays, no intent is written
   (``failed / evidence_not_saved``). See ``evidence.py``.
6. **Verify afterwards, independently of the call's own reply.** A killed container must be seen not
   running; a removed one must be gone from ``get`` *and* from ``list(all=True,
   filters={"id": ...})`` (E14-V2); a removed network must be gone from ``get``. The wait is
   ``verify_wait_s``.

``DockerSandbox.remove_network`` is not used: it returns nothing and swallows every error (E14).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from docker.errors import APIError, NotFound

from control_plane.reconciler import evidence, vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import (
    AUDIT_FAILED,
    CHANGED,
    DAEMON_ERROR,
    DONE,
    EVIDENCE_NOT_SAVED,
    FAILED,
    GONE,
    IN_USE,
    INVALID_ACTION,
    LABELS_CHANGED,
    NOT_AT_REST,
    NOT_GONE_AFTER_REMOVAL,
    NOT_OURS,
    NOT_RUNNING,
    STILL_RUNNING_AFTER_KILL,
    Result,
)

log = logging.getLogger("cyberorch.reconciler")

RUN_LABEL = "cyberorch.run_id"
OWNER_LABEL = "cyberorch.owner"
PROXY_LABEL = "cyberorch.egress_proxy"
ALLOWLIST_LABEL = "cyberorch.allowlist"
NETWORK_PREFIX = "cyberorch-allow-"
LIVE_STATES = frozenset({"running", "paused", "restarting"})
FULL_ID = re.compile(r"[0-9a-f]{64}")
#: how often the verification looks, in seconds; the wait itself is ``verify_wait_s``
POLL_S = 0.2


def perform(action: Action, *, client: Any, th: Thresholds,
            sleep: Callable[[float], None], clock: Callable[[], float],
            intend: Callable[[Action], None] | None = None,
            evidence_dir: str | None = None,
            saved: Callable[[Action, evidence.Saved], None] | None = None) -> Result:
    """Kill or remove what ``action`` names; every path ends in a ``Result``. ``evidence_dir`` and
    ``saved`` serve only the removal of a container whose run's outcome is unknown."""
    if client is None or not FULL_ID.fullmatch(action.subject_id):
        return Result(action, FAILED, INVALID_ACTION)
    try:
        if action.kind == vocab.REMOVE_NETWORK:
            return _remove_network(action, client, th, sleep, clock, intend)
        container = _inspected(client, action)
        if isinstance(container, Result):
            return container
        if action.kind == vocab.KILL_CONTAINER:
            return _kill(action, container, th, sleep, clock, intend)
        return _remove_container(action, container, client, th, sleep, clock, intend,
                                 evidence_dir, saved)
    except APIError:
        return Result(action, FAILED, DAEMON_ERROR)


def declared(action: Action, intend: Callable[[Action], None] | None,
             kept: evidence.Saved | None = None,
             saved: Callable[[Action, evidence.Saved], None] | None = None) -> Result | None:
    """Write the intent just before an irreversible call -- and, after it, what was kept of the
    container (``kept``, only for a run whose outcome is unknown). ``None``: go ahead. A
    ``Result``: a record could not be written, so the call must not be made."""
    if intend is None:
        return None
    try:
        intend(action)
        if kept is not None and saved is not None:
            saved(action, kept)
    except Exception as exc:                                  # noqa: BLE001
        log.error("reconciler: intent not written (%s) for %s; nothing was done",
                  type(exc).__name__, action.kind)
        return Result(action, FAILED, AUDIT_FAILED)
    return None


def _wait_until(check: Callable[[], bool], th: Thresholds, sleep, clock) -> bool:
    """Look until ``check`` is true or ``verify_wait_s`` has passed; always looks at least once."""
    deadline = clock() + th.verify_wait_s
    while True:
        if check():
            return True
        if clock() >= deadline:
            return False
        sleep(POLL_S)


# --- containers ------------------------------------------------------------------------------

def _inspected(client: Any, action: Action) -> Any:
    """The container as it is *now*, or a ``Result`` saying why the action must not go on."""
    try:
        container = client.containers.get(action.subject_id)
        container.reload()
    except NotFound:
        return Result(action, GONE)
    labels = container.labels or {}
    wants_proxy = action.kind == vocab.REMOVE_PROXY
    if container.id != action.subject_id:
        return Result(action, CHANGED, NOT_OURS)
    if (labels.get(RUN_LABEL) != action.run_id or labels.get(OWNER_LABEL) != action.expected_owner
            or (PROXY_LABEL in labels) != wants_proxy):
        return Result(action, CHANGED, LABELS_CHANGED)
    return container


def _state(container: Any) -> str:
    return str(container.attrs.get("State", {}).get("Status", ""))


def _kill(action: Action, container: Any, th: Thresholds, sleep, clock, intend=None) -> Result:
    if _state(container) not in LIVE_STATES:
        return Result(action, CHANGED, NOT_RUNNING)
    if (blocked := declared(action, intend)) is not None:
        return blocked
    try:
        container.kill()
    except APIError:
        try:
            container.reload()
        except NotFound:                               # removed by someone else in the meantime
            return Result(action, GONE)
        if _state(container) not in LIVE_STATES:       # it stopped on its own in the meantime
            return Result(action, CHANGED, NOT_RUNNING)
        raise

    def stopped() -> bool:
        try:
            container.reload()
        except NotFound:
            return True
        return not container.attrs.get("State", {}).get("Running", False)

    if _wait_until(stopped, th, sleep, clock):
        return Result(action, DONE)
    return Result(action, FAILED, STILL_RUNNING_AFTER_KILL)


def _remove_container(action: Action, container: Any, client: Any, th: Thresholds,
                      sleep, clock, intend=None, evidence_dir=None, saved=None) -> Result:
    proxy = action.kind == vocab.REMOVE_PROXY
    if not proxy and _state(container) in LIVE_STATES:
        return Result(action, CHANGED, NOT_AT_REST)        # it started since the plan looked
    kept = None
    if action.reason_code == vocab.RUN_UNKNOWN_OUTCOME and not proxy:
        try:                                    # before the intent: no evidence, no intent, no call
            kept = evidence.save(container, evidence_dir, action.expected_owner)
        except evidence.EvidenceError:
            log.error("reconciler: evidence of a container whose run is unknown was not kept; "
                      "the container stays")
            return Result(action, FAILED, EVIDENCE_NOT_SAVED)
    if (blocked := declared(action, intend, kept, saved)) is not None:
        return blocked

    def gone() -> bool:
        try:
            client.containers.get(action.subject_id)
            return False
        except NotFound:
            pass
        return not client.containers.list(all=True, filters={"id": action.subject_id})

    try:
        container.remove(force=proxy)      # a tool container is removed only if it is at rest
    except NotFound:
        return Result(action, GONE)
    except APIError as exc:
        # Docker answers 409 while another remover is part-way through ("removal of container X
        # is already in progress"), and the container is still listed as it was. If it is gone
        # shortly, someone else removed it: not ours to claim and not a failure (RT8).
        try:
            container.reload()
        except NotFound:
            return Result(action, GONE)
        if not proxy and _state(container) in LIVE_STATES:
            return Result(action, CHANGED, NOT_AT_REST)
        if exc.status_code == 409 and _wait_until(gone, th, sleep, clock):
            return Result(action, GONE)
        raise

    if _wait_until(gone, th, sleep, clock):
        return Result(action, DONE)
    return Result(action, FAILED, NOT_GONE_AFTER_REMOVAL)


# --- networks --------------------------------------------------------------------------------

def _remove_network(action: Action, client: Any, th: Thresholds, sleep, clock,
                    intend=None) -> Result:
    try:
        network = client.networks.get(action.subject_id)
        network.reload()
    except NotFound:
        return Result(action, GONE)
    if (network.id != action.subject_id or network.name != action.name
            or not network.name.startswith(NETWORK_PREFIX)
            or ALLOWLIST_LABEL not in (network.attrs.get("Labels") or {})):
        return Result(action, CHANGED, NOT_OURS)
    # Docker refuses only for running and paused containers; ours is the stricter rule (§1.5)
    if client.containers.list(all=True, filters={"network": network.name}):
        return Result(action, CHANGED, IN_USE)
    if (blocked := declared(action, intend)) is not None:
        return blocked
    def gone() -> bool:
        try:
            client.networks.get(action.subject_id)
            return False
        except NotFound:
            return True

    try:
        network.remove()
    except NotFound:
        return Result(action, GONE)
    except APIError:
        # Docker refuses a removal while another remover is part-way through, and the network is
        # gone by the next look: not ours to claim, and not "in use" (RT8, item 4). A refusal that
        # leaves the network there is the real one.
        if gone():
            return Result(action, GONE)
        return Result(action, FAILED, IN_USE)

    if _wait_until(gone, th, sleep, clock):
        return Result(action, DONE)
    return Result(action, FAILED, NOT_GONE_AFTER_REMOVAL)


def live_mount_sources(client: Any) -> frozenset[str]:
    """Host paths mounted into any container that could still read them: created, running, paused
    or restarting. Re-read by the file half immediately before an unlink (D64-12)."""
    sources: set[str] = set()
    for container in client.containers.list(all=True):
        status = container.attrs.get("State", {}).get("Status")
        if status in LIVE_STATES or status == "created":
            for mount in container.attrs.get("Mounts") or ():
                if mount.get("Source"):
                    sources.add(mount["Source"])
    return frozenset(sources)
