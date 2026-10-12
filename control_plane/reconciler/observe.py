"""What the plan reads: the database through the reader's two functions, Docker with read calls, and
the temporary directory with ``lstat`` (D64 §2.2a). Nothing here changes anything.

The database side takes a *connection* it is handed (``reconciler_reader_scope()`` opens it, in
the caller) and refuses -- ``ObservationError``, not a guess -- anything that is not exactly what
migration 0023's functions return: a different column list, a stage outside the stuck stages, a
value of the wrong type. The Docker side takes a *client*; the file side a directory and a uid. A
test pins that this module calls no verb that changes a container, a network or a file.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import fields
from datetime import datetime
from typing import Any

from sqlalchemy import text

from control_plane.reconciler import vocab
from control_plane.reconciler.model import (
    US,
    ContainerObs,
    FileObs,
    NetworkObs,
    Observation,
    StuckRow,
)

#: Labels the sandbox puts on what it creates (tool_gateway/sandbox.py).
RUN_LABEL = "cyberorch.run_id"
OWNER_LABEL = "cyberorch.owner"
PROXY_LABEL = "cyberorch.egress_proxy"
ALLOWLIST_LABEL = "cyberorch.allowlist"
NETWORK_PREFIX = "cyberorch-allow-"
FILE_PREFIXES = ("cyberorch-cred-", "cyberorch-tls-")

#: Held equal to migrations 0023 and 0024 by a test.
STUCK_ROW_LIMIT = 5000
RUN_IDS_PER_CALL = 2000

STUCK_COLUMNS = tuple(f.name for f in fields(StuckRow))
_TEXT = (str,)
_INT = (int,)
_BOOL = (bool,)
_TYPES: dict[str, tuple[type, ...]] = {
    "engagement_id": _TEXT, "proposal_id": _TEXT, "pipeline_stage": _TEXT,
    "stage_updated_us": _INT, "db_now_us": _INT, "engagement_status": _TEXT,
    "kill_switch_engaged": _BOOL, "enrolled": _BOOL, "capability_id": _TEXT,
    "max_duration_s": _INT, "lease_expires_us": _INT, "capability_revoked": _BOOL,
    "approval_id": _TEXT, "approval_valid_until_us": _INT, "approval_revoked": _BOOL,
    "run_id": _TEXT, "run_status": _TEXT,
}
_REQUIRED = {"engagement_id", "proposal_id", "pipeline_stage", "stage_updated_us", "db_now_us",
             "enrolled"}


class ObservationError(Exception):
    """What was read is not what the contract says it is. The pass stops; nothing is guessed."""


# ---------------------------------------------------------------------------------------------
# the database
# ---------------------------------------------------------------------------------------------

FIRST_PAGE_SQL = "SELECT * FROM reconciler_stuck_proposals()"
NEXT_PAGE_SQL = "SELECT * FROM reconciler_stuck_proposals_after(:after_us, :after_id)"


def _read_page(conn: Any, cursor: tuple[int, str] | None) -> tuple[StuckRow, ...]:
    if cursor is None:
        result = conn.execute(text(FIRST_PAGE_SQL))
    else:
        result = conn.execute(text(NEXT_PAGE_SQL), {"after_us": cursor[0], "after_id": cursor[1]})
    columns = tuple(result.keys())
    if columns != STUCK_COLUMNS:
        raise ObservationError(f"the stuck-proposals function returned columns {columns}")
    return tuple(_stuck_row(dict(zip(columns, values, strict=True))) for values in result)


def read_stuck(conn: Any, *, max_pages: int = 1) -> tuple[tuple[StuckRow, ...], bool]:
    """The stuck proposals, page after page, and whether rows may remain unread.

    Each page is the next ``STUCK_ROW_LIMIT`` rows of ``reconciler_stuck_proposals()`` in
    ``(stage_updated_us, proposal_id)`` order; the next page starts strictly after the last row of
    the one before (a keyset, never an offset). Reading stops at the first page that is not full --
    nothing more -- or after ``max_pages``, and then ``truncated`` is True: the pass says so and
    leaves the rest for the next one (level-triggered). Without paging the oldest 5,000 rows are the
    only ones ever seen, and a row behind 5,000 that the reconciler leaves alone is never reached.

    A page that does not advance the cursor is an error, not a loop. A proposal whose stage
    timestamp moved while the pages were being read can appear twice (it moved later); the later
    reading wins, and the act half's compare-and-set is on whatever it saw.
    """
    seen: dict[str, StuckRow] = {}
    cursor: tuple[int, str] | None = None
    for _ in range(max(1, max_pages)):
        page = _read_page(conn, cursor)
        for row in page:
            seen[row.proposal_id] = row
        if len(page) < STUCK_ROW_LIMIT:
            return tuple(seen.values()), False
        moved = (page[-1].stage_updated_us, page[-1].proposal_id)
        if cursor is not None and moved <= cursor:
            raise ObservationError("a page of stuck proposals did not move past the one before")
        cursor = moved
    return tuple(seen.values()), True


def _stuck_row(values: dict[str, Any]) -> StuckRow:
    for name, value in values.items():
        if value is None:
            if name in _REQUIRED:
                raise ObservationError(f"{name} is NULL")
            continue
        # bool is an int in Python: a boolean where an integer belongs is also wrong
        if type(value) not in _TYPES[name]:
            raise ObservationError(f"{name} has type {type(value).__name__}")
    if values["pipeline_stage"] not in vocab.STUCK_STAGES:
        raise ObservationError("a stage outside the stuck stages was returned")
    return StuckRow(**values)


def read_run_states(conn: Any, run_ids: Iterable[str]) -> dict[str, str]:
    """``reconciler_run_states``: id -> status for the runs the database knows. An id that is not
    in the result is one it does not know."""
    wanted = sorted(set(run_ids))
    states: dict[str, str] = {}
    for start in range(0, len(wanted), RUN_IDS_PER_CALL):
        chunk = wanted[start:start + RUN_IDS_PER_CALL]
        result = conn.execute(
            text("SELECT run_id, status FROM reconciler_run_states(CAST(:ids AS text[]))"),
            {"ids": chunk})
        for run_id, status in result:
            if not isinstance(run_id, str) or not isinstance(status, str):
                raise ObservationError("reconciler_run_states returned a non-text value")
            states[run_id] = status
    return states


# ---------------------------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------------------------

def parse_docker_time(value: str | None) -> int | None:
    """Docker's RFC 3339 with nanoseconds -> microseconds; ``None`` for 0001-01-01 (never)."""
    if not value or value.startswith("0001-01-01"):
        return None
    head, _, rest = value.rstrip("Z").partition(".")
    fraction = (rest + "000000")[:6]
    moment = datetime.fromisoformat(f"{head}.{fraction}+00:00")
    return int(moment.timestamp()) * US + int(fraction)


def container_obs(container: Any) -> ContainerObs:
    attrs = container.attrs
    state = attrs.get("State", {})
    labels = container.labels or {}
    started = parse_docker_time(state.get("StartedAt"))
    return ContainerObs(
        container_id=container.id,
        status=str(state.get("Status", "")),
        run_id=labels.get(RUN_LABEL) or None,
        owner=labels.get(OWNER_LABEL) or None,
        is_proxy=PROXY_LABEL in labels,
        created_us=parse_docker_time(attrs.get("Created")) or 0,
        started_us=started,
        finished_us=parse_docker_time(state.get("FinishedAt")),
    )


def list_containers(client: Any) -> tuple[ContainerObs, ...]:
    """Every container carrying a sandbox run label or the proxy label, in any state."""
    seen: dict[str, Any] = {}
    for label in (RUN_LABEL, PROXY_LABEL):
        for container in client.containers.list(all=True, filters={"label": label}):
            seen[container.id] = container
    return tuple(container_obs(c) for _, c in sorted(seen.items()))


def list_networks(client: Any, containers_of: Callable[[str], Iterable[Any]] | None = None,
                  idle_seen: dict[str, int] | None = None) -> tuple[NetworkObs, ...]:
    """Networks whose name has the sandbox prefix, each with the containers of **any** state
    attached (``created`` and ``exited`` ones included: Docker itself only counts running and
    paused). ``idle_seen`` is the caller's memory of when it first saw each network idle."""
    out = []
    for network in client.networks.list():
        if not network.name.startswith(NETWORK_PREFIX):
            continue
        network.reload()
        attached = (containers_of(network.name) if containers_of is not None else
                    client.containers.list(all=True, filters={"network": network.name}))
        out.append(NetworkObs(
            network_id=network.id, name=network.name,
            has_allowlist_label=ALLOWLIST_LABEL in (network.attrs.get("Labels") or {}),
            created_us=parse_docker_time(network.attrs.get("Created")) or 0,
            attached=tuple(container_obs(c) for c in attached),
            idle_seen_since_us=(idle_seen or {}).get(network.id)))
    return tuple(sorted(out, key=lambda n: n.network_id))


LIVE_STATES = ("created", "running", "paused", "restarting")


def live_mount_sources(client: Any) -> frozenset[str]:
    """Host paths mounted into any container that could still read them (D64-12): created,
    running, paused or restarting -- an exited one no longer needs the file."""
    sources: set[str] = set()
    for container in client.containers.list(all=True):
        if container.attrs.get("State", {}).get("Status") in LIVE_STATES:
            for mount in container.attrs.get("Mounts") or ():
                if mount.get("Source"):
                    sources.add(mount["Source"])
    return frozenset(sources)


# ---------------------------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------------------------

def list_files(directory: str, mounted: frozenset[str]) -> tuple[FileObs, ...]:
    """Entries of ``directory`` whose names start with one of the sweeper's prefixes, through a
    directory fd and ``lstat`` (never following a link)."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        out = []
        for name in sorted(os.listdir(fd)):
            if not name.startswith(FILE_PREFIXES):
                continue
            try:
                info = os.lstat(name, dir_fd=fd)
            except FileNotFoundError:
                continue
            out.append(FileObs(
                directory=directory, name=name, is_regular=stat.S_ISREG(info.st_mode),
                uid=info.st_uid, mtime_us=info.st_mtime_ns // 1000,
                mounted_by_live_container=os.path.join(directory, name) in mounted))
        return tuple(out)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------------------------
# a whole pass
# ---------------------------------------------------------------------------------------------

def observe(conn: Any, client: Any, *, directory: str, expected_uid: int,
            clock_us: Callable[[], int], idle_seen: dict[str, int] | None = None,
            max_pages: int = 1) -> Observation:
    """One pass's reading. The database connection is only used here, and the caller closes it
    before the act half opens its own. ``max_pages`` is ``RECONCILER_MAX_PAGES`` (the service
    always passes it)."""
    rows, truncated = read_stuck(conn, max_pages=max_pages)
    containers = list_containers(client)
    host_now = clock_us()
    run_ids = {c.run_id for c in containers if c.run_id}
    states = read_run_states(conn, run_ids)
    return Observation(
        rows=rows, run_states=states, containers=containers,
        networks=list_networks(client, idle_seen=idle_seen),
        files=list_files(directory, live_mount_sources(client)),
        host_now_us=host_now, expected_uid=expected_uid, rows_truncated=truncated)
