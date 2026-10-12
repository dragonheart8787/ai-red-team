"""What the plan reads and what it hands on: plain, frozen data (D64 §2.2a).

Nothing here holds a connection, a cursor, a Docker object or a file handle -- a test pins that no
field of an ``Action`` has such a type. Times are **integers of microseconds since the epoch**: the
database's own clock for rows (``db_now_us`` arrives with every row), Docker's timestamps for
containers and networks, ``lstat`` for files. The plan compares times from one source with each
other; the single place two clocks meet is a container's ``StartedAt`` against the database's
``now`` (D64 §1.2: the kill bound), and the observer passes the host clock for it explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

US = 1_000_000


# ---------------------------------------------------------------------------------------------
# observations
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class StuckRow:
    """One row of ``reconciler_stuck_proposals()``, with the function's own column names."""

    engagement_id: str
    proposal_id: str
    pipeline_stage: str
    stage_updated_us: int
    db_now_us: int
    engagement_status: str | None
    kill_switch_engaged: bool | None
    enrolled: bool
    capability_id: str | None
    max_duration_s: int | None
    lease_expires_us: int | None
    capability_revoked: bool | None
    approval_id: str | None
    approval_valid_until_us: int | None
    approval_revoked: bool | None
    run_id: str | None
    run_status: str | None


@dataclass(frozen=True)
class ContainerObs:
    """A container as Docker lists and inspects it."""

    container_id: str                 # the FULL id: the only handle an action may use
    status: str                       # created | running | paused | restarting | exited | ...
    run_id: str | None                # label cyberorch.run_id ("" -> None)
    owner: str | None                 # label cyberorch.owner ("" is NO_OWNER -> None)
    is_proxy: bool                    # label cyberorch.egress_proxy
    created_us: int
    started_us: int | None            # None if it never started (Docker's 0001-01-01)
    finished_us: int | None           # None while running or if it never ran


@dataclass(frozen=True)
class NetworkObs:
    """A network as Docker lists it, with every container of any state attached to it."""

    network_id: str                   # full id
    name: str
    has_allowlist_label: bool
    created_us: int
    attached: tuple[ContainerObs, ...] = ()
    #: since when the observer has *seen* it idle (its own memory of earlier passes), if it has
    idle_seen_since_us: int | None = None


@dataclass(frozen=True)
class FileObs:
    """A directory entry in the temporary directory, from ``lstat`` through a directory fd."""

    directory: str
    name: str
    is_regular: bool                  # S_ISREG on the lstat, so a symlink is not
    uid: int
    mtime_us: int
    mounted_by_live_container: bool


@dataclass(frozen=True)
class Observation:
    """Everything one pass read."""

    rows: tuple[StuckRow, ...] = ()
    #: ``reconciler_run_states`` for every run id a container names: id -> status. A run id the
    #: database does not know is *absent* from this mapping.
    run_states: dict[str, str] = field(default_factory=dict)
    containers: tuple[ContainerObs, ...] = ()
    networks: tuple[NetworkObs, ...] = ()
    files: tuple[FileObs, ...] = ()
    #: the host's clock, in microseconds, when the containers were listed
    host_now_us: int = 0
    #: the file owner the sweeper expects (the control plane's uid)
    expected_uid: int = -1
    #: the stuck-proposals result filled its page, so rows beyond it were not seen
    rows_truncated: bool = False


# ---------------------------------------------------------------------------------------------
# what the plan hands on
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Action:
    """One thing the act half is asked to do. Plain data; the act half re-verifies it."""

    kind: str                          # vocab.ACTION_KINDS
    reason_code: str                   # vocab.REASONS[kind]
    subject_id: str                    # proposal id / FULL container or network id / file name
    engagement_id: str | None = None   # for a proposal action, and for an owned container
    run_id: str | None = None
    #: proposal actions: the compare-and-set on what the plan observed
    expected_stage: str | None = None
    planned_stage_updated_us: int | None = None
    #: Docker actions: what the act half re-inspects before touching it
    expected_owner: str | None = None
    name: str | None = None            # a network's name, a file's name
    directory: str | None = None       # a file's directory


@dataclass(frozen=True)
class Report:
    """Something seen and deliberately left alone."""

    subject: str                       # vocab.SUBJECTS
    subject_id: str
    reason_code: str                   # vocab.REPORT_REASONS
    engagement_id: str | None = None


@dataclass(frozen=True)
class Plan:
    actions: tuple[Action, ...] = ()
    reports: tuple[Report, ...] = ()
