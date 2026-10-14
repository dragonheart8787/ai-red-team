"""The plan: what was read, and the configured thresholds, in; what to do and what to leave, out.

A **pure function**. It opens nothing, calls nothing, reads no clock and holds no state: the same
``Observation`` and ``Thresholds`` give the same ``Plan`` in the same order, whatever order the
observations arrived in. It contains **no number of its own** -- not a grace, not a margin, not a
period -- only comparisons against ``Thresholds`` and the unit conversion ``US``; a test reads the
syntax tree and fails on any other numeric literal. Every decision is one of the residues of
docs/D64_RECONCILER_DESIGN.md §1.1:

========  ====================================================  =================================
R1        ``dispatching`` past ``B + P + Q``                    mark ``unknown_outcome``
R2        a container still running past ``StartedAt + B + K``  kill it; keep the corpse; later
                                                                remove it
R3        ``capability_issued``, lease lapsed                   close ``capability_not_live``
R4/R5     ``approved``: engagement killed / approval expired    close (the scheduler's own work is
          or revoked and the engagement not enrolled            left to the scheduler)
R6        ``received`` / ``decided`` past the grace             abandon / close
R7        orphan egress proxy                                   remove
R8        idle network; a network whose range blocked a         remove
          refused run and is not in use (migration 0025)
R9        credential and TLS files                              unlink
========  ====================================================  =================================

What it will not do is as much the point: it never touches a container whose owner label is empty
(probes and lab scripts), never kills on a budget it cannot read, never acts on an object whose run
the database does not know when that object is *running*, never touches a symlink or a file of
another owner, and never removes anything that is attached, mounted or younger than its bound. Those
cases come back as ``Report`` entries -- seen, and left.
"""

from __future__ import annotations

import re

from control_plane.reconciler import vocab
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import (
    NO_BLOCKER,
    US,
    Action,
    ConflictObs,
    ContainerObs,
    FileObs,
    NetworkObs,
    Observation,
    Plan,
    Report,
    StuckRow,
    name_hash_n,
)

#: container states in which a container can still do something (D64 §1.5)
LIVE_STATES = frozenset({"running", "paused", "restarting"})
#: never started / finished: nothing is running, the corpse is evidence
AT_REST_STATES = frozenset({"created", "exited"})
#: a run status that says the run is over; the others say it may still be in flight
RUN_OVER = frozenset({"succeeded", "failed", "unknown_outcome"})

NETWORK_PREFIX = "cyberorch-allow-"
#: what ``tempfile.mkstemp`` makes: 8 characters of [a-z0-9_] after the prefix we give it
CRED_NAME = re.compile(r"^cyberorch-cred-[a-z0-9_]{8}$")
TLS_NAME = re.compile(r"^cyberorch-tls-[a-z0-9_]{8}\.pem$")

#: The order the act half carries actions out in. Kills before the proposals they bear on are
#: declared unknown; containers before the network they hold; files last.
EXECUTION_ORDER = (
    vocab.KILL_CONTAINER, vocab.REMOVE_PROXY, vocab.REMOVE_CONTAINER,
    vocab.MARK_UNKNOWN_OUTCOME, vocab.CLOSE, vocab.ABANDON,
    vocab.REMOVE_NETWORK, vocab.UNLINK_FILE,
)


def plan(obs: Observation, th: Thresholds) -> Plan:
    """The whole pass: proposals, containers and proxies, networks, files."""
    actions: list[Action] = []
    reports: list[Report] = []
    for part in (_proposals(obs.rows, th), _containers(obs, th), _networks(obs, th),
                 _files(obs, th)):
        actions.extend(part[0])
        reports.extend(part[1])
    if obs.rows_truncated:
        reports.append(Report("result", "stuck_proposals", vocab.RESULT_TRUNCATED))
    clock = _docker_clock(obs, th)
    if clock is not None:
        # every age of a Docker object is the daemon's clock against ours: with the two apart, none
        # of them is judged, and nothing that kills or removes one is asked for (ACCEPTANCE 5.93)
        actions = [a for a in actions if a.kind not in vocab.DOCKER_ACTIONS]
        reports.append(clock)
    actions.sort(key=lambda a: (EXECUTION_ORDER.index(a.kind), a.subject_id, a.reason_code))
    reports.sort(key=lambda r: (r.subject, r.subject_id, r.reason_code))
    return Plan(tuple(actions), tuple(reports))


# ---------------------------------------------------------------------------------------------
# proposals: R1, R3, R4, R5, R6
# ---------------------------------------------------------------------------------------------

def _proposals(rows: tuple[StuckRow, ...], th: Thresholds) -> tuple[list[Action], list[Report]]:
    actions: list[Action] = []
    reports: list[Report] = []
    for row in sorted(rows, key=lambda r: (r.stage_updated_us, r.proposal_id)):
        decided = _proposal(row, th)
        if isinstance(decided, Action):
            actions.append(decided)
        elif isinstance(decided, Report):
            reports.append(decided)
    return actions, reports


def _move(row: StuckRow, kind: str, reason: str) -> Action:
    return Action(kind=kind, reason_code=reason, subject_id=row.proposal_id,
                  engagement_id=row.engagement_id, run_id=row.run_id,
                  expected_stage=row.pipeline_stage,
                  planned_stage_updated_us=row.stage_updated_us)


def _report(row: StuckRow, reason: str) -> Report:
    return Report("proposal", row.proposal_id, reason, row.engagement_id)


def _proposal(row: StuckRow, th: Thresholds) -> Action | Report | None:
    now = row.db_now_us
    stage = row.pipeline_stage
    if stage == vocab.STAGE_RECEIVED:
        if now - row.stage_updated_us >= th.stage_grace_s * US:
            return _move(row, vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
        return None
    if stage == vocab.STAGE_DECIDED:
        if now - row.stage_updated_us >= th.stage_grace_s * US:
            return _move(row, vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)
        return None
    if stage == vocab.STAGE_CAPABILITY_ISSUED:
        if row.capability_id is None or row.lease_expires_us is None:
            return _report(row, vocab.CAPABILITY_MISSING)
        if now >= row.lease_expires_us + th.lease_grace_s * US:
            return _move(row, vocab.CLOSE, vocab.CAPABILITY_NOT_LIVE)
        return None
    if stage == vocab.STAGE_APPROVED:
        return _approved(row, th)
    if stage == vocab.STAGE_DISPATCHING:
        if row.capability_id is None:
            return _report(row, vocab.CAPABILITY_MISSING)
        if row.max_duration_s is None:
            return _report(row, vocab.BUDGET_UNREADABLE)
        if now >= row.stage_updated_us + th.unknown_after_s(row.max_duration_s) * US:
            return _move(row, vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME)
        return None
    return _report(row, vocab.UNEXPECTED_STATE)


def _approved(row: StuckRow, th: Thresholds) -> Action | Report | None:
    """Only the proposals the scheduler cannot resolve: a killed engagement (one-way), or an
    engagement it does not serve. A paused engagement is not touched: pause is reversible."""
    if row.kill_switch_engaged is True or row.engagement_status == "killed":
        return _move(row, vocab.CLOSE, vocab.ENGAGEMENT_KILLED)
    if row.enrolled:
        return None
    if row.approval_id is None:
        return _report(row, vocab.APPROVAL_MISSING)
    if row.approval_revoked is True:
        return _move(row, vocab.CLOSE, vocab.APPROVAL_REVOKED)
    if (row.approval_valid_until_us is not None
            and row.db_now_us >= row.approval_valid_until_us + th.approval_grace_s * US):
        return _move(row, vocab.CLOSE, vocab.APPROVAL_EXPIRED)
    return None


def _docker_clock(obs: Observation, th: Thresholds) -> Report | None:
    """A report when the host's clock and the daemon's are not known to agree within the
    configured bound; ``None`` when they are."""
    if obs.docker_skew_us is None:
        return Report("result", "docker_clock", vocab.DOCKER_CLOCK_UNKNOWN)
    if abs(obs.docker_skew_us) > th.max_clock_skew_s * US:
        return Report("result", "docker_clock", vocab.DOCKER_CLOCK_SKEWED)
    return None


# ---------------------------------------------------------------------------------------------
# containers and proxies: R2, R7
# ---------------------------------------------------------------------------------------------

def _containers(obs: Observation, th: Thresholds) -> tuple[list[Action], list[Report]]:
    actions: list[Action] = []
    reports: list[Report] = []
    dispatching = {r.run_id: r for r in obs.rows
                   if r.run_id is not None and r.pipeline_stage == vocab.STAGE_DISPATCHING}
    for c in sorted(obs.containers, key=lambda c: c.container_id):
        decided = _container(c, obs, th, dispatching)
        if isinstance(decided, Action):
            actions.append(decided)
        elif isinstance(decided, Report):
            reports.append(decided)
    return actions, reports


def _docker_action(c: ContainerObs, kind: str, reason: str) -> Action:
    return Action(kind=kind, reason_code=reason, subject_id=c.container_id,
                  engagement_id=c.owner, run_id=c.run_id, expected_owner=c.owner)


def _container(c: ContainerObs, obs: Observation, th: Thresholds,
               dispatching: dict[str, StuckRow]) -> Action | Report | None:
    if c.owner is None:
        return Report("container", c.container_id, vocab.NO_OWNER_LABEL)
    if c.run_id is None:
        return Report("container", c.container_id, vocab.NO_RUN_ID_LABEL)
    if c.status not in LIVE_STATES and c.status not in AT_REST_STATES:
        return Report("container", c.container_id, vocab.UNEXPECTED_STATE, c.owner)
    run_status = obs.run_states.get(c.run_id)
    row = dispatching.get(c.run_id)
    if c.is_proxy:
        return _proxy(c, obs, th, run_status, row)
    if c.status in LIVE_STATES:
        return _overdue_tool(c, obs, th, run_status, row)
    return _at_rest(c, obs, th, run_status)


def _budget_s(th: Thresholds, row: StuckRow | None) -> int | None:
    """The budget a container is judged by: its proposal's, when the proposal is still stuck at
    ``dispatching``; otherwise the cap (the longest a legal run can last). ``None`` means the
    proposal is there and its budget cannot be read -- the plan does not guess."""
    if row is None:
        return th.b_cap_s
    return row.max_duration_s


def _overdue_tool(c: ContainerObs, obs: Observation, th: Thresholds, run_status: str | None,
                  row: StuckRow | None) -> Action | Report | None:
    if run_status is None:
        return Report("container", c.container_id, vocab.RUN_UNKNOWN, c.owner)
    if c.started_us is None:
        return Report("container", c.container_id, vocab.UNEXPECTED_STATE, c.owner)
    budget = _budget_s(th, row)
    if budget is None:
        return Report("container", c.container_id, vocab.BUDGET_UNREADABLE, c.owner)
    if obs.host_now_us >= c.started_us + th.kill_after_s(budget) * US:
        return _docker_action(c, vocab.KILL_CONTAINER, vocab.OVERRAN_DEADLINE)
    return None


def _at_rest(c: ContainerObs, obs: Observation, th: Thresholds,
             run_status: str | None) -> Action | None:
    """An exited or never-started container: its output is kept for the retention window."""
    if c.status in LIVE_STATES:
        return None
    since = c.finished_us if c.finished_us is not None else c.created_us
    if obs.host_now_us - since < th.retention_s * US:
        return None
    if run_status is None:
        return _docker_action(c, vocab.REMOVE_CONTAINER, vocab.NO_RUN_ROW_PAST_GRACE)
    if run_status in RUN_OVER:
        return _docker_action(c, vocab.REMOVE_CONTAINER, vocab.RUN_FINISHED)
    return None        # the run may still be recording: the proposal's own bound decides


def _proxy(c: ContainerObs, obs: Observation, th: Thresholds, run_status: str | None,
           row: StuckRow | None) -> Action | Report | None:
    if run_status is None:
        return Report("container", c.container_id, vocab.RUN_UNKNOWN, c.owner)
    if run_status in RUN_OVER:
        return _docker_action(c, vocab.REMOVE_PROXY, vocab.OWNER_RUN_ENDED)
    if c.status not in LIVE_STATES:
        return None                  # created, not started yet: its dispatch is still setting up
    if c.started_us is None:
        return Report("container", c.container_id, vocab.UNEXPECTED_STATE, c.owner)
    budget = _budget_s(th, row)
    if budget is None:
        return Report("container", c.container_id, vocab.BUDGET_UNREADABLE, c.owner)
    if obs.host_now_us >= c.started_us + th.proxy_overdue_after_s(budget) * US:
        return _docker_action(c, vocab.REMOVE_PROXY, vocab.OVERRAN_DEADLINE)
    return None


# ---------------------------------------------------------------------------------------------
# networks: R8
# ---------------------------------------------------------------------------------------------

def _networks(obs: Observation, th: Thresholds) -> tuple[list[Action], list[Report]]:
    actions: list[Action] = []
    reports: list[Report] = []
    blockers = {c.blocking_hash_n: c for c in obs.conflicts if c.blocking_hash_n != NO_BLOCKER}
    for n in sorted(obs.networks, key=lambda n: n.network_id):
        if _idle_network(n, obs, th):
            actions.append(Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP,
                                  subject_id=n.network_id, name=n.name))
            continue
        decided = _conflict_blocker(n, blockers.get(name_hash_n(n.name)), obs, th)
        if isinstance(decided, Action):
            actions.append(decided)
        elif isinstance(decided, Report):
            reports.append(decided)
    # refusals no network of ours in this database's history explains: a lab's network, or another
    # deployment on the same daemon. Seen and left alone -- we never remove what we cannot name.
    if any(c.blocking_hash_n == NO_BLOCKER and c.conflicts_n >= 1 for c in obs.conflicts):
        reports.append(Report(subject="result", subject_id="network_conflicts",
                              reason_code=vocab.NETWORK_CONFLICT_FOREIGN))
    return actions, reports


def _conflict_blocker(n: NetworkObs, c: ConflictObs | None, obs: Observation,
                      th: Thresholds) -> Action | Report | None:
    """A network of ours that blocked a refused run (D64 pre-deletion §3.3). Removed only if every
    one of these holds; if the first three do and a later one does not, the conflict is
    *unresolved* and reported, because the next refusal will come again.

    1. it is ours (prefix **and** allowlist label) and the database names it as a blocker;
    2. the latest refusal is *after* the allowlist's last use (a later run means it is in use);
    3. no run on its allowlist is unfinished, and none for ``network_conflict_min_idle_s``;
    4. no container of any state is attached (the act half asks Docker again on the spot);
    5. this process has removed it fewer than ``network_conflict_daily_cap`` times in 24 h.
    """
    if c is None or not (n.name.startswith(NETWORK_PREFIX) and n.has_allowlist_label):
        return None
    if c.conflicts_n < 1 or c.last_conflict_us <= c.last_used_us:
        return None
    unresolved = Report(subject="network", subject_id=n.network_id,
                        reason_code=vocab.NETWORK_CONFLICT_UNRESOLVED)
    if c.live_runs_n or c.db_now_us - c.last_used_us < th.network_conflict_min_idle_s * US:
        return unresolved
    if n.attached:
        return unresolved
    if obs.conflict_removals_24h.get(c.blocking_hash_n, 0) >= th.network_conflict_daily_cap:
        return unresolved
    return Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.RANGE_CONFLICT,
                  subject_id=n.network_id, name=n.name)


def _idle_network(n: NetworkObs, obs: Observation, th: Thresholds) -> bool:
    """Ours (the name prefix **and** the allowlist label -- a lookalike has only the first), with no
    container of any state attached, and idle for the configured time. Docker itself refuses only
    for running and paused containers; a created or exited one does not block it, and removing the
    network under a ``created`` one is a dispatch between ``create`` and ``start`` (D64 §1.5)."""
    if not (n.name.startswith(NETWORK_PREFIX) and n.has_allowlist_label):
        return False
    if n.attached:
        return False
    idle_since = max(n.created_us, n.idle_seen_since_us or n.created_us)
    return obs.host_now_us - idle_since >= th.network_idle_s * US


# ---------------------------------------------------------------------------------------------
# files: R9
# ---------------------------------------------------------------------------------------------

def _files(obs: Observation, th: Thresholds) -> tuple[list[Action], list[Report]]:
    actions: list[Action] = []
    reports: list[Report] = []
    for f in sorted(obs.files, key=lambda f: (f.directory, f.name)):
        decided = _file(f, obs, th)
        if isinstance(decided, Action):
            actions.append(decided)
        elif isinstance(decided, Report):
            reports.append(decided)
    return actions, reports


def _file(f: FileObs, obs: Observation, th: Thresholds) -> Action | Report | None:
    if CRED_NAME.fullmatch(f.name):
        kind = "credential_mount"
    elif TLS_NAME.fullmatch(f.name):
        kind = "tls_leaf"
    else:
        return Report("file", f.name, vocab.NAME_MISMATCH)
    if not f.is_regular:
        return Report("file", f.name, vocab.NOT_A_REGULAR_FILE)
    if f.uid != obs.expected_uid:
        return Report("file", f.name, vocab.FOREIGN_OWNER)
    if f.mounted_by_live_container:
        return None
    if obs.host_now_us - f.mtime_us < th.file_age_s() * US:
        return None
    return Action(kind=vocab.UNLINK_FILE, reason_code=kind, subject_id=f.name, name=f.name,
                  directory=f.directory)
