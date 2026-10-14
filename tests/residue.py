"""What a test session must not leave behind (D63).

A suite that leaves state behind makes the next run depend on the last one: a global ``DENY``
overlay made every scheduler test fail on a second local run (D63 closeout 2); a graph fixture
that was never taken back grew the tables until the planner changed its mind about a query
(ACCEPTANCE 5.23); Docker networks of earlier sessions were still there days later. CI starts empty
and never sees any of it.

A fourth kind is **closed**, not compared: the rows the session itself made. Every table the suite
writes is under ``FORCE ROW LEVEL SECURITY`` and the runtime role has no ``DELETE``, so rows are
never removed; but a proposal a test leaves part-way (``received``, ``approved``,
``dispatching`` ...) stays *stuck* for ever, and a full run of the suite left about 600 of them
(605 and 632 measured, ACCEPTANCE 5.23; D64 pre-deletion §2.2 for where the 18,123 that were once
cleaned by hand came from). At the end of the session every stuck proposal of an engagement the
session created is moved to a terminal stage, and every run still in flight in those engagements is
marked ``unknown_outcome`` (``close_session_rows``), the way the reconciler would. Counted and
reported.
What the session made in an engagement it did not register (``CREATED``, filled by
``tests.helpers.make_engagement``) is *found* instead -- a stuck proposal newer than the session's
start that belongs to no registered engagement fails the run, so the registration is not skipped.

Three kinds of thing are compared, **before** the session and **after** it:

* **global policy layers** -- an active layer with no engagement applies to every engagement, so
  one left active is the worst kind of residue. Not cleaned up: the test that published it is
  wrong, and the run fails so that it is found;
* **containers** -- any container, running or not, that did not exist at the start. Not cleaned up,
  for the same reason;
* **networks** -- ``cyberorch-*`` networks that did not exist at the start. The sandbox keeps one
  network per allowlist and removes it only on request (``remove_network``, ADR D58-13): it is
  designed to persist, so a test that makes a sandbox run leaves one. Those are removed here, and
  counted, and the run fails only if one cannot be removed (something is still attached to it).

What was there *before* the session is never touched: a development database keeps its real
baseline, and a Docker host keeps its other containers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from sqlalchemy import create_engine, text

from control_plane.reconciler import observe
from control_plane.state.db import get_engine, global_policy_admin_scope, reconciler_reader_scope

NETWORK_PREFIX = "cyberorch-"

#: the stages a test can leave a proposal in that nothing will ever move it out of
STUCK = ("received", "decided", "approved", "capability_issued", "dispatching")
#: a run still in flight
IN_FLIGHT = ("queued", "dispatching", "running")
#: pages of 5,000 the end-of-session search for unregistered stuck rows reads at most
SEARCH_PAGES = 40

#: engagements this session created (``tests.helpers.make_engagement``); their stuck rows are the
#: session's own
CREATED: set[str] = set()
#: the test file each of them was created in (from ``PYTEST_CURRENT_TEST``), for the per-file count
FILE_OF: dict[str, str] = {}
NOT_IN_A_TEST = "(outside a test: a session fixture)"

#: The most rows -- stuck proposals plus in-flight runs -- a test file may leave for the end of the
#: session to close. **A file not listed may leave none.** The numbers are what each file leaves by
#: design, measured at completion 3 (ACCEPTANCE 5.71): a file that leaves more has a test that
#: stopped finishing what it started, and the run fails naming the file, so that the leak is found
#: where it was made and not as a thousand rows in a development database. A cap is raised only
#: by someone who has read why the file leaves rows.
FILE_CAP: dict[str, int] = {
    # Hypothesis chooses how much of 300 examples x 30 steps leaves a hand-made proposal behind
    # (490, 455 in two measured runs); the bound is generous because the count is not fixed
    "tests/stateful/test_capability_lifecycle.py": 1000,
    # Measured in two full runs, the same both times. Where a reason is given it was found by
    # running the file alone; the others are measured and not yet explained, and say so.
    "tests/test_scheduler_roles.py": 116,        # measured, not yet explained
    "tests/test_approved_dispatch.py": 17,       # measured, not yet explained
    "tests/test_scheduler_skips.py": 14,         # measured, not yet explained
    "tests/test_scheduler_service.py": 8,        # measured, not yet explained
    "tests/test_dispatch_late_result.py": 6,     # 1 proposal + 5 runs; measured, not yet explained
    "tests/test_approvals.py": 6,                # measured, not yet explained
    "tests/test_pipeline_stages.py": 6,          # the three kill -9 experiments: 3 + 3 runs
    "tests/test_dispatch.py": 5,                 # five `received` proposals; not yet explained
    "tests/test_web_console.py": 5,              # measured, not yet explained
    "tests/test_scheduler_e2e.py": 4,            # measured, not yet explained
    "tests/test_stage_vocabulary.py": 3,         # test_st6: approved with no approval row,
                                                 # dispatching, and one received
    "tests/test_network_conflicts_read.py": 3,   # three runs made 'running' by the test itself
    "tests/test_scheduler_structure.py": 1,      # measured, not yet explained
    "tests/test_scheduler_cli.py": 1,            # measured, not yet explained
}


def register(engagement_id: str) -> None:
    """An engagement this session made: its stuck rows are the session's to close, and the file of
    the test that made it is remembered. Called by ``tests.helpers.make_engagement``."""
    CREATED.add(engagement_id)
    FILE_OF.setdefault(engagement_id, current_file())


def current_file() -> str:
    """The test file running now (``PYTEST_CURRENT_TEST`` is ``path::name (phase)``)."""
    running = os.environ.get("PYTEST_CURRENT_TEST", "")
    path = running.split("::", 1)[0].strip()
    return path if path.endswith(".py") else NOT_IN_A_TEST


@dataclass(frozen=True)
class Snapshot:
    layers: frozenset[int]
    containers: frozenset[str] | None            # None: no Docker daemon to look at
    networks: frozenset[str] | None
    #: the database's clock when the session began, in microseconds since the epoch
    started_us: int = 0


@dataclass
class Leftovers:
    layers: list[tuple[int, str, int]] = field(default_factory=list)      # (id, layer, version)
    containers: list[str] = field(default_factory=list)                   # "name (id) status"
    networks_removed: list[str] = field(default_factory=list)
    networks_stuck: list[str] = field(default_factory=list)

    def failures(self) -> list[str]:
        out = []
        if self.layers:
            out.append(f"active policy layers with no engagement left behind: {self.layers}")
        if self.containers:
            out.append(f"containers left behind: {self.containers}")
        if self.networks_stuck:
            out.append(f"networks that could not be removed (something is attached): "
                       f"{self.networks_stuck}")
        return out


def _docker():
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return client
    except Exception:
        return None


def _active_unbound_layers() -> list[tuple[int, str, int]]:
    """Active layers that are not an engagement's own: the global ones and each customer's."""
    with global_policy_admin_scope() as conn:
        return [tuple(r) for r in conn.execute(text(
            "SELECT id, layer, version FROM policy_layers "
            "WHERE engagement_id IS NULL AND active IS TRUE ORDER BY id")).all()]


def database_now_us() -> int:
    with get_engine().connect() as conn:
        return conn.execute(text("SELECT (extract(epoch FROM now()) * 1000000)::bigint")
                            ).scalar_one()


def snapshot() -> Snapshot:
    client = _docker()
    return Snapshot(
        started_us=database_now_us(),
        layers=frozenset(row[0] for row in _active_unbound_layers()),
        containers=None if client is None else frozenset(
            c.id for c in client.containers.list(all=True)),
        networks=None if client is None else frozenset(
            n.name for n in client.networks.list() if n.name.startswith(NETWORK_PREFIX)),
    )


def leftovers(before: Snapshot) -> Leftovers:
    """Compare with ``before``; remove the sandbox networks the session made and say which."""
    found = Leftovers(layers=[
        row for row in _active_unbound_layers() if row[0] not in before.layers])
    client = _docker()
    if client is None or before.containers is None:
        return found
    found.containers = [f"{c.name} ({c.short_id}) {c.status}"
                        for c in client.containers.list(all=True) if c.id not in before.containers]
    for network in client.networks.list():
        if network.name.startswith(NETWORK_PREFIX) and network.name not in (before.networks or ()):
            try:
                network.remove()
                found.networks_removed.append(network.name)
            except Exception:
                found.networks_stuck.append(network.name)
    return found


# ---------------------------------------------------------------------------------------------
# the rows the session made
# ---------------------------------------------------------------------------------------------

@dataclass
class RowsClosed:
    proposals: dict[str, int] = field(default_factory=dict)      # stage it was in -> how many
    runs: int = 0
    engagements: int = 0
    #: stuck proposals newer than the session in an engagement nobody registered
    unregistered: list[tuple[str, str]] = field(default_factory=list)
    #: test file -> (stuck proposals, in-flight runs) its engagements left for the session end
    by_file: dict[str, tuple[int, int]] = field(default_factory=dict)
    caps: dict[str, int] = field(default_factory=lambda: dict(FILE_CAP))

    def over_cap(self) -> dict[str, tuple[int, int]]:
        """File -> (rows it left, its cap) for every file that left more than it may."""
        return {f: (p + r, self.caps.get(f, 0)) for f, (p, r) in sorted(self.by_file.items())
                if p + r > self.caps.get(f, 0)}

    def failures(self) -> list[str]:
        out = []
        if self.unregistered:
            shown = sorted(set(self.unregistered))[:5]
            out.append(f"{len(self.unregistered)} stuck proposal(s) newer than the session in "
                       f"engagements it did not register (tests.helpers.make_engagement does): "
                       f"{shown}")
        for file, (left, cap) in self.over_cap().items():
            out.append(f"{file} left {left} stuck row(s) (proposals {self.by_file[file][0]}, "
                       f"in-flight runs {self.by_file[file][1]}) and may leave {cap}: a test there "
                       f"does not finish what it starts (tests/residue.py FILE_CAP)")
        return out

    def table(self) -> list[str]:
        """One line per file that left anything: what it left, and its cap."""
        return [f"  {file}: {p} proposal(s) + {r} run(s), cap {self.caps.get(file, 0)}"
                for file, (p, r) in sorted(self.by_file.items(), key=lambda kv: -sum(kv[1]))
                if p or r]


CLOSE_PROPOSALS = """
    UPDATE action_proposals
    SET pipeline_stage = CASE WHEN decision IS NULL THEN 'abandoned' ELSE 'closed' END,
        stage_detail = CASE WHEN decision IS NULL THEN 'undecided_past_grace'
                            ELSE 'test_cleanup' END,
        stage_updated_at = now()
    WHERE pipeline_stage = ANY(:stuck)"""
COUNT_STUCK = """
    SELECT pipeline_stage, count(*) FROM action_proposals
    WHERE pipeline_stage = ANY(:stuck) GROUP BY pipeline_stage"""
CLOSE_RUNS = """
    UPDATE tool_runs SET status = 'unknown_outcome', finished_at = coalesce(finished_at, now())
    WHERE status = ANY(:in_flight)"""


def close_session_rows(before: Snapshot) -> RowsClosed:
    """Move the stuck proposals and in-flight runs of every engagement this session created to a
    terminal state, then look for stuck proposals newer than the session that this did not cover.
    The table owner with the engagement bound -- as subject to row-level security as anyone."""
    done = RowsClosed()
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        for eid in sorted(CREATED):
            with engine.begin() as conn:
                conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                             {"e": eid})
                proposals = 0
                for stage, n in conn.execute(text(COUNT_STUCK), {"stuck": list(STUCK)}):
                    done.proposals[stage] = done.proposals.get(stage, 0) + n
                    proposals += n
                conn.execute(text(CLOSE_PROPOSALS), {"stuck": list(STUCK)})
                runs = conn.execute(text(CLOSE_RUNS), {"in_flight": list(IN_FLIGHT)}).rowcount
            done.runs += runs
            done.engagements += 1
            if proposals or runs:
                file = FILE_OF.get(eid, NOT_IN_A_TEST)
                had = done.by_file.get(file, (0, 0))
                done.by_file[file] = (had[0] + proposals, had[1] + runs)
    finally:
        engine.dispose()
    with reconciler_reader_scope() as conn:
        rows, _ = observe.read_stuck(conn, max_pages=SEARCH_PAGES)
    done.unregistered = [(r.engagement_id, r.pipeline_stage) for r in rows
                         if r.stage_updated_us >= before.started_us
                         and r.engagement_id not in CREATED]
    return done
