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

    def failures(self) -> list[str]:
        if not self.unregistered:
            return []
        shown = sorted(set(self.unregistered))[:5]
        return [f"{len(self.unregistered)} stuck proposal(s) newer than the session in engagements "
                f"it did not register (tests.helpers.make_engagement does): {shown}"]


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
                for stage, n in conn.execute(text(COUNT_STUCK), {"stuck": list(STUCK)}):
                    done.proposals[stage] = done.proposals.get(stage, 0) + n
                conn.execute(text(CLOSE_PROPOSALS), {"stuck": list(STUCK)})
                done.runs += conn.execute(text(CLOSE_RUNS), {"in_flight": list(IN_FLIGHT)}).rowcount
            done.engagements += 1
    finally:
        engine.dispose()
    with reconciler_reader_scope() as conn:
        rows, _ = observe.read_stuck(conn, max_pages=SEARCH_PAGES)
    done.unregistered = [(r.engagement_id, r.pipeline_stage) for r in rows
                         if r.stage_updated_us >= before.started_us
                         and r.engagement_id not in CREATED]
    return done
