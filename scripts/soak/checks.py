"""The soak's invariants (D66).

Each check returns a :class:`Result` -- ``ok`` or not, and what it saw. **A check is never relaxed
to make a run pass**: the definitions below were written from the design documents before the
first run, and a failure is a finding. The pure parts (``rising_floor``, ``duplicate_creates``) are
unit-tested in ``tests/test_soak_checks.py`` with series that must fail them.

* **coherence** -- ``assert_coherent`` of ``tests/test_pipeline_stages.py`` over a repeatable-read
  snapshot of every engagement of the soak;
* **no capability on an abandoned proposal** -- stated again in SQL, over all rows, not only by
  ``assert_coherent`` (D64 A7);
* **I7, no run twice** -- no proposal with two runs that ran, no capability with two runs (the
  database), and no run id, and no proposal, for which Docker reported more than one tool container
  created (the witness: ``docker events``);
* **residue does not grow** -- the floor of containers, exited tool containers, proxies, networks
  and temp files, per window, did not rise in each of the last three windows;
* **no connection leak** -- the same for the connections of each process incarnation, and no
  transaction left open ``idle in transaction`` for longer than a minute;
* **audit matches state** -- see ``AUDIT_PAIRS``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scripts.soak import lib


@dataclass
class Result:
    name: str
    ok: bool
    detail: str = ""
    #: False when the check ran but had too little to judge (a series shorter than its windows):
    #: it counts as an execution and not as a judgement, and a run in which a check never judged
    #: anything is a failure (``never_ran``)
    judged: bool = True

    def as_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "judged": self.judged}


#: Every check of a cycle, by the name it reports under. A run in which one of these has **no**
#: execution -- or never judged anything -- has verified nothing about it and is a failure.
CYCLE_CHECKS = (
    "coherence",
    "no capability on an abandoned proposal",
    "I7 database: no proposal and no capability with two runs",
    "I7 docker: no run, no proposal, with two containers created",
    "audit events match state transitions",
    "residue (containers, networks, proxies, files) does not grow",
    "no connection leak",
    "unresolved reconciler intents (listed, not judged)",
    "schema is identical to the one at the start",
)
#: the check made once, after the drain
DRAIN_CHECK = "after the drain nothing of the soak is left"
#: checks that are listed and not judged by design: their executions count, their judgement does not
NOT_JUDGED_BY_DESIGN = ("unresolved reconciler intents (listed, not judged)",)


#: Checks that are **recorded but not enforced in a smoke run**, and only there. A smoke run injects
#: a fault a minute apart so that all six kinds happen in a quarter of an hour. A worker killed or a
#: daemon restarted leaves a run that the reconciler can declare `unknown_outcome` only after
#: B + P + Q, and P (915 s) and Q (300 s) are minimums the code implies and cannot be shortened:
#: about 21 minutes. Exited tool containers therefore pile up for longer than a smoke lasts, and the
#: rising floor the residue check looks for is there by construction. In a soak the windows are 15
#: minutes and the faults 10-20 minutes apart, and the check is an invariant like the others.
SMOKE_NOT_ENFORCED = ("residue (containers, networks, proxies, files) does not grow",)


def is_finding(result: Result, *, smoke: bool) -> bool:
    """Whether a failed result stops the run: all are, except what a smoke run does not enforce."""
    return not result.ok and not (smoke and result.name in SMOKE_NOT_ENFORCED)


def never_ran(results: list[dict], *, expect_drain: bool) -> list[str]:
    """Names of the checks with no execution (or, for the judged ones, no judgement) in a run."""
    wanted = list(CYCLE_CHECKS) + ([DRAIN_CHECK] if expect_drain else [])
    missing = []
    for name in wanted:
        rows = [r for r in results if r["name"] == name]
        if not rows:
            missing.append(f"{name}: never executed")
        elif name not in NOT_JUDGED_BY_DESIGN and not any(r.get("judged", True) for r in rows):
            missing.append(f"{name}: executed {len(rows)} times, never judged anything")
    return missing


def execution_counts(results: list[dict]) -> list[tuple[str, int, int]]:
    """``(name, executions, judged executions)`` for every expected check, zero included."""
    out = []
    for name in list(CYCLE_CHECKS) + [DRAIN_CHECK]:
        rows = [r for r in results if r["name"] == name]
        out.append((name, len(rows), sum(1 for r in rows if r.get("judged", True))))
    return out


def _quote(ids: list[str]) -> str:
    return "ARRAY[" + ", ".join(f"'{i}'" for i in ids) + "]::text[]"


# ---------------------------------------------------------------------------------------------
# the pure parts
# ---------------------------------------------------------------------------------------------

def window_floors(samples: list[tuple[float, float]], window_s: float) -> list[float]:
    """The smallest value in each consecutive window of ``window_s`` seconds, oldest first. A
    window with no sample is skipped."""
    if not samples:
        return []
    start = samples[0][0]
    floors: dict[int, float] = {}
    for ts, value in samples:
        index = int((ts - start) // window_s)
        floors[index] = min(value, floors.get(index, value))
    return [floors[i] for i in sorted(floors)]


def rising_floor(samples: list[tuple[float, float]], window_s: float, *, rises: int = 3
                 ) -> tuple[bool, list[float]]:
    """``True`` if the floor of the series rose in each of the last ``rises`` windows (so, with
    15-minute windows, over the last 45 minutes: something that is only ever added to). The floor,
    not the mean or the peak: a count that goes up and down with the traffic has a flat floor; a
    leak has a floor that climbs."""
    floors = window_floors(samples, window_s)
    if len(floors) < rises + 1:
        return False, floors
    tail = floors[-(rises + 1):]
    return all(b > a for a, b in zip(tail, tail[1:], strict=False)), floors


def duplicate_creates(events: list[dict], proposal_of_run: dict[str, str] | None = None
                      ) -> dict[str, list[str]]:
    """From the witness's ``create`` events of tool containers: the run ids that have more than one
    container, and the proposals that have more than one run's container. ``{}`` when there is
    none."""
    by_run: dict[str, set[str]] = {}
    for event in events:
        if event.get("action") == "create" and not event.get("proxy") and event.get("run_id"):
            by_run.setdefault(event["run_id"], set()).add(event["id"])
    found: dict[str, list[str]] = {}
    for run, containers in by_run.items():
        if len(containers) > 1:
            found.setdefault("run_with_several_containers", []).append(run)
    if proposal_of_run:
        by_proposal: dict[str, set[str]] = {}
        for run, containers in by_run.items():
            proposal = proposal_of_run.get(run)
            if proposal:
                by_proposal.setdefault(proposal, set()).update(containers)
        for proposal, containers in by_proposal.items():
            if len(containers) > 1:
                found.setdefault("proposal_with_several_containers", []).append(proposal)
    return found


# ---------------------------------------------------------------------------------------------
# database checks
# ---------------------------------------------------------------------------------------------

def coherence(engagements: list[str]) -> Result:
    """``assert_coherent`` on a repeatable-read snapshot of each engagement."""
    from contextlib import contextmanager

    from sqlalchemy import text

    from control_plane.state.db import get_engine
    from tests import test_pipeline_stages as stages_tests

    @contextmanager
    def repeatable_read(engagement_id: str):
        with get_engine().connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            with conn.begin():
                conn.execute(text("SELECT set_config('cyberorch.engagement_id', :e, true)"),
                             {"e": engagement_id})
                yield conn

    original = stages_tests.engagement_scope
    stages_tests.engagement_scope = repeatable_read
    problems, seen = [], 0
    try:
        for eid in engagements:
            snap = stages_tests.snapshot(eid)
            seen += len(snap["proposals"])
            try:
                stages_tests.assert_coherent(snap)
            except AssertionError as exc:
                problems.append(f"{eid}: {str(exc)[:300]}")
    finally:
        stages_tests.engagement_scope = original
    return Result("coherence", not problems,
                  f"{seen} proposals in {len(engagements)} engagements" if not problems
                  else "; ".join(problems))


def capability_on_abandoned(engagements: list[str]) -> Result:
    rows = lib.psql(
        "SELECT p.proposal_id, p.pipeline_stage FROM action_proposals p "
        "WHERE p.engagement_id = ANY(" + _quote(engagements) + ") "
        "AND p.pipeline_stage = 'abandoned'"
        " AND EXISTS (SELECT 1 FROM capabilities c WHERE c.proposal_id = p.proposal_id)")
    total = lib.psql("SELECT count(*) FROM action_proposals WHERE engagement_id = ANY("
                     + _quote(engagements) + ") AND pipeline_stage = 'abandoned'")[0][0]
    return Result("no capability on an abandoned proposal", not rows,
                  f"{total} abandoned proposals" if not rows else f"both: {rows[:5]}")


def run_twice_in_the_database(engagements: list[str]) -> Result:
    arr = _quote(engagements)
    proposals = lib.psql(
        "SELECT proposal_id, count(*) FROM tool_runs WHERE engagement_id = ANY(" + arr + ") "
        "AND proposal_id IS NOT NULL AND refusal_code IS NULL GROUP BY 1 HAVING count(*) > 1")
    capabilities = lib.psql(
        "SELECT capability_id, count(*) FROM tool_runs WHERE engagement_id = ANY(" + arr + ") "
        "AND capability_id IS NOT NULL AND refusal_code IS NULL GROUP BY 1 HAVING count(*) > 1")
    runs = lib.psql("SELECT count(*) FROM tool_runs WHERE engagement_id = ANY(" + arr + ")")[0][0]
    bad = bool(proposals or capabilities)
    return Result("I7 database: no proposal and no capability with two runs", not bad,
                  f"{runs} runs" if not bad else f"proposals {proposals[:5]} capabilities "
                                                  f"{capabilities[:5]}")


def run_twice_in_docker(events_path: Path, engagements: list[str]) -> Result:
    events = []
    if events_path.exists():
        for line in events_path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    owners = set(engagements)
    events = [e for e in events if e.get("owner") in owners]
    rows = lib.psql("SELECT run_id, proposal_id FROM tool_runs WHERE engagement_id = ANY("
                    + _quote(engagements) + ") AND proposal_id IS NOT NULL")
    found = duplicate_creates(events, {r[0]: r[1] for r in rows})
    creates = sum(1 for e in events if e.get("action") == "create" and not e.get("proxy"))
    return Result("I7 docker: no run, no proposal, with two containers created", not found,
                  f"{creates} tool containers created" if not found else json.dumps(found)[:400])


def audit_matches_state(engagements: list[str], windows: list[dict] | None = None) -> Result:
    from scripts.soak import audit_pairs
    return audit_pairs.compare(engagements, windows)


def unresolved_intents(engagements: list[str]) -> Result:
    """Not an invariant of the product: the reconciler announces an irreversible action before it
    takes it, and an announcement with no result is a process that died in between (D64 item 4).
    The product's own reader lists them; they are listed here, for a person to read -- never a
    failure."""
    from control_plane.audit.query import unresolved_reconciler_intents
    from control_plane.state.db import engagement_scope

    listed = []
    for eid in engagements:
        with engagement_scope(eid) as conn:
            listed += [(eid, i.kind, i.reason_code, i.subject_id, str(i.ts))
                       for i in unresolved_reconciler_intents(conn)]
    return Result("unresolved reconciler intents (listed, not judged)", True,
                  f"{len(listed)}: " + json.dumps(listed[:8]))


# ---------------------------------------------------------------------------------------------
# series checks
# ---------------------------------------------------------------------------------------------

def residue_does_not_grow(samples: list[dict], window_s: float) -> Result:
    series = {
        "containers": lambda s: (sum(s["docker"]["tools"].values())
                                 + sum(s["docker"]["proxies"].values())),
        "exited_tool_containers": lambda s: s["docker"]["tools"]["exited"],
        "proxies": lambda s: sum(s["docker"]["proxies"].values()),
        "networks": lambda s: s["docker"]["networks"],
        "temp_files": lambda s: s["docker"]["files"],
    }
    problems, floors = [], {}
    usable = [s for s in samples if s.get("docker")]
    for name, pick in series.items():
        points = [(s["ts"], float(pick(s))) for s in usable]
        rising, f = rising_floor(points, window_s)
        floors[name] = f
        if rising:
            problems.append(f"{name}: floor {f[-4:]}")
    judged = any(len(f) >= 4 for f in floors.values())
    return Result("residue (containers, networks, proxies, files) does not grow", not problems,
                  "; ".join(problems) if problems else f"floors per window: {json.dumps(floors)}",
                  judged=judged)


def no_connection_leak(samples: list[dict], window_s: float) -> Result:
    problems = []
    by_pid: dict[int, list[tuple[float, float]]] = {}
    for s in samples:
        for stats in (s.get("procs") or {}).values():
            if stats:
                by_pid.setdefault(stats["pid"], []).append(
                    (s["ts"], float(stats["pg_connections"])))
    for pid, points in by_pid.items():
        rising, floors = rising_floor(points, window_s)
        if rising:
            problems.append(f"pid {pid}: connection floor {floors[-4:]}")
    totals = [(s["ts"], float(s["pg"]["total"])) for s in samples if s.get("pg")]
    rising, floors = rising_floor(totals, window_s)
    if rising:
        problems.append(f"database backends: floor {floors[-4:]}")
    idle = max((s["pg"]["idle_in_transaction_max_age_s"] for s in samples if s.get("pg")),
               default=0)
    if idle > 60:
        problems.append(f"a transaction was idle in transaction for {idle} s")
    judged = len(window_floors(totals, window_s)) >= 4
    return Result("no connection leak", not problems,
                  "; ".join(problems) if problems else
                  f"{len(by_pid)} process incarnations; longest idle-in-transaction {idle} s",
                  judged=judged)


def schema_unchanged(before: dict[str, str]) -> Result:
    """``snapshot_schema`` now, against the one taken before anything started. Nothing in a soak
    runs DDL: a difference is a finding. Read as the table owner (the schema, not any row)."""
    import os

    from sqlalchemy import create_engine

    from control_plane.state.schema_snapshot import diff, snapshot_schema

    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"])
    try:
        with engine.connect() as conn:
            lines = diff(before, snapshot_schema(conn))
    finally:
        engine.dispose()
    return Result("schema is identical to the one at the start", not lines,
                  f"{len(before)} facts, identical" if not lines else "; ".join(lines[:10]))


def schema_now() -> dict[str, str]:
    import os

    from sqlalchemy import create_engine

    from control_plane.state.schema_snapshot import snapshot_schema

    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"])
    try:
        with engine.connect() as conn:
            return snapshot_schema(conn)
    finally:
        engine.dispose()
