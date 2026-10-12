"""The reconciler beside the scheduler and beside the dispatch it may meet (D64 §3.2-§3.3, step 6d).

What is shown, and how it can fail:

* **CT1** both processes' loops run in one database for several cycles, with a fixture holding every
  state-only residue class and a stream of real dispatches through the scheduler. Afterwards: every
  approved proposal ran exactly once, the scheduler's proposals are coherent and untouched by the
  reconciler, every residue row is where it should be, and there is one audit event per action and
  none for anything that did not happen.
* **CT2** the order inverted: the scheduler is already running on an engagement with stale rows,
  then the reconciler arrives. The scheduler's ``dispatching`` and ``capability_issued`` counts fall
  to zero, and nothing is dispatched twice.
* **CT3** ``kill -9`` of the real process in the middle of a pass, over and over, then a clean run:
  eventually every row is where it should be, no event describes something that did not happen, no
  event is written twice. *What is not promised:* an action committed and killed before its audit
  record is written has no record -- the test counts those and bounds them by the number of kills.
* **CT4** is in ``test_reconciler_lock.py``; **CT5** a real run inside its deadline is not touched
  and an overdue one is killed (deletions on, tests only).
* **RT1/RT2/RT6** the reconciler marks a dispatch unknown while the container is "running" and the
  result arrives late (E17 with the real reconciler), the result arriving first, and two passes
  acting on the same action; **RT5** the engagement is killed: whichever of the scheduler and the
  reconciler goes first, nothing runs and the row ends ``closed``.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import docker
import pytest
from sqlalchemy import text

from control_plane.orchestrator import dispatch, stages
from control_plane.reconciler import act, emit
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.lock import SingletonLock
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import DONE, LOST_RACE
from control_plane.reconciler.service import Reconciler
from control_plane.scheduler import decide
from control_plane.state.db import engagement_scope
from tests import scheduler_support as sup
from tests.helpers import committing_scope
from tests.reconciler_support import (
    EXPECTED,
    _capability,
    _proposal,
    _run,
    freshen,
    make_room_in_the_page,
    residue_world,
)
from tests.test_pipeline_stages import CIDR, FakeSandbox, assert_coherent, go, snapshot
from tests.test_reconciler_config import VALID
from tests.test_reconciler_service import MADE, _locks_are_let_go, events  # noqa: F401

REPO = Path(__file__).resolve().parents[1]
TH = Thresholds(
    stage_grace_s=3600, lease_grace_s=30, approval_grace_s=30, b_cap_s=1800, p_proxy_s=915,
    q_proxy_s=300, kill_margin_s=60, retention_s=86400, network_idle_s=3600,
    network_sweep_period_s=86400, verify_wait_s=10, summary_period_s=3600,
    retry_after_failure_s=1800)
SCHED_CIDR = "10.96.62.0/24"


class NoDocker:
    containers = SimpleNamespace(list=lambda **kw: [])
    networks = SimpleNamespace(list=lambda: [])


def recon(*engagements, settings=None, th=TH, client=None, tmp=None):
    r = Reconciler(settings=settings or Settings(Mode.STATE_ONLY), th=th,
                   client=client or NoDocker(), directory=tmp or tempfile.gettempdir(),
                   expected_uid=os.getuid(), lock=SingletonLock(), watchdog_interval=0.2,
                   only_engagements=frozenset(engagements))
    MADE.append(r)
    return r


def scheduler_world(eid, registry, n):
    sup.publish_engagement_policy(eid)
    scope_id = sup.register_scope(registry, type="cidr", value=SCHED_CIDR)
    sup.enroll(eid)
    return [sup.approved_proposal(eid, scope_id, host=f"10.96.62.{10 + i}") for i in range(n)]


def stage_of(eid, pid):
    with committing_scope(eid) as conn:
        return stages.stage_of(conn, pid)


@pytest.fixture(autouse=True)
def _withdrawn_afterwards():
    enrolled: list[str] = []
    yield enrolled
    for eid in enrolled:
        sup.withdraw(eid)


def run_threads(*targets):
    errors: list[BaseException] = []

    def guarded(fn):
        def inner():
            try:
                fn()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
        return inner

    threads = [threading.Thread(target=guarded(t)) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not any(t.is_alive() for t in threads), "a loop did not finish"
    assert errors == [], errors


# ---------------------------------------------------------------------------------------------
# CT1
# ---------------------------------------------------------------------------------------------

def test_ct1_both_loops_run_in_one_database_for_several_cycles(engagement_factory,
                                                                _withdrawn_afterwards):
    (s_eng, s_reg), (r_eng, _) = engagement_factory(), engagement_factory()
    _withdrawn_afterwards.append(s_eng)
    approved = scheduler_world(s_eng, s_reg, 4)
    residue = residue_world(r_eng)
    sandbox = FakeSandbox()
    barrier = threading.Barrier(2)
    reconciler = recon(s_eng, r_eng)

    def scheduler_loop():
        with sup.running(sandbox) as sched:
            barrier.wait(30)
            for _ in range(8):
                sched.tick()
                time.sleep(0.05)

    def reconciler_loop():
        reconciler.begin()
        barrier.wait(30)
        for _ in range(8):
            reconciler.pass_once()
            time.sleep(0.05)
        reconciler.finish("signal")

    run_threads(scheduler_loop, reconciler_loop)

    # every approved proposal ran exactly once, nobody else touched them
    assert sandbox.calls == len(approved)
    assert [stage_of(s_eng, p)[0] for p in approved] == [stages.RECORDED] * len(approved)
    assert_coherent(snapshot(s_eng))
    assert events(s_eng) == [], "the reconciler wrote about an engagement it had nothing to do in"
    # every residue row is where it should be, with exactly one event each and nothing more
    for name, pid in residue.items():
        stage, detail, _ = EXPECTED[name]
        assert stage_of(r_eng, pid) == (stage, detail), name
    written = events(r_eng)
    assert sorted(e["subject_id"] for e in written) == sorted(residue.values())
    assert all(e["actor"] == "reconciler" for e in written)


# ---------------------------------------------------------------------------------------------
# CT2
# ---------------------------------------------------------------------------------------------

def test_ct2_the_scheduler_first_then_the_reconciler_arrives(engagement_factory,
                                                             _withdrawn_afterwards):
    (eid, registry), = [engagement_factory()]
    _withdrawn_afterwards.append(eid)
    approved = scheduler_world(eid, registry, 3)
    stale = _proposal(eid, "dispatching")
    cap = _capability(eid, stale, '{"max_duration_seconds": 120}')
    _run(eid, stale, cap, "running")
    lapsed = _proposal(eid, "capability_issued")
    _capability(eid, lapsed, '{"max_duration_seconds": 60}',
                lease="TIMESTAMPTZ '1970-01-02 01:00:00+00'")
    sandbox = FakeSandbox()

    with sup.running(sandbox) as sched:
        first = sched.tick()
        assert sorted(first.dispatched) == sorted(approved)
        before = decide.observe(eid)
        assert (before.dispatching, before.capability_issued) == (1, 1)    # the stale rows
        r = recon(eid)
        r.begin()
        report = r.pass_once()
        r.finish("signal")
        assert report.outcomes == {"done": 2}
        sched.tick()                                                         # and a tick after
    after = decide.observe(eid)
    assert (after.dispatching, after.capability_issued) == (0, 0)
    assert sandbox.calls == len(approved)                                    # nothing ran twice
    assert stage_of(eid, stale) == ("recorded", "unknown_outcome")
    assert stage_of(eid, lapsed) == ("closed", "capability_not_live")


# ---------------------------------------------------------------------------------------------
# CT3 -- kill -9
# ---------------------------------------------------------------------------------------------

SCRIPT = str(REPO / "scripts" / "run_reconciler.py")


def _count_abandoned(eid):
    with engagement_scope(eid) as conn:
        return conn.execute(text(
            "SELECT count(*) FROM action_proposals WHERE pipeline_stage = 'abandoned'")
        ).scalar_one()


def test_ct3_kill_minus_nine_in_the_middle_of_a_pass_then_a_clean_run(engagement_id, tmp_path):
    rows = [_proposal(engagement_id, "received") for _ in range(120)]
    env = {k: v for k, v in os.environ.items() if not k.startswith("RECONCILER_")
           or k == "RECONCILER_READER_DATABASE_URL"}
    env.update(VALID)
    argv = [sys.executable, SCRIPT, "--mode", "state-only", "--once", "--engagement",
            engagement_id, "--directory", str(tmp_path)]
    kills = 0
    for _ in range(3):
        child = subprocess.Popen(argv, env=env, cwd=str(REPO), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        before = _count_abandoned(engagement_id)
        while time.monotonic() < deadline and child.poll() is None:
            if _count_abandoned(engagement_id) > before:       # it has begun to move rows
                time.sleep(0.05)
                child.send_signal(signal.SIGKILL)
                kills += 1
                break
            time.sleep(0.01)
        child.wait(timeout=30)
        if _count_abandoned(engagement_id) == len(rows):
            break
    assert kills >= 1, "the process was never caught mid-pass"

    done = subprocess.run(argv, env=env, cwd=str(REPO), capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr                  # the dead process left no lock behind
    assert _count_abandoned(engagement_id) == len(rows)

    written = [e["subject_id"] for e in events(engagement_id, emit.PROPOSAL_ABANDONED)]
    assert len(written) == len(set(written)), "an event was written twice"
    assert set(written) <= set(rows), "an event describes something that is not there"
    missing = len(rows) - len(written)
    assert 0 <= missing <= kills, (
        f"{missing} abandoned rows have no event; at most one per kill ({kills}) is the window "
        "between the commit and the audit record")


# ---------------------------------------------------------------------------------------------
# CT5 -- real Docker
# ---------------------------------------------------------------------------------------------

def test_ct5_a_live_run_inside_its_deadline_is_not_touched_and_an_overdue_one_is_killed(
        engagement_id):
    client = docker.from_env()
    client.ping()
    make_room_in_the_page()           # a fresh row must be within the first 5,000 stuck rows
    live_run, overdue_run = f"RUN-{uuid.uuid4().hex[:8]}", f"RUN-{uuid.uuid4().hex[:8]}"

    def container(run_id):
        c = client.containers.create(
            "python:3.12-slim", command=["sleep", "300"],
            labels={"cyberorch.run_id": run_id, "cyberorch.owner": engagement_id})
        c.start()
        return c

    live, overdue = container(live_run), container(overdue_run)
    try:
        for run_id, budget in ((live_run, 600), (overdue_run, 1)):
            pid = _proposal(engagement_id, "dispatching")
            cap = _capability(engagement_id, pid, f'{{"max_duration_seconds": {budget}}}')
            with engagement_scope(engagement_id) as conn:
                conn.execute(text(
                    "INSERT INTO tool_runs (run_id, engagement_id, proposal_id, capability_id, "
                    "tool, tool_version, normalized_target, execution_fingerprint, status) "
                    "VALUES (:r, :e, :p, :c, 'nmap', '1', 't', 'fp', 'running')"),
                    {"r": run_id, "e": engagement_id, "p": pid, "c": cap})
            freshen(engagement_id, pid)                      # inside its own B + P + Q: not stale
        time.sleep(3)                                         # the budget of 1 s + the margin pass
        quick = Thresholds(**{**TH.__dict__, "kill_margin_s": 1})
        r = recon(engagement_id, settings=Settings(Mode.STATE_ONLY, allow_deletions=True),
                  th=quick, client=client)
        r.begin()
        try:
            report = r.pass_once()
        finally:
            r.finish("signal")
        assert report.outcomes == {"done": 1}
        live.reload()
        overdue.reload()
        assert live.status == "running", "the run inside its deadline was touched"
        assert overdue.status != "running", "the overdue run is still running"
        killed = events(engagement_id, emit.CONTAINER_KILLED)
        assert [e["payload"] for e in killed] == [
            {"run_id": overdue_run, "reason_code": "overran_deadline"}]
    finally:
        for c in (live, overdue):
            try:
                c.remove(force=True)
            except docker.errors.NotFound:
                pass


# ---------------------------------------------------------------------------------------------
# RT1 / RT2 / RT6 -- the reconciler and a live dispatch
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


def planned_unknown_outcome(eid: str) -> Action:
    with engagement_scope(eid) as conn:
        pid, us = conn.execute(text(
            "SELECT proposal_id, (extract(epoch FROM stage_updated_at) * 1000000)::bigint "
            "FROM action_proposals WHERE pipeline_stage = 'dispatching'")).one()
    return Action(kind="mark_unknown_outcome", reason_code="unknown_outcome", subject_id=pid,
                  engagement_id=eid, expected_stage="dispatching", planned_stage_updated_us=us)


def test_rt1_the_reconciler_marks_the_dispatch_unknown_while_it_runs_and_the_result_is_late(world):
    eid = world["engagement_id"]
    seen = {}

    def during(_kwargs):
        seen["result"] = act.carry_out([planned_unknown_outcome(eid)], Settings(Mode.STATE_ONLY))[0]

    outcome = go(world, sandbox=FakeSandbox(during=during))
    assert seen["result"].outcome == DONE
    assert outcome.decision == "ALLOW" and outcome.run_id and outcome.failure is None
    snap = snapshot(eid)
    (p,) = snap["proposals"]
    assert (p["stage"], p["detail"], p["dispatch_state"]) == (
        stages.RECORDED, "succeeded", "succeeded")             # the late result replaced "unknown"
    assert snap["audit"].get("run.late_result") == 1
    assert snap["audit"].get("tool_run.succeeded") == 1
    assert_coherent(snap)


def test_rt2_the_result_first_then_the_reconciler_s_planned_action_matches_no_row(world):
    eid = world["engagement_id"]
    planned = {}

    def during(_kwargs):
        planned["action"] = planned_unknown_outcome(eid)

    go(world, sandbox=FakeSandbox(during=during))
    before = snapshot(eid)
    hooked = []
    (result,) = act.carry_out([planned["action"]], Settings(Mode.STATE_ONLY),
                              on_verified=hooked.append)
    assert result.outcome == LOST_RACE and hooked == []
    assert snapshot(eid) == before                              # the dispatch's result is untouched
    assert dispatch.reconcile_stale_dispatches.__name__          # (the old helper stays a helper)


def test_rt6_two_passes_acting_on_the_same_action_move_one_row_and_write_one_event(
        engagement_id):
    pid = _proposal(engagement_id, "decided")
    with engagement_scope(engagement_id) as conn:
        us = conn.execute(text(
            "SELECT (extract(epoch FROM stage_updated_at) * 1000000)::bigint "
            "FROM action_proposals WHERE proposal_id = :p"), {"p": pid}).scalar_one()
    same = Action(kind="close", reason_code="abandoned_after_decision", subject_id=pid,
                  engagement_id=engagement_id, expected_stage="decided",
                  planned_stage_updated_us=us)
    one, two = recon(engagement_id), recon(engagement_id)         # the lock is bypassed: no begin()
    barrier = threading.Barrier(2)
    results = []

    def act_once(r):
        def go_():
            barrier.wait(10)
            results.extend(act.carry_out([same], r.settings, record=r._record,
                                          on_verified=r._audit))
        return go_

    run_threads(act_once(one), act_once(two))
    assert sorted(r.outcome for r in results) == sorted([DONE, LOST_RACE])
    assert len(events(engagement_id, emit.PROPOSAL_CLOSED)) == 1


# ---------------------------------------------------------------------------------------------
# RT5 -- the engagement is killed
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("reconciler_first", [True, False])
def test_rt5_a_killed_engagement_ends_closed_whichever_goes_first_and_nothing_runs(
        engagement_factory, _withdrawn_afterwards, reconciler_first):
    eid, registry = engagement_factory()
    _withdrawn_afterwards.append(eid)
    (pid,) = scheduler_world(eid, registry, 1)
    sup.kill(eid)
    sandbox = FakeSandbox()
    r = recon(eid)

    def reconcile():
        r.begin()
        report = r.pass_once()
        r.finish("signal")
        assert report.outcomes == {"done": 1}

    with sup.running(sandbox) as sched:
        if reconciler_first:
            reconcile()
            sched.tick()
        else:
            sched.tick()
            reconcile()
    assert sandbox.calls == 0
    assert stage_of(eid, pid) == ("closed", "engagement_killed")
    assert [e["subject_id"] for e in events(eid, emit.PROPOSAL_CLOSED)] == [pid]
