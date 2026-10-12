"""The reconciler as a process (D64 step 6d): lock, observe, plan, act, audit -- and when it stops.

Every pass here is limited to the engagement a test made (``only_engagements``): the development
database holds thousands of stuck rows from earlier runs, and a test that reconciled all of them
would be acting on other people's rows.

* **state-only** moves the rows, audits each move *after* it happened (shown by reading the state
  inside the audit call), writes ``started`` / ``stopped``, and a second pass finds nothing to do;
* **dry-run** takes no lock, moves nothing, writes no audit record at all;
* **it stops, with its own exit code**, on a lock held elsewhere (2), an audit record it cannot
  write (3: the action it describes has happened, which is exactly why it stops), a lost database
  (4), an unreachable Docker (5), a lost lock (6, before acting), anything else (1);
* **a failure is reported once and counted after**: ``action_failed`` once per (object, kind,
  reason) per process, and a ``failure_summary`` once per period, only if something failed;
* **a network is judged idle by how long this process has seen it idle**;
* **the command line**: no default mode, two modes, a refused configuration is exit 8 naming the
  keys, nothing else on the screen.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from docker.errors import DockerException
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from control_plane.audit.logger import AuditWriteError
from control_plane.reconciler import act, emit, service
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.lock import SingletonLock
from control_plane.reconciler.service import Reconciler, StopService
from control_plane.state.db import (
    engagement_scope,
    global_auditor_scope,
    open_reconciler_lock_connection,
)
from tests import scheduler_support as sup
from tests.helpers import committing_scope
from tests.reconciler_support import EXPECTED, _proposal, residue_world
from tests.test_reconciler_config import VALID

REPO = Path(__file__).resolve().parents[1]
TH = Thresholds(
    stage_grace_s=3600, lease_grace_s=30, approval_grace_s=30, b_cap_s=1800, p_proxy_s=915,
    q_proxy_s=300, kill_margin_s=60, retention_s=86400, network_idle_s=3600,
    network_sweep_period_s=86400, verify_wait_s=10, summary_period_s=3600,
    retry_after_failure_s=1800)
STATE_ONLY = Settings(Mode.STATE_ONLY)
DRY_RUN = Settings(Mode.DRY_RUN)


class FakeDocker:
    def __init__(self, containers=(), networks=()):
        self.containers = SimpleNamespace(list=lambda **kw: list(containers))
        self.networks = SimpleNamespace(list=lambda: list(networks))


MADE: list[Reconciler] = []


@pytest.fixture(autouse=True)
def _locks_are_let_go():
    """A test that fails must not leave the lock held for the tests after it."""
    yield
    while MADE:
        MADE.pop().lock.close()


def reconciler(eid, settings=STATE_ONLY, th=TH, client=None, tmp_path=None, **kw):
    kw.setdefault("lock", SingletonLock())
    kw.setdefault("watchdog_interval", 0.2)
    made = Reconciler(settings=settings, th=th, client=client or FakeDocker(),
                      directory=str(tmp_path or "/nonexistent-dir-for-tests"),
                      expected_uid=os.getuid(), only_engagements=frozenset({eid}), **kw)
    MADE.append(made)
    return made


@pytest.fixture
def emptydir(tmp_path):
    return tmp_path


def acts(planned: dict) -> dict:
    """What was planned to be done: without the report that the page of stuck rows was full, which a
    development database (thousands of stuck rows from earlier runs) always says."""
    return {k: v for k, v in planned.items() if k != "report:result_truncated"}


def state(eid, pid):
    with engagement_scope(eid) as conn:
        return tuple(conn.execute(text(
            "SELECT pipeline_stage, stage_detail FROM action_proposals WHERE proposal_id = :p"),
            {"p": pid}).one())


def events(eid, *types):
    with committing_scope(eid) as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT event_type, payload, actor, subject_id FROM audit_log "
            "WHERE engagement_id = :e AND event_type = ANY(:t) ORDER BY audit_id"),
            {"e": eid, "t": list(types) or list(emit.EVENTS)}).mappings()]


def global_events(instance_id, *types):
    with global_auditor_scope() as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT event_type, payload, actor FROM audit_log WHERE scope = 'global' "
            "AND event_type = ANY(:t) AND payload->>'instance_id' = :i ORDER BY audit_id"),
            {"t": list(types) or list(emit.EVENTS), "i": instance_id}).mappings()]


# ---------------------------------------------------------------------------------------------
# state-only
# ---------------------------------------------------------------------------------------------

def test_a_state_only_pass_moves_the_rows_audits_each_and_a_second_pass_does_nothing(
        engagement_id, emptydir):
    world = residue_world(engagement_id)
    r = reconciler(engagement_id, tmp_path=emptydir)
    r.begin()
    try:
        first = r.pass_once()
        for name, pid in world.items():
            stage, detail, _event = EXPECTED[name]
            assert state(engagement_id, pid) == (stage, detail), name
        assert first.outcomes == {"done": 5}
        written = events(engagement_id)
        by_subject = {e["subject_id"]: e for e in written}
        assert set(by_subject) == set(world.values())
        for name, pid in world.items():
            stage, detail, event = EXPECTED[name]
            assert by_subject[pid]["event_type"] == event
            assert by_subject[pid]["payload"] == {"proposal_id": pid, "reason_code": detail}
            assert by_subject[pid]["actor"] == "reconciler"
        second = r.pass_once()
        assert second.outcomes == {} and acts(second.planned) == {}
        assert len(events(engagement_id)) == 5                  # nothing new
    finally:
        r.finish("signal")
    started = global_events(r.instance_id, emit.STARTED)
    assert len(started) == 1 and started[0]["payload"]["mode"] == "state_only"
    assert acts(started[0]["payload"]["planned"]) == {
        "abandon:undecided_past_grace": 1, "close:abandoned_after_decision": 1,
        "close:capability_not_live": 1, "close:approval_expired": 1,
        "mark_unknown_outcome:unknown_outcome": 1}
    stopped = global_events(r.instance_id, emit.STOPPED)
    assert [s["payload"]["reason_code"] for s in stopped] == ["signal"]


def test_a_transitions_event_is_written_in_the_transaction_that_makes_it(
        engagement_id, emptydir, monkeypatch):
    """At the moment the event is written the change is visible on the writing connection and *not*
    on any other (it is not committed): they commit together or not at all."""
    world = residue_world(engagement_id)
    seen = {}
    real = emit.emit_in_transaction

    def watching(conn, event_type, payload, **kw):
        pid = payload["proposal_id"]
        here = tuple(conn.execute(text(
            "SELECT pipeline_stage, stage_detail FROM action_proposals WHERE proposal_id = :p"),
            {"p": pid}).one())
        seen[pid] = (here, state(kw["engagement_id"], pid))       # `state` opens another connection
        return real(conn, event_type, payload, **kw)

    monkeypatch.setattr(service.emit, "emit_in_transaction", watching)
    r = reconciler(engagement_id, tmp_path=emptydir)
    r.begin()
    try:
        r.pass_once()
    finally:
        r.finish("signal")
    for name, pid in world.items():
        stage, detail, event = EXPECTED[name]
        here, elsewhere = seen[pid]
        assert here == (stage, detail), f"{name}: the writer does not see its own change"
        assert elsewhere[0] != stage, f"{name}: the change was committed before its event"
        assert state(engagement_id, pid)[:2] == (stage, detail)
    assert len(events(engagement_id)) == 5


def test_a_pass_limited_to_an_engagement_leaves_every_other_engagements_rows_alone(
        engagement_factory, emptydir):
    (mine, _), (theirs, _) = engagement_factory(), engagement_factory()
    mine_rows, theirs_rows = residue_world(mine), residue_world(theirs)
    r = reconciler(mine, tmp_path=emptydir)
    r.begin()
    try:
        assert r.pass_once().outcomes == {"done": 5}
    finally:
        r.finish("signal")
    assert {state(theirs, pid)[0] for pid in theirs_rows.values()} == {
        "received", "decided", "capability_issued", "approved", "dispatching"}
    assert all(state(mine, pid)[0] in ("abandoned", "closed", "recorded")
               for pid in mine_rows.values())
    assert events(theirs) == []


# ---------------------------------------------------------------------------------------------
# dry-run
# ---------------------------------------------------------------------------------------------

def test_a_dry_run_takes_no_lock_moves_nothing_and_writes_no_audit_record(engagement_id, emptydir):
    world = residue_world(engagement_id)
    holder = SingletonLock()
    assert holder.acquire() is True                  # the real thing is running
    try:
        r = reconciler(engagement_id, DRY_RUN, tmp_path=emptydir)
        try:
            r.begin()                                # a dry run does not contend for the lock
        except StopService as stopped:
            pytest.fail(f"a dry run contended for the lock: {stopped.reason}")
        report = r.pass_once()
        r.finish("signal")
    finally:
        holder.close()
    assert report.outcomes == {"dry_run": 5}
    assert sum(acts(report.planned).values()) == 5
    for name, pid in world.items():
        assert state(engagement_id, pid)[0] in ("received", "decided", "capability_issued",
                                                "approved", "dispatching"), name
    assert events(engagement_id) == []
    assert global_events(r.instance_id) == []


# ---------------------------------------------------------------------------------------------
# stopping
# ---------------------------------------------------------------------------------------------

def test_a_second_reconciler_is_refused_with_exit_2_and_says_so(engagement_id, emptydir):
    holder = SingletonLock()
    assert holder.acquire() is True
    try:
        r = reconciler(engagement_id, tmp_path=emptydir)
        assert r.serve(max_passes=1) == service.EXIT_LOCK_HELD == 2
    finally:
        holder.close()
    refused = global_events(r.instance_id, emit.START_REFUSED)
    assert [e["payload"] for e in refused] == [
        {"instance_id": r.instance_id, "reason_code": "lock_held"}]
    assert global_events(r.instance_id, emit.STARTED) == []


def test_a_transition_whose_record_cannot_be_written_is_not_made_and_the_service_stops(
        engagement_id, emptydir, monkeypatch):
    world = residue_world(engagement_id)

    def failing(conn, event_type, payload, **kw):
        raise AuditWriteError("cannot write")

    monkeypatch.setattr(service.emit, "emit_in_transaction", failing)
    r = reconciler(engagement_id, tmp_path=emptydir)
    assert r.serve(max_passes=3, interval=0) == service.EXIT_AUDIT_FAILED == 3
    # nothing is changed and unrecorded: the transaction rolled back with the record
    original = {"received": "received", "decided": "decided", "lapsed": "capability_issued",
                "approved": "approved", "dispatching": "dispatching"}
    for name, pid in world.items():
        assert state(engagement_id, pid)[0] == original[name], name
    assert events(engagement_id, *emit.TRANSACTIONAL_EVENTS) == []     # no record of a change
    failures = events(engagement_id, emit.ACTION_FAILED)                # but each attempt is told
    assert len(failures) == 5
    assert {f["payload"]["reason_code"] for f in failures} == {"audit_failed"}
    stopped = global_events(r.instance_id, emit.STOPPED)
    assert [s["payload"]["reason_code"] for s in stopped] == ["audit_failed"]


def test_a_lost_lock_stops_the_service_before_it_acts_exit_6(engagement_id, emptydir):
    world = residue_world(engagement_id)
    r = reconciler(engagement_id, tmp_path=emptydir)
    r.begin()
    with open_reconciler_lock_connection() as killer:
        pid = r.lock._conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
        killer.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
    time.sleep(0.3)
    with pytest.raises(StopService) as stopped:
        r.pass_once()
    assert stopped.value.reason == "lock_lost" and stopped.value.exit_code == 6
    assert state(engagement_id, world["received"])[0] == "received"       # nothing was touched
    r.finish("lock_lost")


@pytest.mark.parametrize("raised, code", [
    (OperationalError("SELECT 1", {}, Exception("connection lost")), service.EXIT_DB_LOST),
    (DockerException("daemon gone"), service.EXIT_DOCKER_LOST),
    (ConnectionError("socket closed"), service.EXIT_DOCKER_LOST),
    (RuntimeError("something nobody planned for"), service.EXIT_UNEXPECTED),
])
def test_each_kind_of_fault_has_its_own_exit_code(engagement_id, emptydir, monkeypatch, raised,
                                                  code):
    r = reconciler(engagement_id, tmp_path=emptydir)

    def boom(*a, **kw):
        raise raised

    monkeypatch.setattr(service.observe, "observe", boom)
    assert r.serve(max_passes=1) == code
    assert r.lock.held() is False                  # and it let go of the lock on the way out
    assert code in (4, 5, 1)


def test_a_missing_directory_is_an_unexpected_error_and_not_a_lost_docker(engagement_id):
    r = reconciler(engagement_id)                           # the default directory does not exist
    assert r.serve(max_passes=1) == service.EXIT_UNEXPECTED


def test_the_exit_codes_are_distinct_and_the_scheduler_s_where_they_overlap():
    from control_plane.scheduler import vocab as scheduler_vocab
    codes = {"ok": service.EXIT_OK, "unexpected": service.EXIT_UNEXPECTED,
             "lock_held": service.EXIT_LOCK_HELD, "audit": service.EXIT_AUDIT_FAILED,
             "db": service.EXIT_DB_LOST, "docker": service.EXIT_DOCKER_LOST,
             "lock_lost": service.EXIT_LOCK_LOST, "config": service.EXIT_CONFIG_REFUSED}
    assert len(set(codes.values())) == len(codes)
    assert (service.EXIT_OK, service.EXIT_UNEXPECTED, service.EXIT_LOCK_HELD,
            service.EXIT_AUDIT_FAILED, service.EXIT_DB_LOST, service.EXIT_DOCKER_LOST,
            service.EXIT_LOCK_LOST) == (
        scheduler_vocab.EXIT_OK, scheduler_vocab.EXIT_UNEXPECTED, scheduler_vocab.EXIT_LOCK_HELD,
        scheduler_vocab.EXIT_AUDIT_FAILED, scheduler_vocab.EXIT_DB_LOST,
        scheduler_vocab.EXIT_DOCKER_LOST, scheduler_vocab.EXIT_LOCK_LOST)
    assert set(service.EXIT_CODE_OF_STOP) == set(emit.STOP_REASONS)


# ---------------------------------------------------------------------------------------------
# failures: once, then counted, then summarised
# ---------------------------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_failed_action_is_reported_once_per_object_and_counted_in_a_periodic_summary(
        engagement_id, emptydir, monkeypatch):
    first = _proposal(engagement_id, "received")
    second = _proposal(engagement_id, "received")

    def broken(*a, **kw):
        raise OperationalError("UPDATE", {}, Exception("secret detail that must not be audited"))

    monkeypatch.setattr(act, "_move", broken)
    clock = Clock()
    r = reconciler(engagement_id, tmp_path=emptydir, monotonic=clock)
    r.begin()
    try:
        for _ in range(3):
            report = r.pass_once()
            assert report.outcomes == {"failed": 2}
        failed = events(engagement_id, emit.ACTION_FAILED)
        assert {e["subject_id"] for e in failed} == {first, second}
        assert len(failed) == 2                                   # once each, not once per pass
        assert all(e["payload"]["reason_code"] == "db_error" for e in failed)
        assert "secret" not in repr(failed)
        assert global_events(r.instance_id, emit.FAILURE_SUMMARY) == []      # not yet
        clock.now += TH.summary_period_s
        r.pass_once()
        (summary,) = global_events(r.instance_id, emit.FAILURE_SUMMARY)
        assert summary["payload"] == {"instance_id": r.instance_id, "passes": 4,
                                      "failed": {"abandon:db_error": 8}}
        clock.now += TH.summary_period_s
        r.pass_once()                                   # a window with failures again...
        assert len(global_events(r.instance_id, emit.FAILURE_SUMMARY)) == 2
    finally:
        r.finish("signal")
    assert state(engagement_id, first)[0] == "received"


def test_a_period_without_a_failure_writes_no_summary(engagement_id, emptydir):
    clock = Clock()
    r = reconciler(engagement_id, tmp_path=emptydir, monotonic=clock)
    r.begin()
    try:
        r.pass_once()
        clock.now += 10 * TH.summary_period_s
        r.pass_once()
    finally:
        r.finish("signal")
    assert global_events(r.instance_id, emit.FAILURE_SUMMARY) == []


# ---------------------------------------------------------------------------------------------
# networks: how long this process has seen them idle
# ---------------------------------------------------------------------------------------------

def test_a_network_is_not_planned_for_removal_in_the_first_idle_period_of_a_new_process(
        engagement_id, emptydir, monkeypatch):
    monkeypatch.setattr(service.observe, "read_stuck", lambda conn: ((), False))
    clock = {"us": 1_800_000_000 * 1_000_000}

    class Net:
        id = "c" * 64
        name = "cyberorch-allow-0123456789ab"
        attrs = {"Created": "2020-01-01T00:00:00Z",
                 "Labels": {"cyberorch.allowlist": "10.9.0.0/29"}}

        def reload(self):
            return None

    client = FakeDocker(networks=[Net()])
    client.containers = SimpleNamespace(list=lambda **kw: [])
    r = Reconciler(settings=STATE_ONLY, th=TH, client=client, directory=str(emptydir),
                   expected_uid=os.getuid(), lock=SingletonLock(),
                   wall_clock_us=lambda: clock["us"])
    r.begin()
    try:
        # created long ago, but this process has only just seen it idle
        assert "remove_network:idle_sweep" not in r.pass_once().planned
        clock["us"] += (TH.network_idle_s - 1) * 1_000_000
        assert "remove_network:idle_sweep" not in r.pass_once().planned
        clock["us"] += 1_000_000
        report = r.pass_once()
        assert report.planned.get("remove_network:idle_sweep") == 1
        assert report.outcomes == {"skipped_deletions_off": 1}              # and the flag is off
    finally:
        r.finish("signal")


# ---------------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------------

SCRIPT = str(REPO / "scripts" / "run_reconciler.py")


def cli(*args, env=None):
    base = {k: v for k, v in os.environ.items() if not k.startswith("RECONCILER_")
            or k == "RECONCILER_READER_DATABASE_URL"}
    return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True,
                          env={**base, **(env or {})}, cwd=str(REPO), timeout=120)


def test_there_is_no_default_mode_and_no_third_one():
    none = cli()
    assert none.returncode == 2 and "--mode" in none.stderr
    wrong = cli("--mode", "full", env=VALID)
    assert wrong.returncode == 2 and "invalid choice" in wrong.stderr
    # (a dry run, one pass, one engagement that does not exist: were an option accepted, this would
    # still change nothing)
    for forbidden in ("--allow-deletions", "--delete", "--force"):
        refused = cli("--mode", "dry-run", "--once", "--engagement", "ENG-NONE", forbidden,
                      env=VALID)
        assert refused.returncode == 2 and "unrecognized arguments" in refused.stderr, forbidden


def test_a_refused_configuration_is_exit_8_naming_the_keys_and_nothing_else(engagement_id):
    partial = {k: v for k, v in VALID.items() if k != "RECONCILER_B_CAP_S"}
    done = cli("--mode", "state-only", "--once", "--engagement", engagement_id, env=partial)
    assert done.returncode == service.EXIT_CONFIG_REFUSED == 8
    assert "RECONCILER_B_CAP_S" in done.stderr and "missing" in done.stderr
    assert "postgresql" not in done.stderr and "password" not in done.stderr.lower()
    assert done.stdout == ""
    refused = [e for e in global_events("RECON-config-refused", emit.START_REFUSED)]
    assert refused and refused[-1]["payload"]["reason_code"] == "config_refused"
    dry = cli("--mode", "dry-run", "--once", env={})
    assert dry.returncode == 8 and dry.stdout == ""


def test_dry_run_on_the_command_line_prints_what_it_would_do_and_changes_nothing(
        engagement_id, tmp_path):
    world = residue_world(engagement_id)
    done = cli("--mode", "dry-run", "--once", "--engagement", engagement_id,
               "--directory", str(tmp_path), env=VALID)
    assert done.returncode == 0, done.stderr
    lines = [ln for ln in done.stdout.splitlines() if ln.startswith("{")]
    assert sum('"outcome": "dry_run"' in ln for ln in lines) == 5
    assert "summary" in lines[-1]
    assert {state(engagement_id, p)[0] for p in world.values()} == {
        "received", "decided", "capability_issued", "approved", "dispatching"}
    assert events(engagement_id) == []


def test_state_only_on_the_command_line_moves_the_rows_and_audits(engagement_id, tmp_path):
    world = residue_world(engagement_id)
    done = cli("--mode", "state-only", "--once", "--engagement", engagement_id,
               "--directory", str(tmp_path), env=VALID)
    assert done.returncode == 0, done.stderr
    assert state(engagement_id, world["received"]) == ("abandoned", "undecided_past_grace")
    assert len(events(engagement_id)) == 5
    assert "reconciler stopped (exit 0)" in done.stderr


def test_the_start_order_is_a_convention_and_the_script_says_so():
    text_ = Path(SCRIPT).read_text()
    assert "Start order" in text_ and "convention, not a check" in text_
    assert "Start order" in Path(service.__file__).read_text()


def test_the_thresholds_the_command_line_needs_are_all_of_them():
    assert {f"RECONCILER_{f.name.upper()}" for f in dataclasses.fields(Thresholds)} == set(VALID)
    _ = sup, Mode
