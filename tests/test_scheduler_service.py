"""The scheduler's failure behaviour (D62): every way it stops, and that it does not dispatch when
it should not.

v0 has no failure ladder (D58-6): anything it cannot account for stops the service with its own exit
code. These tests fix that table, and the property behind each row -- *no dispatch happens after the
condition is known*.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

import control_plane.scheduler.decide as decide_module
import control_plane.scheduler.emit as emit_module
import control_plane.scheduler.execute as execute_module
from control_plane.audit.logger import AuditWriteError
from control_plane.orchestrator import stages
from control_plane.scheduler import state, vocab
from control_plane.scheduler.lock import SingletonLock
from control_plane.scheduler.service import Scheduler, StopService
from tests import scheduler_support as sup
from tests.helpers import committing_scope
from tests.test_scheduler_skips import RecordingSandbox

CIDR = "10.96.69.0/24"
HOST = "10.96.69.9"


@pytest.fixture
def world(engagement_id, registry):
    sup.publish_engagement_policy(engagement_id)
    scope_id = sup.register_scope(registry, type="cidr", value=CIDR)
    sup.enroll(engagement_id)
    pid = sup.approved_proposal(engagement_id, scope_id, host=HOST)
    yield {"engagement_id": engagement_id, "scope_id": scope_id, "proposal_id": pid}
    sup.withdraw(engagement_id)


def _stage(w):
    with committing_scope(w["engagement_id"]) as conn:
        return stages.stage_of(conn, w["proposal_id"])


def _global_events(*types):
    """Global-scope events, newest first, as the ``global_auditor`` role reads them."""
    from control_plane.audit.query import list_global_audit
    from control_plane.state.db import global_auditor_scope
    with global_auditor_scope() as conn:
        return [{"event_type": e.event_type, "payload": e.payload}
                for e in list_global_audit(conn, event_types=list(types), limit=5)]


# ---------------------------------------------------------------------------------------------
# one instance at a time
# ---------------------------------------------------------------------------------------------

def test_a_second_instance_is_refused_before_it_reads_anything(world):
    sandbox = RecordingSandbox()
    with sup.running(sandbox):
        second = Scheduler(sandbox=sandbox, lock=SingletonLock())
        code = second.run(interval=0, max_ticks=3)
        assert code == vocab.EXIT_LOCK_HELD
        assert sandbox.calls == 0
        assert not second.started
        assert _global_events("scheduler.start_refused")[0]["payload"] == {
            "instance_id": second.instance_id, "reason_code": vocab.LOCK_HELD}
    assert _stage(world)[0] == stages.APPROVED


def test_the_lock_is_free_again_once_the_first_instance_has_stopped(world):
    with sup.running(RecordingSandbox()):
        pass
    sandbox = RecordingSandbox()
    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=1) == vocab.EXIT_OK
    assert sandbox.calls == 1


def test_a_killed_lock_connection_stops_dispatching(world):
    """Lost connection = lost lock = stop. Terminate the lock's own backend; nothing dispatches."""
    sandbox = RecordingSandbox()
    sched = Scheduler(sandbox=sandbox, watchdog_interval=0.1)
    sched.start()
    try:
        with sched.lock._mutex:
            pid = sched.lock._conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
        from control_plane.state.db import open_scheduler_lock_connection
        killer = open_scheduler_lock_connection()
        try:
            assert killer.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid}).scalar_one()
        finally:
            killer.close()
        with pytest.raises(StopService) as stop:
            sched.tick()
        assert stop.value.reason == vocab.STOP_LOCK_LOST
        assert stop.value.exit_code == vocab.EXIT_LOCK_LOST
    finally:
        sched.stop(vocab.STOP_LOCK_LOST)
    assert sandbox.calls == 0 and _stage(world)[0] == stages.APPROVED
    assert sup.audit(world["engagement_id"], "scheduler.dispatched") == []


def test_run_returns_the_lock_lost_exit_code(world):
    sandbox = RecordingSandbox()
    sched = Scheduler(sandbox=sandbox, watchdog_interval=0.1)

    ticks = []
    real_tick = sched.tick

    def tick_after_losing_the_lock():
        ticks.append(1)
        sched.lock._conn.close()            # the session ends; the server drops the lock
        return real_tick()

    sched.tick = tick_after_losing_the_lock
    assert sched.run(interval=0, max_ticks=3) == vocab.EXIT_LOCK_LOST
    assert sandbox.calls == 0 and len(ticks) == 1


# ---------------------------------------------------------------------------------------------
# a decision that cannot be recorded is not carried out
# ---------------------------------------------------------------------------------------------

def test_if_the_decision_cannot_be_audited_nothing_is_dispatched(world, monkeypatch):
    real = emit_module.record_audit

    def refuse_dispatch_records(**kwargs):
        if kwargs["event_type"] == vocab.DISPATCHED:
            raise AuditWriteError("audit_log unavailable")
        return real(**kwargs)

    monkeypatch.setattr(emit_module, "record_audit", refuse_dispatch_records)
    sandbox = RecordingSandbox()

    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=3) == vocab.EXIT_AUDIT_FAILED

    assert sandbox.calls == 0
    assert _stage(world)[0] == stages.APPROVED
    assert sup.rows(world["engagement_id"], "SELECT 1 FROM capabilities") == []
    assert sup.audit(world["engagement_id"], "scheduler.dispatched") == []
    assert not _decided(world)            # no `dispatch_decided` row either: record, then act


def _decided(world) -> bool:
    from control_plane.state.db import scheduler_reader_scope
    with scheduler_reader_scope(world["engagement_id"]) as conn:
        return bool(conn.execute(text(
            "SELECT 1 FROM scheduler_state WHERE proposal_id = :p AND disposition = :d"),
            {"p": world["proposal_id"], "d": vocab.DISPATCH_DECIDED}).all())


# ---------------------------------------------------------------------------------------------
# the rest of the stop table
# ---------------------------------------------------------------------------------------------

def test_a_lost_database_connection_stops_the_service_with_its_own_code(world, monkeypatch):
    def gone(*_a, **_k):
        raise OperationalError("SELECT 1", {}, Exception("server closed the connection"))

    monkeypatch.setattr(decide_module, "read_enrollment", gone)
    sandbox = RecordingSandbox()
    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=2) == vocab.EXIT_DB_LOST
    assert sandbox.calls == 0


def test_an_unreachable_docker_stops_the_service_before_the_dispatch(world, monkeypatch):
    monkeypatch.setattr(execute_module, "docker_reachable", lambda: False)
    sandbox = RecordingSandbox()
    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=2) == vocab.EXIT_DOCKER_LOST
    assert sandbox.calls == 0
    assert _stage(world)[0] == stages.APPROVED          # nothing closed it: it is still waiting


def test_an_unexpected_error_stops_the_service(world, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("something nobody planned for")

    monkeypatch.setattr(execute_module, "prepare", boom)
    code = Scheduler(sandbox=RecordingSandbox()).run(interval=0, max_ticks=2)
    assert code == vocab.EXIT_UNEXPECTED


def test_a_dispatched_proposal_that_is_still_approved_afterwards_stops_the_service(
    world, monkeypatch,
):
    """The exit-7 rule, applied to a proposal that really was handed over (and only to those)."""
    # hands the proposal over, and nothing moves
    monkeypatch.setattr(execute_module, "dispatch", lambda *a, **k: None)
    sandbox = RecordingSandbox()

    assert Scheduler(sandbox=sandbox).run(interval=0, max_ticks=3) == vocab.EXIT_NOT_ADVANCED
    assert sandbox.calls == 0
    assert len(sup.audit(world["engagement_id"], "scheduler.dispatched")) == 1   # one attempt only


# ---------------------------------------------------------------------------------------------
# crash between the decision and the dispatch
# ---------------------------------------------------------------------------------------------

def test_a_decision_recorded_before_a_crash_is_counted_at_the_next_start(world):
    """`scheduler.dispatched` means "decided to attempt". A restart finds the proposal approved,
    with a decision on record: that is reported (``approved_redispatch``), and it is dispatched --
    once -- because ``dispatch_approved`` is idempotent on the stage."""
    eid, pid = world["engagement_id"], world["proposal_id"]
    state.record_proposal(eid, pid, vocab.DISPATCH_DECIDED, vocab.APPROVED_AND_IDLE)
    sandbox = RecordingSandbox()

    sched = Scheduler(sandbox=sandbox)
    sched.start()
    try:
        started = _global_events("scheduler.started")[0]["payload"]
        assert started["approved_redispatch"][eid] == 1
        assert started["approved_waiting"][eid] == 1
        assert eid in started["enrolled"]
        assert sched.tick().dispatched == [pid]
    finally:
        sched.stop(vocab.STOP_SIGNAL)
    assert sandbox.calls == 1 and _stage(world) == (stages.RECORDED, "succeeded")
