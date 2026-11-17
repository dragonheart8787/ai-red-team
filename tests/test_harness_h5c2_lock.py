"""D69 H5c2 (B): the harness's lock -- its own key, one instance at a time, and lost means stop.

The shape follows the scheduler's lock tests (``tests/test_scheduler_service.py``): a second
instance is refused before it reads anything, the lock is free again once the first has gone, a
killed lock connection stops the run, and ``run`` returns the lock-lost exit code. H5-7: a key the
scheduler also uses, or a second instance that does not exit, must turn these red.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.pool import NullPool

from control_plane.scheduler.lock import LOCK_KEY as SCHEDULER_KEY
from harness.exit_codes import EXIT_LOCK_HELD, EXIT_LOCK_LOST
from harness.lock import (
    KEY,
    HarnessLock,
    LockGuardedPorts,
    LockLost,
    format_key,
    open_lock_connection,
)
from scripts import run_harness
from tests.harness_h5c2_roles import HOOKS
from tests.test_harness_h5c1_support import make_world, proposal_rows, task_rows
from tests.test_harness_h5c2_support import enrolled

#: the ten ports and how many arguments each takes
ARITY = {"enrolled": 0, "accepts_work": 1, "live_tasks": 1, "take_snapshot": 1, "plan": 2,
         "claim": 1, "work": 3, "load_policy": 1, "propose": 5, "complete": 3}


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _try(conn, key: int) -> bool:
    return bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar_one())


def _kill(lock: HarnessLock) -> None:
    """End the session that holds ``lock`` -- what a lost connection is -- from another session."""
    with lock._mutex:
        pid = lock._conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
    killer = open_lock_connection()
    try:
        assert killer.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid}).scalar_one()
    finally:
        killer.close()


def _argv(**override) -> list[str]:
    args = {"--role-factory": "tests.harness_h5c2_roles:build", "--objective": "o",
            "--window-limit": "25", "--max-rounds": "1", "--max-model-calls": "100",
            "--no-progress-limit": "5", "--live-task-limit": "200", **override}
    return ["run", *(part for pair in args.items() for part in pair)]


# -- the key ----------------------------------------------------------------------------------


def test_the_key_is_the_registered_value_and_is_not_the_schedulers():
    assert KEY == 0x0D69_5C4E_D000_0001
    assert format_key() == "0x0D69_5C4E_D000_0001"
    assert KEY != SCHEDULER_KEY
    assert SCHEDULER_KEY == 0x0D62_5C4E_D000_0001          # (the one it is not)


def test_a_lock_the_scheduler_holds_does_not_block_the_harness_and_the_reverse(db_available):
    scheduler = open_lock_connection()
    other = open_lock_connection()
    lock = HarnessLock()
    try:
        assert _try(scheduler, SCHEDULER_KEY) is True        # the scheduler's key, held
        assert lock.acquire() is True                         # the harness is not kept out
        assert _try(other, SCHEDULER_KEY) is False            # (and that key really is held)
        assert _try(other, KEY) is False                      # the harness's own key is held
    finally:
        lock.close()
        scheduler.close()
        other.close()


# -- one instance at a time -------------------------------------------------------------------


def test_a_second_instance_cannot_take_the_lock_and_can_when_the_first_has_closed(db_available):
    first, second = HarnessLock(), HarnessLock()
    assert first.acquire() is True
    assert second.acquire() is False
    assert second.held() is False
    first.close()
    third = HarnessLock()
    try:
        assert third.acquire() is True
    finally:
        third.close()


def test_the_lock_is_on_a_connection_of_its_own_with_no_pool(db_available):
    lock = HarnessLock()
    assert lock.acquire()
    try:
        assert isinstance(lock._conn.engine.pool, NullPool)
        assert lock.held() is True
    finally:
        lock.close()


def test_a_second_run_exits_with_code_2_before_it_reads_anything(
        db_available, monkeypatch, capsys):
    first = HarnessLock()
    assert first.acquire()
    called = []

    def refuse(spec):
        called.append(spec)
        raise RuntimeError("the role factory is not wanted by a second instance")

    monkeypatch.setattr(run_harness, "_roles", refuse)
    try:
        code = run_harness.main(_argv(), lock=HarnessLock(), register=lambda *a: None)
    finally:
        first.close()
    out = capsys.readouterr()
    assert code == EXIT_LOCK_HELD == 2
    assert called == []                                    # the role factory was not even called
    assert out.out == "" and "holds the harness lock" in out.err


def test_the_lock_is_free_again_once_a_run_has_stopped(world, monkeypatch):
    monkeypatch.setenv("H5C2_SCOPE_ID", world.scope_id)
    with enrolled(world.engagement_id):
        assert run_harness.main(_argv(), lock=HarnessLock(), register=lambda *a: None) in (0, 13)
    again = HarnessLock()
    try:
        assert again.acquire() is True
    finally:
        again.close()


# -- lost means stop --------------------------------------------------------------------------


class _Spy:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(*args):
            self.calls.append(name)
        return call


@pytest.mark.parametrize("port", sorted(ARITY))
def test_once_the_lock_is_lost_no_port_is_called_and_the_call_raises(db_available, port):
    lock = HarnessLock()
    assert lock.acquire()
    spy = _Spy()
    guarded = LockGuardedPorts(spy, lock)
    arguments = ("E",) * ARITY[port]
    try:
        getattr(guarded, port)(*arguments)
        assert spy.calls == [port]                         # held: the call goes through
        _kill(lock)
        with pytest.raises(LockLost):
            getattr(guarded, port)(*arguments)
        assert spy.calls == [port]                         # lost: nothing more reached the ports
        assert lock.lost.is_set()
    finally:
        lock.close()


def test_a_killed_lock_connection_is_noticed_by_the_watchdog(db_available):
    lock = HarnessLock()
    assert lock.acquire()
    lock.start_watchdog(0.05)
    try:
        _kill(lock)
        assert lock.lost.wait(5), "the watchdog did not notice the lost lock"
    finally:
        lock.close()


def test_run_returns_the_lock_lost_exit_code_and_cleans_nothing_up(world, monkeypatch):
    monkeypatch.setenv("H5C2_SCOPE_ID", world.scope_id)
    lock = HarnessLock()
    HOOKS["work"] = lambda: _kill(lock)                    # the session ends during the Worker call
    try:
        with enrolled(world.engagement_id):
            code = run_harness.main(_argv(), lock=lock, register=lambda *a: None)
    finally:
        HOOKS.clear()
    assert code == EXIT_LOCK_LOST == 6
    assert lock.lost.is_set()
    # nothing was proposed or completed after the loss: the claimed task is still claimed and the
    # two others are still queued (a fault cleans nothing up, and nothing may be written now)
    assert proposal_rows(world.engagement_id) == []
    assert sorted(row[1] for row in task_rows(world.engagement_id)) == [
        "claimed", "queued", "queued"]
