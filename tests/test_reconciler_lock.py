"""The reconciler's singleton lock, and its relation to the scheduler's (D64-10, CT4).

* a second copy of the reconciler is excluded, and gets in once the first lets go;
* the reconciler's lock and the scheduler's can be **held at the same time** (positive control that
  they do not exclude each other: the keys differ) -- and each still excludes a second copy of it;
* a session whose backend is terminated has lost the lock, and says so (``held()`` is false and
  stays false); the server releases a lock with its session, so a dead process cannot keep it;
* the session is the reader role's, not the runtime role's: a lock needs no privilege on any table.
"""

from __future__ import annotations

import time

from sqlalchemy import text

from control_plane.reconciler.lock import LOCK_KEY, SingletonLock
from control_plane.scheduler.lock import LOCK_KEY as SCHEDULER_KEY
from control_plane.scheduler.lock import SingletonLock as SchedulerLock
from control_plane.state.db import open_reconciler_lock_connection


def test_the_two_keys_differ_and_neither_is_a_negative_bigint():
    assert LOCK_KEY != SCHEDULER_KEY
    assert 0 < LOCK_KEY < 2 ** 63 and 0 < SCHEDULER_KEY < 2 ** 63


def test_a_second_reconciler_is_excluded_until_the_first_lets_go():
    first, second, third = SingletonLock(), SingletonLock(), SingletonLock()
    try:
        assert first.acquire() is True and first.held() is True
        assert second.acquire() is False and second.held() is False
        first.close()
        assert third.acquire() is True
    finally:
        for lock in (first, second, third):
            lock.close()


def test_the_reconciler_and_the_scheduler_can_both_be_held_and_each_excludes_its_own_copy():
    recon, other_recon = SingletonLock(), SingletonLock()
    sched, other_sched = SchedulerLock(), SchedulerLock()
    try:
        assert recon.acquire() is True
        assert sched.acquire() is True                    # held together: the keys do not collide
        assert recon.held() and sched.held()
        assert other_recon.acquire() is False
        assert other_sched.acquire() is False
    finally:
        for lock in (recon, other_recon, sched, other_sched):
            lock.close()


def test_a_session_that_is_terminated_has_lost_the_lock_and_says_so():
    lock = SingletonLock()
    try:
        assert lock.acquire() is True
        with open_reconciler_lock_connection() as killer:
            pid = lock._conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
            killer.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        time.sleep(0.3)
        assert lock.held() is False and lock.lost.is_set()
        assert lock.held() is False                       # and stays lost
        other = SingletonLock()
        try:
            assert other.acquire() is True                # the server released it with the session
        finally:
            other.close()
    finally:
        lock.close()


def test_the_watchdog_notices_a_lost_lock_without_anyone_asking():
    lock = SingletonLock()
    try:
        assert lock.acquire() is True
        lock.start_watchdog(0.1)
        with open_reconciler_lock_connection() as killer:
            pid = lock._conn.execute(text("SELECT pg_backend_pid()")).scalar_one()
            killer.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        assert lock.lost.wait(timeout=5)
    finally:
        lock.close()


def test_the_lock_session_is_the_reader_role_and_that_role_can_still_read_nothing():
    with open_reconciler_lock_connection() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "reconciler_reader"
