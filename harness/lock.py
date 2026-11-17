"""D69 H5c2 (B): the harness's singleton lock -- one run at a time (plan item 47, choice 3.6).

A Postgres *session* advisory lock on a dedicated connection, in the shape of the scheduler's
(``control_plane/scheduler/lock.py``): the server releases a session lock when the session ends, so
it cannot outlive a dead process and there is no table to clean and no lease to tune. A second
instance's ``pg_try_advisory_lock`` returns false and it exits before it reads anything.

* **The key is its own**: :data:`KEY`, ``0x0D69_5C4E_D000_0001``. The scheduler's is
  ``0x0D62_5C4E_D000_0001`` (this module does not import it; a test does and compares). Two runs of
  the harness exclude each other, whatever engagements they work on (the loop is serial across all
  of them), and neither excludes the scheduler.
* **The connection is its own**: unpooled, autocommit, with TCP keepalives, as ``cyberorch_app``,
  the role the harness already connects as. No role and no table are added; ``pg_try_advisory_lock``
  needs no grant.
* **Lost connection = lost lock = stop.** :meth:`HarnessLock.held` asks the server whether this
  session still holds the key; an error is "lost" and stays lost. A watchdog thread asks every
  ``interval`` seconds, and :class:`LockGuardedPorts` asks before **every** port call of the loop:
  once the lock is lost no port is called again (nothing is read, claimed, proposed or completed),
  the call raises :class:`LockLost`, and the loop ends the way it ends for any fault it did not
  expect (nothing cleaned up). The entry script turns that into exit code 6. A call already in
  flight cannot be interrupted -- nothing in v0 can stop a container that is running.

It guards against an accident (two runs); it is not an authorization mechanism: another role can
take the same key, which only stops the harness from starting.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from sqlalchemy import Connection, create_engine, text
from sqlalchemy.pool import NullPool

from control_plane.state.db import database_url
from harness.ports import LoopPorts

#: The advisory-lock key. Fixed, so every instance contends for the same one.
KEY = 0x0D69_5C4E_D000_0001

_HELD = text("""
    SELECT EXISTS (
        SELECT 1 FROM pg_locks
        WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
          AND ((classid::bigint << 32) | objid::bigint) = :k)
""")


def format_key(key: int = KEY) -> str:
    """The key as the banner prints it: ``0x0D69_5C4E_D000_0001``."""
    digits = f"{key:016X}"
    return "0x" + "_".join(digits[i:i + 4] for i in range(0, 16, 4))


class LockLost(RuntimeError):
    """The session that held the lock is gone: nothing may be done any more."""


def open_lock_connection() -> Connection:
    """One dedicated, unpooled, autocommit connection for the lock, as ``cyberorch_app``.

    Its own engine and no pool: the lock belongs to *this* session, so the session must not be
    shared, recycled or pre-pinged away. TCP keepalives make a vanished server noticed in seconds.
    The caller owns it and closes it.
    """
    engine = create_engine(
        database_url(), poolclass=NullPool, future=True, isolation_level="AUTOCOMMIT",
        connect_args={"keepalives": 1, "keepalives_idle": 5, "keepalives_interval": 2,
                      "keepalives_count": 3},
    )
    return engine.connect()


class HarnessLock:
    def __init__(self, connect: Callable[[], Connection] = open_lock_connection):
        self._connect = connect
        self._conn: Connection | None = None
        self._mutex = threading.Lock()
        self.lost = threading.Event()
        self._watchdog: threading.Thread | None = None
        self._stop = threading.Event()

    def acquire(self) -> bool:
        """Take the lock; False if another instance holds it."""
        self._conn = self._connect()
        got = bool(self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"),
                                      {"k": KEY}).scalar_one())
        if not got:
            self.close()
        return got

    def held(self) -> bool:
        """Whether this session still holds the lock. An error is 'lost', and stays lost."""
        if self.lost.is_set() or self._conn is None:
            return False
        try:
            with self._mutex:
                ok = bool(self._conn.execute(_HELD, {"k": KEY}).scalar_one())
        except Exception:  # noqa: BLE001 - any failure of the lock session is "lost"
            ok = False
        if not ok:
            self.lost.set()
        return ok

    def assert_held(self) -> None:
        if not self.held():
            raise LockLost("the harness lock is lost")

    def start_watchdog(self, interval: float = 2.0) -> None:
        def watch() -> None:
            while not self._stop.wait(interval):
                if not self.held():
                    return

        self._watchdog = threading.Thread(target=watch, name="harness-lock-watchdog", daemon=True)
        self._watchdog.start()

    def close(self) -> None:
        self._stop.set()
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing a dead session is not an error
                pass


class LockGuardedPorts:
    """The loop's ports, each preceded by a look at the lock: once it is lost, none is called."""

    def __init__(self, ports: LoopPorts, lock: HarnessLock):
        self._ports = ports
        self._lock = lock

    def enrolled(self):
        self._lock.assert_held()
        return self._ports.enrolled()

    def accepts_work(self, engagement_id):
        self._lock.assert_held()
        return self._ports.accepts_work(engagement_id)

    def live_tasks(self, engagement_id):
        self._lock.assert_held()
        return self._ports.live_tasks(engagement_id)

    def take_snapshot(self, engagement_id):
        self._lock.assert_held()
        return self._ports.take_snapshot(engagement_id)

    def plan(self, engagement_id, snapshot):
        self._lock.assert_held()
        return self._ports.plan(engagement_id, snapshot)

    def claim(self, engagement_id):
        self._lock.assert_held()
        return self._ports.claim(engagement_id)

    def work(self, engagement_id, task_id, snapshot):
        self._lock.assert_held()
        return self._ports.work(engagement_id, task_id, snapshot)

    def load_policy(self, engagement_id):
        self._lock.assert_held()
        return self._ports.load_policy(engagement_id)

    def propose(self, engagement_id, task_id, proposal, policy, idempotency_key):
        self._lock.assert_held()
        return self._ports.propose(engagement_id, task_id, proposal, policy, idempotency_key)

    def complete(self, engagement_id, task_id, summary):
        self._lock.assert_held()
        return self._ports.complete(engagement_id, task_id, summary)
