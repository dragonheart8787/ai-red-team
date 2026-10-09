"""The singleton guard: one scheduler at a time (D62, D58-2).

A Postgres *session* advisory lock on a dedicated connection. The server releases a session lock
when the session ends, so it cannot outlive a dead process: no table to clean, no heartbeat row, no
lease to tune. A second instance's ``pg_try_advisory_lock`` returns false and it exits before
reading anything.

"Lost connection = lost lock = stop dispatching." The lock is checked on the same session before and
after every dispatch (a dispatch can run for the whole ``max_duration_seconds`` of a container),
and a watchdog thread checks it every ``interval`` seconds meanwhile. It cannot stop a container
already running -- nothing in v0 can (D44-7/D58-16) -- it sets ``lost`` so that no further dispatch
starts. It guards against accidents; it is not an authorization mechanism (another role can take the
same key, which only prevents the scheduler from starting).
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from sqlalchemy import Connection, text

from control_plane.state.db import open_scheduler_lock_connection

#: The advisory-lock key. Fixed, so every instance contends for the same one.
LOCK_KEY = 0x0D62_5C4E_D000_0001

_HELD = text("""
    SELECT EXISTS (
        SELECT 1 FROM pg_locks
        WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
          AND ((classid::bigint << 32) | objid::bigint) = :k)
""")


class SingletonLock:
    def __init__(self, connect: Callable[[], Connection] = open_scheduler_lock_connection):
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
                                      {"k": LOCK_KEY}).scalar_one())
        if not got:
            self.close()
        return got

    def held(self) -> bool:
        """Whether this session still holds the lock. An error is 'lost', and stays lost."""
        if self.lost.is_set() or self._conn is None:
            return False
        try:
            with self._mutex:
                ok = bool(self._conn.execute(_HELD, {"k": LOCK_KEY}).scalar_one())
        except Exception:  # noqa: BLE001 - any failure of the lock session is "lost"
            ok = False
        if not ok:
            self.lost.set()
        return ok

    def start_watchdog(self, interval: float = 2.0) -> None:
        def watch() -> None:
            while not self._stop.wait(interval):
                if not self.held():
                    return
        self._watchdog = threading.Thread(target=watch, name="scheduler-lock-watchdog", daemon=True)
        self._watchdog.start()

    def close(self) -> None:
        self._stop.set()
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing a dead session is not an error
                pass
