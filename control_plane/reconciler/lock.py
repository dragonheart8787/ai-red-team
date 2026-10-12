"""The singleton guard: one reconciler at a time (D64-10, D58-2).

The same mechanism as the scheduler's -- a Postgres *session* advisory lock on a dedicated
connection, which the server releases when the session ends, so it cannot outlive a dead process --
and a **different key**. Two keys on purpose (D64-10): the reconciler and the scheduler may run at
the same time (a long reconcile must not stop dispatch, nor the reverse); each is excluded only
against a second copy of itself. What makes that safe is the guarded updates, the time bounds and
the dispatch-side fixes of 5.74, not the lock; and "reconcile first" is an operator convention that
nothing here, or anywhere, enforces (docs/D64_RECONCILER_DESIGN.md §3.3).

"Lost connection = lost lock = stop acting." The lock is checked on the same session before a pass
and after it, and a watchdog thread checks it every ``interval`` seconds meanwhile. It cannot undo
an action already taken; it sets ``lost`` so that no further pass starts.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from sqlalchemy import Connection, text

from control_plane.state.db import open_reconciler_lock_connection

#: The advisory-lock key. Fixed, so every instance contends for the same one -- and not the
#: scheduler's (0x0D62_5C4E_D000_0001): the two must be holdable together.
LOCK_KEY = 0x0D64_5EC0_0000_0001

_HELD = text("""
    SELECT EXISTS (
        SELECT 1 FROM pg_locks
        WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
          AND ((classid::bigint << 32) | objid::bigint) = :k)
""")


class SingletonLock:
    def __init__(self, connect: Callable[[], Connection] = open_reconciler_lock_connection):
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
        self._watchdog = threading.Thread(target=watch, name="reconciler-lock-watchdog",
                                          daemon=True)
        self._watchdog.start()

    def close(self) -> None:
        self._stop.set()
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing a dead session is not an error
                pass
