"""Helpers the H5b tests share (no test is in this file; its name is what the task allows).

``owner_transaction`` is a transaction as ``migration_owner`` that is **always rolled back**, in
which the table's ``FORCE ROW LEVEL SECURITY`` is off for the owner (as ``make_room_in_the_page`` in
``tests/reconciler_support.py`` and the migrations' own data statements do it), so a test can write
rows, change the table's definition and read through the real reader on the same connection, and
leave nothing behind. DDL is transactional in PostgreSQL: a ``DROP CONSTRAINT`` made inside is
undone by the rollback, and the tests that rely on it check that it was.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

TABLE = "harness_enrolment"
PURPOSE_CHECK = "harness_enrolment_purpose_check"


@contextmanager
def owner_transaction() -> Iterator[Connection]:
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    conn = engine.connect()
    trans = conn.begin()
    try:
        conn.execute(text("SET LOCAL lock_timeout = '10s'"))
        conn.execute(text(f"ALTER TABLE {TABLE} NO FORCE ROW LEVEL SECURITY"))
        yield conn
    finally:
        trans.rollback()
        conn.close()
        engine.dispose()


def same_connection(conn: Connection):
    """A ``connect`` for the reader that hands out ``conn`` and does not close it."""
    return lambda: nullcontext(conn)


def read_only_flag_spy(conn: Connection, seen: list[bool]):
    """A ``connect(read_only)`` for the CLI that hands out ``conn`` and notes what was asked."""
    def connect(read_only: bool):
        seen.append(read_only)
        return nullcontext(conn)
    return connect
