"""D69 H5b: the enrolment list, read from the database (``harness_enrolment``, migration 0031).

:class:`EnrolledFromDatabase` is the real :class:`~harness.enrolment.EnrolmentReader`: the loop asks
it for the engagements it may work on, once per round. It returns the engagement ids of the rows
that are **not withdrawn and whose purpose is** ``harness_lab``, in the order they were registered
and then by id, so the same table always gives the same answer. The filter on the purpose is not a
decoration: the column's ``CHECK`` allows one value today, and a reader that did not ask for it
would pick up whatever purpose a later migration adds.

The read is a **read-only transaction** as ``cyberorch_app`` with no engagement bound -- the table
is global (the reader has to list ids to know which engagement to open), and its row-level security
names that role. This module only reads: it holds no ``INSERT`` and no ``UPDATE``, and the one place
that writes the list is ``scripts/manage_harness_enrolment.py``, which nothing in the loop imports.
It imports nothing of the scheduler.

``connect`` is how a test (or another caller) supplies the connection; the default is
:func:`read_only_connection`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager

from sqlalchemy import text
from sqlalchemy.engine import Connection

from control_plane.state.db import get_engine

PURPOSE = "harness_lab"

_SQL = text(
    "SELECT engagement_id FROM harness_enrolment "
    "WHERE withdrawn_at IS NULL AND purpose = 'harness_lab' "
    "ORDER BY enrolled_at, engagement_id"
)


@contextmanager
def read_only_connection() -> Iterator[Connection]:
    """A read-only transaction as ``cyberorch_app``, no engagement bound."""
    with get_engine().begin() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        yield conn


class EnrolledFromDatabase:
    """The engagements registered for the harness, read from ``harness_enrolment``."""

    def __init__(self, connect: Callable[[], AbstractContextManager[Connection]] | None = None):
        self._connect = connect if connect is not None else read_only_connection

    def enrolled(self) -> tuple[str, ...]:
        with self._connect() as conn:
            rows = conn.execute(_SQL).all()
        return tuple(row[0] for row in rows)
