"""Shared fixtures.

Tests connect as ``cyberorch_app`` — the same role the application uses. This
matters: §8.6 warns that RLS suites which connect as a privileged role pass
while production leaks, because the test role was never subject to the policies
in the first place.
"""

from __future__ import annotations

import contextlib
import os
import uuid

import pytest
from sqlalchemy import text

from control_plane.config import load_dotenv
from control_plane.state.db import get_engine
from tests import residue
from tests.helpers import (
    EngagementManager,
    deactivate_global_layer,
    ensure_test_baseline,
    make_engagement,
)

# Credentials come from the environment or the gitignored .env that
# scripts/init_db.sh writes — never from a literal in the test suite.
load_dotenv()


@pytest.fixture(scope="session")
def db_available() -> bool:
    """Fail — do not skip — when the database is unreachable.

    Most of what this suite verifies (RLS, append-only grants, resolver
    precedence) only exists in the database. Skipping those tests turns a red
    run green while checking nothing, which is the §8.6 failure mode wearing a
    different hat. Set CYBERORCH_ALLOW_DB_SKIP=1 to opt into skipping in an
    environment that genuinely has no PostgreSQL.
    """
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - environment guard
        message = (
            f"PostgreSQL not reachable ({exc}).\n"
            "Run scripts/init_db.sh first. These tests assert database-enforced "
            "security properties and are not meaningful without it."
        )
        if os.environ.get("CYBERORCH_ALLOW_DB_SKIP") == "1":
            pytest.skip(message)
        pytest.fail(message, pytrace=False)
    return True


@pytest.fixture(scope="session", autouse=True)
def _nothing_is_left_behind(request):
    """Compare the world after the session with the world before it (tests/residue.py).

    Set up first and torn down last -- ``_a_global_baseline_exists`` asks for it, so the baseline
    this session published has been retired by the time the comparison is made. A failure here is
    an ERROR at the end of the run: the run does not pass while it is true.
    """
    try:
        before = residue.snapshot()
    except Exception:  # pragma: no cover - no database; db_available reports it
        yield
        return
    yield
    found = residue.leftovers(before)
    rows = residue.close_session_rows(before)
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    capture = request.config.pluginmanager.get_plugin("capturemanager")
    lines = []
    if found.networks_removed:
        lines.append(f"residue: removed {len(found.networks_removed)} sandbox network(s) the "
                     f"session left behind (the sandbox keeps one per allowlist by design)")
    if rows.proposals or rows.runs:
        lines.append(f"residue: closed {sum(rows.proposals.values())} stuck proposal(s) "
                     f"{dict(sorted(rows.proposals.items()))} and {rows.runs} in-flight run(s) the "
                     f"session left in {rows.engagements} engagement(s) it created, by test file:")
        lines += rows.table()
    if reporter is not None and lines:
        # (written past the capture of the fixture's teardown, so that a passing run shows it too)
        with capture.global_and_fixture_disabled() if capture else contextlib.nullcontext():
            for line in lines:
                reporter.write_line(line)
    if found.failures() or rows.failures():
        pytest.fail("the test session left state behind:\n  "
                    + "\n  ".join(found.failures() + rows.failures()), pytrace=False)


@pytest.fixture(scope="session", autouse=True)
def _a_global_baseline_exists(_nothing_is_left_behind):
    """``create_engagement`` refuses when no global baseline is in force (5.20, D54), so a
    session that makes engagements needs one. Ensured once, for the whole session, and retired
    afterwards only if this session published it. Skipped when there is no database: tests that
    need one fail through ``db_available`` with the better message."""
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:  # pragma: no cover - environment guard, reported by db_available
        yield
        return
    published = ensure_test_baseline()
    yield
    if published is not None:
        deactivate_global_layer(published, actor="test-session-teardown")


@pytest.fixture(autouse=True)
def _reconciler_test_rows_are_closed_out():
    """Stuck rows the reconciler's tests made are moved to a terminal stage when the test ends, so
    a development database does not fill up with them (tests/reconciler_support.py)."""
    yield
    from tests.reconciler_support import close_touched
    close_touched()


@pytest.fixture
def engagement_id(db_available) -> str:
    """Create a throwaway engagement and return its id."""
    eid = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    make_engagement(eid)
    return eid



@pytest.fixture
def registry(engagement_id) -> EngagementManager:
    return EngagementManager(engagement_id)


@pytest.fixture
def engagement_factory(db_available):
    """Build additional engagements on demand, each with its own manager.

    The ``engagement_id`` fixture gives a test one engagement, which is what
    almost every test wants. Anything asserting an *isolation* property needs
    two — a second engagement to be excluded from — and a test that fabricates
    the second one by hand tends to skip the parts that make the first one real.
    """
    def make() -> tuple[str, EngagementManager]:
        eid = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
        make_engagement(eid)
        return eid, EngagementManager(eid)
    return make
