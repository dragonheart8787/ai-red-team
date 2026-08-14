"""Shared fixtures.

Tests connect as ``cyberorch_app`` — the same role the application uses. This
matters: §8.6 warns that RLS suites which connect as a privileged role pass
while production leaks, because the test role was never subject to the policies
in the first place.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from control_plane.config import load_dotenv
from control_plane.state.db import engagement_scope, get_engine

# Credentials come from the environment or the gitignored .env that
# scripts/init_db.sh writes — never from a literal in the test suite.
load_dotenv()


@pytest.fixture(scope="session")
def db_available() -> bool:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - environment guard
        pytest.skip(f"PostgreSQL not reachable ({exc}). Run scripts/init_db.sh first.")
    return True


@pytest.fixture
def engagement_id(db_available) -> str:
    """Create a throwaway engagement and return its id."""
    eid = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(eid) as conn:
        conn.execute(
            text("""
                INSERT INTO engagements
                    (engagement_id, customer_id, policy_snapshot_version)
                VALUES (:eid, 'CUST-TEST', 1)
            """),
            {"eid": eid},
        )
    return eid
