"""Shared test helpers."""

from __future__ import annotations

import uuid

from sqlalchemy import Connection, text

from control_plane.orchestrator.engagement import create_engagement
from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import registry_admin_scope


def make_engagement(
    engagement_id: str, customer_id: str = "CUST-TEST", *, actor: str = "test-harness"
) -> None:
    """Create an engagement through the real operation (D39).

    Every test that needs an engagement — the shared fixtures and every test
    that builds a second one by hand — calls this rather than writing the
    INSERT itself. Two reasons, not one:

    * it is the one canonical construction path, the same principle
      :class:`EngagementManager` already applies to scope and metadata — a
      test that fabricates the row by hand tends to skip the parts that make
      the real one real;
    * after D39, ``cyberorch_app`` no longer has INSERT on ``engagements``
      (migration 0010) — a test that still wrote the raw SQL would now fail
      with ``InsufficientPrivilege``, which is the *correct* outcome for a
      fixture taking a shortcut around the Engagement Manager role, not a bug
      to work around.
    """
    with registry_admin_scope(engagement_id) as conn:
        create_engagement(
            conn, engagement_id=engagement_id, customer_id=customer_id, actor=actor,
        )


def make_tool_run(
    conn: Connection, *, engagement_id: str, tool: str = "bloodhound-python",
    normalized_target: str = "test.local", status: str = "succeeded",
) -> str:
    """A minimal ``tool_runs`` row for tests that need a real run_id to hang
    evidence, a Security Graph batch, or a provenance edge off of, without
    running an actual dispatch.
    """
    run_id = f"RUN-TEST-{uuid.uuid4().hex[:12]}"
    conn.execute(
        text("""
            INSERT INTO tool_runs (run_id, engagement_id, tool, tool_version,
                normalized_target, execution_fingerprint, status)
            VALUES (:run, :eng, :tool, 'test', :target, :fp, :status)
        """),
        {"run": run_id, "eng": engagement_id, "tool": tool,
         "target": normalized_target, "fp": f"fp-{run_id}", "status": status},
    )
    return run_id


class EngagementManager:
    """Test-side stand-in for the Engagement Manager (§5).

    Seeds registry rows over the ``registry_admin`` connection, the same way
    production does. Tests deliberately do not get a privileged shortcut for
    building fixtures: seeding through a role that can do more than the real
    writer would leave the actual permission path untested, which is the §8.6
    lesson in a different place.
    """

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    def scope(self, *, actor: str = "engagement-manager", **kwargs):
        with registry_admin_scope(self.engagement_id) as conn:
            return register_scope_object(
                conn, engagement_id=self.engagement_id, actor=actor, **kwargs
            )

    def metadata(self, *, actor: str = "engagement-manager", **kwargs):
        with registry_admin_scope(self.engagement_id) as conn:
            return register_metadata(
                conn, engagement_id=self.engagement_id, actor=actor, **kwargs
            )
