"""Shared test helpers."""

from __future__ import annotations

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
