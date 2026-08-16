"""Shared test helpers."""

from __future__ import annotations

from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import registry_admin_scope


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
