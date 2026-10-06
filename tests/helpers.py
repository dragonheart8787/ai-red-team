"""Shared test helpers."""

from __future__ import annotations

import uuid
from contextlib import contextmanager

from sqlalchemy import Connection, text

from control_plane.orchestrator.engagement import create_engagement
from control_plane.policy.layers import deactivate_policy_layer, publish_policy_layer
from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import global_policy_admin_scope, registry_admin_scope


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


def publish_global_layer(
    *, layer: str, version: int, document, actor: str = "test-harness",
    customer_id: str | None = None,
) -> int:
    """Publish a *global* policy layer the only way the database allows (5.37).

    A global layer applies to every engagement, so it is written on the
    ``global_policy_admin`` connection with no engagement bound -- not from an
    ``engagement_scope``, which the runtime role can no longer use for it. Commits on its
    own, so the row is visible to every later engagement connection.
    """
    with global_policy_admin_scope() as conn:
        return publish_policy_layer(
            conn, engagement_id=None, layer=layer, version=version, document=document,
            actor=actor, scoped_to_engagement=False, customer_id=customer_id,
        )


def deactivate_global_layer(layer_id: int, *, actor: str = "test-teardown") -> bool:
    """Retire a global layer on the ``global_policy_admin`` connection (5.37)."""
    with global_policy_admin_scope() as conn:
        return deactivate_policy_layer(conn, layer_id=layer_id, actor=actor)


_TEST_BASELINE_ID: int | None = None


def ensure_test_baseline() -> int | None:
    """Make sure a global baseline exists, as ``create_engagement`` now requires (5.20, D54).

    An engagement created with no baseline in force is refused, so every test that makes one
    needs the platform owner's step to have happened. If none is active this publishes a
    **neutral** one (an empty document adds nothing to the merge) on the ``global_policy_admin``
    connection and returns its id, so the session can retire it; if one exists it publishes
    nothing and returns ``None``. A fresh CI database has none, which is exactly the case.
    """
    global _TEST_BASELINE_ID
    with global_policy_admin_scope() as conn:
        exists = conn.execute(text(
            "SELECT 1 FROM policy_layers WHERE layer = 'baseline_global' "
            "AND engagement_id IS NULL AND customer_id IS NULL AND active IS TRUE LIMIT 1"
        )).first()
    if exists:
        return None
    _TEST_BASELINE_ID = publish_global_layer(
        layer="baseline_global", version=uuid.uuid4().int % 2_000_000_000, document={},
        actor="test-harness")
    return _TEST_BASELINE_ID


@contextmanager
def committing_scope(engagement_id: str):
    """``engagement_scope``, except every statement commits as it runs (D60).

    ``propose_action`` and the ``dispatch_*`` functions open their own transactions, one per
    stage, so the capability, the proposal row or the revocation a test sets up first has to be
    *committed* for them to see it -- exactly as it is in production, where each stage commits
    before the next begins. A test that builds its fixture inside one open transaction and then
    dispatches would be testing a state no running system can be in.

    The engagement is bound for the session rather than the transaction (there is no transaction),
    and cleared on the way out so the pooled connection carries nothing into its next checkout.
    """
    from sqlalchemy import text

    from control_plane.state.db import get_engine

    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("SELECT set_config('cyberorch.engagement_id', :eid, false)"),
                     {"eid": engagement_id})
        try:
            yield conn
        finally:
            conn.execute(text("SELECT set_config('cyberorch.engagement_id', '', false)"))
