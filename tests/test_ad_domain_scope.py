"""D42-1: ad_domain scope objects authorize collection only.

Two backstops, tested separately on purpose. ``register_scope_object``'s
guard (control_plane/registry/scope_registry.py) is what a caller actually
sees; migration 0011's ``ad_domain_collection_only`` CHECK constraint is what
holds even if that guard is bypassed, edited out, or never called at all —
the same "the database is the real enforcement" relationship
``assert_registry_admin`` has to the role grant it explains (control_plane/
state/db.py). A test that only exercises the Python guard would not know the
difference between "this is enforced" and "this is enforced today, by
exactly one function remembering to check."
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import exc as sa_exc
from sqlalchemy import text

from control_plane.registry.scope_registry import ScopeValueError, register_scope_object
from control_plane.state.db import registry_admin_scope


def test_ad_domain_scope_can_grant_ad_collect(registry):
    scope = registry.scope(
        scope_object_id=f"SCOPE-{uuid.uuid4().hex[:8]}",
        type="ad_domain", value="corp.example.com", allowed_actions=["ad.collect"],
    )
    assert scope.type == "ad_domain"
    assert scope.allowed_actions == ("ad.collect",)


@pytest.mark.parametrize(
    "allowed_actions",
    [["network.scan"], ["ad.collect", "network.scan"], ["web.get"]],
)
def test_register_scope_object_refuses_ad_domain_with_any_other_action(
    engagement_id, allowed_actions,
):
    with registry_admin_scope(engagement_id) as conn:
        with pytest.raises(ScopeValueError, match="ad_domain scope objects may only grant"):
            register_scope_object(
                conn, engagement_id=engagement_id,
                scope_object_id=f"SCOPE-{uuid.uuid4().hex[:8]}",
                type="ad_domain", value="corp.example.com",
                allowed_actions=allowed_actions, actor="test-harness",
            )


def test_ad_domain_collection_only_is_enforced_by_the_schema_itself(engagement_id):
    """Mutation-style verification of the real backstop, not the guard.

    Bypasses register_scope_object's guard entirely with a raw INSERT on the
    registry_admin connection -- the same privilege level the guarded
    function itself runs under -- and confirms the database refuses it via
    migration 0011's CHECK constraint, independent of any Python code path
    remembering to ask.
    """
    with registry_admin_scope(engagement_id) as conn:
        with pytest.raises(sa_exc.IntegrityError, match="ad_domain_collection_only"):
            conn.execute(
                text("""
                    INSERT INTO scope_registry (scope_object_id, engagement_id, type,
                        value, allowed_actions, registered_by)
                    VALUES (:sid, :eng, 'ad_domain', 'corp.example.com',
                            ARRAY['network.scan'], 'test-harness')
                """),
                {"sid": f"SCOPE-{uuid.uuid4().hex[:8]}", "eng": engagement_id},
            )
