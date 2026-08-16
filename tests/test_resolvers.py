"""Authorization Resolver and Metadata Resolver (§5, I6b, I6c, I8, I10).

Registry rows are seeded through the ``registry`` fixture, which writes as
``registry_admin``; the resolvers then read as ``cyberorch_app``. That split is
the production arrangement (§5), so these tests exercise the real permission
path rather than a privileged shortcut.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from control_plane.canonicalizer.authorization import (
    DENY_ACTION_NOT_ALLOWED,
    DENY_SCOPE_OBJECT_MISSING,
    DENY_SOURCE_NOT_SCOPE,
    DENY_TARGET_NOT_COVERED,
    action_matches,
    resolve_authorization,
)
from control_plane.canonicalizer.metadata import resolve_metadata
from control_plane.canonicalizer.target import normalize_target
from control_plane.registry.metadata_registry import MetadataRow
from control_plane.state.db import engagement_scope, registry_admin_scope
from tests.helpers import EngagementManager


def _target(itype: str, value: str, **kw):
    return normalize_target({"logical_identity": {"type": itype, "value": value}, **kw})


def _auth(scope_object_id: str | None, source: str = "engagement_scope"):
    return {"source": source, "scope_object_id": scope_object_id}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _authorize(engagement_id, target, action, scope_object_id, source="engagement_scope"):
    """Resolve as cyberorch_app — the role the resolvers really run under."""
    with engagement_scope(engagement_id) as conn:
        return resolve_authorization(
            conn, target=target, action=action,
            authorization=_auth(scope_object_id, source),
        )


def _classify(engagement_id, target):
    with engagement_scope(engagement_id) as conn:
        return resolve_metadata(conn, target=target)


# --------------------------------------------------------------------------
# action_matches — §4.1.5 writes patterns like "web.*"
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "action,allowed,expected",
    [
        ("web.get", ["web.*"], True),
        ("web.post.form", ["web.*"], True),
        ("network.scan", ["network.recon", "network.scan"], True),
        ("network.scan", ["network.recon"], False),
        ("web.get", ["*"], True),
        ("webhook.send", ["web.*"], False),   # not a namespace boundary
        ("web", ["web.*"], False),
        ("data.read", [], False),
    ],
)
def test_action_matching(action, allowed, expected):
    assert action_matches(action, allowed) is expected


# --------------------------------------------------------------------------
# Authorization Resolver
# --------------------------------------------------------------------------

def test_authorized_when_scope_object_covers_target_and_action(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid)
    assert result.authorized is True
    assert result.reasons == ()
    assert result.scope_object.value == "app.customer-a.com"


def test_fqdn_scope_does_not_authorize_a_scan_of_the_resolved_ip(engagement_id, registry):
    """§4.1.5's worked example, and the heart of I8.

    SCOPE-1 authorizes web.* against the name. The agent resolves the name to
    203.0.113.17 and wants network.scan against the address. Without a cidr
    scope object covering that address, this must not be authorized — the
    address may well be a shared load balancer carrying someone else's traffic.
    """
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    result = _authorize(engagement_id, _target("ip", "203.0.113.17"),
                        "network.scan", sid)
    assert result.authorized is False
    assert DENY_TARGET_NOT_COVERED in result.reasons
    assert DENY_ACTION_NOT_ALLOWED in result.reasons


def test_cidr_scope_authorizes_the_ip(engagement_id, registry):
    """The other half of §4.1.5: with its own cidr scope object, it works."""
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.recon", "network.scan"])
    result = _authorize(engagement_id, _target("ip", "10.20.0.7"), "network.scan", sid)
    assert result.authorized is True


def test_cidr_scope_does_not_cover_an_fqdn_target(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.scan"])
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "network.scan", sid)
    assert result.authorized is False
    assert DENY_TARGET_NOT_COVERED in result.reasons


def test_cidr_scope_does_not_cover_an_ip_outside_it(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="cidr", value="10.20.0.0/24",
                   allowed_actions=["network.scan"])
    result = _authorize(engagement_id, _target("ip", "10.20.1.7"), "network.scan", sid)
    assert result.authorized is False


def test_wildcard_fqdn_scope_covers_subdomains_only(engagement_id, registry):
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="*.customer-a.com",
                   allowed_actions=["web.*"])
    sub = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"), "web.get", sid)
    apex = _authorize(engagement_id, _target("fqdn", "customer-a.com"), "web.get", sid)
    lookalike = _authorize(
        engagement_id, _target("fqdn", "evil-customer-a.com"), "web.get", sid
    )
    assert sub.authorized is True
    assert apex.authorized is False
    assert lookalike.authorized is False


def test_unknown_scope_object_is_not_authorized(engagement_id):
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", "SCOPE-DOES-NOT-EXIST")
    assert result.authorized is False
    assert result.reasons == (DENY_SCOPE_OBJECT_MISSING,)


def test_scope_object_from_another_engagement_is_invisible(engagement_id):
    """I4 and I8 together: RLS makes another engagement's scope object absent.

    registry_admin has no BYPASSRLS, so even the writer stays inside one
    engagement — the point of not making it an administrator.
    """
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    sid = _uid("SCOPE")
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
    EngagementManager(other).scope(
        scope_object_id=sid, type="fqdn", value="app.customer-a.com",
        allowed_actions=["web.*"],
    )
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid)
    assert result.authorized is False
    assert DENY_SCOPE_OBJECT_MISSING in result.reasons


def test_deactivated_scope_object_stops_authorizing(engagement_id, registry):
    from control_plane.registry.scope_registry import deactivate_scope_object

    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    with registry_admin_scope(engagement_id) as conn:
        deactivate_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, actor="em"
        )
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid)
    assert result.authorized is False


@pytest.mark.parametrize("source", ["dns", "tool_observed", "web_content", "", None])
def test_discovery_sources_cannot_authorize(engagement_id, registry, source):
    """I8: discovery may create candidates, never authorization."""
    sid = _uid("SCOPE")
    registry.scope(scope_object_id=sid, type="fqdn", value="app.customer-a.com",
                   allowed_actions=["web.*"])
    result = _authorize(engagement_id, _target("fqdn", "app.customer-a.com"),
                        "web.get", sid, source=source)
    assert result.authorized is False
    assert DENY_SOURCE_NOT_SCOPE in result.reasons


def test_resolver_signature_excludes_discovery():
    """I8, structurally: discovery is not an argument this function accepts."""
    import inspect

    params = set(inspect.signature(resolve_authorization).parameters)
    assert "discovery" not in params
    assert params == {"conn", "target", "action", "authorization"}


# --------------------------------------------------------------------------
# Metadata Resolver — the precedence rule
# --------------------------------------------------------------------------

def test_authoritative_row_becomes_the_canonical_classification(engagement_id, registry):
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value="db.customer-a.com",
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["PII"], resource_class=["customer_database"],
    )
    result = _classify(engagement_id, _target("fqdn", "db.customer-a.com"))
    assert result.known is True
    assert result.authority == "AUTHORITATIVE"
    assert result.data_class == ("PII",)
    assert result.resource_class == ("customer_database",)


def test_unregistered_identity_is_unknown(engagement_id):
    """§5: unknown is a legitimate answer, not an error and not 'high risk'."""
    result = _classify(engagement_id, _target("fqdn", "never-seen.example.com"))
    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.observations == ()


@pytest.mark.parametrize("authority", ["OBSERVED", "INFERRED", "LLM_HINT"])
def test_lower_tiers_never_produce_a_canonical_classification(
    engagement_id, registry, authority
):
    """The precedence rule.

    A row exists and says the resource is a harmless static site. Because no
    AUTHORITATIVE row exists, the canonical answer stays UNKNOWN: a lower tier
    cannot fill the gap, only sit beside it as an observation.
    """
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn",
        identity_value="app.customer-a.com", authority=authority,
        source="policy_reviewer", data_class=["public_marketing"],
        resource_class=["static_site"],
    )
    result = _classify(engagement_id, _target("fqdn", "app.customer-a.com"))

    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.resource_class == ()
    # ...but the claim is preserved, so OPA can still use it to tighten.
    assert len(result.observations) == 1
    assert result.observations[0].authority == authority
    assert result.observations[0].data_class == ("public_marketing",)


def test_lower_tiers_cannot_dilute_an_authoritative_classification(engagement_id, registry):
    """Scenario B's precondition (I6b)."""
    ident = "db.customer-a.com"
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["PII"], resource_class=["customer_database"],
    )
    registry.metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="LLM_HINT", source="adversarial_fake_reviewer",
        data_class=[], resource_class=["static_site"],
    )
    result = _classify(engagement_id, _target("fqdn", ident))

    assert result.known is True
    assert result.authority == "AUTHORITATIVE"
    assert result.data_class == ("PII",)
    assert result.as_dict()["data_class"] == ["PII"]
    assert [o.authority for o in result.observations] == ["LLM_HINT"]


def test_database_prevents_two_authoritative_rows_for_one_identity(engagement_id):
    """First line of defence: the unique index makes a conflict unstorable."""
    ident = "conflict.customer-a.com"
    with pytest.raises(IntegrityError):
        with registry_admin_scope(engagement_id) as conn:
            for dclass in ("PII", "public"):
                conn.execute(
                    text("""
                        INSERT INTO metadata_registry (asset_id, engagement_id,
                            identity_type, identity_value, data_class,
                            classification_source, classification_authority)
                        VALUES (:aid, :eid, 'fqdn', :ival, ARRAY[:dc],
                                'manual', 'AUTHORITATIVE')
                    """),
                    {"aid": _uid("ASSET"), "eid": engagement_id,
                     "ival": ident, "dc": dclass},
                )


def test_conflicting_authoritative_rows_fail_closed(engagement_id, monkeypatch):
    """I10: CONFLICT resolves to not-known, never to a picked winner."""
    rows = [
        MetadataRow(
            asset_id=f"ASSET-{i}", engagement_id=engagement_id, identity_type="fqdn",
            identity_value="conflict.customer-a.com", resource_class=(),
            data_class=(dclass,), classification_source="manual",
            classification_authority="AUTHORITATIVE", classification_version=1,
        )
        for i, dclass in enumerate(("PII", "public"))
    ]
    monkeypatch.setattr(
        "control_plane.canonicalizer.metadata.lookup", lambda conn, **kw: rows
    )
    result = _classify(engagement_id, _target("fqdn", "conflict.customer-a.com"))

    assert result.authority == "CONFLICT"
    assert result.known is False
    assert result.data_class == ()


def test_metadata_is_engagement_scoped(engagement_id):
    """I4: another engagement's classification must not leak in."""
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    ident = "shared-name.example.com"
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
    EngagementManager(other).metadata(
        asset_id=_uid("ASSET"), identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared", data_class=["PII"],
    )
    result = _classify(engagement_id, _target("fqdn", ident))
    assert result.known is False


def test_registry_writes_are_audited(engagement_id, registry):
    """§5: who changed which classification to what, and when."""
    asset_id = _uid("ASSET")
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn",
        identity_value="audited.customer-a.com", authority="AUTHORITATIVE",
        source="customer_declared", data_class=["PII"],
    )
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT actor, event_type, payload FROM audit_log "
                 "WHERE subject_id = :s"),
            {"s": asset_id},
        ).mappings().one()
    assert row["actor"] == "engagement-manager"
    assert row["event_type"] == "metadata.registered"
    assert row["payload"]["authority"] == "AUTHORITATIVE"
    assert row["payload"]["db_role"] == "registry_admin"
    assert row["payload"]["before"] is None
    assert row["payload"]["after"]["data_class"] == ["PII"]


def test_reclassification_records_the_previous_value(engagement_id, registry):
    """§5 wants what it changed *from*, not only what it now says.

    A downgrade from PII to public is the edit an investigator most needs to
    see, and an audit record holding only the new value cannot show it.
    """
    asset_id = _uid("ASSET")
    ident = "changed.customer-a.com"
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared", data_class=["PII"],
    )
    registry.metadata(
        asset_id=asset_id, identity_type="fqdn", identity_value=ident,
        authority="AUTHORITATIVE", source="customer_declared",
        data_class=["public_marketing"], actor="engagement-manager-2",
    )
    with engagement_scope(engagement_id) as conn:
        rows = conn.execute(
            text("SELECT actor, event_type, payload FROM audit_log "
                 "WHERE subject_id = :s ORDER BY audit_id"),
            {"s": asset_id},
        ).mappings().all()

    assert [r["event_type"] for r in rows] == [
        "metadata.registered", "metadata.reclassified",
    ]
    change = rows[1]["payload"]
    assert change["before"]["data_class"] == ["PII"]
    assert change["after"]["data_class"] == ["public_marketing"]
    assert rows[1]["actor"] == "engagement-manager-2"


def test_registry_writes_require_an_actor(engagement_id):
    with registry_admin_scope(engagement_id) as conn:
        from control_plane.registry.metadata_registry import register_metadata

        with pytest.raises(ValueError):
            register_metadata(
                conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
                identity_type="fqdn", identity_value="x.customer-a.com",
                authority="AUTHORITATIVE", source="customer_declared", actor="",
            )
