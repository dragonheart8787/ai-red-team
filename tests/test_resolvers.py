"""Authorization Resolver and Metadata Resolver (§5, I6b, I6c, I8, I10)."""

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
from control_plane.registry.metadata_registry import MetadataRow, register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import engagement_scope

SCOPE_AUTH = {"source": "engagement_scope", "scope_object_id": None}


def _target(itype: str, value: str, **kw):
    return normalize_target({"logical_identity": {"type": itype, "value": value}, **kw})


def _auth(scope_object_id: str | None, source: str = "engagement_scope"):
    return {"source": source, "scope_object_id": scope_object_id}


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


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

def test_authorized_when_scope_object_covers_target_and_action(engagement_id):
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="app.customer-a.com", allowed_actions=["web.*"],
            actor="engagement-manager",
        )
        result = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="web.get", authorization=_auth(sid),
        )
    assert result.authorized is True
    assert result.reasons == ()
    assert result.scope_object.value == "app.customer-a.com"


def test_fqdn_scope_does_not_authorize_a_scan_of_the_resolved_ip(engagement_id):
    """§4.1.5's worked example, and the heart of I8.

    SCOPE-1 authorizes web.* against the name. The agent resolves the name to
    203.0.113.17 and wants network.scan against the address. Without a cidr
    scope object covering that address, this must not be authorized — the
    address may well be a shared load balancer carrying someone else's traffic.
    """
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="app.customer-a.com", allowed_actions=["web.*"],
            actor="engagement-manager",
        )
        result = resolve_authorization(
            conn, target=_target("ip", "203.0.113.17"),
            action="network.scan", authorization=_auth(sid),
        )
    assert result.authorized is False
    assert DENY_TARGET_NOT_COVERED in result.reasons
    assert DENY_ACTION_NOT_ALLOWED in result.reasons


def test_cidr_scope_authorizes_the_ip(engagement_id):
    """The other half of §4.1.5: with its own cidr scope object, it works."""
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="cidr",
            value="10.20.0.0/24", allowed_actions=["network.recon", "network.scan"],
            actor="engagement-manager",
        )
        result = resolve_authorization(
            conn, target=_target("ip", "10.20.0.7"),
            action="network.scan", authorization=_auth(sid),
        )
    assert result.authorized is True


def test_cidr_scope_does_not_cover_an_fqdn_target(engagement_id):
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="cidr",
            value="10.20.0.0/24", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
        result = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="network.scan", authorization=_auth(sid),
        )
    assert result.authorized is False
    assert DENY_TARGET_NOT_COVERED in result.reasons


def test_cidr_scope_does_not_cover_an_ip_outside_it(engagement_id):
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="cidr",
            value="10.20.0.0/24", allowed_actions=["network.scan"],
            actor="engagement-manager",
        )
        result = resolve_authorization(
            conn, target=_target("ip", "10.20.1.7"),
            action="network.scan", authorization=_auth(sid),
        )
    assert result.authorized is False


def test_wildcard_fqdn_scope_covers_subdomains_only(engagement_id):
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="*.customer-a.com", allowed_actions=["web.*"],
            actor="engagement-manager",
        )
        sub = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="web.get", authorization=_auth(sid))
        apex = resolve_authorization(
            conn, target=_target("fqdn", "customer-a.com"),
            action="web.get", authorization=_auth(sid))
        lookalike = resolve_authorization(
            conn, target=_target("fqdn", "evil-customer-a.com"),
            action="web.get", authorization=_auth(sid))
    assert sub.authorized is True
    assert apex.authorized is False
    assert lookalike.authorized is False


def test_unknown_scope_object_is_not_authorized(engagement_id):
    with engagement_scope(engagement_id) as conn:
        result = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="web.get", authorization=_auth("SCOPE-DOES-NOT-EXIST"),
        )
    assert result.authorized is False
    assert result.reasons == (DENY_SCOPE_OBJECT_MISSING,)


def test_scope_object_from_another_engagement_is_invisible(engagement_id):
    """I4 and I8 together: RLS makes another engagement's scope object absent."""
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    sid = _uid("SCOPE")
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
        register_scope_object(
            conn, engagement_id=other, scope_object_id=sid, type="fqdn",
            value="app.customer-a.com", allowed_actions=["web.*"], actor="em",
        )
    with engagement_scope(engagement_id) as conn:
        result = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="web.get", authorization=_auth(sid),
        )
    assert result.authorized is False
    assert DENY_SCOPE_OBJECT_MISSING in result.reasons


def test_deactivated_scope_object_stops_authorizing(engagement_id):
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="app.customer-a.com", allowed_actions=["web.*"], actor="em",
        )
        conn.execute(
            text("UPDATE scope_registry SET active = FALSE WHERE scope_object_id = :s"),
            {"s": sid},
        )
        result = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="web.get", authorization=_auth(sid),
        )
    assert result.authorized is False


@pytest.mark.parametrize("source", ["dns", "tool_observed", "web_content", "", None])
def test_discovery_sources_cannot_authorize(engagement_id, source):
    """I8: discovery may create candidates, never authorization.

    Every value here is a legitimate *discovery* source. Presented as an
    authorization source, each is refused outright — the resolver does not even
    look for a matching scope object.
    """
    sid = _uid("SCOPE")
    with engagement_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=sid, type="fqdn",
            value="app.customer-a.com", allowed_actions=["web.*"], actor="em",
        )
        result = resolve_authorization(
            conn, target=_target("fqdn", "app.customer-a.com"),
            action="web.get", authorization=_auth(sid, source=source),
        )
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

def test_authoritative_row_becomes_the_canonical_classification(engagement_id):
    with engagement_scope(engagement_id) as conn:
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
            identity_type="fqdn", identity_value="db.customer-a.com",
            authority="AUTHORITATIVE", source="customer_declared",
            data_class=["PII"], resource_class=["customer_database"], actor="em",
        )
        result = resolve_metadata(conn, target=_target("fqdn", "db.customer-a.com"))
    assert result.known is True
    assert result.authority == "AUTHORITATIVE"
    assert result.data_class == ("PII",)
    assert result.resource_class == ("customer_database",)


def test_unregistered_identity_is_unknown(engagement_id):
    """§5: unknown is a legitimate answer, not an error and not 'high risk'."""
    with engagement_scope(engagement_id) as conn:
        result = resolve_metadata(conn, target=_target("fqdn", "never-seen.example.com"))
    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.observations == ()


@pytest.mark.parametrize("authority", ["OBSERVED", "INFERRED", "LLM_HINT"])
def test_lower_tiers_never_produce_a_canonical_classification(engagement_id, authority):
    """The precedence rule.

    A row exists and says the resource is a harmless static site. Because no
    AUTHORITATIVE row exists, the canonical answer stays UNKNOWN: a lower tier
    cannot fill the gap, only sit beside it as an observation.
    """
    with engagement_scope(engagement_id) as conn:
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
            identity_type="fqdn", identity_value="app.customer-a.com",
            authority=authority, source="policy_reviewer",
            data_class=["public_marketing"], resource_class=["static_site"],
            actor="em",
        )
        result = resolve_metadata(conn, target=_target("fqdn", "app.customer-a.com"))

    assert result.known is False
    assert result.authority == "UNKNOWN"
    assert result.data_class == ()
    assert result.resource_class == ()
    # ...but the claim is preserved, so OPA can still use it to tighten.
    assert len(result.observations) == 1
    assert result.observations[0].authority == authority
    assert result.observations[0].data_class == ("public_marketing",)


def test_lower_tiers_cannot_dilute_an_authoritative_classification(engagement_id):
    """Scenario B's precondition (I6b).

    The adversarial reviewer files an LLM_HINT saying "no sensitive data".
    The customer has declared PII at AUTHORITATIVE. What OPA is told is the
    customer's declaration — the reviewer's claim is visible but segregated,
    and it does not remove, weaken or average out a single canonical value.
    """
    ident = "db.customer-a.com"
    with engagement_scope(engagement_id) as conn:
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
            identity_type="fqdn", identity_value=ident,
            authority="AUTHORITATIVE", source="customer_declared",
            data_class=["PII"], resource_class=["customer_database"], actor="em",
        )
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
            identity_type="fqdn", identity_value=ident,
            authority="LLM_HINT", source="adversarial_fake_reviewer",
            data_class=[], resource_class=["static_site"], actor="em",
        )
        result = resolve_metadata(conn, target=_target("fqdn", ident))

    assert result.known is True
    assert result.authority == "AUTHORITATIVE"
    assert result.data_class == ("PII",)
    assert result.as_dict()["data_class"] == ["PII"]
    assert [o.authority for o in result.observations] == ["LLM_HINT"]


def test_database_prevents_two_authoritative_rows_for_one_identity(engagement_id):
    """First line of defence: the unique index makes a conflict unstorable."""
    ident = "conflict.customer-a.com"
    with pytest.raises(IntegrityError):
        with engagement_scope(engagement_id) as conn:
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
    """I10: CONFLICT resolves to not-known, never to a picked winner.

    Reaching this branch means something wrote around the registry API and
    defeated the index above — exactly the situation in which guessing a winner
    would be worst. The lookup is stubbed because the database will not let the
    bad state exist, and the resolver must still refuse to invent an answer.
    """
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
    with engagement_scope(engagement_id) as conn:
        result = resolve_metadata(
            conn, target=_target("fqdn", "conflict.customer-a.com")
        )

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
        register_metadata(
            conn, engagement_id=other, asset_id=_uid("ASSET"),
            identity_type="fqdn", identity_value=ident, authority="AUTHORITATIVE",
            source="customer_declared", data_class=["PII"], actor="em",
        )
    with engagement_scope(engagement_id) as conn:
        result = resolve_metadata(conn, target=_target("fqdn", ident))
    assert result.known is False


def test_registry_writes_are_audited(engagement_id):
    """§5: who changed which classification to what, and when."""
    asset_id = _uid("ASSET")
    with engagement_scope(engagement_id) as conn:
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=asset_id,
            identity_type="fqdn", identity_value="audited.customer-a.com",
            authority="AUTHORITATIVE", source="customer_declared",
            data_class=["PII"], actor="engagement-manager",
        )
        row = conn.execute(
            text("SELECT actor, event_type, payload FROM audit_log "
                 "WHERE subject_id = :s"),
            {"s": asset_id},
        ).mappings().one()
    assert row["actor"] == "engagement-manager"
    assert row["event_type"] == "metadata.registered"
    assert row["payload"]["authority"] == "AUTHORITATIVE"


def test_registry_writes_require_an_actor(engagement_id):
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(ValueError):
            register_metadata(
                conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
                identity_type="fqdn", identity_value="x.customer-a.com",
                authority="AUTHORITATIVE", source="customer_declared", actor="",
            )
