"""Authorization Resolver (§5) — "is there a scope object authorizing this?"

Kept separate from the Metadata Resolver on purpose. Merging "is this
authorized" with "what is this resource" is the v0.2 bug that v0.3 fixed, and
the two questions have different trust models: authorization comes only from
typed scope objects registered by the Engagement Manager, while metadata
arrives at four different tiers of credibility.

The resolver answers three things, all against the Scope Registry:

1. Does ``authorization.scope_object_id`` name a live scope object?
2. Does that scope object *cover* the canonical target, given its type?
3. Does its ``allowed_actions`` cover the requested action?

The proposal's ``discovery`` block is never read here. That is I8 in one line:
discovery explains how a candidate was found and may at most trigger
escalation; it can never produce authorization. A test asserts this by feeding
in the most trustworthy-looking discovery block available and confirming it
changes nothing.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Connection

from control_plane.canonicalizer.target import CanonicalTarget
from control_plane.registry.scope_registry import ScopeObject, get_scope_object

# §4.1: authorization.source must name a typed scope object. Any other value —
# "dns", "tool_observed", "web_content" — is a discovery source wearing the
# wrong hat, and is refused rather than interpreted.
VALID_AUTHORIZATION_SOURCES = frozenset({"engagement_scope"})

DENY_SCOPE_OBJECT_MISSING = "authorization_scope_object_not_found"
DENY_SOURCE_NOT_SCOPE = "authorization_source_is_not_a_scope_object"
DENY_TARGET_NOT_COVERED = "target_not_covered_by_scope_object"
DENY_ACTION_NOT_ALLOWED = "action_not_in_scope_object_allowed_actions"


@dataclass(frozen=True)
class AuthorizationResolution:
    """What the Scope Registry says. OPA re-derives this; it does not trust it.

    ``authorized`` exists for the control plane's own fail-fast checks and for
    the audit record. §5's Rego still receives the scope objects themselves and
    reaches its own conclusion, so a bug here cannot silently authorize
    anything on its own.
    """

    authorized: bool
    scope_object_id: str | None = None
    scope_object: ScopeObject | None = None
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "scope_object_id": self.scope_object_id,
            "scope_object": self.scope_object.as_dict() if self.scope_object else None,
            "reasons": list(self.reasons),
        }


def action_matches(action: str, allowed_actions: tuple[str, ...] | list[str]) -> bool:
    """Match an action against a scope object's ``allowed_actions``.

    §4.1.5 writes patterns like ``web.*`` and ``network.scan``, so exact string
    membership is not enough. A ``*`` matches one namespace level and below:
    ``web.*`` covers ``web.get`` and ``web.post.form``, and a bare ``*`` covers
    everything. Nothing else is treated as a wildcard — no globbing, no
    regular expressions, no prefix matching on partial words, since a scope
    pattern that matches more than it visibly says is a way to widen
    authorization by accident.
    """
    for pattern in allowed_actions:
        if pattern == action or pattern == "*":
            return True
        if pattern.endswith(".*") and action.startswith(pattern[:-1]):
            return True
    return False


def scope_covers_target(scope: ScopeObject, target: CanonicalTarget) -> bool:
    """Type-aware containment.

    The asymmetries here are the whole point of typed scope objects (§4.1.5):
    an ``fqdn`` scope never covers an IP target, and a ``cidr`` scope never
    covers an fqdn target. Resolving ``app.customer-a.com`` to ``203.0.113.17``
    tells you where to send packets; authorizing ``network.scan`` against that
    address needs its own cidr scope object.
    """
    identity = target.logical_identity
    if scope.type == "fqdn":
        if identity.type != "fqdn":
            return False
        if scope.value.startswith("*."):
            suffix = scope.value[1:]  # ".example.com"
            return identity.value.endswith(suffix) and identity.value != suffix[1:]
        return identity.value == scope.value

    if scope.type == "ip":
        return identity.type == "ip" and identity.value == scope.value

    if scope.type == "cidr":
        if identity.type not in ("ip", "cidr"):
            return False
        try:
            network = ipaddress.ip_network(scope.value, strict=False)
            if identity.type == "ip":
                return ipaddress.ip_address(identity.value) in network
            return ipaddress.ip_network(identity.value, strict=False).subnet_of(network)
        except (ValueError, TypeError):
            return False

    if scope.type in ("url", "repo", "ad_domain"):
        return identity.type == scope.type and identity.value == scope.value

    return False


def resolve_authorization(
    conn: Connection,
    *,
    target: CanonicalTarget,
    action: str,
    authorization: Mapping[str, Any],
) -> AuthorizationResolution:
    """Resolve a proposal's ``authorization`` block against the Scope Registry.

    Note the signature: there is no ``discovery`` parameter. The information
    simply is not available to this function, which is a stronger guarantee
    than remembering not to read it.
    """
    source = authorization.get("source")
    scope_object_id = authorization.get("scope_object_id")

    reasons: list[str] = []
    if source not in VALID_AUTHORIZATION_SOURCES:
        reasons.append(DENY_SOURCE_NOT_SCOPE)
    if not scope_object_id:
        reasons.append(DENY_SCOPE_OBJECT_MISSING)
    if reasons:
        return AuthorizationResolution(False, scope_object_id, None, tuple(reasons))

    scope = get_scope_object(conn, scope_object_id)
    if scope is None:
        # RLS also lands here when the scope object belongs to another
        # engagement: from inside this engagement it does not exist.
        return AuthorizationResolution(
            False, scope_object_id, None, (DENY_SCOPE_OBJECT_MISSING,)
        )

    if not scope_covers_target(scope, target):
        reasons.append(DENY_TARGET_NOT_COVERED)
    if not action_matches(action, scope.allowed_actions):
        reasons.append(DENY_ACTION_NOT_ALLOWED)

    return AuthorizationResolution(
        authorized=not reasons,
        scope_object_id=scope_object_id,
        scope_object=scope,
        reasons=tuple(reasons),
    )
