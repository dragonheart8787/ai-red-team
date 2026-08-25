"""Hierarchical classification inheritance — downward restriction only (D25).

A separate module, and that is D3's third binding constraint rather than a
filing preference. The exact-precedence rule — "an AUTHORITATIVE row decides,
every other tier is an observation" — is short enough to verify by reading, and
its tests in ``tests/test_resolvers.py`` are left untouched by this deliverable.
Mixing inheritance cases into them would make both harder to check, and would
lose the regression guarantee that matters most here: that adding inheritance
perturbed exact resolution not at all.

What this module pins, per ADR_CLASSIFICATION_INHERITANCE.md:

* the containment geometry, per identity type (§2), including the types that
  deliberately inherit nothing;
* that inheritance only ever *restricts* — it reaches ``observations`` and
  never the canonical fields, and never sets ``known`` (§3);
* that the stricter-wins conflict case resolves through §5's existing
  ``forbidden_data_observed`` deny path rather than new policy (§3);
* that the containment arithmetic really is shared with the Authorization
  Resolver rather than reimplemented (§6) — the D14-style check that a shared
  predicate is actually shared;
* that extracting it left ``scope_covers_target`` behaving identically (§6),
  proven against the pre-refactor implementation rather than asserted.
"""

from __future__ import annotations

import itertools
import uuid

import pytest

from control_plane.canonicalizer.metadata import (
    INHERITED,
    INHERITED_SOURCE_PREFIX,
    UNKNOWN,
    resolve_metadata,
)
from control_plane.canonicalizer.target import normalize_target
from control_plane.state.db import engagement_scope


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _resolve(engagement_id, itype: str, ivalue: str):
    with engagement_scope(engagement_id) as conn:
        return resolve_metadata(
            conn,
            target=normalize_target(
                {"logical_identity": {"type": itype, "value": ivalue}}
            ),
        )


def _inherited(resolution):
    return [o for o in resolution.observations if o.authority == INHERITED]


# ---------------------------------------------------------------------------
# §2 — what "parent" means, per identity type
# ---------------------------------------------------------------------------

def test_an_ip_inherits_from_its_enclosing_cidr(engagement_id, registry):
    """The gap D25 exists to close (ADR §1).

    A range is declared PII; a host inside it has no row of its own. Before
    inheritance the host read as UNKNOWN, as though the declaration on its
    enclosing range had never been made.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    resolution = _resolve(engagement_id, "ip", "10.79.0.42")

    inherited = _inherited(resolution)
    assert len(inherited) == 1
    assert inherited[0].data_class == ("PII",)
    # The observation names the exact row it came from, so an investigator
    # reading it can find the declaration rather than guessing at one.
    assert inherited[0].source == f"{INHERITED_SOURCE_PREFIX}cidr:10.79.0.0/24"


def test_a_subnet_inherits_from_its_supernet(engagement_id, registry):
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/16", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    resolution = _resolve(engagement_id, "cidr", "10.79.5.0/24")

    assert [o.data_class for o in _inherited(resolution)] == [("PII",)]


def test_a_neighbouring_range_is_not_an_ancestor(engagement_id, registry):
    """Containment, not proximity. Sibling ranges inherit nothing."""
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    resolution = _resolve(engagement_id, "ip", "10.80.0.42")

    assert _inherited(resolution) == []
    assert resolution.authority == UNKNOWN


def test_a_subdomain_inherits_from_its_parent_domain(engagement_id, registry):
    registry.metadata(asset_id=_uid("ASSET"), identity_type="fqdn",
                      identity_value="pii.customer-a.com",
                      authority="AUTHORITATIVE", source="customer_declared",
                      data_class=["PII"])

    resolution = _resolve(engagement_id, "fqdn", "api.pii.customer-a.com")

    assert [o.data_class for o in _inherited(resolution)] == [("PII",)]


def test_a_suffix_that_is_not_a_label_boundary_is_not_a_parent(
    engagement_id, registry
):
    """``customer-a.com`` is not under ``a.com`` (ADR §2.1).

    The string does end with ``a.com``, but the boundary falls inside the
    ``customer-a`` label. Substring suffix matching is how a classification
    comes to reach a domain nobody registered — the same failure mode §4.1.5
    refuses on the authorization side.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="fqdn",
                      identity_value="a.com", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    resolution = _resolve(engagement_id, "fqdn", "customer-a.com")

    assert _inherited(resolution) == []


def test_a_name_never_inherits_from_a_network_or_the_reverse(
    engagement_id, registry
):
    """Crossing name and address would mean resolving one to the other.

    §8.9/I8 forbids that as an authorization input, and D25 forbids it as a
    classification input for the same reason: a name and an address are
    different identities even when they point at the same host.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])
    registry.metadata(asset_id=_uid("ASSET"), identity_type="fqdn",
                      identity_value="customer-a.com", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    assert _inherited(_resolve(engagement_id, "fqdn", "host.customer-b.com")) == []
    assert _inherited(_resolve(engagement_id, "ip", "10.90.0.1")) == []


@pytest.mark.parametrize(
    "itype,parent,child",
    [
        ("url", "https://host.example.com/admin",
         "https://host.example.com/admin/users"),
        ("repo", "github.com/org", "github.com/org/repo"),
        ("ad_domain", "corp.example.com", "child.corp.example.com"),
    ],
)
def test_url_repo_and_ad_domain_inherit_nothing(
    engagement_id, registry, itype, parent, child
):
    """ADR §2.2: no containment arithmetic is defined for these, so none is used.

    Each has structure a human reads as hierarchy, and for each the "obvious"
    reading is a policy choice rather than arithmetic. Defining one by accident,
    because the code path happened to be open, is exactly what the exact-lookup
    rule exists to refuse.

    Mutation testing found these types are guarded twice, independently, which
    is worth recording because it changes how this test should be read. Adding
    them to ``ANCESTOR_TYPES`` alone leaves the suite green — not a gap, but an
    equivalent mutant: ``identity_contains`` still has no containment
    arithmetic for them, so it answers False and nothing is inherited. Breaching
    *both* guards — listing the types **and** giving the primitive, say, a URL
    path-prefix rule — turns this test red. So it does catch an accidental
    implementation; what it cannot catch is a half-implementation, because a
    half-implementation does nothing.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type=itype,
                      identity_value=parent, authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    resolution = _resolve(engagement_id, itype, child)

    assert _inherited(resolution) == []
    assert resolution.authority == UNKNOWN
    assert resolution.known is False


# ---------------------------------------------------------------------------
# §3 — inheritance restricts, and only restricts
# ---------------------------------------------------------------------------

def test_inheritance_never_makes_a_resource_known(engagement_id, registry):
    """D3 constraint 2, and the whole downward-relaxation prohibition.

    An inherited classification must be incapable of satisfying a privilege
    prerequisite. §5 reads ``known`` for that, and only a row against the
    resource's own identity may set it.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"],
                      resource_class=["database"])

    resolution = _resolve(engagement_id, "ip", "10.79.0.42")

    assert resolution.known is False
    assert resolution.authority == UNKNOWN
    assert resolution.resource_class == ()
    assert resolution.data_class == ()
    assert resolution.asset_id is None
    # The restriction still arrived — it is simply not canonical.
    assert _inherited(resolution)[0].data_class == ("PII",)


def test_an_unclassified_parent_says_nothing_about_its_children(
    engagement_id, registry
):
    """The other half of the asymmetry: absence of a mark is not a clean bill.

    A range nobody classified does not make its hosts clean, so a child with no
    row of its own stays UNKNOWN rather than inheriting an implied "fine".
    """
    # A parent range exists in the registry, but only at a lower tier.
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="OBSERVED",
                      source="nmap_banner", data_class=["network_service"])

    resolution = _resolve(engagement_id, "ip", "10.79.0.42")

    assert _inherited(resolution) == []
    assert resolution.known is False


def test_a_lower_tier_ancestor_never_produces_inheritance(engagement_id, registry):
    """D3 constraint 1 — I6b closed from the inheritance side.

    If an OBSERVED or LLM_HINT parent could produce an inherited classification,
    inheritance would be a second route by which a low tier reaches a child's
    classification. Only AUTHORITATIVE ancestors descend.
    """
    for authority, source in (("OBSERVED", "nmap_banner"),
                              ("INFERRED", "model_guess"),
                              ("LLM_HINT", "reviewer_hint")):
        registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                          identity_value="10.79.0.0/24", authority=authority,
                          source=source, data_class=["PII"])

    resolution = _resolve(engagement_id, "ip", "10.79.0.42")

    assert _inherited(resolution) == []


def test_a_resource_does_not_inherit_from_its_own_row(engagement_id, registry):
    """A row is not its own ancestor.

    ``identity_contains`` is reflexive — a set does contain itself — so the
    equal case is excluded by the classification path rather than by the
    geometry. Without that, a resource's own canonical classification would be
    duplicated into its observations, where ``non_authoritative_sensitivity``
    would read a disagreement between a row and itself.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    resolution = _resolve(engagement_id, "cidr", "10.79.0.0/24")

    assert resolution.known is True
    assert resolution.data_class == ("PII",)
    assert _inherited(resolution) == []


def test_a_child_keeps_its_own_canonical_class_while_the_parent_tightens(
    engagement_id, registry
):
    """The conflict case the brief flagged (ADR §3), and why it is not CONFLICT.

    The child's own AUTHORITATIVE row says one thing; an AUTHORITATIVE ancestor
    says another. These two rows describe *different identities* and do not
    disagree, so CONFLICT stays reserved for two authoritative rows about the
    same identity (I10). The child keeps its own canonical classification and
    the ancestor's rides along as an observation — where, on a deny-listed
    class, it denies.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])
    registry.metadata(asset_id=_uid("ASSET"), identity_type="ip",
                      identity_value="10.79.0.42", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=[],
                      resource_class=["web_endpoint"])

    resolution = _resolve(engagement_id, "ip", "10.79.0.42")

    # Canonical is the child's own row, untouched by the ancestor.
    assert resolution.known is True
    assert resolution.authority == "AUTHORITATIVE"
    assert resolution.data_class == ()
    assert resolution.resource_class == ("web_endpoint",)
    # And the stricter ancestor is present, as an observation.
    assert [o.data_class for o in _inherited(resolution)] == [("PII",)]


def test_the_closest_and_the_broadest_ancestor_both_contribute(
    engagement_id, registry
):
    """Nesting: every AUTHORITATIVE ancestor tightens, not just the nearest.

    Picking one would be a precedence rule, and a precedence rule among
    observations is a way for a laxer ancestor to suppress a stricter one.
    Tightening-only means the union, so there is nothing to choose between.
    """
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/16", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])
    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.5.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["card_data"])

    resolution = _resolve(engagement_id, "ip", "10.79.5.9")

    classes = {c for o in _inherited(resolution) for c in o.data_class}
    assert classes == {"PII", "card_data"}


def test_an_inherited_class_reaches_opas_deny_path(engagement_id, registry):
    """§3's stricter-wins, end to end, through the policy that already existed.

    ``forbidden_data_observed`` denies on a deny-listed class from any tier, so
    an inherited PII classification denies without one line of new Rego — and it
    denies even though the child's own canonical row says the resource holds no
    sensitive data, because observations and canonical are unioned on the deny
    side and neither can suppress the other.
    """
    from control_plane.policy.engine import evaluate
    from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy

    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])
    registry.metadata(asset_id=_uid("ASSET"), identity_type="ip",
                      identity_value="10.79.0.42", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=[],
                      resource_class=["web_endpoint"])
    scope_id = _uid("SCOPE")
    registry.scope(scope_object_id=scope_id, type="cidr", value="10.79.0.0/24",
                   allowed_actions=["network.scan"])

    policy = merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"}),
                    actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
    target = normalize_target(
        {"logical_identity": {"type": "ip", "value": "10.79.0.42"}}
    )
    with engagement_scope(engagement_id) as conn:
        resolution = resolve_metadata(conn, target=target)

    decision = evaluate({
        "canonical": {"target": target.as_dict(), "risk": "low"},
        "action": {
            "action": "network.scan",
            "authorization": {"source": "engagement_scope",
                              "scope_object_id": scope_id},
            "discovery": {"introduced_by_untrusted": False},
            "possible_sensitive_data_hint": [],
            "writes_data": False, "changes_state": False,
        },
        "policy": {**policy.as_dict(), "scope_objects": [
            {"id": scope_id, "type": "cidr", "value": "10.79.0.0/24",
             "allowed_actions": ["network.scan"]},
        ]},
        "authorization_resolution": {"scope_object_id": scope_id,
                                     "authorized": True},
        "resource_metadata": resolution.as_dict(),
        "capability_request": {"max_targets": 1},
        "usage": {"requests_in_window": 0},
    })

    assert decision.decision == "DENY"
    assert "forbidden_data_observed" in decision.deny_reasons
    # Not a conflict: the two authoritative rows describe different identities.
    assert "classification_conflict" not in decision.deny_reasons


# ---------------------------------------------------------------------------
# §6 — the containment primitive really is shared, and sharing changed nothing
# ---------------------------------------------------------------------------

def test_the_metadata_path_uses_the_shared_containment_predicate(
    engagement_id, registry, monkeypatch
):
    """D14-style: verify the shared predicate is actually shared.

    Patching ``identity_contains`` where the Metadata Resolver looks it up must
    change what the Metadata Resolver concludes. If inheritance had its own copy
    of the arithmetic — the option ADR §6 rejected, and the one D15's mutation
    testing punished — this test would pass unaffected, which is exactly the
    drift it exists to make impossible.
    """
    import control_plane.canonicalizer.metadata as metadata_mod

    registry.metadata(asset_id=_uid("ASSET"), identity_type="cidr",
                      identity_value="10.79.0.0/24", authority="AUTHORITATIVE",
                      source="customer_declared", data_class=["PII"])

    assert _inherited(_resolve(engagement_id, "ip", "10.79.0.42"))

    seen: list[tuple[str, str, str, str]] = []

    def spy(parent_type, parent_value, child_type, child_value):
        seen.append((parent_type, parent_value, child_type, child_value))
        return False

    monkeypatch.setattr(metadata_mod, "identity_contains", spy)

    assert _inherited(_resolve(engagement_id, "ip", "10.79.0.42")) == []
    assert ("cidr", "10.79.0.0/24", "ip", "10.79.0.42") in seen


def test_the_authorization_path_uses_the_shared_containment_predicate(
    monkeypatch
):
    """The same check from the other side, so neither caller can quietly fork."""
    import control_plane.canonicalizer.authorization as authz_mod
    from control_plane.registry.scope_registry import ScopeObject

    scope = ScopeObject(
        scope_object_id="SCOPE-1", engagement_id="ENG-1", type="cidr",
        value="10.79.0.0/24", allowed_actions=("network.scan",), version=1,
        active=True,
    )
    target = normalize_target(
        {"logical_identity": {"type": "ip", "value": "10.79.0.42"}}
    )
    assert authz_mod.scope_covers_target(scope, target) is True

    monkeypatch.setattr(authz_mod, "identity_contains", lambda *a: False)
    assert authz_mod.scope_covers_target(scope, target) is False


# The pre-D25 implementation, copied verbatim from ``authorization.py`` as it
# stood at d0369d6. It is the oracle for the refactor: "the existing tests still
# pass" shows the cases someone thought to write down, and the brief asked for
# more than that.
def _legacy_scope_covers_target(scope, target) -> bool:
    import ipaddress

    from control_plane.canonicalizer.target import scope_value_is_canonical

    identity = target.logical_identity
    if not scope_value_is_canonical(scope.type, scope.value):
        return False

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


# Values chosen to hit every branch of both implementations and the seams
# between them: wildcard and bare fqdn, the non-label-boundary suffix, v4 and
# v6, a network and a host inside it, cross-family comparison (which makes
# ``subnet_of`` raise TypeError), values that will not parse at all, and the
# empty string.
_GRID_VALUES = [
    "customer-a.com", "a.com", "app.customer-a.com", "*.customer-a.com",
    "*.a.com", "10.79.0.0/24", "10.79.0.0/16", "10.79.0.42", "10.80.0.42",
    "10.79.0.0/25", "192.168.0.0/16", "2001:db8::/32", "2001:db8::1",
    "::1", "https://host.example.com/admin", "github.com/org",
    "corp.example.com", "not a value", "10.79.0.2/24", "", "*.", "*.com",
]
_GRID_TYPES = ["fqdn", "ip", "cidr", "url", "repo", "ad_domain"]


def test_containment_refactor_is_behaviour_preserving():
    """The extraction changed no answer, proven rather than inspected.

    ADR §6 required the refactor of ``scope_covers_target`` to be
    behaviour-preserving. This runs the pre-refactor implementation beside the
    current one over every combination of scope type/value and target
    type/value in the grid above — several thousand cases, including malformed
    and adversarial values — and requires them to agree on every single one.

    A differential test rather than a re-run of the old suite, because the old
    suite proves the refactor kept the behaviours somebody wrote a test for.
    D15's lesson is that the dangerous branch is the one nobody reached: the
    fail-open cidr branch survived a green suite precisely because no test
    created an unparseable scope object.
    """
    from control_plane.canonicalizer.authorization import scope_covers_target
    from control_plane.canonicalizer.target import CanonicalizationError
    from control_plane.registry.scope_registry import ScopeObject

    checked = 0
    disagreements = []
    for (stype, svalue), (itype, ivalue) in itertools.product(
        itertools.product(_GRID_TYPES, _GRID_VALUES),
        itertools.product(_GRID_TYPES, _GRID_VALUES),
    ):
        try:
            target = normalize_target(
                {"logical_identity": {"type": itype, "value": ivalue}}
            )
        except CanonicalizationError:
            # Not a target the pipeline can produce; both implementations agree
            # by never being called on it.
            continue

        scope = ScopeObject(
            scope_object_id="SCOPE-GRID", engagement_id="ENG-GRID", type=stype,
            value=svalue, allowed_actions=("network.scan",), version=1,
            active=True,
        )
        new = scope_covers_target(scope, target)
        old = _legacy_scope_covers_target(scope, target)
        checked += 1
        if new != old:
            disagreements.append((stype, svalue, itype, ivalue, old, new))

    assert not disagreements, (
        f"{len(disagreements)} of {checked} cases changed behaviour: "
        f"{disagreements[:10]}"
    )
    # Guard against the grid silently collapsing to nothing, which would make
    # the assertion above vacuously true — the failure mode D9 found when
    # `deactivate_scope` fired 95 times and revoked nothing every time.
    assert checked > 1000, f"only {checked} combinations exercised"
