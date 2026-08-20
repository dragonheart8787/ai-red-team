"""The constraint algebra of §4.5, over generated layer combinations.

``merge_policy`` is a pure function, so the properties that matter about it are
algebraic rather than temporal — which is why this is a plain Hypothesis
property test and not another rule on the stateful machine. Nothing here
depends on the order operations happened in; putting it in the state machine
would make it slower to run and no more convincing.

What the existing tests cover is each identity once, with hand-picked values:
``test_merge.py`` proves ``UNIVERSE ∩ A = A`` for one A. What they cannot cover
is the combination — four layers, five dimensions, each layer independently
silent or not. The neutral elements exist precisely so that a silent layer
disappears from the result, and "disappears" is a claim about every
combination, including the ones nobody thought to write down.

The generators deliberately produce layers that set nothing. A layer that
always says something would never exercise the neutral element at all, which is
the bug §4.5 calls out by name: folding an unset ``scope_allow`` in as ``[]``
denies everything the moment one layer stays silent.
"""

from __future__ import annotations

import math

from hypothesis import given, settings
from hypothesis import strategies as st

from control_plane.policy.merge import (
    ALLOW,
    DENY,
    INHERIT,
    LAYER_ORDER,
    UNIVERSE,
    PolicyLayer,
    Sentinel,
    merge_policy,
)

# Small alphabets on purpose: overlap between layers is where intersection and
# union are interesting, and wide random strings almost never overlap.
SCOPES = st.sampled_from(["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12",
                          "app.example.com", "*.example.com"])
DATA = st.sampled_from(["PII", "PHI", "customer_database", "credentials",
                        "public"])
ACTIONS = st.sampled_from(["network.scan", "network.recon", "data.read",
                           "data.write", "exploit.run"])

DECISIONS = st.sampled_from([ALLOW, DENY, INHERIT])


@st.composite
def layers(draw, name: str) -> PolicyLayer:
    """One layer, each dimension independently present or absent.

    The ``st.just(UNIVERSE)`` and ``math.inf`` branches, and the empty sets and
    dicts the collection strategies produce, are what generate a silent
    dimension. That is the case the neutral elements exist for, and a generator
    that always said something would never reach it.
    """
    scope_allow = draw(st.one_of(
        st.just(UNIVERSE),
        st.frozensets(SCOPES, min_size=0, max_size=3),
    ))
    return PolicyLayer(
        name=name,
        scope_allow=scope_allow,
        scope_deny=draw(st.frozensets(SCOPES, max_size=3)),
        data_deny=draw(st.frozensets(DATA, max_size=3)),
        rate_limit=draw(st.one_of(
            st.just(math.inf),
            st.floats(min_value=0, max_value=1000, allow_nan=False,
                      allow_infinity=False),
        )),
        actions=draw(st.dictionaries(ACTIONS, DECISIONS, max_size=4)),
    )


@st.composite
def four_layers(draw) -> tuple[PolicyLayer, ...]:
    return tuple(draw(layers(name)) for name in LAYER_ORDER)


PROPERTY = settings(max_examples=400, deadline=None)


# ---------------------------------------------------------------------------
# The four neutral elements (§4.5)
# ---------------------------------------------------------------------------

@PROPERTY
@given(four_layers())
def test_silencing_a_layer_can_only_widen_the_result(quad):
    """The neutral-element law with teeth, stated as an ordering.

    The first version of this test asserted that merging the same four layers
    twice gave the same answer, which is determinism wearing a neutral-element
    costume — it would have passed against any implementation at all.

    The substantive claim is directional: replacing a layer with a silent one
    removes constraints, so the result can only widen or stay put. If a silent
    layer ever *tightened* something, its "neutral" element would not be
    neutral.

    Holds for the four set-and-scalar dimensions. Actions are excluded, and
    finding out why was the point of writing this: see
    ``test_silencing_a_layer_can_tighten_an_action_because_allow_is_an_opinion``.
    """
    merged = merge_policy(*quad)

    for index in range(4):
        replaced = list(quad)
        replaced[index] = PolicyLayer(name=LAYER_ORDER[index])
        widened = merge_policy(*replaced)

        assert widened.data_deny <= merged.data_deny
        assert widened.scope_deny <= merged.scope_deny
        assert widened.rate_limit >= merged.rate_limit

        if isinstance(widened.scope_allow, Sentinel):
            pass  # UNIVERSE is as wide as it gets
        else:
            assert isinstance(merged.scope_allow, Sentinel) or (
                merged.scope_allow <= widened.scope_allow
            )

        # Actions are deliberately excluded; see the test below for why they
        # do not obey this ordering.


@PROPERTY
@given(four_layers())
def test_an_actions_change_is_always_attributable_to_the_silenced_layer(quad):
    """The neutral-element law for actions, which is attribution not ordering.

    Two wrong versions preceded this one, and both were the test being wrong
    rather than the code. "Silencing only widens" fails because silencing the
    only layer that said ALLOW drops the permission and ``resolve_action``
    falls back to DENY. "Only ALLOW -> DENY is safe" fails too, because a layer
    carries denials as well as permissions, so silencing the layer that said
    DENY lets another layer's ALLOW through.

    Neither is a defect. A layer states permissions and prohibitions in the same
    field, so removing it can move a decision either way, and the direction is
    not the invariant. The invariant is that it moves *only* when the silenced
    layer had an opinion: if it said nothing about an action, silencing it
    changes nothing about that action. That is what "INHERIT is the neutral
    element" actually means.

    Safety is carried by DENY-dominance among the layers that are present, and
    by the overlay-tightening properties below — both tested separately.
    """
    merged = merge_policy(*quad)

    for index in range(4):
        replaced = list(quad)
        replaced[index] = PolicyLayer(name=LAYER_ORDER[index])
        widened = merge_policy(*replaced)

        for action in {k for layer in quad for k in layer.actions}:
            if merged.action_decision(action) == widened.action_decision(action):
                continue
            stated = quad[index].actions.get(action, INHERIT)
            assert stated in (ALLOW, DENY), (
                f"silencing {LAYER_ORDER[index]} moved {action} from "
                f"{merged.action_decision(action)} to "
                f"{widened.action_decision(action)}, but that layer had said "
                f"{stated!r} about it"
            )


@PROPERTY
@given(four_layers())
def test_an_already_silent_layer_is_indistinguishable_from_a_fresh_one(quad):
    """The identity itself: a layer that sets nothing contributes nothing."""
    baseline, overlay, customer, engagement = quad
    explicit = merge_policy(
        baseline, overlay, customer,
        PolicyLayer(name="engagement", scope_allow=UNIVERSE,
                    scope_deny=frozenset(), data_deny=frozenset(),
                    rate_limit=math.inf, actions={}),
    )
    defaulted = merge_policy(baseline, overlay, customer,
                             PolicyLayer(name="engagement"))
    assert explicit == defaulted


@PROPERTY
@given(four_layers())
def test_universe_is_the_identity_for_scope_allow(quad):
    """``UNIVERSE ∩ A = A``, and all-UNIVERSE stays UNIVERSE.

    The second half is the §4.5 bug: with every layer silent the result must be
    unconstrained, never the empty set.
    """
    merged = merge_policy(*quad)
    explicit = [layer.scope_allow for layer in quad
                if not isinstance(layer.scope_allow, Sentinel)]

    if not explicit:
        assert merged.scope_allow is UNIVERSE
    else:
        expected = frozenset.intersection(*explicit)
        assert merged.scope_allow == expected
        # Intersection only ever narrows.
        for value in explicit:
            assert merged.scope_allow <= value


@PROPERTY
@given(four_layers())
def test_empty_is_the_identity_for_the_deny_sets(quad):
    """``∅ ∪ A = A``, and union only ever grows."""
    merged = merge_policy(*quad)

    assert merged.scope_deny == frozenset().union(
        *(layer.scope_deny for layer in quad)
    )
    assert merged.data_deny == frozenset().union(
        *(layer.data_deny for layer in quad)
    )
    for layer in quad:
        assert layer.scope_deny <= merged.scope_deny
        assert layer.data_deny <= merged.data_deny


@PROPERTY
@given(four_layers())
def test_infinity_is_the_identity_for_rate_limit(quad):
    """``min`` with ∞ present, and never a raise on a single opinion."""
    merged = merge_policy(*quad)
    limits = [layer.rate_limit for layer in quad]

    assert merged.rate_limit == min(limits)
    if all(math.isinf(limit) for limit in limits):
        assert math.isinf(merged.rate_limit)
    for limit in limits:
        assert merged.rate_limit <= limit


@PROPERTY
@given(four_layers())
def test_action_precedence_is_deny_dominant_and_fails_closed(quad):
    """INHERIT is the identity; DENY beats ALLOW; silence denies (I10)."""
    merged = merge_policy(*quad)

    mentioned = {key for layer in quad for key in layer.actions}
    for action in mentioned:
        stated = [layer.actions[action] for layer in quad
                  if action in layer.actions and layer.actions[action] != INHERIT]
        decision = merged.action_decision(action)

        if DENY in stated:
            assert decision == DENY, "an explicit DENY was outvoted"
        elif ALLOW in stated:
            assert decision == ALLOW
        else:
            # Every layer INHERIT, or none mentioned it outside INHERIT.
            assert decision == DENY, "all-INHERIT must fail closed"

    # An action nobody named at all is denied, whatever the layers said.
    assert merged.action_decision("never.mentioned.by.anyone") == DENY


# ---------------------------------------------------------------------------
# The emergency overlay can only tighten (§4.5, I2)
# ---------------------------------------------------------------------------

@PROPERTY
@given(four_layers())
def test_the_result_is_never_wider_than_the_emergency_overlay_alone(quad):
    """I2 as an ordering, over every combination.

    The overlay's own constraints survive the merge whatever the other three
    layers say. A merge that could relax an overlay entry would be a way to
    escape an emergency tightening by publishing something permissive beside
    it — the property that makes the overlay worth having at all.
    """
    baseline, overlay, customer, engagement = quad
    merged = merge_policy(*quad)

    # Deny lists: everything the overlay denied is still denied.
    assert overlay.scope_deny <= merged.scope_deny
    assert overlay.data_deny <= merged.data_deny

    # Allow list: the merged allow list is never broader than the overlay's.
    if not isinstance(overlay.scope_allow, Sentinel):
        assert not isinstance(merged.scope_allow, Sentinel)
        assert merged.scope_allow <= overlay.scope_allow

    # Rate limit: never raised above what the overlay set.
    assert merged.rate_limit <= overlay.rate_limit

    # Actions: an overlay DENY is final.
    for action, decision in overlay.actions.items():
        if decision == DENY:
            assert merged.action_decision(action) == DENY


@PROPERTY
@given(four_layers(), layers("emergency_overlay"))
def test_adding_a_tightening_overlay_never_widens_the_result(quad, extra):
    """I2 as monotonicity: tightening the overlay cannot loosen the outcome.

    Compares merging with the original overlay against merging with an overlay
    that has been tightened — its deny sets unioned with the extra layer's, its
    rate limit lowered. Every dimension of the result must move the same way or
    stay put.
    """
    baseline, overlay, customer, engagement = quad
    tightened = PolicyLayer(
        name="emergency_overlay",
        scope_allow=overlay.scope_allow,
        scope_deny=overlay.scope_deny | extra.scope_deny,
        data_deny=overlay.data_deny | extra.data_deny,
        rate_limit=min(overlay.rate_limit, extra.rate_limit),
        actions={
            **overlay.actions,
            **{a: DENY for a, d in extra.actions.items() if d == DENY},
        },
    )

    before = merge_policy(baseline, overlay, customer, engagement)
    after = merge_policy(baseline, tightened, customer, engagement)

    assert after.data_deny >= before.data_deny
    assert after.scope_deny >= before.scope_deny
    assert after.rate_limit <= before.rate_limit
    for action, decision in before.actions.items():
        if decision == DENY:
            assert after.action_decision(action) == DENY, (
                f"{action} was DENY and became {after.action_decision(action)}"
            )


# ---------------------------------------------------------------------------
# Structural properties
# ---------------------------------------------------------------------------

@PROPERTY
@given(four_layers())
def test_merging_is_deterministic(quad):
    """Same inputs, same output. Cheap, and it catches accidental set ordering."""
    assert merge_policy(*quad) == merge_policy(*quad)


@PROPERTY
@given(four_layers())
def test_the_merged_policy_serializes_without_losing_the_distinction(quad):
    """UNIVERSE and an empty allow list must not both become ``[]``.

    They mean opposite things — unconstrained versus nothing permitted — and
    the serialized form is what Rego reads, so collapsing them here would be a
    fail-open in the one place §4.5 warns about.
    """
    merged = merge_policy(*quad)
    document = merged.as_dict()

    if merged.scope_allow is UNIVERSE:
        assert document["scope_allow"] == str(UNIVERSE)
    else:
        assert document["scope_allow"] == sorted(merged.scope_allow)
        assert document["scope_allow"] != str(UNIVERSE)

    # JSON has no infinity; null is how "no limit" survives the trip.
    if math.isinf(merged.rate_limit):
        assert document["rate_limit"] is None
    else:
        assert document["rate_limit"] == merged.rate_limit
