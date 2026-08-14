"""Constraint algebra tests (§4.5, I2).

§4.5 asks for at least three cases per constraint -- nothing set, one layer
set, several layers in conflict -- because each neutral element fails in its
own direction and the failures look plausible in isolation. An allow list that
collapses to empty and an action map that reads silence as DENY are both
"obviously correct" until you notice one denies the whole engagement and the
other denies things nobody ever forbade.
"""

from __future__ import annotations

import math

import pytest

from control_plane.policy.merge import (
    ALLOW,
    DENY,
    INHERIT,
    UNIVERSE,
    EmergencyOverlayError,
    PolicyLayer,
    merge_policy,
    resolve_action,
    validate_emergency_overlay,
)


def layers(**overrides) -> tuple[PolicyLayer, ...]:
    """Four neutral layers, with named ones replaced."""
    return tuple(
        overrides.get(name, PolicyLayer(name=name))
        for name in ("baseline_global", "emergency_overlay", "customer", "engagement")
    )


# ---------------------------------------------------------------------------
# Nothing set anywhere
# ---------------------------------------------------------------------------

def test_all_layers_unset_yields_neutral_elements():
    merged = merge_policy(*layers())
    assert merged.scope_allow is UNIVERSE, "unset allow list must be UNIVERSE, not empty"
    assert merged.scope_deny == frozenset()
    assert merged.data_deny == frozenset()
    assert math.isinf(merged.rate_limit)
    assert merged.actions == {}


def test_all_unset_serializes_without_inventing_limits():
    doc = merge_policy(*layers()).as_dict()
    assert doc["scope_allow"] == "UNIVERSE"
    assert doc["rate_limit"] is None, "no limit must not serialize as a limit of zero"
    assert doc["scope_deny"] == []
    assert doc["data_deny"] == []


def test_action_nobody_mentioned_is_denied():
    """All-INHERIT resolves to DENY: silence is not permission (I10)."""
    assert merge_policy(*layers()).action_decision("network.scan") == DENY


# ---------------------------------------------------------------------------
# One layer set
# ---------------------------------------------------------------------------

def test_single_layer_allow_list_survives_the_other_three():
    """UNIVERSE ∩ A = A.

    This is the §4.5 bug stated as a test. Folding the three unset layers in as
    empty sets would intersect to nothing and deny the engagement outright.
    """
    merged = merge_policy(*layers(
        customer=PolicyLayer(name="customer", scope_allow=frozenset({"10.20.0.0/24"}))
    ))
    assert merged.scope_allow == frozenset({"10.20.0.0/24"})


def test_enabling_an_emergency_overlay_does_not_deny_everything():
    """The exact regression §4.5 describes.

    An overlay carries no scope_allow by design. If unset meant empty, pushing
    any overlay -- the mechanism meant for tightening a live incident -- would
    take every running engagement offline instead.
    """
    baseline = PolicyLayer(name="baseline_global", scope_allow=frozenset({"10.20.0.0/24"}))
    overlay = PolicyLayer(name="emergency_overlay", data_deny=frozenset({"PII"}))

    before = merge_policy(*layers(baseline_global=baseline))
    after = merge_policy(*layers(baseline_global=baseline, emergency_overlay=overlay))

    assert after.scope_allow == before.scope_allow == frozenset({"10.20.0.0/24"})
    assert after.data_deny == frozenset({"PII"})


def test_single_layer_rate_limit_applies():
    """min over an iterable, not min(*iterable), which raises on one element."""
    merged = merge_policy(*layers(
        customer=PolicyLayer(name="customer", rate_limit=20)
    ))
    assert merged.rate_limit == 20
    assert merged.as_dict()["rate_limit"] == 20


@pytest.mark.parametrize(
    "layer_name", ["baseline_global", "emergency_overlay", "customer", "engagement"]
)
def test_a_single_deny_anywhere_denies(layer_name):
    """I2: position does not matter. DENY is dominant wherever it appears."""
    merged = merge_policy(*layers(**{
        layer_name: PolicyLayer(name=layer_name, actions={"network.scan": DENY})
    }))
    assert merged.action_decision("network.scan") == DENY


def test_a_single_allow_permits_when_nobody_objects():
    merged = merge_policy(*layers(
        engagement=PolicyLayer(name="engagement", actions={"network.scan": ALLOW})
    ))
    assert merged.action_decision("network.scan") == ALLOW


# ---------------------------------------------------------------------------
# Several layers in conflict
# ---------------------------------------------------------------------------

def test_allow_lists_intersect():
    merged = merge_policy(*layers(
        baseline_global=PolicyLayer(
            name="baseline_global", scope_allow=frozenset({"10.20.0.0/24", "10.30.0.0/24"})
        ),
        customer=PolicyLayer(
            name="customer", scope_allow=frozenset({"10.20.0.0/24", "10.40.0.0/24"})
        ),
    ))
    assert merged.scope_allow == frozenset({"10.20.0.0/24"})


def test_deny_lists_union():
    merged = merge_policy(*layers(
        baseline_global=PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"})),
        customer=PolicyLayer(name="customer", data_deny=frozenset({"customer_database"})),
        engagement=PolicyLayer(name="engagement", scope_deny=frozenset({"10.20.0.1"})),
    ))
    assert merged.data_deny == frozenset({"PII", "customer_database"})
    assert merged.scope_deny == frozenset({"10.20.0.1"})


def test_rate_limit_takes_the_minimum():
    """§1.2(b)'s worked example: min(100, 20, 50) = 20."""
    merged = merge_policy(*layers(
        baseline_global=PolicyLayer(name="baseline_global", rate_limit=100),
        customer=PolicyLayer(name="customer", rate_limit=20),
        engagement=PolicyLayer(name="engagement", rate_limit=50),
    ))
    assert merged.rate_limit == 20


def test_inner_allow_cannot_reopen_an_outer_deny():
    """I2, stated directly.

    The Engagement layer is innermost and closest to execution. It still cannot
    reopen what the Baseline Global layer denied -- otherwise "policy only ever
    tightens" would not hold, and §4.5's alternative "first non-INHERIT wins"
    phrasing would permit exactly this.
    """
    merged = merge_policy(*layers(
        baseline_global=PolicyLayer(name="baseline_global", actions={"data.read": DENY}),
        engagement=PolicyLayer(name="engagement", actions={"data.read": ALLOW}),
    ))
    assert merged.action_decision("data.read") == DENY


def test_emergency_overlay_deny_overrides_an_engagement_allow():
    """The overlay's purpose: tighten globally, immediately, mid-engagement."""
    merged = merge_policy(*layers(
        baseline_global=PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        emergency_overlay=PolicyLayer(
            name="emergency_overlay", actions={"network.scan": DENY}
        ),
        engagement=PolicyLayer(name="engagement", actions={"network.scan": ALLOW}),
    ))
    assert merged.action_decision("network.scan") == DENY


@pytest.mark.parametrize(
    "decisions,expected",
    [
        ([INHERIT, INHERIT, INHERIT, INHERIT], DENY),
        ([ALLOW, INHERIT, INHERIT, INHERIT], ALLOW),
        ([ALLOW, INHERIT, INHERIT, DENY], DENY),
        ([DENY, INHERIT, INHERIT, ALLOW], DENY),
        ([ALLOW, ALLOW, ALLOW, ALLOW], ALLOW),
        ([DENY, DENY, DENY, DENY], DENY),
    ],
)
def test_action_resolution_table(decisions, expected):
    assert resolve_action(decisions) == expected


# ---------------------------------------------------------------------------
# Merging can only tighten (I2)
# ---------------------------------------------------------------------------

def test_adding_a_layer_never_widens_anything():
    """Whatever a fourth layer says, the result is no more permissive."""
    three = merge_policy(*layers(
        baseline_global=PolicyLayer(
            name="baseline_global",
            scope_allow=frozenset({"a", "b", "c"}),
            data_deny=frozenset({"PII"}),
            rate_limit=100,
            actions={"network.scan": ALLOW, "data.read": ALLOW},
        )
    ))
    four = merge_policy(*layers(
        baseline_global=PolicyLayer(
            name="baseline_global",
            scope_allow=frozenset({"a", "b", "c"}),
            data_deny=frozenset({"PII"}),
            rate_limit=100,
            actions={"network.scan": ALLOW, "data.read": ALLOW},
        ),
        engagement=PolicyLayer(
            name="engagement",
            scope_allow=frozenset({"a", "b"}),
            data_deny=frozenset({"secrets"}),
            rate_limit=10,
            actions={"data.read": DENY},
        ),
    ))

    assert four.scope_allow <= three.scope_allow
    assert four.data_deny >= three.data_deny
    assert four.rate_limit <= three.rate_limit
    for action in ("network.scan", "data.read"):
        if three.action_decision(action) == DENY:
            assert four.action_decision(action) == DENY


# ---------------------------------------------------------------------------
# Emergency overlay validation (§4.5)
# ---------------------------------------------------------------------------

def test_overlay_may_not_carry_scope_allow():
    with pytest.raises(EmergencyOverlayError):
        validate_emergency_overlay({"scope_allow": ["*"]})


def test_overlay_may_not_allow_an_action():
    with pytest.raises(EmergencyOverlayError):
        validate_emergency_overlay({"actions": {"network.scan": ALLOW}})


def test_overlay_may_deny():
    validate_emergency_overlay({"actions": {"network.scan": DENY}, "data_deny": ["PII"]})


# ---------------------------------------------------------------------------
# Document parsing
# ---------------------------------------------------------------------------

def test_absent_and_null_keys_both_mean_no_opinion():
    absent = PolicyLayer.from_document("customer", {})
    explicit_null = PolicyLayer.from_document(
        "customer", {"scope_allow": None, "rate_limit": None, "data_deny": None}
    )
    assert absent.scope_allow is UNIVERSE
    assert explicit_null.scope_allow is UNIVERSE
    assert math.isinf(explicit_null.rate_limit)
    assert explicit_null.data_deny == frozenset()


def test_an_empty_allow_list_is_not_the_same_as_an_absent_one():
    """A deliberate empty list means "nothing"; absent means "no opinion"."""
    empty = PolicyLayer.from_document("customer", {"scope_allow": []})
    assert empty.scope_allow == frozenset()
    assert empty.scope_allow is not UNIVERSE
    assert merge_policy(*layers(customer=empty)).scope_allow == frozenset()


def test_explicit_inherit_string_is_treated_as_no_opinion():
    layer = PolicyLayer.from_document(
        "customer", {"actions": {"network.scan": "INHERIT", "data.read": DENY}}
    )
    assert "network.scan" not in layer.actions
    assert layer.actions["data.read"] == DENY
