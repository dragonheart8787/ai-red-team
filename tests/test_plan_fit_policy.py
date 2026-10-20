"""P1 made enforceable (D68 S3): the switch, the policy input, the rules -- and that none of it
can do anything but ask for a human.

The switch is ``task_relation_enforce`` in a policy layer. It merges by OR, so a layer can only turn
it on. The signal enters the policy input only when it exists, and ``approval_reasons`` is the only
thing that reads it. The property test at the bottom runs the real policy over every combination and
requires that adding the signal never makes a decision more permissive.
"""

from __future__ import annotations

import itertools

import pytest

from control_plane.plan_fit import relation as r
from control_plane.policy.engine import build_policy_input, evaluate
from control_plane.policy.layers import (
    PolicyLayerError,
    load_effective_policy,
    publish_policy_layer,
)
from control_plane.policy.merge import (
    ALLOW,
    EmergencyOverlayError,
    PolicyLayer,
    merge_policy,
    validate_emergency_overlay,
)
from tests.helpers import committing_scope

# ---------------------------------------------------------------------------------------------
# the switch
# ---------------------------------------------------------------------------------------------


def layers(**flags):
    names = ("baseline_global", "emergency_overlay", "customer", "engagement")
    return merge_policy(*(PolicyLayer(name=n, task_relation_enforce=flags.get(n, False))
                          for n in names))


def test_the_switch_is_off_when_no_layer_says_anything():
    assert layers().task_relation_enforce is False
    assert layers().as_dict()["task_relation_enforce"] is False


@pytest.mark.parametrize(
    "layer", ["baseline_global", "emergency_overlay", "customer", "engagement"])
def test_any_one_layer_turns_it_on(layer):
    assert layers(**{layer: True}).task_relation_enforce is True


def test_no_layer_can_turn_off_what_another_turned_on():
    """OR, not last-writer: the merge of a layer that says false with one that says true is true,
    in every order."""
    names = ("baseline_global", "emergency_overlay", "customer", "engagement")
    for on in names:
        flags = {n: (n == on) for n in names}
        assert layers(**flags).task_relation_enforce is True


@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False), (None, False), ("true", False), ("false", False), (1, False),
    (0, False), ([], False),
])
def test_only_a_real_true_turns_it_on_when_read_from_a_document(value, expected):
    layer = PolicyLayer.from_document("engagement", {"task_relation_enforce": value})
    assert layer.task_relation_enforce is expected


def test_a_document_that_does_not_mention_it_leaves_it_off():
    assert PolicyLayer.from_document("engagement", {"actions": {}}).task_relation_enforce is False
    assert PolicyLayer.from_document("engagement", None).task_relation_enforce is False


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, []])
def test_publication_refuses_anything_but_a_boolean(engagement_id, value):
    """A switch read as "is True" would silently not enforce on the string "true"; refused at
    publication instead, naming the field."""
    with committing_scope(engagement_id) as conn:
        with pytest.raises(PolicyLayerError, match="task_relation_enforce must be a boolean"):
            publish_policy_layer(
                conn, engagement_id=engagement_id, layer="engagement", version=1,
                document={"task_relation_enforce": value}, actor="policy-admin",
                scoped_to_engagement=True)


def test_the_overlay_may_turn_it_on_and_never_say_anything_else_about_it():
    validate_emergency_overlay({"task_relation_enforce": True})
    for value in (False, "true", 1, None):
        with pytest.raises(EmergencyOverlayError):
            validate_emergency_overlay({"task_relation_enforce": value})


def test_the_switch_reaches_the_loaded_policy_and_only_that_engagement(
    engagement_id, engagement_factory
):
    """Published as an engagement layer, read back through the real loader: on for that
    engagement, off for another."""
    other_id, _ = engagement_factory()
    with committing_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {"network.scan": "ALLOW"}, "task_relation_enforce": True},
            actor="policy-admin", scoped_to_engagement=True)
    with committing_scope(engagement_id) as conn:
        assert load_effective_policy(conn, engagement_id).task_relation_enforce is True
    with committing_scope(other_id) as conn:
        assert load_effective_policy(conn, other_id).task_relation_enforce is False


def test_rows_of_one_layer_name_are_combined_without_dropping_the_switch(engagement_id):
    """The loader folds every active row of a layer name into one (``_combine``): a second routine
    that builds a layer field by field, and the place a new field is dropped. One row that turns the
    switch on, and a later one that does not mention it, give on."""
    with committing_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"task_relation_enforce": True}, actor="policy-admin",
            scoped_to_engagement=True)
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=2,
            document={"task_relation_enforce": False, "actions": {"network.scan": "ALLOW"}},
            actor="policy-admin", scoped_to_engagement=True)
    with committing_scope(engagement_id) as conn:
        assert load_effective_policy(conn, engagement_id).task_relation_enforce is True


# ---------------------------------------------------------------------------------------------
# the policy input
# ---------------------------------------------------------------------------------------------

def _input(plan_fit):
    from control_plane.canonicalizer.authorization import AuthorizationResolution
    from control_plane.canonicalizer.metadata import MetadataResolution
    from control_plane.canonicalizer.target import normalize_target

    target = normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}})
    return build_policy_input(
        target=target, action="network.scan",
        authorization=AuthorizationResolution(authorized=True, scope_object_id="SCOPE-2"),
        metadata=MetadataResolution(known=True, data_class=(), resource_class=(), authority="x"),
        policy=layers(), scope_objects=[], plan_fit=plan_fit)


def test_an_absent_signal_is_an_absent_key():
    assert "plan_fit" not in _input(None)


def test_a_present_signal_is_passed_as_given_and_copied():
    signal = {"version": "plan_fit_v1", "task_relation": "no_task", "sub_cause": "task_id_absent"}
    built = _input(signal)
    assert "plan_fit" in built, "the signal did not reach the policy input"
    got = built["plan_fit"]
    assert got == signal and got is not signal


# ---------------------------------------------------------------------------------------------
# what a stored signal becomes
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("relation,sub", [
    (value, sub) for value, subs in r.SUB_CAUSES.items() for sub in subs])
def test_a_stored_signal_this_code_knows_goes_through_unchanged(relation, sub):
    stored = {"version": "plan_fit_v1", "task_relation": relation, "sub_cause": sub}
    assert r.policy_signal(stored) == stored


@pytest.mark.parametrize("stored", [
    None, "matches_task", 7, [], {},
    {"version": "plan_fit_v2", "task_relation": "matches_task", "sub_cause": None},
    {"version": "plan_fit_v1", "task_relation": "probably_fine", "sub_cause": None},
    {"version": "plan_fit_v1", "task_relation": "matches_task", "sub_cause": "different_target"},
    {"version": "plan_fit_v1", "task_relation": "differs_from_task", "sub_cause": None},
    {"task_relation": "matches_task", "sub_cause": None},
])
def test_anything_else_is_unrecognized_and_never_reads_as_a_match(stored):
    got = r.policy_signal(stored)
    assert got["task_relation"] == r.UNRECOGNIZED
    assert got["task_relation"] not in (r.MATCHES_TASK, r.NO_TASK)


# ---------------------------------------------------------------------------------------------
# the property: the signal can only ask for a human
# ---------------------------------------------------------------------------------------------

RANK = {"ALLOW": 0, "HUMAN_APPROVAL": 1, "DENY": 2}

BASE = {
    "action": {
        "action": "network.scan",
        "authorization": {"source": "engagement_scope", "scope_object_id": "SCOPE-2"},
        "discovery": {"source": "explicit_scope"},
        "possible_sensitive_data_hint": [], "writes_data": False, "changes_state": False,
    },
    "canonical": {"target": {"logical_identity": {"type": "ip", "value": "10.20.0.7"},
                             "address_count": 1}, "risk": "low"},
    "capability_request": {"max_duration_seconds": 120, "max_targets": 1, "max_concurrency": 1,
                           "tool": {}},
    "authorization_resolution": {"authorized": True, "scope_object_id": "SCOPE-2"},
    "resource_metadata": {"known": True, "data_class": ["network_service"],
                          "resource_class": ["host"],
                          "classification": {"authority": "AUTHORITATIVE"}, "observations": []},
    "policy": {
        "scope_objects": [{"id": "SCOPE-2", "type": "cidr", "value": "10.20.0.0/24",
                           "allowed_actions": ["network.recon", "network.scan"]}],
        "scope_allow": "UNIVERSE", "scope_deny": [], "data_deny": ["PII", "customer_database"],
        "rate_limit": None, "actions": {"network.scan": "ALLOW"},
    },
    "usage": {"requests_in_window": 0},
}


def scenario(name, enforce):
    request = {**BASE, "policy": {**BASE["policy"], "task_relation_enforce": enforce}}
    if name == "allowed":
        return request
    if name == "worried":
        return {**request, "canonical": {**BASE["canonical"], "risk": "high"}}
    if name == "denied":
        return {**request, "authorization_resolution": {"authorized": False,
                                                        "scope_object_id": None}}
    raise AssertionError(name)


SIGNALS = {
    "absent": None,
    "matches": {"version": "plan_fit_v1", "task_relation": "matches_task", "sub_cause": None},
    "no_task": {"version": "plan_fit_v1", "task_relation": "no_task",
                "sub_cause": "task_id_absent"},
    "differs": {"version": "plan_fit_v1", "task_relation": "differs_from_task",
                "sub_cause": "different_target"},
    "not_live": {"version": "plan_fit_v1", "task_relation": "task_not_live",
                 "sub_cause": "task_status_not_live"},
    "unrecognized": {"version": "plan_fit_v1", "task_relation": "unrecognized",
                     "sub_cause": None},
    "damaged": {"version": "plan_fit_v1"},
}


def decide(name, enforce, signal):
    request = scenario(name, enforce)
    if signal is not None:
        request = {**request, "plan_fit": signal}
    return evaluate(request)


@pytest.mark.parametrize("name", ["allowed", "worried", "denied"])
@pytest.mark.parametrize("enforce", [False, True])
def test_the_signal_never_makes_a_decision_more_permissive(name, enforce):
    """Over every signal, switch state and starting point (allowed, already asking for a human,
    denied): the decision with the signal is at least as strict as without it; a DENY stays a DENY
    with its reasons; the reasons the signal does not own are kept; ``matches_task`` is the same as
    no signal at all; and with the switch off, no signal changes anything."""
    without = decide(name, enforce, None)
    assert without.engine_error is None
    for label, signal in SIGNALS.items():
        got = decide(name, enforce, signal)
        assert got.engine_error is None, (label, got)
        assert RANK[got.decision] >= RANK[without.decision], (label, got, without)
        assert got.deny_reasons == without.deny_reasons, label
        assert set(without.approval_reasons) <= set(got.approval_reasons), label
        assert set(got.approval_reasons) - set(without.approval_reasons) <= {
            "proposal_without_task", "proposal_outside_task"}, label
        if label == "matches" or not enforce:
            assert got == without, label
        if name == "denied":
            assert got.decision == "DENY"


def test_the_signal_only_ever_adds_one_of_two_reasons():
    seen = set()
    for enforce, label in itertools.product([True], SIGNALS):
        seen |= set(decide("allowed", enforce, SIGNALS[label]).approval_reasons)
    assert seen == {"proposal_without_task", "proposal_outside_task"}


def test_an_allow_stays_an_allow_only_for_a_match_or_no_signal():
    allowed = {label for label, signal in SIGNALS.items()
               if decide("allowed", True, signal).decision == ALLOW}
    assert allowed == {"absent", "matches"}
