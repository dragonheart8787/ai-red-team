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
    # DP-13: a match by containment is a match to the policy -- the sub-cause is for counting
    "subset": {"version": "plan_fit_v1", "task_relation": "matches_task",
               "sub_cause": "subset_of_task_range"},
    # a decision stored before the rule: it said "differs" and still does
    "differs_inside_old": {"version": "plan_fit_v1", "task_relation": "differs_from_task",
                           "sub_cause": "same_action_target_inside_task_target"},
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
        if label in ("matches", "subset") or not enforce:
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
    assert allowed == {"absent", "matches", "subset"}


# ---------------------------------------------------------------------------------------------
# D68 S5: the second switch, ``goal_fit_enforce``, and the goal-fit half of the signal
# ---------------------------------------------------------------------------------------------

def test_every_switch_is_a_field_of_the_layer_and_the_effective_policy():
    """A third switch added to ``ENFORCE_SWITCHES`` and not to the dataclasses (or the reverse) is
    caught here rather than found by the loader dropping it."""
    import dataclasses

    from control_plane.policy.merge import ENFORCE_SWITCHES, EffectivePolicy

    assert ENFORCE_SWITCHES == ("task_relation_enforce", "goal_fit_enforce")
    for switch in ENFORCE_SWITCHES:
        for cls in (PolicyLayer, EffectivePolicy):
            field = {f.name: f for f in dataclasses.fields(cls)}[switch]
            assert field.default is False, (cls.__name__, switch)
        assert switch in layers().as_dict() and layers().as_dict()[switch] is False


@pytest.mark.parametrize("switch", ["task_relation_enforce", "goal_fit_enforce"])
def test_each_switch_is_an_or_of_the_layers_and_independent_of_the_other(switch):
    names = ("baseline_global", "emergency_overlay", "customer", "engagement")
    other = ({"task_relation_enforce", "goal_fit_enforce"} - {switch}).pop()
    for on in names:
        merged = merge_policy(*(PolicyLayer(name=n, **{switch: n == on}) for n in names))
        assert getattr(merged, switch) is True and getattr(merged, other) is False
    assert getattr(merge_policy(*(PolicyLayer(name=n) for n in names)), switch) is False


@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False), (None, False), ("true", False), (1, False), ([], False),
])
def test_only_a_real_true_turns_goal_fit_on_when_read_from_a_document(value, expected):
    assert PolicyLayer.from_document(
        "engagement", {"goal_fit_enforce": value}).goal_fit_enforce is expected


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, []])
def test_publication_refuses_a_non_boolean_goal_fit_switch(engagement_id, value):
    with committing_scope(engagement_id) as conn:
        with pytest.raises(PolicyLayerError, match="goal_fit_enforce must be a boolean"):
            publish_policy_layer(
                conn, engagement_id=engagement_id, layer="engagement", version=1,
                document={"goal_fit_enforce": value}, actor="policy-admin",
                scoped_to_engagement=True)


def test_the_overlay_may_turn_goal_fit_on_and_never_off():
    validate_emergency_overlay({"goal_fit_enforce": True})
    for value in (False, "true", 1, None):
        with pytest.raises(EmergencyOverlayError):
            validate_emergency_overlay({"goal_fit_enforce": value})


def test_goal_fit_reaches_the_loaded_policy_and_survives_the_combining_of_rows(
    engagement_id, engagement_factory
):
    """Through the real loader and its ``_combine``: on for that engagement, off for another; and a
    later row that does not mention it does not turn it off."""
    other_id, _ = engagement_factory()
    with committing_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"goal_fit_enforce": True}, actor="policy-admin", scoped_to_engagement=True)
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=2,
            document={"goal_fit_enforce": False, "actions": {"network.scan": "ALLOW"}},
            actor="policy-admin", scoped_to_engagement=True)
    with committing_scope(engagement_id) as conn:
        loaded = load_effective_policy(conn, engagement_id)
        assert loaded.goal_fit_enforce is True and loaded.task_relation_enforce is False
    with committing_scope(other_id) as conn:
        assert load_effective_policy(conn, other_id).goal_fit_enforce is False


MATCH = SIGNALS["matches"]


def goal(value, cause=None, *, base=MATCH):
    return {**base, "goal_fit": value, "goal_fit_cause": cause}


GOAL_SIGNALS = {
    "plausible": goal("plausible"),
    "implausible": goal("implausible"),
    "insufficient": goal("insufficient_context"),
    "not assessed, failed": goal("not_assessed", "failed"),
    "not assessed, disabled": goal("not_assessed", "disabled"),
    "not assessed, not applicable": goal("not_assessed", "not_applicable"),
    "not assessed, no cause": goal("not_assessed", None),
    "not assessed, odd cause": goal("not_assessed", "tired"),
    "plausible with a cause": goal("plausible", "failed"),
    "unrecognized": goal("unrecognized"),
    "outside the vocabulary": goal("probably_fine"),
    "a list": goal([]),
    "None": goal(None),
    "no goal_fit at all": MATCH,
}
EXPECTED_REASON = {
    "plausible": None, "implausible": "plan_implausible", "insufficient": "plan_unverified",
    "not assessed, failed": "plan_check_failed", "not assessed, disabled": None,
    "not assessed, not applicable": None, "not assessed, no cause": "plan_check_failed",
    "not assessed, odd cause": "plan_check_failed",
    # the policy reads ``plausible`` as quiet whatever the cause; ``policy_signal`` (tested below)
    # turns a damaged pair into ``unrecognized`` before it gets here
    "plausible with a cause": None,
    "unrecognized": "plan_check_failed", "outside the vocabulary": "plan_check_failed",
    "a list": "plan_check_failed", "None": "plan_check_failed", "no goal_fit at all": None,
}


def decide_both(name, *, task, goal_switch, signal):
    request = scenario(name, task)
    request = {**request, "policy": {**request["policy"], "goal_fit_enforce": goal_switch}}
    if signal is not None:
        request = {**request, "plan_fit": signal}
    return evaluate(request)


@pytest.mark.parametrize("label", list(GOAL_SIGNALS))
def test_each_goal_fit_value_asks_under_its_own_name_when_the_switch_is_on(label):
    got = decide_both("allowed", task=False, goal_switch=True, signal=GOAL_SIGNALS[label])
    reason = EXPECTED_REASON[label]
    assert got.engine_error is None
    assert set(got.approval_reasons) == ({reason} if reason else set())
    assert got.decision == ("HUMAN_APPROVAL" if reason else "ALLOW")


@pytest.mark.parametrize("label", list(GOAL_SIGNALS))
def test_with_the_switch_off_no_goal_fit_value_changes_anything(label):
    off = decide_both("allowed", task=False, goal_switch=False, signal=GOAL_SIGNALS[label])
    assert off == decide_both("allowed", task=False, goal_switch=False, signal=MATCH)
    assert off.decision == "ALLOW"


@pytest.mark.parametrize("name", ["allowed", "worried", "denied"])
@pytest.mark.parametrize("task", [False, True])
@pytest.mark.parametrize("goal_switch", [False, True])
def test_the_goal_fit_never_makes_a_decision_more_permissive(name, task, goal_switch):
    """Every goal-fit value x every starting point x both switches: at least as strict as the same
    request without a goal-fit, a DENY stays a DENY with its reasons, the reasons it does not own
    are kept, and it owns exactly three."""
    without = decide_both(name, task=task, goal_switch=goal_switch, signal=MATCH)
    for label, signal in GOAL_SIGNALS.items():
        got = decide_both(name, task=task, goal_switch=goal_switch, signal=signal)
        assert got.engine_error is None, (label, got)
        assert RANK[got.decision] >= RANK[without.decision], (label, got, without)
        assert got.deny_reasons == without.deny_reasons, label
        assert set(without.approval_reasons) <= set(got.approval_reasons), label
        assert set(got.approval_reasons) - set(without.approval_reasons) <= {
            "plan_implausible", "plan_unverified", "plan_check_failed"}, label
        if name == "denied":
            assert got.decision == "DENY"


def test_the_goal_fit_adds_exactly_three_reasons_and_plausible_is_not_one_of_them():
    seen = set()
    for signal in GOAL_SIGNALS.values():
        seen |= set(decide_both("allowed", task=False, goal_switch=True,
                                signal=signal).approval_reasons)
    assert seen == {"plan_implausible", "plan_unverified", "plan_check_failed"}


def test_the_two_switches_read_only_their_own_half_of_the_signal():
    both = {**SIGNALS["differs"], "goal_fit": "implausible", "goal_fit_cause": None}
    only_task = decide_both("allowed", task=True, goal_switch=False, signal=both)
    only_goal = decide_both("allowed", task=False, goal_switch=True, signal=both)
    assert set(only_task.approval_reasons) == {"proposal_outside_task"}
    assert set(only_goal.approval_reasons) == {"plan_implausible"}
    together = decide_both("allowed", task=True, goal_switch=True, signal=both)
    assert set(together.approval_reasons) == {"proposal_outside_task", "plan_implausible"}


# ``policy_signal``: the goal-fit half of the replay

@pytest.mark.parametrize("value,cause", [
    ("plausible", None), ("implausible", None), ("insufficient_context", None),
    ("not_assessed", "failed"), ("not_assessed", "disabled"), ("not_assessed", "not_applicable"),
])
def test_a_stored_goal_fit_this_code_knows_goes_through_unchanged(value, cause):
    stored = {**MATCH, "goal_fit": value, "goal_fit_cause": cause}
    assert r.policy_signal(stored) == stored


def test_a_stored_signal_without_a_goal_fit_stays_without_one():
    """A row decided before Q1 existed: absent is not invented (it would read as a failed check and
    refuse every such approval)."""
    assert "goal_fit" not in r.policy_signal(MATCH)
    assert "goal_fit_cause" not in r.policy_signal(MATCH)


@pytest.mark.parametrize("value,cause", [
    ("probably_fine", None), ("plausible", "failed"), ("not_assessed", None),
    ("not_assessed", "tired"), (None, None), ([], None), ({}, {}), (7, "failed"),
    ("implausible", []),
])
def test_a_stored_goal_fit_this_code_does_not_know_becomes_unrecognized(value, cause):
    got = r.policy_signal({**MATCH, "goal_fit": value, "goal_fit_cause": cause})
    assert (got["goal_fit"], got["goal_fit_cause"]) == (r.UNRECOGNIZED, None)
    assert got["task_relation"] == "matches_task", "the two halves are judged apart"


def test_a_damaged_task_relation_does_not_take_the_goal_fit_with_it_or_the_other_way():
    got = r.policy_signal({"version": "plan_fit_v1", "task_relation": "probably_fine",
                           "sub_cause": None, "goal_fit": "plausible", "goal_fit_cause": None})
    assert (got["task_relation"], got["goal_fit"]) == (r.UNRECOGNIZED, "plausible")


def test_the_replay_never_raises_whatever_a_damaged_row_holds():
    """``policy_signal`` runs on rows read back from the database. An operand that is a list or an
    object must be refused as unrecognised, not raise from a set or dict membership test."""
    junk = [None, [], {}, {"a": 1}, 1, 1.5, True, "x", ("a",), object(), "matches_task",
            "not_assessed", "plausible"]
    for rel, sub, value, cause in itertools.product(junk, junk, junk, junk):
        stored = {"version": "plan_fit_v1", "task_relation": rel, "sub_cause": sub,
                  "goal_fit": value, "goal_fit_cause": cause}
        try:
            got = r.policy_signal(stored)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"the replay raised {type(exc).__name__} on {stored!r}")
        assert got["task_relation"] in {*r.SUB_CAUSES, r.UNRECOGNIZED}
        assert got["goal_fit"] in {"plausible", "implausible", "insufficient_context",
                                   "not_assessed", r.UNRECOGNIZED}
