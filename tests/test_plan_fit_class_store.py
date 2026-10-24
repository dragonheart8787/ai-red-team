"""Q1 per action class (D68 DP-15): the list, the quiet states, the exit rule, the report.

Opts in to the real class store (``q1_class_store_live``): the record of each call and the exit
rule write global tables nothing can empty, so every test here uses a class name of its own
(``dp15x.<random>``) and leaves nothing that could change another test or a later run.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from agents.base_agent import GoalFitAssessment
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.fake.fake_plan_fit import ScriptedPlanFit, UnavailableFakePlanFit
from control_plane.api.function_api import propose_action
from control_plane.plan_fit import class_store as store
from control_plane.plan_fit import classes as c
from control_plane.plan_fit import goal_fit as gf
from control_plane.plan_fit import relation as r
from control_plane.policy.layers import PolicyLayerError, publish_policy_layer
from control_plane.policy.merge import (
    ALLOW,
    EmergencyOverlayError,
    PolicyLayer,
    goal_fit_actions_of,
    merge_policy,
    validate_emergency_overlay,
)
from control_plane.state.db import (
    engagement_scope,
    get_engine,
    global_policy_admin_scope,
)
from tests.task_support import task_for
from tests.test_approved_dispatch import CIDR, _proposal, rows
from tests.test_pipeline_stages import FakeSandbox

pytestmark = pytest.mark.usefixtures("switch_as_published", "q1_class_store_live")


def fresh_class() -> str:
    return f"dp15x.c{uuid.uuid4().hex[:10]}"


def record(action: str, outcomes: list[str]) -> list:
    """Append the outcomes in order (oldest first) through the pipeline's own function."""
    verdicts = []
    for outcome in outcomes:
        with get_engine().begin() as conn:
            verdicts.append(store.record_and_review(conn, action, outcome))
    return verdicts


def live_suspension(action: str) -> bool:
    with get_engine().begin() as conn:
        return action in store.suspended_actions(conn)


def admin_clear(action: str, who: str = "operator-test") -> bool:
    with global_policy_admin_scope() as conn:
        return store.clear_suspension(conn, action, who)


OK, BAD = c.ANSWERED, c.FAILED


# -- the gate: which classes are asked -----------------------------------------------------------

def relation(value=r.MATCHES_TASK, sub=None):
    return r.TaskRelation(value, sub)


def ask(validator, action, **kw):
    return gf.assess_goal_fit(
        validator=validator, relation=relation(),
        task_context={"goal": "Scan the host", "action": action, "canonical_target": "ip:10.0.0.5"},
        proposal_action=action, proposal_target="ip:10.0.0.5", **kw)


def test_a_class_outside_the_list_is_not_asked_and_records_why():
    validator = ScriptedPlanFit("plausible")
    got = ask(validator, "network.scan")              # the default list is empty
    assert (got.value, got.cause) == ("not_assessed", "class_not_enabled")
    assert validator.queries == [] and got.asked is False and got.outcome is None


def test_a_class_in_the_list_is_asked_once():
    validator = ScriptedPlanFit("implausible")
    got = ask(validator, "network.scan", enabled_actions=frozenset({"network.scan"}))
    assert got.value == "implausible" and len(validator.queries) == 1
    assert got.asked is True and got.outcome == c.ANSWERED


def test_another_class_in_the_list_does_not_let_this_one_in():
    validator = ScriptedPlanFit("plausible")
    got = ask(validator, "network.scan", enabled_actions=frozenset({"code.secrets"}))
    assert got.cause == "class_not_enabled" and validator.queries == []


def test_a_suspended_class_is_not_asked_even_though_it_is_listed():
    validator = ScriptedPlanFit("plausible")
    listed = frozenset({"network.scan"})
    got = ask(validator, "network.scan", enabled_actions=listed,
              suspended_actions=frozenset({"network.scan"}))
    assert got.cause == "class_suspended" and validator.queries == []
    assert got.outcome is None


def test_a_suspension_state_that_could_not_be_read_is_read_as_suspended():
    validator = ScriptedPlanFit("plausible")
    got = ask(validator, "network.scan", enabled_actions=frozenset({"network.scan"}),
              suspended_actions=None)
    assert got.cause == "class_suspended" and validator.queries == []


def test_the_older_quiet_states_still_come_first():
    assert gf.assess_goal_fit(
        validator=None, relation=relation(), task_context=None, proposal_action="network.scan",
        proposal_target=None, enabled_actions=frozenset({"network.scan"})).cause == "disabled"
    assert ask(ScriptedPlanFit("plausible"), "network.scan",
               enabled_actions=frozenset({"network.scan"})).value == "plausible"
    got = gf.assess_goal_fit(
        validator=ScriptedPlanFit("plausible"),
        relation=relation(r.DIFFERS_FROM_TASK, r.DIFFERENT_TARGET),

        task_context=None, proposal_action="network.scan", proposal_target=None,
        enabled_actions=frozenset({"network.scan"}))
    assert got.cause == "not_applicable"


def test_a_failed_call_counts_for_the_class_and_a_gate_does_not():
    failing = UnavailableFakePlanFit()
    got = ask(failing, "network.scan", enabled_actions=frozenset({"network.scan"}))
    assert (got.value, got.cause) == ("not_assessed", "failed") and got.outcome == c.FAILED
    assert ask(failing, "network.scan").outcome is None


# -- the list is policy ---------------------------------------------------------------------------

def test_the_list_is_empty_by_default_and_merges_by_union():
    assert PolicyLayer.from_document("x", {}).goal_fit_actions == frozenset()
    a = PolicyLayer.from_document("a", {"goal_fit_actions": ["network.scan"]})
    b = PolicyLayer.from_document("b", {"goal_fit_actions": ["web.get", "network.scan"]})
    empty = PolicyLayer(name="e")
    merged = merge_policy(a, empty, empty, b)
    assert merged.goal_fit_actions == {"network.scan", "web.get"}
    assert merged.as_dict()["goal_fit_actions"] == ["network.scan", "web.get"]
    assert merge_policy(empty, empty, empty, empty).goal_fit_actions == frozenset()


@pytest.mark.parametrize("junk", ["network.scan", {"network.scan": True}, 7, True, [3],
                                  ["network.scan", "Bad Name"], ["network.scan", None],
                                  [["network.scan"]], "", ["a.b.c"]])
def test_a_list_that_is_not_a_list_of_class_names_reads_as_no_class(junk):
    assert goal_fit_actions_of(junk) == frozenset()
    layer = PolicyLayer.from_document("x", {"goal_fit_actions": junk})
    assert layer.goal_fit_actions == frozenset()


def test_publication_refuses_a_malformed_list_and_accepts_a_good_one(engagement_id):
    with engagement_scope(engagement_id) as conn:
        for bad in ("network.scan", ["network.scan", 3], ["no_dot"], {"a": "b"}):
            with pytest.raises(PolicyLayerError):
                publish_policy_layer(conn, engagement_id=engagement_id, layer="engagement",
                                     version=1, document={"goal_fit_actions": bad},
                                     actor="t", scoped_to_engagement=True)


def test_an_overlay_may_carry_the_list_because_it_only_adds_checks():
    validate_emergency_overlay({"goal_fit_actions": ["network.scan"]})
    with pytest.raises(EmergencyOverlayError):
        validate_emergency_overlay({"goal_fit_actions": ["network.scan"],
                                   "actions": {"network.scan": ALLOW}})


# -- with the switch on, a class outside the list behaves as with the switch off ------------------

def pipeline_world(engagement_id, registry, *extra_actions):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan", *extra_actions])
    return {"engagement_id": engagement_id, "scope_id": scope_id}


def run(world, validator, *, switch, listed=frozenset(), action="network.scan", reviewer=None):
    proposal = dataclasses.replace(_proposal(world), action=action)
    proposal = dataclasses.replace(proposal, task_id=task_for(world["engagement_id"], proposal))
    policy = merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII", "customer_database"}),
                    actions={"network.scan": ALLOW, action: ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement", goal_fit_enforce=switch,
                    goal_fit_actions=frozenset(listed)))
    return propose_action(
        engagement_id=world["engagement_id"], proposal=proposal,
        reviewer=reviewer or HonestFakeReviewer(), policy=policy, agent_id="worker-1",
        sandbox=FakeSandbox(), network_allowlist=[CIDR], plan_fit_validator=validator)


def stored_goal_fit(world, proposal_id):
    got = rows(world, "SELECT reviewer_hints FROM action_proposals WHERE proposal_id = :p",
               p=proposal_id)[0]["reviewer_hints"]["plan_fit"]
    return got["goal_fit"], got["goal_fit_cause"]


@pytest.mark.parametrize("validator_factory", [
    lambda: ScriptedPlanFit("implausible"),
    lambda: ScriptedPlanFit("insufficient_context"),
    lambda: UnavailableFakePlanFit(),
])
def test_switch_on_and_class_outside_the_list_is_the_same_as_switch_off(
        engagement_id, registry, validator_factory):
    """The point of the list. Whatever the validator would have said -- an answer that asks for a
    person, or a failure -- a class that is not listed is not asked, and the decision, the reasons
    and what is stored are those of the switch being off. The validator is never called."""
    world = pipeline_world(engagement_id, registry)
    on_validator, off_validator = validator_factory(), validator_factory()
    on = run(world, on_validator, switch=True)
    off = run(world, off_validator, switch=False)
    assert (on.decision, on.approval_reasons, on.deny_reasons) == (
        off.decision, off.approval_reasons, off.deny_reasons)
    assert on.decision == "ALLOW" and on.approval_reasons == ()
    assert on_validator.queries == [] and off_validator.queries == []
    assert stored_goal_fit(world, on.proposal_id) == ("not_assessed", "class_not_enabled")
    assert stored_goal_fit(world, off.proposal_id) == ("not_assessed", "class_not_enabled")


def test_the_same_proposal_is_asked_once_the_class_is_listed(engagement_id, registry):
    world = pipeline_world(engagement_id, registry)
    validator = ScriptedPlanFit("implausible")
    out = run(world, validator, switch=True, listed={"network.scan"})
    assert out.decision == "HUMAN_APPROVAL" and out.approval_reasons == ("plan_implausible",)
    assert len(validator.queries) == 1


def test_a_listed_class_with_the_switch_off_is_asked_and_recorded_but_changes_nothing(
        engagement_id, registry):
    """Shadow mode is how a class earns its numbers: asked, stored, no decision moved."""
    world = pipeline_world(engagement_id, registry)
    validator = ScriptedPlanFit("implausible")
    out = run(world, validator, switch=False, listed={"network.scan"})
    assert out.decision == "ALLOW" and out.approval_reasons == ()
    assert len(validator.queries) == 1
    assert stored_goal_fit(world, out.proposal_id) == ("implausible", None)


# -- the exit rule, on the real store and the real pipeline ---------------------------------------

def test_a_call_is_recorded_and_below_thirty_calls_nothing_happens():
    action = fresh_class()
    assert record(action, [BAD] * 29) == [None] * 29
    assert not live_suspension(action)


def test_thirty_failures_in_thirty_calls_suspend_the_class_once():
    action = fresh_class()
    verdicts = record(action, [BAD] * 31)
    taken = [v for v in verdicts if v is not None]
    assert len(taken) == 1 and verdicts[29] is taken[0]           # the thirtieth call did it
    assert (taken[0].n, taken[0].failed) == (30, 30)
    assert live_suspension(action)


def test_exactly_thirty_percent_stays_and_just_above_it_goes():
    stays, goes = fresh_class(), fresh_class()
    assert record(stays, [OK] * 21 + [BAD] * 9) == [None] * 30       # 9/30 = 30.0%
    assert record(goes, [OK] * 20 + [BAD] * 10)[-1] is not None      # 10/30 = 33.3%
    assert not live_suspension(stays) and live_suspension(goes)


def test_only_the_last_fifty_count():
    action = fresh_class()
    history = [OK] * 36 + [BAD] * 14                  # 14/50 = 28%: stays
    assert record(action, history) == [None] * 50
    # two more calls push the two oldest answers out: 15 failed in the last 50 = 30%, still in
    assert record(action, [OK, BAD]) == [None, None]
    # one more failure and the window holds 16 of 50 (32%): out
    assert record(action, [BAD])[-1] is not None
    assert live_suspension(action)


def test_a_suspended_class_can_be_cleared_only_by_the_operator_and_starts_over():
    action = fresh_class()
    record(action, [BAD] * 30)
    assert live_suspension(action)
    assert admin_clear(action) is True and not live_suspension(action)
    assert admin_clear(action) is False                              # nothing live to clear
    # the old failures are the reason it was out: the window starts again from the clearing
    with get_engine().begin() as conn:
        assert store.recent_outcomes(conn, action) == []
    assert record(action, [BAD] * 29) == [None] * 29                  # 29 new calls: too few again
    assert not live_suspension(action)
    assert record(action, [BAD])[-1] is not None                      # the 30th since


def test_the_runtime_role_cannot_clear_a_suspension_or_change_or_delete_a_record():
    action = fresh_class()
    record(action, [BAD] * 30)
    for statement in (
            "UPDATE goal_fit_suspensions SET cleared_at = now(), cleared_by = 'x' "
            "WHERE action = :a",
            "DELETE FROM goal_fit_suspensions WHERE action = :a",
            "UPDATE goal_fit_calls SET outcome = 'answered' WHERE action = :a",
            "DELETE FROM goal_fit_calls WHERE action = :a"):
        with pytest.raises(DBAPIError):
            with get_engine().begin() as conn:
                conn.execute(text(statement), {"a": action})
    assert live_suspension(action)


def test_the_operator_role_cannot_write_calls_or_new_suspensions_and_changes_nothing_but_clearing():
    action = fresh_class()
    record(action, [BAD] * 30)
    for statement in (
            "INSERT INTO goal_fit_calls (action, outcome) VALUES (:a, 'answered')",
            "INSERT INTO goal_fit_suspensions (action, window_n, window_failed) "
            "VALUES (:a, 1, 1)",
            "UPDATE goal_fit_suspensions SET window_failed = 0 WHERE action = :a",
            "DELETE FROM goal_fit_suspensions WHERE action = :a"):
        with pytest.raises(DBAPIError):
            with global_policy_admin_scope() as conn:
                conn.execute(text(statement), {"a": action})
    assert admin_clear(action)
    with global_policy_admin_scope() as conn:                        # a cleared one stays cleared
        try:
            conn.execute(text("UPDATE goal_fit_suspensions SET cleared_by = 'someone else' "
                              "WHERE action = :a"), {"a": action})
        except DBAPIError:
            pass
    with global_policy_admin_scope() as conn:
        assert conn.execute(text("SELECT cleared_by FROM goal_fit_suspensions WHERE action = :a"),
                            {"a": action}).scalar_one() == "operator-test"


def test_a_class_cannot_have_two_live_suspensions_and_names_are_checked_by_the_database():
    action = fresh_class()
    record(action, [BAD] * 30)
    with get_engine().begin() as conn:
        assert store.suspend(conn, action, c.ExitVerdict(True, 30, 30, 1.0)) is False
    for bad_name in ("NoDot", "a.b.c", "x; DROP TABLE y"):
        with pytest.raises(DBAPIError):
            with get_engine().begin() as conn:
                conn.execute(text("INSERT INTO goal_fit_calls (action, outcome) "
                                  "VALUES (:a, 'failed')"), {"a": bad_name})
    with pytest.raises(DBAPIError):
        with get_engine().begin() as conn:
            conn.execute(text("INSERT INTO goal_fit_calls (action, outcome) "
                              "VALUES ('a.b', 'maybe')"))


def test_through_the_pipeline_thirty_failures_take_the_class_out_and_it_is_not_asked_again(
        engagement_id, registry):
    action = fresh_class()
    world = pipeline_world(engagement_id, registry, action)
    validator = UnavailableFakePlanFit()
    for _ in range(29):
        run(world, validator, switch=False, listed={action}, action=action)
    assert not live_suspension(action) and len(validator.queries) == 29
    last = run(world, validator, switch=False, listed={action}, action=action)
    assert live_suspension(action) and len(validator.queries) == 30
    # the thirtieth call was the failed one that tipped it, and its own answer is a failure
    assert stored_goal_fit(world, last.proposal_id) == ("not_assessed", "failed")
    after = run(world, validator, switch=True, listed={action}, action=action)
    assert len(validator.queries) == 30                               # not asked
    assert stored_goal_fit(world, after.proposal_id) == ("not_assessed", "class_suspended")
    assert after.approval_reasons == () and after.decision == "ALLOW"   # and nobody is asked for
    events = rows(world, "SELECT payload FROM audit_log WHERE event_type = "
                  "'plan_fit.class_suspended' AND payload->>'action' = :a", a=action)
    assert len(events) == 1
    payload = events[0]["payload"]
    assert (payload["window_calls"], payload["window_failed"]) == (30, 30)


def test_a_store_that_cannot_be_written_does_not_interrupt_a_proposal(
        engagement_id, registry, monkeypatch):
    from control_plane.api import function_api
    from control_plane.plan_fit import class_store

    def broken(conn, action, outcome):
        raise RuntimeError("the store is down")

    monkeypatch.setattr(class_store, "record_and_review", broken)
    world = pipeline_world(engagement_id, registry)
    out = run(world, ScriptedPlanFit("plausible"), switch=True, listed={"network.scan"})
    assert out.decision == "ALLOW"
    asked = gf.GoalFit(
        GoalFitAssessment("v", "plausible", None), {}, asked=True)
    assert function_api._review_class(asked, "a.b") is None


def test_a_suspension_state_that_cannot_be_read_is_read_as_suspended_through_the_pipeline(
        engagement_id, registry, monkeypatch):
    from control_plane.plan_fit import class_store

    def unreadable(conn):
        raise RuntimeError("the store is down")

    monkeypatch.setattr(class_store, "suspended_actions", unreadable)
    world = pipeline_world(engagement_id, registry)
    validator = ScriptedPlanFit("implausible")
    out = run(world, validator, switch=True, listed={"network.scan"})
    assert validator.queries == []                       # not asked: the quiet side
    assert stored_goal_fit(world, out.proposal_id) == ("not_assessed", "class_suspended")
    assert out.decision == "ALLOW" and out.approval_reasons == ()


# -- admission: advice, from the numbers ---------------------------------------------------------

def table_row(action):
    with global_policy_admin_scope() as conn:
        return next(r_ for r_ in store.class_table(conn, ()) if r_["action"] == action)


def test_forty_clean_calls_are_recommended_and_thirty_nine_are_not():
    short, enough = fresh_class(), fresh_class()
    record(short, [OK] * 39)
    record(enough, [OK] * 40)
    assert table_row(short)["recommend_admission"] is False
    row = table_row(enough)
    assert row["recommend_admission"] is True and (row["n"], row["failed"]) == (40, 0)
    assert row["upper95"] == pytest.approx(c.wilson_upper(0, 40), abs=1e-4)


def test_two_failures_in_forty_are_not_recommended_one_is():
    one, two = fresh_class(), fresh_class()
    record(one, [OK] * 39 + [BAD])
    record(two, [OK] * 38 + [BAD] * 2)
    assert table_row(one)["recommend_admission"] is True              # 12.9%
    assert table_row(two)["recommend_admission"] is False             # 16.5%


def test_the_report_counts_calls_since_the_class_was_last_cleared():
    action = fresh_class()
    record(action, [BAD] * 30)
    assert table_row(action)["n"] == 30
    admin_clear(action)
    assert not any(r_["action"] == action and r_["n"] for r_ in _table())
    record(action, [OK] * 3)
    assert table_row(action)["n"] == 3


def _table():
    with global_policy_admin_scope() as conn:
        return store.class_table(conn, ())


def test_a_listed_or_suspended_class_is_never_recommended_again():
    listed, suspended = fresh_class(), fresh_class()
    record(listed, [OK] * 60)
    record(suspended, [BAD] * 30)
    with global_policy_admin_scope() as conn:
        by = {r_["action"]: r_ for r_ in store.class_table(conn, [listed])}
    assert by[listed]["state"] == "in the list" and by[listed]["recommend_admission"] is False
    assert by[suspended]["state"] == "suspended" and by[suspended]["recommend_admission"] is False


def test_the_tool_prints_the_numbers_and_says_it_only_recommends():
    from scripts import manage_goal_fit_classes as tool

    action = fresh_class()
    record(action, [OK] * 40)
    out = tool.render([table_row(action)])
    assert "RECOMMEND ADMISSION" in out and action in out and "advice" in out
    assert "admitted only by publishing" in out


def test_the_tool_has_no_way_to_write_the_list():
    from pathlib import Path

    source = Path("scripts/manage_goal_fit_classes.py").read_text()
    assert "publish_policy_layer" not in source and "INSERT INTO policy_layers" not in source
