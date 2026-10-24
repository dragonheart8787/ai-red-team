"""Q1 per action class (D68 DP-15): the list, the quiet states, the exit rule, the report.

Opts in to the real class store (``q1_class_store_live``): the record of each call and the exit
rule write global tables nothing can empty, so every test here uses a class name of its own
(``dp15x.<random>``) and leaves nothing that could change another test or a later run.
"""

from __future__ import annotations

import dataclasses
import json
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
    global_auditor_scope,
    global_policy_admin_scope,
)
from tests.task_support import task_for
from tests.test_approved_dispatch import CIDR, _proposal, rows
from tests.test_pipeline_stages import FakeSandbox

pytestmark = pytest.mark.usefixtures("switch_as_published", "q1_class_store_live")


def fresh_class() -> str:
    return f"dp15x.c{uuid.uuid4().hex[:10]}"


def record(action: str, outcomes: list) -> list:
    """Append the outcomes in order (oldest first) through the pipeline's own function. An item is
    an outcome (a failure with no kind is ``unclassified``, as every failure was before kinds), or
    ``(outcome, kind)``."""
    verdicts = []
    for outcome in outcomes:
        outcome, kind = outcome if isinstance(outcome, tuple) else (outcome, None)
        with get_engine().begin() as conn:
            verdicts.append(store.record_and_review(conn, action, outcome, kind))
    return verdicts


def live_suspension(action: str) -> bool:
    with get_engine().begin() as conn:
        return action in store.suspended_actions(conn)


REASON = "wording of the goal template changed; 30 test calls answered"


def admin_clear(action: str, who: str = "operator-test", reason: str = REASON) -> bool:
    with global_policy_admin_scope() as conn:
        return store.clear_suspension(conn, action, who, reason)


OK, BAD = c.ANSWERED, c.FAILED
REF, TRA, UNC = (BAD, "refusal"), (BAD, "transport"), (BAD, "unclassified")


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


def class_calls(action):
    """(outcome, ...) of the calls recorded for a class, oldest first."""
    with get_engine().begin() as conn:
        return [r_[0] for r_ in conn.execute(text(
            "SELECT outcome FROM goal_fit_calls WHERE action = :a ORDER BY call_id"),
            {"a": action})]


def plan_fit_without_goal_fit(world, proposal_id):
    got = rows(world, "SELECT reviewer_hints FROM action_proposals WHERE proposal_id = :p",
               p=proposal_id)[0]["reviewer_hints"]["plan_fit"]
    return {k: v for k, v in got.items() if not k.startswith("goal_fit")}


@pytest.mark.parametrize("make_validator,stored,outcome", [
    (lambda: ScriptedPlanFit("plausible"), ("plausible", None), c.ANSWERED),
    (lambda: ScriptedPlanFit("implausible"), ("implausible", None), c.ANSWERED),
    (lambda: UnavailableFakePlanFit(), ("not_assessed", "failed"), c.FAILED),
], ids=["passes", "judged-not-matching", "always-fails"])
def test_a_listed_class_with_goal_fit_enforce_off_is_asked_and_counted_and_decides_as_unlisted(
        engagement_id, registry, make_validator, stored, outcome):
    """The shadow mode a class earns its numbers in. ``switch`` is ``goal_fit_enforce`` (Q1's
    switch; ``task_relation_enforce`` is P1's and plays no part here). With the class listed and
    the switch off: (a) the validator is really called, (b) each call is recorded, so ``n``
    accumulates, and (c) whatever the validator says -- including failing every time -- the
    decision, its reasons and the task relation stored with it are exactly those of the same
    proposal with the class outside the list, and no ``plan_check_failed`` arises. The one thing
    that differs is the goal fit stored: the answer, which is what the recording is for."""
    action = fresh_class()
    world = pipeline_world(engagement_id, registry, action)
    unlisted_validator, listed_validator = make_validator(), make_validator()

    unlisted = run(world, unlisted_validator, switch=False, listed=frozenset(), action=action)
    assert unlisted_validator.queries == [] and class_calls(action) == []

    first = run(world, listed_validator, switch=False, listed={action}, action=action)
    second = run(world, listed_validator, switch=False, listed={action}, action=action)

    assert len(listed_validator.queries) == 2                                     # (a)
    assert class_calls(action) == [outcome, outcome]                              # (b)
    row = table_row(action)
    assert (row["n"], row["failed"]) == (2, 2 if outcome == c.FAILED else 0)
    for listed in (first, second):                                                # (c)
        assert (listed.decision, listed.approval_reasons, listed.deny_reasons) == (
            unlisted.decision, unlisted.approval_reasons, unlisted.deny_reasons)
        assert "plan_check_failed" not in listed.approval_reasons
        assert listed.approval_reasons == () and listed.decision == "ALLOW"
        assert stored_goal_fit(world, listed.proposal_id) == stored
        assert (plan_fit_without_goal_fit(world, listed.proposal_id)
                == plan_fit_without_goal_fit(world, unlisted.proposal_id))
    assert stored_goal_fit(world, unlisted.proposal_id) == ("not_assessed", "class_not_enabled")


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


# -- admission is judged over a rolling window ---------------------------------------------------

def test_admission_reads_the_last_fifty_calls_and_not_the_whole_history():
    """200 good calls long ago, then 8 failures in the most recent calls: over everything that is
    8 in 218 (a Wilson bound near 7%, recommended); over the last 50 it is 8 in 50 (near 28%, not).
    The failures stay under the exit rule's 30%, so the class is still in the table."""
    action = fresh_class()
    record(action, [OK] * 200 + [BAD] * 5 + [OK] * 5 + [BAD] * 3 + [OK] * 5)
    row = table_row(action)
    assert (row["n"], row["n_total"]) == (50, 218)
    assert (row["failed"], row["failed_total"]) == (8, 8)
    assert c.wilson_upper(8, 218) <= c.ADMIT_UPPER < c.wilson_upper(8, 50)
    assert row["recommend_admission"] is False                  # the cumulative rate would say yes
    assert row["upper95"] == pytest.approx(c.wilson_upper(8, 50), abs=1e-4)


def test_old_failures_leave_the_window_and_the_class_can_be_recommended():
    action = fresh_class()
    record(action, [OK] * 40 + [BAD] * 4 + [OK] * 50)           # 4 failures, then 50 good
    row = table_row(action)
    assert (row["n"], row["failed"]) == (50, 0) and row["n_total"] == 94
    assert row["recommend_admission"] is True


def test_the_window_is_short_of_forty_calls_when_the_class_has_fewer():
    action = fresh_class()
    record(action, [OK] * 39)
    assert table_row(action)["recommend_admission"] is False
    record(action, [OK])
    assert table_row(action)["recommend_admission"] is True


# -- a clearing says why, and the database holds it to it -----------------------------------------

@pytest.mark.parametrize("reason", ["", "   ", "short", "x" * 501, "two\nlines of reason", None, 7])
def test_a_clearing_without_a_usable_reason_is_refused_in_the_code(reason):
    action = fresh_class()
    record(action, [BAD] * 30)
    with pytest.raises(ValueError):
        with global_policy_admin_scope() as conn:
            store.clear_suspension(conn, action, "operator-test", reason)
    assert live_suspension(action)


def test_the_database_refuses_a_clearing_without_a_reason_even_when_the_code_is_bypassed():
    action = fresh_class()
    record(action, [BAD] * 30)
    for statement in (
            "UPDATE goal_fit_suspensions SET cleared_at = now(), cleared_by = 'someone' "
            "WHERE action = :a AND cleared_at IS NULL",
            "UPDATE goal_fit_suspensions SET cleared_at = now(), cleared_by = 'someone', "
            "cleared_reason = '' WHERE action = :a AND cleared_at IS NULL"):
        with pytest.raises(DBAPIError):
            with global_policy_admin_scope() as conn:
                conn.execute(text(statement), {"a": action})
    assert live_suspension(action)


def test_the_reason_is_stored_with_the_clearing_and_cannot_be_edited_afterwards():
    action = fresh_class()
    record(action, [BAD] * 30)
    assert admin_clear(action, "alice", "  the goal template no longer names AD collection  ")
    with global_policy_admin_scope() as conn:
        row = conn.execute(text(
            "SELECT cleared_by, cleared_reason FROM goal_fit_suspensions WHERE action = :a"),
            {"a": action}).one()
    assert tuple(row) == ("alice", "the goal template no longer names AD collection")
    with global_policy_admin_scope() as conn:                   # the row is frozen once cleared
        try:
            conn.execute(text("UPDATE goal_fit_suspensions SET cleared_reason = 'another story' "
                              "WHERE action = :a"), {"a": action})
        except DBAPIError:
            pass
    with global_policy_admin_scope() as conn:
        assert conn.execute(text(
            "SELECT cleared_reason FROM goal_fit_suspensions WHERE action = :a"),
            {"a": action}).scalar_one() == "the goal template no longer names AD collection"


def test_the_runtime_role_cannot_write_a_reason_either():
    action = fresh_class()
    record(action, [BAD] * 30)
    with pytest.raises(DBAPIError):
        with get_engine().begin() as conn:
            conn.execute(text("UPDATE goal_fit_suspensions SET cleared_reason = 'x' * 20 "
                              "WHERE action = :a"), {"a": action})


# -- the tool checks who is clearing --------------------------------------------------------------

def test_the_tool_refuses_a_clearing_by_a_shared_account_or_under_another_name():
    from scripts import manage_goal_fit_classes as tool

    def problem(actor, identity):
        return tool.identity_problem(actor, identity) or ""

    assert tool.identity_problem(None, "alice") is None
    assert tool.identity_problem("alice", "alice") is None
    assert "shared account" in problem(None, "root")
    assert "shared account" in problem("root", "root")
    assert "not the login" in problem("bob", "alice")
    assert tool.identity_problem(None, "") is not None


def _loginuid_file(tmp_path, content):
    path = tmp_path / "loginuid"
    if content is not None:
        path.write_text(content)
    return str(path)


def _account(monkeypatch, tool, name):
    import pwd

    monkeypatch.setattr(tool.pwd, "getpwuid", lambda uid: pwd.struct_passwd(
        (name, "x", uid, uid, "", f"/home/{name}", "/bin/sh")))


def test_the_kernels_login_uid_is_the_identity_when_it_is_readable(tmp_path, monkeypatch):
    from scripts import manage_goal_fit_classes as tool

    _account(monkeypatch, tool, "gina")
    got = tool.resolve_identity(loginuid_path=_loginuid_file(tmp_path, "1000\n"),
                                environ={"SUDO_USER": "someone-else"})
    assert (got.name, got.source, got.unverified) == ("gina", "loginuid", False)


def test_an_environment_variable_cannot_change_who_the_kernel_says_is_logged_in(
        tmp_path, monkeypatch):
    """The point of reading ``/proc/self/loginuid``: ``SUDO_USER=somebody python ...`` forges the
    fallback and nothing else."""
    from scripts import manage_goal_fit_classes as tool

    _account(monkeypatch, tool, "gina")
    monkeypatch.setattr(tool.getpass, "getuser", lambda: "also-not-gina")
    path = _loginuid_file(tmp_path, "1000")
    for forged in ({"SUDO_USER": "mallory"}, {"SUDO_USER": "root"},
                   {"LOGNAME": "mallory", "USER": "mallory"}, {}):
        got = tool.resolve_identity(loginuid_path=path, environ=forged)
        assert got.name == "gina" and not got.unverified, forged


def test_a_login_uid_with_no_account_is_still_the_kernels_answer(tmp_path, monkeypatch):
    from scripts import manage_goal_fit_classes as tool

    def nobody(uid):
        raise KeyError(uid)

    monkeypatch.setattr(tool.pwd, "getpwuid", nobody)
    got = tool.resolve_identity(loginuid_path=_loginuid_file(tmp_path, "4242"), environ={})
    assert (got.name, got.source) == ("uid:4242", "loginuid")


@pytest.mark.parametrize("content", [None, "4294967295", "4294967295\n", "", "not a number",
                                     "-1"])
def test_without_a_usable_login_uid_it_falls_back_to_the_environment_and_says_so(
        tmp_path, monkeypatch, content):
    """Unreadable (no file), unset (4294967295: containers, some services), empty or garbage:
    the environment's answer, which can be forged, marked as unverified."""
    from scripts import manage_goal_fit_classes as tool

    monkeypatch.setattr(tool.getpass, "getuser", lambda: "dave")
    path = _loginuid_file(tmp_path, content)
    assert tool.read_loginuid(path) is None
    got = tool.resolve_identity(loginuid_path=path, environ={"SUDO_USER": "carol"})
    assert (got.name, got.source, got.unverified) == ("carol", "environment", True)
    got = tool.resolve_identity(loginuid_path=path, environ={})
    assert (got.name, got.source, got.unverified) == ("dave", "environment", True)


def test_a_directory_where_the_file_should_be_is_unreadable_not_an_error(tmp_path):
    from scripts import manage_goal_fit_classes as tool

    assert tool.read_loginuid(str(tmp_path)) is None


def _cleared_events(action):
    """The global audit events of the clearing, read as ``global_auditor`` (global-scope records
    are not visible to an engagement's role)."""
    with global_auditor_scope() as conn:
        return [row[0] for row in conn.execute(text(
            "SELECT payload FROM audit_log WHERE event_type = 'plan_fit.class_cleared' "
            "AND subject_id = :a ORDER BY audit_id"), {"a": action})]


def test_the_tool_clears_as_the_login_with_the_reason_and_refuses_otherwise(monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool

    def as_(name, source="loginuid"):
        monkeypatch.setattr(tool, "login_identity", lambda: tool.Identity(name, source))

    action = fresh_class()
    record(action, [BAD] * 30)
    as_("erin")
    assert tool._clear(action, "mallory", REASON, True) == 1             # another person's name
    assert tool._clear(action, None, None, True) == 1                    # no reason
    assert tool._clear(action, None, "too short", True) == 1
    assert tool._clear("NotAClass", None, REASON, True) == 1
    assert live_suspension(action)
    as_("root")
    assert tool._clear(action, None, REASON, True) == 1                  # a shared account
    as_("root", "environment")
    assert tool._clear(action, None, REASON, True) == 1                  # also on the weak path
    assert live_suspension(action) and not _cleared_events(action)
    as_("erin")
    assert tool._clear(action, "erin", REASON, True) == 0
    assert not live_suspension(action)
    with global_policy_admin_scope() as conn:
        row = conn.execute(text("SELECT cleared_by, cleared_reason FROM goal_fit_suspensions "
                                "WHERE action = :a"), {"a": action}).one()
    assert tuple(row) == ("erin", REASON)
    (event,) = _cleared_events(action)
    assert event["identity_unverified"] is False and event["identity_source"] == "loginuid"
    assert event["reason"] == REASON and event["action"] == action
    assert "refused" in capsys.readouterr().err


def test_a_clearing_by_the_environments_name_is_audited_as_identity_unverified(
        monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool

    action = fresh_class()
    record(action, [BAD] * 30)
    monkeypatch.setattr(tool, "login_identity", lambda: tool.Identity("heidi", "environment"))
    assert tool._clear(action, None, REASON, True) == 0
    (event,) = _cleared_events(action)
    assert event["identity_unverified"] is True and event["identity_source"] == "environment"
    assert "identity_unverified" in capsys.readouterr().out


def test_a_clearing_that_clears_nothing_leaves_no_audit_event(monkeypatch):
    from scripts import manage_goal_fit_classes as tool

    action = fresh_class()
    monkeypatch.setattr(tool, "login_identity", lambda: tool.Identity("ivan", "loginuid"))
    assert tool._clear(action, None, REASON, True) == 1                  # nothing to clear
    assert _cleared_events(action) == []


def test_the_tool_does_not_take_the_name_from_the_command_line_alone():
    import subprocess
    import sys

    got = subprocess.run(
        [sys.executable, "scripts/manage_goal_fit_classes.py", "clear", "--action", "a.b"],
        capture_output=True, text=True)
    assert got.returncode != 0 or "refused" in got.stderr


# -- the classes suspended in a period ------------------------------------------------------------

def test_the_period_lists_the_classes_suspended_and_how_each_ended():
    live, cleared = fresh_class(), fresh_class()
    record(live, [BAD] * 30)
    record(cleared, [BAD] * 30)
    admin_clear(cleared, "frank", "wording fixed and checked on thirty calls")
    with get_engine().begin() as conn:
        rows = {r_["action"]: r_ for r_ in store.suspensions_in_period(conn)}
    assert rows[live]["live"] is True and rows[cleared]["live"] is False
    assert rows[cleared]["cleared_by"] == "frank"
    lines = "\n".join(c.suspension_lines([rows[live], rows[cleared]], None))
    assert "all time" in lines and f"{live}: taken out" in lines and "STILL SUSPENDED" in lines
    assert "cleared" in lines and "by frank: wording fixed and checked on thirty calls" in lines
    assert "30 of 30 failed" in lines


def test_the_period_ends_at_since_and_an_empty_period_says_none():
    action = fresh_class()
    record(action, [BAD] * 30)
    with get_engine().begin() as conn:
        assert not [r_ for r_ in store.suspensions_in_period(conn, "2999-01-01")
                    if r_["action"] == action]
        assert [r_ for r_ in store.suspensions_in_period(conn, "2000-01-01")
                if r_["action"] == action]
    assert c.suspension_lines([], "2999-01-01") == [
        "classes suspended this period (since 2999-01-01): none"]


def test_both_reports_end_with_the_classes_suspended_this_period():
    from scripts import manage_goal_fit_classes as tool
    from scripts import plan_fit_report as report

    action = fresh_class()
    record(action, [BAD] * 30)
    with get_engine().begin() as conn:
        rows = store.suspensions_in_period(conn)
    text_ = tool.render([], rows, None)
    assert "classes suspended this period" in text_ and action in text_
    assert "window" in text_ and "total" in text_
    empty_summary = {"proposals": 0, "decided": 0, "decisions": {}, "with_plan_fit": 0,
                     "without_plan_fit": 0, "task_relation": {}, "task_relation_sub_cause": {},
                     "goal_fit": {}, "dp13_inside_task_target": report.rate(0, 0),
                     "dp13_rule_use": {"of_proposals": report.rate(0, 0),
                                       "of_matches": report.rate(0, 0)},
                     "dp13_proposals_on_network_tasks": {
                         "single_host_inside": report.rate(0, 0), "by_relation": {}},
                     "would_add": {}}
    out = report.render({"engagements": {"A": empty_summary}, "total": empty_summary,
                         "since": None, "class_suspensions": rows})
    assert "classes suspended this period" in out and action in out
    assert "classes suspended this period (all time): none" in report.render(
        {"engagements": {}, "total": empty_summary, "since": None, "class_suspensions": []})


# -- failure kinds: what the exit rule counts ------------------------------------------------------

def suspended(action):
    return live_suspension(action)


def test_thirty_transport_failures_do_not_suspend_a_class_and_neither_do_a_hundred():
    action = fresh_class()
    assert record(action, [TRA] * 30) == [None] * 30
    assert record(action, [TRA] * 70) == [None] * 70
    assert not suspended(action)


def test_thirty_refusal_failures_suspend_the_class_at_the_thirtieth():
    action = fresh_class()
    verdicts = record(action, [REF] * 30)
    assert verdicts[:29] == [None] * 29 and verdicts[29] is not None
    assert (verdicts[29].n, verdicts[29].failed) == (30, 30) and suspended(action)


def test_unclassified_failures_count_as_the_class_own():
    action = fresh_class()
    assert record(action, [UNC] * 29) == [None] * 29 and not suspended(action)
    assert record(action, [UNC])[-1] is not None and suspended(action)
    legacy = fresh_class()                               # a failure recorded with no kind at all
    assert record(legacy, [BAD] * 30)[-1] is not None and suspended(legacy)


def test_the_mixed_boundary_counts_only_refusal_and_unclassified_among_the_non_transport():
    """9 of 30 is 30%: stays. 10 of 30 is 33%: goes. Transport failures are in neither the
    numerator nor the denominator, so no number of them moves the line either way."""
    stays, goes, hidden = fresh_class(), fresh_class(), fresh_class()
    assert record(stays, [OK] * 21 + [REF] * 9) == [None] * 30
    assert record(goes, [OK] * 20 + [REF] * 9 + [UNC])[-1] is not None
    # the same 9 failures in 30 judgements with 60 outage failures interleaved: still stays
    mixed = []
    for item in [OK] * 21 + [REF] * 9:
        mixed += [item, TRA, TRA]
    assert record(hidden, mixed) == [None] * len(mixed)
    assert not suspended(stays) and not suspended(hidden) and suspended(goes)


def test_transport_failures_do_not_hide_a_class_that_really_fails():
    """Ten refusals among thirty judgements suspend the class however many transport failures
    are mixed in: they do not dilute the rate."""
    action = fresh_class()
    mixed = []
    for item in [OK] * 20 + [REF] * 10:
        mixed += [item, TRA]
    verdicts = record(action, mixed)
    assert verdicts[-1] is not None or any(v is not None for v in verdicts)
    assert suspended(action)


def test_a_transport_failure_is_recorded_but_is_not_in_the_window_or_the_judgements():
    action = fresh_class()
    record(action, [OK] * 40 + [TRA] * 10 + [REF])
    with get_engine().begin() as conn:
        assert store.recent_outcomes(conn, action)[:3] == ["failed", "answered", "answered"]
        assert len(store.recent_outcomes(conn, action)) == 41
    row = table_row(action)
    assert (row["n"], row["failed"]) == (41, 1)                 # judgements only
    assert (row["refusal_total"], row["transport_total"], row["unclassified_total"]) == (1, 10, 0)
    assert (row["n_total"], row["failed_total"]) == (41, 1)
    assert len(class_calls(action)) == 51                       # but every call is on record


def test_the_database_ties_a_kind_to_a_failure():
    action = fresh_class()
    insert = "INSERT INTO goal_fit_calls (action, outcome, failure_kind) VALUES (:a, "
    for statement in (
            insert + "'answered', 'refusal')",
            "INSERT INTO goal_fit_calls (action, outcome) VALUES (:a, 'failed')",
            insert + "'failed', 'novel')",
            insert + "'failed', '')"):
        with pytest.raises(DBAPIError):
            with get_engine().begin() as conn:
                conn.execute(text(statement), {"a": action})
    with get_engine().begin() as conn:
        for outcome, kind in ((c.ANSWERED, None), (c.FAILED, "refusal"), (c.FAILED, "transport"),
                              (c.FAILED, "unclassified")):
            conn.execute(text("INSERT INTO goal_fit_calls (action, outcome, failure_kind) "
                              "VALUES (:a, :o, :k)"), {"a": action, "o": outcome, "k": kind})
    with pytest.raises(ValueError):
        with get_engine().begin() as conn:
            store.record_call(conn, action, c.FAILED, "novel")


def test_through_the_pipeline_transport_failures_never_suspend_and_still_ask_a_person(
        engagement_id, registry):
    action = fresh_class()
    world = pipeline_world(engagement_id, registry, action)
    validator = UnavailableFakePlanFit("transport")
    outs = [run(world, validator, switch=True, listed={action}, action=action) for _ in range(32)]
    assert len(validator.queries) == 32 and not suspended(action)        # asked every time
    assert all(o.decision == "HUMAN_APPROVAL" and o.approval_reasons == ("plan_check_failed",)
               for o in outs)                                             # fail-closed, unchanged
    assert stored_goal_fit(world, outs[-1].proposal_id) == ("not_assessed", "failed")


def test_through_the_pipeline_refusals_suspend_the_class_and_the_next_one_is_quiet(
        engagement_id, registry):
    action = fresh_class()
    world = pipeline_world(engagement_id, registry, action)
    validator = UnavailableFakePlanFit("refusal")
    for _ in range(30):
        run(world, validator, switch=True, listed={action}, action=action)
    assert suspended(action) and len(validator.queries) == 30
    after = run(world, validator, switch=True, listed={action}, action=action)
    assert len(validator.queries) == 30 and after.approval_reasons == ()
    assert stored_goal_fit(world, after.proposal_id) == ("not_assessed", "class_suspended")


# -- a suspected outage of the validator ----------------------------------------------------------

def flush_window():
    """30 answered calls on a class of their own, so the last 30 calls of the whole table (which
    other tests also write to) are known."""
    record(fresh_class(), [OK] * 30)


def outage_rows():
    with get_engine().begin() as conn:
        return store.outages_in_period(conn)


def global_outage_events():
    with global_auditor_scope() as conn:
        return [row[0] for row in conn.execute(text(
            "SELECT payload FROM audit_log WHERE event_type = "
            "'plan_fit.validator_outage_suspected' ORDER BY audit_id"))]


def reviewed(kind, action):
    """One call through the pipeline's own recording function, as the pipeline makes it."""
    from control_plane.api import function_api

    fit = gf.GoalFit(GoalFitAssessment("v", "not_assessed", "failed"),
                     {"failure_kind": kind}, asked=True)
    return function_api._review_class(fit, action)


def test_more_than_half_of_the_last_thirty_calls_failing_in_transport_raises_one_alert():
    flush_window()
    action = fresh_class()
    before_rows, before_events = len(outage_rows()), len(global_outage_events())
    for _ in range(15):
        reviewed("transport", action)                      # 15 of 30: exactly half: nothing
    assert len(outage_rows()) == before_rows
    reviewed("transport", action)                          # 16 of 30: over half
    assert len(outage_rows()) == before_rows + 1
    assert len(global_outage_events()) == before_events + 1
    row = outage_rows()[-1]
    assert (row["window_n"], row["window_transport"]) == (30, 16)
    event = global_outage_events()[-1]
    assert (event["window_calls"], event["window_transport"]) == (30, 16)
    for _ in range(14):
        reviewed("transport", action)                      # the outage goes on: still one alert
    assert len(outage_rows()) == before_rows + 1 and not suspended(action)


def test_the_alert_suspends_nothing_and_the_classes_involved_stay_in():
    flush_window()
    classes_ = [fresh_class() for _ in range(3)]
    for i in range(24):
        reviewed("transport", classes_[i % 3])
    assert all(not suspended(a) for a in classes_)


def test_fewer_than_thirty_calls_or_other_kinds_do_not_raise_the_alert():
    flush_window()
    before = len(outage_rows())
    action = fresh_class()
    for _ in range(14):
        reviewed("transport", action)
    for kind in ("refusal", "unclassified"):
        for _ in range(16):
            reviewed(kind, fresh_class())
    assert len(outage_rows()) == before                    # 14 transport of 46: never over half
    flush_window()
    for _ in range(15):
        reviewed("transport", action)
        reviewed("refusal", fresh_class())
    assert len(outage_rows()) == before                    # alternating: exactly half, not over


def test_a_new_alert_follows_a_recovery():
    flush_window()
    before = len(outage_rows())
    action = fresh_class()
    for _ in range(16):
        reviewed("transport", action)
    flush_window()                                         # the service is back
    for _ in range(16):
        reviewed("transport", action)
    assert len(outage_rows()) == before + 2


def test_the_runtime_role_cannot_rewrite_or_remove_an_alert():
    flush_window()
    for _ in range(16):
        reviewed("transport", fresh_class())
    for statement in ("UPDATE goal_fit_outage_suspicions SET window_transport = 0",
                      "DELETE FROM goal_fit_outage_suspicions"):
        with pytest.raises(DBAPIError):
            with get_engine().begin() as conn:
                conn.execute(text(statement))


def test_both_reports_end_with_the_validator_outages_of_the_period():
    from scripts import manage_goal_fit_classes as tool
    from scripts import plan_fit_report as report

    flush_window()
    for _ in range(16):
        reviewed("transport", fresh_class())
    with get_engine().begin() as conn:
        rows = store.outages_in_period(conn)
    text_ = tool.render([], [], None, rows)
    assert "validator outage suspected this period (all time):" in text_
    assert "16 of the last 30 calls failed in transport" in text_
    empty = {"proposals": 0, "decided": 0, "decisions": {}, "with_plan_fit": 0,
             "without_plan_fit": 0, "task_relation": {}, "task_relation_sub_cause": {},
             "goal_fit": {}, "dp13_inside_task_target": report.rate(0, 0),
             "dp13_rule_use": {"of_proposals": report.rate(0, 0), "of_matches": report.rate(0, 0)},
             "dp13_proposals_on_network_tasks": {
                 "single_host_inside": report.rate(0, 0), "by_relation": {}}, "would_add": {}}
    out = report.render({"engagements": {}, "total": empty, "since": None,
                         "class_suspensions": [], "validator_outages": rows})
    assert "validator outage suspected this period (all time):" in out
    assert "validator outage suspected this period (all time): none" in report.render(
        {"engagements": {}, "total": empty, "since": None, "class_suspensions": [],
         "validator_outages": []})


# -- every look at the admission report is recorded -----------------------------------------------

def _as(monkeypatch, tool, name="judy", source="loginuid"):
    monkeypatch.setattr(tool, "login_identity", lambda: tool.Identity(name, source))


def _class_line(output, action):
    (line,) = [ln for ln in output.splitlines() if ln.startswith(action + " ")]
    return line.split()


def _views(action):
    with get_engine().begin() as conn:
        return [tuple(r_) for r_ in conn.execute(text(
            "SELECT window_n, window_failed, upper95, viewer, identity_unverified "
            "FROM goal_fit_report_views WHERE action = :a ORDER BY view_id"), {"a": action})]


def test_each_run_of_the_report_is_a_look_and_the_count_accumulates(monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool

    _as(monkeypatch, tool)
    action = fresh_class()
    record(action, [OK] * 12 + [BAD] * 3)
    assert tool._report(False, None) == 0
    first = _class_line(capsys.readouterr().out, action)
    looks_at = ["class", "window", "failed", "upper95", "total", "tot.fail", "refusal", "unclass",
                "transp", "looks", "n@first"].index("looks")
    assert first[looks_at] == "1" and first[looks_at + 1] == "15"       # first look: n was 15
    record(action, [OK] * 20)
    assert tool._report(False, None) == 0
    second = _class_line(capsys.readouterr().out, action)
    assert second[looks_at] == "2" and second[looks_at + 1] == "15"     # the first n is kept
    assert second[1] == "35"                                            # the window has moved on
    assert tool._report(True, None) == 0
    shown = json.loads(capsys.readouterr().out)
    row = next(r_ for r_ in shown["classes"] if r_["action"] == action)
    assert (row["looks"], row["n_at_first_look"], shown["this_run_recorded"]) == (3, 15, True)
    assert [v[:2] for v in _views(action)] == [(15, 3), (35, 3), (35, 3)]


def test_a_look_records_the_window_and_who_looked_by_the_same_path_as_a_clearing(
        monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool

    action = fresh_class()
    record(action, [OK] * 40)
    _as(monkeypatch, tool, "kim", "loginuid")
    tool._report(False, None)
    _as(monkeypatch, tool, "lee", "environment")
    tool._report(False, None)
    capsys.readouterr()
    views = _views(action)
    assert len(views) == 2, views
    (n1, f1, u1, who1, weak1), (n2, f2, u2, who2, weak2) = views
    assert (n1, f1, who1, weak1) == (40, 0, "kim", False)
    assert (n2, f2, who2, weak2) == (40, 0, "lee", True)
    assert u1 == pytest.approx(c.wilson_upper(0, 40), abs=1e-4) == pytest.approx(u2, abs=1e-4)


def test_the_report_does_not_change_the_list_a_suspension_or_a_call(monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool

    _as(monkeypatch, tool)
    live, spare = fresh_class(), fresh_class()
    record(live, [REF] * 30)                       # suspended
    record(spare, [OK] * 45)

    def snapshot():
        with global_policy_admin_scope() as conn:
            return {
                "suspensions": conn.execute(text(
                    "SELECT suspension_id, action, cleared_at, cleared_by, cleared_reason "
                    "FROM goal_fit_suspensions ORDER BY suspension_id")).all(),
                "calls": conn.execute(text("SELECT count(*), max(call_id) "
                                           "FROM goal_fit_calls")).all(),
                "layers": conn.execute(text(
                    "SELECT count(*), max(id), count(*) FILTER (WHERE active) "
                    "FROM policy_layers")).all(),
                "outages": conn.execute(text(
                    "SELECT count(*) FROM goal_fit_outage_suspicions")).all(),
            }

    before = snapshot()
    assert tool._report(False, None) == 0 and tool._report(True, "2000-01-01") == 0
    capsys.readouterr()
    assert snapshot() == before
    assert suspended(live)


def test_a_look_that_cannot_be_written_still_prints_the_report_and_says_so(monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool

    _as(monkeypatch, tool)
    action = fresh_class()
    record(action, [OK] * 41)
    tool._report(False, None)
    capsys.readouterr()                                                # one look is on record

    def refuse(*args, **kwargs):
        raise RuntimeError("the table is not writable")

    monkeypatch.setattr(store, "record_views", refuse)
    assert tool._report(False, None) == 0                              # it is still a report
    out = capsys.readouterr().out
    assert "THIS RUN WAS NOT RECORDED" in out
    line = _class_line(out, action)
    assert line[line.index("41") + 0] == "41"                          # the numbers are all there
    assert "RECOMMEND ADMISSION" in out
    assert len(_views(action)) == 1                                    # and nothing was written
    assert tool._report(True, None) == 0
    assert json.loads(capsys.readouterr().out)["this_run_recorded"] is False

    monkeypatch.setattr(store, "view_counts", refuse)                  # nothing can be read either
    assert tool._report(False, None) == 0
    out = capsys.readouterr().out
    assert "THIS RUN WAS NOT RECORDED" in out and _class_line(out, action)[10] == "?"


def test_the_record_of_looks_is_append_only_and_only_the_runtime_role_writes_it():
    action = fresh_class()
    with get_engine().begin() as conn:
        store.record_views(conn, [{"action": action, "n": 0, "failed": 0, "upper95": 1.0}],
                           "mia", False)
    for statement in ("UPDATE goal_fit_report_views SET window_n = 0",
                      "DELETE FROM goal_fit_report_views"):
        with pytest.raises(DBAPIError):
            with get_engine().begin() as conn:
                conn.execute(text(statement))
    for statement in ("SELECT * FROM goal_fit_report_views",
                      "INSERT INTO goal_fit_report_views (action, window_n, window_failed, "
                      "upper95, viewer, identity_unverified) VALUES ('a.b', 0, 0, 1, 'x', false)"):
        with pytest.raises(DBAPIError):
            with global_policy_admin_scope() as conn:
                conn.execute(text(statement))
    with pytest.raises(ValueError):
        with get_engine().begin() as conn:
            store.record_views(conn, [], "", False)
    with pytest.raises(DBAPIError):                                     # a view names its viewer
        with get_engine().begin() as conn:
            conn.execute(text("INSERT INTO goal_fit_report_views (action, window_n, window_failed, "
                              "upper95, viewer, identity_unverified) "
                              "VALUES (:a, 0, 0, 1, '', false)"), {"a": action})


# -- transport failures are shown per class, with their share, in both reports -------------------

def test_the_class_table_counts_transport_failures_and_their_share_of_all_calls():
    action = fresh_class()
    record(action, [OK] * 30 + [REF] * 3 + [TRA] * 10 + [UNC] * 2)
    row = table_row(action)
    assert (row["n_total"], row["failed_total"]) == (35, 5)             # judgements only
    assert (row["refusal_total"], row["unclassified_total"], row["transport_total"]) == (3, 2, 10)
    assert row["calls_all"] == 45 and row["transport_share"] == pytest.approx(10 / 45, abs=1e-4)
    quiet = fresh_class()
    record(quiet, [OK] * 3)
    assert table_row(quiet)["transport_share"] == 0.0 and table_row(quiet)["transport_total"] == 0


def test_both_reports_show_a_classes_transport_failures_and_share_and_decide_nothing(
        monkeypatch, capsys):
    from scripts import manage_goal_fit_classes as tool
    from scripts import plan_fit_report as report

    action = fresh_class()
    record(action, [OK] * 40 + [TRA] * 10)
    shown = None
    with global_policy_admin_scope() as conn:
        shown = tool.render(store.class_table(conn, ()), [], None, [], {}, True)
    line = next(ln for ln in shown.splitlines() if ln.startswith(action + " ")).split()
    header = next(ln for ln in shown.splitlines() if ln.startswith("class")).split()
    assert line[header.index("transp")] == "10"
    assert line[header.index("transp%")] == "20.0%"                     # 10 of 50 calls
    rows = report.collect_class_calls()
    mine = next(r_ for r_ in rows if r_["action"] == action)
    assert (mine["transport_total"], mine["transport_share"]) == (10, 0.2)
    text_ = "\n".join(c.class_call_lines(rows))
    assert action in text_ and "20.0%" in text_
    # the admission recommendation is the 40 judgements, untouched by the 10 transport failures
    assert table_row(action)["recommend_admission"] is True
