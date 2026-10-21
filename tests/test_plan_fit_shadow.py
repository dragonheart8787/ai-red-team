"""The shadow report (D68 S6): what the switches would ask for, read from what was stored.

Three things are tested. The restatement of the policy's rules (``shadow.would_ask``) equals the
real policy over every signal and every pair of switches -- it is the one thing in the report that
could drift unseen. The summary is right on rows whose answer is known. And the report, run against
the real database, counts what was really decided, in the engagement it is pointed at and no other.

Opts out of the enforced run (``switch_as_published``): the report is about decisions made with the
switches *off*, and a seam that forced them on would remove the very proposals it counts.
"""

from __future__ import annotations

import itertools
import json
import re
import uuid
from pathlib import Path

import pytest

from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from agents.fake.fake_plan_fit import ScriptedPlanFit
from control_plane.plan_fit import relation as r
from control_plane.plan_fit import shadow
from control_plane.policy.engine import evaluate
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from scripts import plan_fit_report as rep
from tests.task_support import task_for
from tests.test_approved_dispatch import CIDR, HOST, _proposal
from tests.test_pipeline_stages import FakeSandbox
from tests.test_plan_fit_policy import BASE

pytestmark = pytest.mark.usefixtures("switch_as_published")
REPO = Path(__file__).resolve().parent.parent

PLAN_REASONS = set(shadow.ALL_REASONS)


# ---------------------------------------------------------------------------------------------
# the restatement equals the policy
# ---------------------------------------------------------------------------------------------

def stored_signals():
    relations = [(v, s) for v, subs in r.SUB_CAUSES.items() for s in subs]
    goals = [None, ("plausible", None), ("implausible", None), ("insufficient_context", None),
             ("not_assessed", "failed"), ("not_assessed", "disabled"),
             ("not_assessed", "not_applicable"), ("not_assessed", None), ("not_assessed", "tired"),
             ("plausible", "failed"), ("probably_fine", None), ([], None), (None, None)]
    out = [None, "matches_task", 7, [], {}, {"version": "plan_fit_v1"}]
    for (value, sub), goal in itertools.product(relations, goals):
        stored = {"version": "plan_fit_v1", "task_relation": value, "sub_cause": sub}
        if goal is not None:
            stored.update(goal_fit=goal[0], goal_fit_cause=goal[1])
        out.append(stored)
    out.append({"version": "plan_fit_v1", "task_relation": "probably_fine", "sub_cause": None,
                "goal_fit": "implausible", "goal_fit_cause": None})
    return out


def policy_reasons(stored, task, goal):
    request = {**BASE, "policy": {**BASE["policy"], "task_relation_enforce": task,
                                  "goal_fit_enforce": goal}}
    if stored is not None:
        request = {**request, "plan_fit": r.policy_signal(stored)}
    got = evaluate(request)
    assert got.engine_error is None, got
    return tuple(sorted(set(got.approval_reasons) & PLAN_REASONS))


@pytest.mark.parametrize("task,goal", [(False, False), (True, False), (False, True), (True, True)])
def test_the_restatement_equals_the_real_policy_for_every_stored_signal(task, goal):
    signals = stored_signals()
    assert len(signals) > 130
    for stored in signals:
        asked = tuple(sorted(shadow.would_ask(stored, task_enforce=task, goal_enforce=goal)))
        assert asked == policy_reasons(stored, task, goal), (task, goal, stored)


def test_a_decision_with_no_stored_plan_fit_asks_for_nothing_under_both():
    assert shadow.would_ask(None, task_enforce=True, goal_enforce=True) == ()


def test_the_reasons_the_report_knows_are_the_reasons_the_policy_can_give():
    """If the policy gained a fourth plan-fit reason this list would be stale; the grid above
    would not notice a reason it never produced."""
    seen = set()
    for stored in stored_signals():
        seen |= set(policy_reasons(stored, True, True))
    assert seen == PLAN_REASONS


# ---------------------------------------------------------------------------------------------
# the summary, on rows whose answer is known
# ---------------------------------------------------------------------------------------------

def plan(relation="matches_task", sub=None, goal=None):
    stored = {"version": "plan_fit_v1", "task_relation": relation, "sub_cause": sub}
    if goal:
        stored.update(goal_fit=goal[0], goal_fit_cause=goal[1])
    return stored


def row(decision, stored):
    return {"decision": decision, "pipeline_stage": "recorded", "plan_fit": stored}


ROWS = [
    row("ALLOW", plan()),
    row("ALLOW", plan(goal=("plausible", None))),
    row("ALLOW", plan(goal=("implausible", None))),
    row("ALLOW", plan(goal=("not_assessed", "failed"))),
    row("ALLOW", plan("no_task", "task_id_absent")),
    row("ALLOW", plan("differs_from_task", "same_action_target_inside_task_target")),
    row("ALLOW", plan("differs_from_task", "different_target")),
    row("HUMAN_APPROVAL", plan("no_task", "task_id_absent", ("implausible", None))),
    row("DENY", plan("no_task", "task_id_absent")),
    row("ALLOW", None),
    {"decision": None, "pipeline_stage": "received", "plan_fit": None},
]


def test_the_summary_counts_what_the_rows_say():
    s = rep.summarize(ROWS, [])
    assert (s["proposals"], s["decided"]) == (11, 10)
    assert s["decisions"] == {"ALLOW": 8, "HUMAN_APPROVAL": 1, "DENY": 1}
    assert (s["with_plan_fit"], s["without_plan_fit"]) == (9, 1)
    assert s["task_relation"] == {"matches_task": 4, "no_task": 3, "differs_from_task": 2}
    assert s["task_relation_sub_cause"] == {
        "no_task/task_id_absent": 3,
        "differs_from_task/same_action_target_inside_task_target": 1,
        "differs_from_task/different_target": 1}
    assert s["goal_fit"]["plausible/-"] == 1 and s["goal_fit"]["implausible/-"] == 2
    assert s["goal_fit"]["not_assessed/failed"] == 1
    assert s["goal_fit"]["absent (decided before Q1)"] == 5
    assert s["dp13_inside_task_target"]["k"] == 1 and s["dp13_inside_task_target"]["n"] == 2


def test_the_summary_says_how_many_allows_each_switch_would_send_to_a_human():
    s = rep.summarize(ROWS, [])["would_add"]
    # ALLOW with a plan_fit: 7 rows (the ALLOW with none is not counted: it asks for nothing)
    assert s["p1_only"]["allow_decisions"] == 7
    assert s["p1_only"]["would_become_human_approval"]["k"] == 3        # no_task + 2 differs
    assert s["p1_only"]["by_reason"] == {"proposal_without_task": 1, "proposal_outside_task": 2}
    assert s["q1_only"]["would_become_human_approval"]["k"] == 2        # implausible + failed
    assert s["q1_only"]["by_reason"] == {"plan_implausible": 1, "plan_check_failed": 1}
    assert s["both"]["would_become_human_approval"]["k"] == 5
    # the already-asked row gains a reason and adds no approval
    assert s["q1_only"]["reasons_gained_by_already_asked"] == {"plan_implausible": 1}
    assert s["p1_only"]["reasons_gained_by_already_asked"] == {"proposal_without_task": 1}


def test_a_deny_is_never_counted_as_something_a_switch_would_add():
    only_deny = rep.summarize([row("DENY", plan("no_task", "task_id_absent"))], [])
    for scenario in only_deny["would_add"].values():
        assert scenario["allow_decisions"] == 0
        assert scenario["would_become_human_approval"]["k"] == 0


def test_the_validator_events_become_provenance_and_latency():
    events = [
        {"validator_id": "v1", "validator": {"prompt_sha256": "a" * 64},
         "call": {"latency_seconds": 2.0, "input_tokens": 100, "output_tokens": 4}},
        {"validator_id": "v1", "validator": {"prompt_sha256": "a" * 64},
         "call": {"latency_seconds": 4.0, "input_tokens": 100, "output_tokens": 6}},
        {"validator_id": "control-plane", "error_type": "KeyError"},
    ]
    v = rep.summarize([], events)["validator"]
    assert v["events"] == 3 and v["ids"] == {"v1": 2, "control-plane": 1}
    assert v["prompts"]["a" * 12] == 2 and v["errors"] == {"KeyError": 1}
    assert v["calls"] == 2 and v["latency_median"] == 3.0 and v["latency_p95"] == 4.0
    assert v["tokens"] == {"input": 200, "output": 10}


def test_the_totals_add_counts_and_recompute_rates_rather_than_averaging_them():
    a = rep.summarize(ROWS, [])
    b = rep.summarize([row("ALLOW", plan("no_task", "task_id_absent"))], [])
    total = rep.combine({"A": a, "B": b})
    assert total["proposals"] == 12 and total["engagements"] == 2
    assert total["decisions"]["ALLOW"] == 9
    both = total["would_add"]["p1_only"]
    assert both["allow_decisions"] == 8 and both["would_become_human_approval"]["k"] == 4
    assert both["would_become_human_approval"]["n"] == 8


# ---------------------------------------------------------------------------------------------
# against the real database
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id}


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"))


def decide(world, validator, *, task="matching", host=HOST):
    import dataclasses

    from control_plane.api.function_api import propose_action

    proposal = _proposal(world, host=host)
    eid = world["engagement_id"]
    if task == "matching":
        proposal = dataclasses.replace(proposal, task_id=task_for(eid, proposal))
    elif task == "other":
        other = _proposal(world, host="10.61.0.99")
        proposal = dataclasses.replace(proposal, task_id=task_for(eid, other))
    out = propose_action(
        engagement_id=eid, proposal=proposal, reviewer=HonestFakeReviewer(), policy=_policy(),
        agent_id="worker-1", sandbox=FakeSandbox(), network_allowlist=[CIDR],
        plan_fit_validator=validator)
    assert out.decision == "ALLOW"            # the switches are off: nothing is asked of a human
    return out


def test_the_report_counts_what_was_really_decided(world):
    decide(world, ScriptedPlanFit("plausible"), host="10.61.0.5")
    decide(world, ScriptedPlanFit("implausible"), host="10.61.0.6")
    decide(world, ScriptedPlanFit("insufficient_context"), host="10.61.0.7")
    decide(world, None, task="none", host="10.61.0.8")
    decide(world, ScriptedPlanFit("plausible"), task="other", host="10.61.0.9")

    s = rep.collect(world["engagement_id"])
    assert (s["proposals"], s["decided"], s["with_plan_fit"]) == (5, 5, 5)
    assert s["decisions"] == {"ALLOW": 5}
    assert s["task_relation"] == {"matches_task": 3, "no_task": 1, "differs_from_task": 1}
    assert s["goal_fit"] == {"plausible/-": 1, "implausible/-": 1, "insufficient_context/-": 1,
                             "not_assessed/disabled": 1, "not_assessed/not_applicable": 1}
    w = s["would_add"]
    assert w["p1_only"]["would_become_human_approval"]["k"] == 2
    assert w["p1_only"]["by_reason"] == {"proposal_without_task": 1, "proposal_outside_task": 1}
    assert w["q1_only"]["would_become_human_approval"]["k"] == 2
    assert w["q1_only"]["by_reason"] == {"plan_implausible": 1, "plan_unverified": 1}
    assert w["both"]["would_become_human_approval"]["k"] == 4
    assert s["validator"]["events"] == 5 and s["validator"]["ids"]["scripted-plan-fit"] == 3


def test_a_row_decided_before_the_signal_is_counted_apart(world):
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope

    decide(world, None, task="none")
    with engagement_scope(world["engagement_id"]) as conn:
        conn.execute(text(
            "UPDATE action_proposals SET reviewer_hints = reviewer_hints - 'plan_fit'"))
    s = rep.collect(world["engagement_id"])
    assert (s["with_plan_fit"], s["without_plan_fit"]) == (0, 1)
    assert all(w["would_become_human_approval"]["k"] == 0 for w in s["would_add"].values())


def test_the_report_of_one_engagement_does_not_see_another(world, engagement_factory):
    other_id, other_registry = engagement_factory()
    scope = f"SCOPE-{uuid.uuid4().hex[:8]}"
    other_registry.scope(scope_object_id=scope, type="cidr", value=CIDR,
                         allowed_actions=["network.scan"])
    decide({"engagement_id": other_id, "scope_id": scope}, None, task="none")
    decide(world, None, task="none", host="10.61.0.5")
    decide(world, None, task="none", host="10.61.0.6")
    assert rep.collect(world["engagement_id"])["proposals"] == 2
    assert rep.collect(other_id)["proposals"] == 1


def test_since_narrows_the_window(world):
    decide(world, None, task="none")
    assert rep.collect(world["engagement_id"], since="2000-01-01T00:00:00Z")["proposals"] == 1
    assert rep.collect(world["engagement_id"], since="2999-01-01T00:00:00Z")["proposals"] == 0


def test_the_command_line_needs_named_engagements_and_prints_json(world, capsys):
    with pytest.raises(SystemExit) as stop:
        rep.main([])
    assert stop.value.code == 2
    decide(world, ScriptedPlanFit("implausible"))
    assert rep.main(["--engagement", world["engagement_id"], "--json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["total"]["proposals"] == 1
    assert printed["engagements"][world["engagement_id"]]["goal_fit"] == {"implausible/-": 1}
    assert rep.main(["--engagement", world["engagement_id"]]) == 0
    text = capsys.readouterr().out
    assert "if enabled" in text and "Nothing here is a decision" in text


def test_the_report_only_reads():
    source = (REPO / "scripts" / "plan_fit_report.py").read_text()
    assert not re.search(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b", source), (
        "the report must not write")


def test_dp13_as_asked_counts_proposals_for_a_task_on_a_network():
    network = {"task_target_kind": "cidr"}
    rows = [
        {**row("ALLOW", plan()), **network},                                        # same network
        {**row("ALLOW", plan("differs_from_task", "same_action_target_inside_task_target")),
         **network},                                                                # one host in it
        {**row("ALLOW", plan("differs_from_task", "same_action_target_inside_task_target")),
         **network},
        {**row("ALLOW", plan("differs_from_task", "different_target")), **network},  # elsewhere
        {**row("ALLOW", plan("differs_from_task", "same_action_target_inside_task_target")),
         "task_target_kind": "ip"},                                      # not a network task
    ]
    got = rep.summarize(rows, [])["dp13_proposals_on_network_tasks"]
    assert (got["single_host_inside"]["k"], got["single_host_inside"]["n"]) == (2, 4)
    assert got["by_relation"] == {"matches_task": 1, "differs_from_task": 3}
    total = rep.combine({"A": rep.summarize(rows, []), "B": rep.summarize(rows[:2], [])})
    assert total["dp13_proposals_on_network_tasks"]["single_host_inside"]["n"] == 4 + 2
    assert total["dp13_proposals_on_network_tasks"]["single_host_inside"]["k"] == 2 + 1


def test_the_report_joins_the_task_of_each_proposal(world):
    decide(world, None, task="matching", host="10.61.0.5")
    s = rep.collect(world["engagement_id"])
    assert s["dp13_proposals_on_network_tasks"]["single_host_inside"]["n"] == 0   # an ip task


def test_a_host_proposed_inside_a_network_task_is_counted_from_the_real_rows(world):
    import dataclasses

    from agents.base_agent import ProposedTask
    from control_plane.api.function_api import create_task, propose_action
    from control_plane.state.db import engagement_scope

    eid = world["engagement_id"]
    task = ProposedTask(
        goal="Scan the network for open ports", action="network.scan",
        scope_object_id=world["scope_id"],
        target={"logical_identity": {"type": "cidr", "value": CIDR}})
    with engagement_scope(eid) as conn:
        task_id = create_task(conn, engagement_id=eid, task=task, created_by="supervisor")
    proposal = dataclasses.replace(_proposal(world, host=HOST), task_id=task_id)
    out = propose_action(
        engagement_id=eid, proposal=proposal, reviewer=HonestFakeReviewer(), policy=_policy(),
        agent_id="worker-1", sandbox=FakeSandbox(), network_allowlist=[CIDR])
    assert out.decision == "ALLOW"
    got = rep.collect(eid)["dp13_proposals_on_network_tasks"]
    assert (got["single_host_inside"]["k"], got["single_host_inside"]["n"]) == (1, 1)
    assert got["by_relation"] == {"differs_from_task": 1}
