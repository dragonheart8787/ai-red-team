"""D69 H5a2: what happens to one claimed task (``harness/loop.py``, ``harness/worker_step.py``).

Every claimed task is completed exactly once on every path the loop controls -- a Worker that
failed, an action outside the allowlist, an engagement that stopped accepting work, a proposal that
went through, a cap that interrupted -- and the summary it is completed with comes from
``build_summary`` (or is ``not_run``) and goes through the one guarded function. The model is
called once per task and never asked again.
"""

from __future__ import annotations

from collections import Counter

import pytest

from harness import loop
from harness.exit_codes import StopReason
from harness.idempotency import derive_key
from harness.ports import PlannedTask, PlanResult, WorkResult
from harness.signals import SignalFlag
from tests.harness_fakes import FakeOutcome, FakePorts, drive

# -- every claimed task is completed exactly once ----------------------------------------------


def _worker_failed(ports: FakePorts) -> dict:
    ports.work_script = [WorkResult(None, True)]
    return {}


def _action_outside_the_allowlist(ports: FakePorts) -> dict:
    ports.work_script = [WorkResult({"action": "ad.collect"}, False, "ad.collect")]
    return {}


def _engagement_stopped_accepting_work(ports: FakePorts) -> dict:
    ports.after("work", lambda p, engagement_id, task_id, snapshot: p.closed.add(engagement_id))
    return {}


def _proposal_went_through(ports: FakePorts) -> dict:
    return {}


def _cap_interrupted(ports: FakePorts) -> dict:
    return {"max_calls": 2}         # plan, work -- and the proposal is the third call


@pytest.mark.parametrize("path", [
    _worker_failed, _action_outside_the_allowlist, _engagement_stopped_accepting_work,
    _proposal_went_through, _cap_interrupted,
], ids=lambda f: f.__name__.lstrip("_"))
def test_every_claimed_task_is_completed_exactly_once(path):
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    limits = path(ports)

    run = drive(ports, max_rounds=1, **limits)

    created = [task_id for _, task_id in ports.created]
    completions = Counter(task_id for _, task_id, _ in ports.completed)
    assert len(created) == 2
    assert completions == Counter(created)                      # each one, and each exactly once
    assert max(completions.values()) == 1
    assert run.result.reason in (StopReason.CAP_REACHED,)       # a controlled stop in every case


def test_the_task_of_each_path_is_completed_with_the_summary_of_that_path():
    expected = {
        "worker failed": ("not_run", _worker_failed),
        "action outside the allowlist": ("not_run", _action_outside_the_allowlist),
        "engagement stopped accepting work": ("not_run", _engagement_stopped_accepting_work),
        "proposal went through": ("executed", _proposal_went_through),
    }
    for label, (summary, path) in expected.items():
        ports = FakePorts(("ENG-1",), tasks_per_plan=1)
        limits = path(ports)

        drive(ports, max_rounds=1, **limits)

        assert [s for _, _, s in ports.completed] == [summary], label


def test_a_cap_that_interrupts_a_claimed_task_completes_it_as_not_run_and_stops_with_code_13():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)

    run = drive(ports, max_rounds=5, max_calls=2)

    first, second = (task_id for _, task_id in ports.created)
    assert ports.count("work") == 1 and ports.count("propose") == 0
    assert ports.completed == [("ENG-1", first, "not_run"), ("ENG-1", second, "not_run")]
    assert run.result.reason is StopReason.CAP_REACHED
    assert run.counters.count("not_run") == 2


def test_a_cap_met_before_the_work_call_completes_the_claimed_task_as_not_run():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    run = drive(ports, max_rounds=5, max_calls=1)

    task_id = ports.created[0][1]
    assert ports.count("claim") == 1 and ports.count("work") == 0
    assert ports.completed == [("ENG-1", task_id, "not_run")]
    assert run.result.reason is StopReason.CAP_REACHED


# -- the Worker is asked once -------------------------------------------------------------------


@pytest.mark.parametrize("answer", [
    WorkResult(None, True), WorkResult(None, False), WorkResult({"action": "ad.collect"}, False,
                                                                "ad.collect"),
], ids=["refusal", "no proposal", "action outside the allowlist"])
def test_work_is_called_exactly_once_per_task_also_when_the_worker_returns_nothing(answer):
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.work_script = [answer, answer, answer]

    drive(ports, max_rounds=1)

    assert ports.count("work") == 1
    assert ports.count("propose") == 0


def test_a_worker_that_declines_is_not_counted_as_an_allowlist_refusal():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.work_script = [WorkResult(None, True)]

    run = drive(ports, max_rounds=1)

    assert run.refusals.total == 0
    assert run.counters.count("not_run") == 1


@pytest.mark.parametrize("action", ["ad.collect", "web.get", "code.scan", "", None, 5])
def test_a_proposal_with_an_action_outside_the_allowlist_is_not_proposed(action):
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.work_script = [WorkResult({"action": action}, False, action)]

    run = drive(ports, max_rounds=1)

    task_id = ports.created[0][1]
    assert ports.count("propose") == 0
    assert ports.count("load_policy") == 0
    assert run.refusals.count(side="proposal") == 1
    assert ports.completed == [("ENG-1", task_id, "not_run")]
    assert run.counters.count("not_run") == 1


@pytest.mark.parametrize("action", ["network.scan", "network.recon"])
def test_a_proposal_on_the_allowlist_is_proposed(action):
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.work_script = [WorkResult({"action": action}, False, action)]

    run = drive(ports, max_rounds=1)

    assert ports.count("propose") == 1
    assert run.refusals.total == 0


# -- claim, plan -------------------------------------------------------------------------------


def test_a_claim_that_returns_none_ends_the_claim_loop_without_a_fault():
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    ports.claim_none.add("ENG-1")

    run = drive(ports, max_rounds=2, no_progress=100)

    assert run.result.reason is StopReason.CAP_REACHED
    assert ports.count("claim") == 2                            # one per round, no more
    assert ports.count("work") == 0
    assert len(ports.completed) == 4                            # the four unclaimed, as not_run


@pytest.mark.parametrize("planned", [
    PlanResult((), "plan_refused"), PlanResult((), "plan_returned_none"), PlanResult(),
], ids=["refused", "returned none", "empty plan"])
def test_a_planning_failure_or_an_empty_plan_leaves_nothing_to_claim_and_is_not_a_fault(planned):
    ports = FakePorts(("ENG-1",))
    ports.plan_script = [planned]

    run = drive(ports, max_rounds=1)

    assert ports.count("claim") == 0
    assert ports.completed == []
    assert run.result.reason is StopReason.CAP_REACHED


def test_a_failed_plan_that_still_created_a_task_does_not_lose_track_of_it():
    ports = FakePorts(("ENG-1",))
    ports.plan_script = [PlanResult((PlannedTask("T-X"),), "plan_refused")]

    run = drive(ports, max_rounds=1)

    assert ports.count("claim") == 0                            # a failed plan has nothing to claim
    assert ports.completed == [("ENG-1", "T-X", "not_run")]     # but the task is cleaned up
    assert run.result.reason is StopReason.CAP_REACHED


# -- the key and the policy --------------------------------------------------------------------


def test_the_idempotency_key_of_a_proposal_is_derive_key_of_the_task_id_and_1():
    ports = FakePorts(("ENG-1", "ENG-2"), tasks_per_plan=2)

    drive(ports, max_rounds=1)

    keys = [(p["task_id"], p["idempotency_key"]) for p in ports.proposed]
    assert len(keys) == 4
    assert all(key == derive_key(task_id, 1) for task_id, key in keys)
    assert all(key == f"h5:{task_id}:1" for task_id, key in keys)
    assert len({key for _, key in keys}) == 4                   # four tasks, four different keys


def test_a_proposal_gets_the_policy_read_for_it_and_the_proposal_the_worker_made():
    ports = FakePorts(("ENG-1", "ENG-2"), tasks_per_plan=2)

    drive(ports, max_rounds=1)

    assert ports.count("load_policy") == ports.count("propose") == 4
    for proposed, policy in zip(ports.proposed, ports.policies, strict=True):
        assert proposed["policy"] is policy
        assert proposed["policy"].engagement_id == proposed["engagement_id"]
        assert proposed["proposal"]["task"] == proposed["task_id"]


def test_the_policy_is_read_after_the_worker_answered_and_the_checks_passed():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    drive(ports, max_rounds=1)

    order = ports.order()
    assert order.index("work") < order.index("accepts_work", order.index("work")) \
        < order.index("load_policy") < order.index("propose") < order.index("complete")


# -- the counters follow the ids of the outcome -------------------------------------------------


@pytest.mark.parametrize("outcome, summary, counted", [
    (FakeOutcome("ALLOW"), "not_executed", "not_executed"),
    (FakeOutcome("ALLOW", "network_in_use_by_another_engagement"), "not_executed",
     "not_executed"),
    (FakeOutcome("ALLOW", None, "RUN-1", None), "unknown_outcome", "unknown_outcome"),
    (FakeOutcome("ALLOW", "dispatch_in_progress_or_unknown_outcome", "RUN-1"),
     "unknown_outcome", "unknown_outcome"),
    (FakeOutcome("ALLOW", "dedup_hit", "RUN-1", None), "dedup_hit", "deduplicated"),
    (FakeOutcome("DENY", "tool_run_timed_out", "RUN-1", None), "unknown_outcome",
     "unknown_outcome"),
    (FakeOutcome("ALLOW", None, "RUN-1", "EV-1"), "executed", None),
    (FakeOutcome("ALLOW", "tool_run_timed_out", "RUN-1", "EV-1"), "executed", None),
    (FakeOutcome("DENY", "capability_refused"), "DENY:capability_refused", None),
    (FakeOutcome("HUMAN_APPROVAL"), "HUMAN_APPROVAL", None),
], ids=[
    "allow, no ids", "allow, no ids, a failure code", "allow, a run id only",
    "allow, a run id only, a code", "dedup hit", "deny with a run id only", "executed",
    "executed with a timeout code", "deny, no ids", "human approval, no ids",
])
def test_the_counters_follow_the_ids_of_the_outcome_and_not_its_decision(
        outcome, summary, counted):
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.outcome_script = [outcome]

    run = drive(ports, max_rounds=1)

    task_id = ports.created[0][1]
    assert ports.completed == [("ENG-1", task_id, summary)]
    expected = dict.fromkeys(("skipped_engagement", "not_run", "not_executed",
                              "unknown_outcome", "deduplicated"), 0)
    if counted is not None:
        expected[counted] = 1
    assert run.counters.snapshot() == expected


def test_free_text_in_an_outcome_reaches_neither_the_summary_nor_the_counters():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    ports.outcome_script = [FakeOutcome(
        "ALLOW", "invalid fqdn 'evil.example' in url 'http://evil.example/x'", "RUN-1", None)]

    run = drive(ports, max_rounds=1)

    assert [summary for _, _, summary in ports.completed] == ["unknown_outcome"]
    assert "evil.example" not in repr(run.result)


# -- the guard on the one function that writes a summary ------------------------------------------


@pytest.mark.parametrize("summary", [
    "free text MODEL-WORDS-7c1f", "", "ALLOW:other", "executed:x", None,
])
def test_complete_refuses_a_summary_outside_the_closed_set_and_writes_nothing(summary):
    ports = FakePorts(("ENG-1",))

    with pytest.raises(ValueError):
        loop._complete(ports, "ENG-1", "T-1", summary)

    assert ports.count("complete") == 0


@pytest.mark.parametrize("summary", [
    "not_run", "executed", "unknown_outcome", "not_executed", "dedup_hit", "DENY",
    "DENY:capability_refused", "HUMAN_APPROVAL:other",
])
def test_complete_writes_a_summary_of_the_closed_set_and_not_run_among_them(summary):
    ports = FakePorts(("ENG-1",))

    loop._complete(ports, "ENG-1", "T-1", summary)

    assert ports.completed == [("ENG-1", "T-1", summary)]


def test_a_summary_the_builder_made_outside_the_closed_set_is_refused_before_it_is_written(
        monkeypatch):
    monkeypatch.setattr(loop, "build_summary", lambda outcome: "free text MODEL-WORDS-7c1f")
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)

    run = drive(ports, max_rounds=1)

    assert run.result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert ports.count("complete") == 0


# -- the stop flag: only at safe points -----------------------------------------------------------


@pytest.mark.parametrize("where", ["work", "propose", "complete"])
def test_a_stop_flag_set_in_the_middle_of_a_task_is_seen_after_the_task_is_completed(where):
    ports = FakePorts(("ENG-1",), tasks_per_plan=2)
    flag = SignalFlag()
    ports.after(where, lambda p, *args: flag.set())

    run = drive(ports, max_rounds=5, flag=flag)

    first, second = (task_id for _, task_id in ports.created)
    assert ports.completed == [("ENG-1", first, "executed"), ("ENG-1", second, "not_run")]
    assert ports.count("propose") == 1
    assert ports.count("claim") == 1                            # the flag is read before a claim
    assert run.result.reason is StopReason.SIGNAL_OR_ONCE


def test_a_stop_flag_that_is_already_set_stops_before_the_first_round():
    ports = FakePorts(("ENG-1",))
    flag = SignalFlag()
    flag.set()

    run = drive(ports, flag=flag)

    assert ports.log == []
    assert run.result.rounds == 0
    assert run.result.reason is StopReason.SIGNAL_OR_ONCE


def test_a_stop_flag_is_read_between_engagements_and_before_a_claim():
    ports = FakePorts(("ENG-1", "ENG-2"), tasks_per_plan=2)
    flag = SignalFlag()
    ports.after("plan", lambda p, engagement_id, snapshot: flag.set())

    run = drive(ports, max_rounds=5, flag=flag)

    assert [call[1] for call in ports.calls("plan")] == ["ENG-1"]    # ENG-2 is never visited
    assert ports.count("claim") == 0
    assert len(ports.completed) == 2                                # ENG-1's two tasks, as not_run
    assert all(summary == "not_run" for _, _, summary in ports.completed)
    assert run.result.reason is StopReason.SIGNAL_OR_ONCE


def test_a_stop_flag_set_during_the_last_task_of_a_round_stops_at_the_end_of_that_round():
    ports = FakePorts(("ENG-1",), tasks_per_plan=1)
    flag = SignalFlag()
    ports.after("complete", lambda p, *args: flag.set())

    run = drive(ports, max_rounds=5, flag=flag)

    assert run.result.rounds == 1
    assert ports.count("propose") == 1
    assert run.result.reason is StopReason.SIGNAL_OR_ONCE
