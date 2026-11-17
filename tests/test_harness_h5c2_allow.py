"""D69 H5c2 (A): the real shape of an answer, with a proposal that is ALLOWed and reaches a sandbox.

Until here no test of H5 ran the real pipeline past a DENY (the test database has a neutral
baseline), so ``harness/result_summary.py`` had only been shown the shapes its authors expected.
Here an engagement layer allows ``network.scan``, the Worker is scripted, the sandbox is a stand-in,
and the pipeline answers. Each test names the shape it saw as ``(decision, run_id, evidence_id,
failure)`` and asserts what ``executed_state`` and the summary say about it, on the real rows.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from control_plane.state.db import engagement_scope
from harness.exit_codes import StopReason
from harness.result_summary import (
    STATE_DEDUPLICATED,
    STATE_EXECUTED,
    STATE_NOT_EXECUTED,
    STATE_UNKNOWN_OUTCOME,
    VALID_SUMMARIES,
    build_summary,
    executed_state,
)
from tests.test_harness_h5c1_support import (
    count_rows,
    make_world,
    proposal_rows,
    task_rows,
)
from tests.test_harness_h5c2_support import (
    RaisingSandbox,
    allowed,
    an_unavailable_sandbox,
    drive2,
    make_rig2,
)
from tool_gateway.sandbox import NotStarted


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _shape(outcome) -> tuple:
    return (outcome.decision, outcome.run_id is not None, outcome.evidence_id is not None,
            outcome.failure)


def _completion_audits(engagement_id: str) -> list[str]:
    with engagement_scope(engagement_id) as conn:
        return [str(r[0]) for r in conn.execute(text(
            "SELECT payload FROM audit_log WHERE event_type = 'task.completed'"))]


# -- executed ----------------------------------------------------------------------------------


def test_an_allowed_proposal_is_executed_with_a_run_and_evidence_and_is_counted(world):
    with allowed(world.engagement_id):
        rig = make_rig2(world)
        result = drive2(rig, no_progress=1)

    (outcome,) = rig.adapter.outcomes
    assert _shape(outcome) == ("ALLOW", True, True, None)
    assert executed_state(outcome.run_id, outcome.evidence_id, outcome.failure) == STATE_EXECUTED
    assert build_summary(outcome) == "executed"
    assert rig.sandbox.calls == 1
    ((_, status, _, _, _, summary),) = task_rows(world.engagement_id)
    assert (status, summary) == ("completed", "executed")
    ((_, _, stage, decision, _),) = proposal_rows(world.engagement_id)
    assert decision == "ALLOW" and stage == "recorded"
    assert count_rows(world.engagement_id, "tool_runs") == 1
    # an executed task is progress (with a limit of one round without it, the loop is still
    # running when the round cap stops it) and is counted under no name: the five counters are
    # the outcomes that are not an execution
    assert result.reason is StopReason.CAP_REACHED
    assert rig.counters.snapshot() == dict.fromkeys(rig.counters.snapshot(), 0)


# -- deduplicated ------------------------------------------------------------------------------


def test_a_second_task_for_the_same_work_is_a_dedup_hit_and_not_an_unknown_outcome(world):
    """Two tasks of one round name the same work, with two keys (``h5:<task>:1`` each). The pipeline
    finds the earlier run: a run id, **no evidence id**, the failure ``dedup_hit``."""
    with allowed(world.engagement_id):
        rig = make_rig2(world, tasks_for_call=lambda call: [world.task(5), world.task(5)])
        result = drive2(rig, no_progress=1)

    first, second = rig.adapter.outcomes
    assert _shape(first) == ("ALLOW", True, True, None)
    assert _shape(second) == ("ALLOW", True, False, "dedup_hit")
    assert second.run_id == first.run_id                  # the run it found, not a new one
    assert executed_state(second.run_id, second.evidence_id, second.failure) == STATE_DEDUPLICATED
    assert executed_state(second.run_id, second.evidence_id, None) == STATE_UNKNOWN_OUTCOME
    assert build_summary(second) == "dedup_hit"
    assert rig.sandbox.calls == 1 and count_rows(world.engagement_id, "tool_runs") == 1
    assert sorted(row[5] for row in task_rows(world.engagement_id)) == ["dedup_hit", "executed"]
    assert rig.counters.count("deduplicated") == 1
    assert rig.counters.count("unknown_outcome") == 0
    assert result.reason is StopReason.CAP_REACHED


def test_the_same_key_asked_again_answers_from_the_rows_and_runs_nothing_again(world):
    """Not a dedup: a repeated call with the key of a recorded proposal reads it back, with the run
    **and** the evidence, and starts nothing."""
    with allowed(world.engagement_id):
        rig = make_rig2(world)
        drive2(rig)
        ((task_id, *_),) = task_rows(world.engagement_id)
        task = world.task(5)
        again = rig.adapter.propose(
            world.engagement_id, task_id, world.proposal(task, None),
            rig.adapter.load_policy(world.engagement_id), f"h5:{task_id}:1")

    first, repeated = rig.adapter.outcomes
    assert _shape(repeated) == ("ALLOW", True, True, None) and again is repeated
    assert repeated.run_id == first.run_id and repeated.evidence_id == first.evidence_id
    assert rig.sandbox.calls == 1 and count_rows(world.engagement_id, "tool_runs") == 1
    assert len(proposal_rows(world.engagement_id)) == 1


# -- unknown_outcome ---------------------------------------------------------------------------


def test_a_sandbox_that_fails_after_the_run_began_is_an_unknown_outcome(world):
    marker = "SANDBOX-TEXT-5c2f19"
    with allowed(world.engagement_id):
        rig = make_rig2(world, sandbox=an_unavailable_sandbox(marker))
        result = drive2(rig, no_progress=1)

    (outcome,) = rig.adapter.outcomes
    assert outcome.decision == "ALLOW" and outcome.run_id is not None
    assert outcome.evidence_id is None and outcome.failure not in (None, "dedup_hit")
    assert executed_state(outcome.run_id, outcome.evidence_id, outcome.failure) == \
        STATE_UNKNOWN_OUTCOME
    assert build_summary(outcome) == "unknown_outcome"
    ((_, status, _, _, _, summary),) = task_rows(world.engagement_id)
    assert (status, summary) == ("completed", "unknown_outcome")
    assert rig.counters.count("unknown_outcome") == 1
    assert rig.sandbox.calls == 1
    assert result.reason is StopReason.CAP_REACHED


# -- not_executed ------------------------------------------------------------------------------


def test_a_denied_proposal_has_neither_id_and_is_not_executed(world):
    """No layer allows it: the neutral baseline denies, and nothing reaches the sandbox."""
    rig = make_rig2(world)

    result = drive2(rig, no_progress=1)

    (outcome,) = rig.adapter.outcomes
    assert outcome.decision == "DENY" and outcome.run_id is None and outcome.evidence_id is None
    assert executed_state(outcome.run_id, outcome.evidence_id, outcome.failure) == \
        STATE_NOT_EXECUTED
    assert build_summary(outcome) == "DENY"
    assert rig.sandbox.calls == 0 and count_rows(world.engagement_id, "tool_runs") == 0
    ((_, _, _, _, _, summary),) = task_rows(world.engagement_id)
    assert summary == "DENY"
    assert result.reason is StopReason.CAP_REACHED


def test_an_allowed_proposal_the_sandbox_refused_before_it_started_is_not_executed(world):
    """``NotStarted`` is a refusal before any container: no run id, no evidence id, and the failure
    is the fixed code ``sandbox_not_started``; the sandbox's own ``reason`` text is not carried."""
    with allowed(world.engagement_id):
        rig = make_rig2(world, sandbox=RaisingSandbox(NotStarted("docker_unreachable", "x")))
        drive2(rig, no_progress=1)

    (outcome,) = rig.adapter.outcomes
    assert _shape(outcome) == ("ALLOW", False, False, "sandbox_not_started")
    assert executed_state(outcome.run_id, outcome.evidence_id, outcome.failure) == \
        STATE_NOT_EXECUTED
    assert build_summary(outcome) == "not_executed"
    ((_, _, _, _, _, summary),) = task_rows(world.engagement_id)
    assert summary == "not_executed"
    assert rig.counters.count("not_executed") == 1 and rig.sandbox.calls == 1


# -- the summary is a word of the closed list, never the failure's text ------------------------


def _bad_target(world, marker):
    def make(task, task_id):
        return ProposedAction(
            action=task.action,
            target={"logical_identity": {"type": "ip", "value": marker}},
            authorization={"source": "engagement_scope", "scope_object_id": world.scope_id},
            discovery={"source": "explicit_scope"}, task_id=task_id)
    return make


def _with_reason(world, marker):
    def make(task, task_id):
        return ProposedAction(
            action=task.action, target=dict(task.target),
            authorization={"source": "engagement_scope", "scope_object_id": world.scope_id},
            discovery={"source": "explicit_scope"}, task_id=task_id, reason=marker)
    return make


def test_the_summary_never_holds_the_text_of_a_failure_in_any_of_three_places(world):
    """Where text of a Worker or of an exception can come back in an outcome, each given a marker:
    (1) the Worker's target string, in the failure of a refused proposal (``function_api.py:589``);
    (2) the text of the sandbox's exception, in the failure of a run whose outcome is unknown
    (``dispatch.py:482``); (3) the Worker's own ``reason`` text, on a proposal that is executed."""
    markers = {"target": "WORKER-TARGET-7b21c4", "sandbox": "SANDBOX-TEXT-5c2f19",
               "reason": "WORKER-REASON-31d8e0"}
    rigs = {}

    rig = make_rig2(world, make_proposal=_bad_target(world, markers["target"]))
    drive2(rig, no_progress=1)
    rigs["target"] = rig

    with allowed(world.engagement_id):
        rig = make_rig2(world, sandbox=an_unavailable_sandbox(markers["sandbox"]),
                        tasks_for_call=lambda call: [world.task(6)])
        drive2(rig, no_progress=1)
        rigs["sandbox"] = rig

        rig = make_rig2(world, make_proposal=_with_reason(world, markers["reason"]),
                        tasks_for_call=lambda call: [world.task(7)])
        drive2(rig, no_progress=1)
        rigs["reason"] = rig

    # the summary of each is a word of the closed list that does not hold the text ...
    expected = {"target": "DENY:other", "sandbox": "unknown_outcome", "reason": "executed"}
    for place, rig in rigs.items():
        assert len(rig.adapter.outcomes) == 1, place
        summary = build_summary(rig.adapter.outcomes[0])
        assert summary == expected[place], (place, summary)
        assert summary in VALID_SUMMARIES
    # ... and the text really is in the outcome in the first two places, so the test looks at
    # the right thing
    assert markers["target"] in str(rigs["target"].adapter.outcomes[0].failure)
    assert markers["sandbox"] in str(rigs["sandbox"].adapter.outcomes[0].failure)
    written = [row[5] for row in task_rows(world.engagement_id)]
    assert sorted(written) == sorted(expected.values()), written
    for marker in markers.values():
        assert not any(marker in summary for summary in written)
        assert not any(marker in line for line in _completion_audits(world.engagement_id))
