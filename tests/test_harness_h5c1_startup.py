"""D69 H5c1: ``live_tasks`` and the start-up check on the real tables (plan items 50, 57 and 81).

``live_tasks`` is what the loop's start-up check reads: an engagement that already holds a queued,
claimed or running task is refused (code 10) before anything is planned or claimed. ``query_state``
returns the first 50 tasks of *any* state, oldest first, so a read that does not filter by state in
the SQL lets 60 old completed tasks hide the one queued task behind them -- the check would pass
(fail open). These tests make that state for real: 60 completed tasks, then one queued task.

* the 60 + 1 test, and the limit that is refused rather than cut short (H5-56, H5-57);
* H5-17: a new loop, an empty ledger, one live task: code 10 and no one is called;
* H5-25: the check itself writes no row;
* H5-29: the check comes before the first claim, measured on the ``tasks`` rows.
"""

from __future__ import annotations

import pytest

from harness import loop_adapter
from harness.exit_codes import EXIT_CODE, EXIT_FAULT_OUTSIDE_LIST, EXIT_STARTUP_REFUSED, StopReason
from harness.loop_adapter import LIVE_STATUSES, LiveTasksNotReadable
from harness.ports import LiveTask
from tests.test_harness_h5c1_support import (
    claimed_task,
    completed_task,
    count_rows,
    drive,
    make_rig,
    make_world,
    proposal_rows,
    queued_task,
    task_rows,
)


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


def _count_calls(monkeypatch, name: str) -> list:
    """Wrap ``harness.loop_adapter.<name>`` so that its calls are counted and still made."""
    calls: list = []
    real = getattr(loop_adapter, name)

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(loop_adapter, name, spy)
    return calls


# -- live_tasks --------------------------------------------------------------------------------


def test_live_tasks_gives_the_queued_and_the_claimed_task_and_not_the_completed_one(world):
    completed_task(world, 13)                  # (claim takes the oldest queued task: oldest first)
    claimed = claimed_task(world, 12)
    queued = queued_task(world, 11)
    adapter = make_rig(world).adapter

    live = adapter.live_tasks(world.engagement_id)

    assert {(t.task_id, t.status) for t in live} == {(queued, "queued"), (claimed, "claimed")}
    assert all(isinstance(t, LiveTask) for t in live)


def test_live_tasks_of_an_engagement_with_none_is_empty(world):
    completed_task(world, 14)
    assert make_rig(world).adapter.live_tasks(world.engagement_id) == ()


def test_live_tasks_asks_for_the_three_live_states_with_a_filter_and_a_limit(world, monkeypatch):
    seen = _count_calls(monkeypatch, "query_state")
    rig = make_rig(world, live_task_limit=7)

    rig.adapter.live_tasks(world.engagement_id)

    assert LIVE_STATUSES == ("queued", "claimed", "running")
    (call,) = seen
    assert tuple(call["task_status"]) == ("queued", "claimed", "running")
    assert call["task_limit"] == 8                      # the limit and one more, to see an overflow


def test_sixty_completed_tasks_and_then_one_queued_task_are_refused_with_code_10(world):
    """Plan item 81: the old completed tasks fill the first page; the queued one is behind them."""
    for n in range(1, 61):
        completed_task(world, n)
    queued = queued_task(world, 100)
    assert count_rows(world.engagement_id, "tasks") == 61
    rig = make_rig(world, live_task_limit=50)           # 50 is query_state's own default page
    before = task_rows(world.engagement_id)

    result = drive(rig.adapter)

    assert result.reason is StopReason.STARTUP_REFUSED
    assert EXIT_CODE[result.reason] == EXIT_STARTUP_REFUSED
    assert rig.supervisor.plan_calls == 0 and rig.worker.work_calls == 0
    assert task_rows(world.engagement_id) == before
    assert [t.task_id for t in rig.adapter.live_tasks(world.engagement_id)] == [queued]


def test_more_live_tasks_than_the_limit_is_refused_and_never_returned_cut_short(world):
    for n in range(41, 45):
        queued_task(world, n)
    rig = make_rig(world, live_task_limit=3)

    with pytest.raises(LiveTasksNotReadable):
        rig.adapter.live_tasks(world.engagement_id)

    # the loop meets it as a fault: nothing is planned, claimed or cleaned up
    before = task_rows(world.engagement_id)
    result = drive(rig.adapter)
    assert result.reason is StopReason.FAULT_OUTSIDE_LIST
    assert EXIT_CODE[result.reason] == EXIT_FAULT_OUTSIDE_LIST
    assert rig.supervisor.plan_calls == 0
    assert task_rows(world.engagement_id) == before


def test_exactly_as_many_live_tasks_as_the_limit_are_all_returned(world):
    ids = {queued_task(world, n) for n in range(51, 54)}
    live = make_rig(world, live_task_limit=3).adapter.live_tasks(world.engagement_id)
    assert {t.task_id for t in live} == ids


# -- the start-up check on the real rows -------------------------------------------------------


@pytest.mark.parametrize("state", ["queued", "claimed"])
def test_a_new_loop_with_a_live_task_on_the_engagement_ends_with_code_10_and_calls_no_one(
        world, state, monkeypatch):
    """H5-17 (plan item 57): no restart; a new loop, an empty ledger, one live task."""
    live = queued_task(world, 31) if state == "queued" else claimed_task(world, 31)
    proposed = _count_calls(monkeypatch, "propose_action")
    rig = make_rig(world)

    result = drive(rig.adapter)

    assert result.reason is StopReason.STARTUP_REFUSED
    assert EXIT_CODE[result.reason] == EXIT_STARTUP_REFUSED == 10
    assert len(proposed) == 0                           # zero propose_action calls
    assert rig.reviewer.calls == 0                      # zero Reviewer calls
    assert rig.supervisor.plan_calls == 0 and rig.worker.work_calls == 0
    assert proposal_rows(world.engagement_id) == []
    assert [row[0] for row in task_rows(world.engagement_id)] == [live]


def test_the_start_up_check_writes_no_row(world):
    """H5-25: the check on the real database reads and writes nothing."""
    claimed = claimed_task(world, 33)
    queued = queued_task(world, 32)
    rig = make_rig(world)
    before = task_rows(world.engagement_id)
    audit_before = _audit_count(world.engagement_id)

    result = drive(rig.adapter)

    assert result.reason is StopReason.STARTUP_REFUSED
    assert task_rows(world.engagement_id) == before    # status, owner, lease, updated_at, summary
    assert {row[0] for row in before} == {queued, claimed}
    assert _audit_count(world.engagement_id) == audit_before
    assert count_rows(world.engagement_id, "action_proposals") == 0


def test_the_start_up_check_comes_before_the_first_claim_on_the_real_rows(world):
    """H5-29: no ``tasks`` row is changed to ``claimed`` or given an owner by a refused start."""
    queued = queued_task(world, 34)
    rig = make_rig(world)

    result = drive(rig.adapter)

    assert result.reason is StopReason.STARTUP_REFUSED
    rows = {row[0]: row for row in task_rows(world.engagement_id)}
    _, status, owner, lease, _, summary = rows[queued]
    assert (status, owner, lease, summary) == ("queued", None, None, None)
    # and nothing was planned either: no second task exists
    assert list(rows) == [queued]
    assert rig.supervisor.plan_calls == 0


def test_an_engagement_with_no_live_task_is_not_refused(world):
    rig = make_rig(world)
    result = drive(rig.adapter)
    assert result.reason is not StopReason.STARTUP_REFUSED
    assert rig.supervisor.plan_calls == 1


def _audit_count(engagement_id: str) -> int:
    from sqlalchemy import text

    from control_plane.state.db import engagement_scope
    with engagement_scope(engagement_id) as conn:
        return conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one()
