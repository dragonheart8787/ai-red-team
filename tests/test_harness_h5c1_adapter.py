"""D69 H5c1: the real adapter's ports one by one, on the test database (loop_adapter.py).

The scripted roles, the fake sandbox and the helpers are in ``tests/test_harness_h5c1_support.py``.
What is shown here, each against real rows:

* the construction guards (the window size is required, a sandbox and a reviewer are required);
* ``accepts_work`` follows the engagement's status and kill switch;
* H5-16: ``take_snapshot`` offers the real registry's candidates through the allowlist filter, and
  ``plan`` uses the candidates of the snapshot it is given -- it does not read the registry again;
* no port leaves a connection checked out (the pool's count is the same before and after);
* ``claim`` and ``complete`` write through the control plane's own functions.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from control_plane.orchestrator.engagement import pause_engagement
from control_plane.policy.merge import EffectivePolicy
from control_plane.state.db import engagement_scope, get_engine
from harness.loop_adapter import LoopAdapter, LoopSnapshot
from tests.test_harness_h5c1_support import (
    WINDOW,
    FakeSandbox,
    ScriptedSupervisor,
    ScriptedWorker,
    kill,
    make_rig,
    make_world,
    task_rows,
)


@pytest.fixture
def world(engagement_id, registry):
    return make_world(engagement_id, registry)


# -- construction ------------------------------------------------------------------------------


def _kwargs(world, **override):
    rig = make_rig(world)
    base = dict(enrolment=rig.adapter, supervisor=rig.supervisor, worker=rig.worker,
                reviewer=rig.reviewer, sandbox=rig.sandbox, objective="o", window_limit=WINDOW)
    base.update(override)
    return base


def test_the_window_size_is_required_and_has_no_default(world):
    kwargs = _kwargs(world)
    del kwargs["window_limit"]
    with pytest.raises(TypeError):
        LoopAdapter(**kwargs)


@pytest.mark.parametrize("bad", [0, -1, True, "25", None, 2.5], ids=repr)
def test_a_window_size_that_is_not_a_positive_integer_is_refused(world, bad):
    with pytest.raises(ValueError):
        LoopAdapter(**_kwargs(world, window_limit=bad))


@pytest.mark.parametrize("missing", ["sandbox", "reviewer"])
def test_an_adapter_without_a_sandbox_or_a_reviewer_is_refused(world, missing):
    with pytest.raises(ValueError):
        LoopAdapter(**_kwargs(world, **{missing: None}))


def test_a_live_task_limit_that_is_not_a_positive_integer_is_refused(world):
    for bad in (0, -3, True, "3"):
        with pytest.raises(ValueError):
            LoopAdapter(**_kwargs(world, live_task_limit=bad))


# -- accepts_work ------------------------------------------------------------------------------


def test_an_active_engagement_accepts_work_and_a_paused_or_killed_one_does_not(world):
    adapter = make_rig(world).adapter
    assert adapter.accepts_work(world.engagement_id) is True
    with engagement_scope(world.engagement_id) as conn:
        pause_engagement(conn, engagement_id=world.engagement_id, actor="test", reason="test")
    assert adapter.accepts_work(world.engagement_id) is False
    kill(world.engagement_id)
    assert adapter.accepts_work(world.engagement_id) is False


def test_an_engagement_that_does_not_exist_does_not_accept_work(world):
    assert make_rig(world).adapter.accepts_work("ENG-NOBODY-MADE-THIS") is False


# -- H5-16: the candidates of the real registry, through the allowlist -------------------------


def test_take_snapshot_offers_the_real_registrys_candidates_filtered_to_the_allowlist(world):
    both, other, mixed = (f"SCOPE-{uuid.uuid4().hex[:8]}" for _ in range(3))
    world.registry.scope(scope_object_id=both, type="cidr", value="10.83.0.0/24",
                         allowed_actions=["network.scan", "network.recon"])
    world.registry.scope(scope_object_id=other, type="cidr", value="10.84.0.0/24",
                         allowed_actions=["web.post", "ad.collect"])
    world.registry.scope(scope_object_id=mixed, type="cidr", value="10.85.0.0/24",
                         allowed_actions=["network.scan", "web.post"])
    adapter = make_rig(world).adapter

    snapshot = adapter.take_snapshot(world.engagement_id)

    assert isinstance(snapshot, LoopSnapshot)
    offered = {c.scope_object_id: c.allowed_actions for c in snapshot.candidates}
    # a scope object left with no allowed action is not offered; the others keep only those
    assert offered == {
        world.scope_id: ("network.scan",),
        both: ("network.scan", "network.recon"),
        mixed: ("network.scan",),
    }
    for candidate in snapshot.candidates:
        assert set(candidate.allowed_actions) <= {"network.scan", "network.recon"}, candidate


def test_a_snapshot_is_of_the_engagement_it_was_taken_for_and_has_the_given_window(world):
    snapshot = make_rig(world).adapter.take_snapshot(world.engagement_id)
    assert snapshot.engagement_id == world.engagement_id
    assert snapshot.round.limit == WINDOW


def test_plan_uses_the_candidates_of_its_snapshot_and_does_not_read_the_registry_again(
        world):
    rig = make_rig(world)
    snapshot = rig.adapter.take_snapshot(world.engagement_id)
    late = f"SCOPE-{uuid.uuid4().hex[:8]}"
    world.registry.scope(scope_object_id=late, type="cidr", value="10.86.0.0/24",
                         allowed_actions=["network.scan"])

    rig.adapter.plan(world.engagement_id, snapshot)

    (seen,) = rig.supervisor.seen_candidates
    assert seen == snapshot.candidates
    assert late not in {c.scope_object_id for c in seen}
    # the registry did change in between: a new snapshot has it
    later = rig.adapter.take_snapshot(world.engagement_id)
    assert late in {c.scope_object_id for c in later.candidates}


def test_work_is_given_the_candidates_of_the_snapshot_too(world):
    rig = make_rig(world)
    snapshot = rig.adapter.take_snapshot(world.engagement_id)
    planned = rig.adapter.plan(world.engagement_id, snapshot)
    task_id = rig.adapter.claim(world.engagement_id)
    assert task_id == planned.created[0].task_id
    world.registry.scope(scope_object_id=f"SCOPE-{uuid.uuid4().hex[:8]}", type="cidr",
                         value="10.87.0.0/24", allowed_actions=["network.scan"])

    result = rig.adapter.work(world.engagement_id, task_id, snapshot)

    assert result.refusal is False and result.action == "network.scan"
    assert rig.worker.seen == [(task_id, snapshot.candidates)]


def test_a_snapshot_of_another_engagement_or_none_is_refused(world, engagement_factory):
    other, _ = engagement_factory()
    rig = make_rig(world)
    snapshot = rig.adapter.take_snapshot(world.engagement_id)
    with pytest.raises(TypeError):
        rig.adapter.plan(other, snapshot)
    with pytest.raises(TypeError):
        rig.adapter.plan(world.engagement_id, object())
    assert rig.supervisor.plan_calls == 0


# -- claim, complete, work, policy -------------------------------------------------------------


def test_claim_takes_one_queued_task_for_the_worker_and_complete_writes_its_summary(world):
    rig = make_rig(world)
    assert rig.adapter.claim(world.engagement_id) is None              # nothing queued
    planned = rig.adapter.plan(world.engagement_id,
                               rig.adapter.take_snapshot(world.engagement_id))
    (created,) = planned.created

    claimed = rig.adapter.claim(world.engagement_id)

    assert claimed == created.task_id
    ((task_id, status, owner, lease, _, summary),) = task_rows(world.engagement_id)
    assert (task_id, status, owner, summary) == (claimed, "claimed", "scripted-worker", None)
    assert lease is not None
    rig.adapter.complete(world.engagement_id, claimed, "not_run")
    ((_, status, _, _, _, summary),) = task_rows(world.engagement_id)
    assert (status, summary) == ("completed", "not_run")


def test_work_for_a_task_this_adapter_did_not_plan_is_refused(world):
    rig = make_rig(world)
    snapshot = rig.adapter.take_snapshot(world.engagement_id)
    with pytest.raises(LookupError):
        rig.adapter.work(world.engagement_id, "TASK-NOT-PLANNED-HERE", snapshot)
    assert rig.worker.work_calls == 0


def test_a_worker_that_returns_nothing_is_a_refusal_with_no_proposal(world):
    rig = make_rig(world, make_proposal=lambda task, task_id: None)
    snapshot = rig.adapter.take_snapshot(world.engagement_id)
    (created,) = rig.adapter.plan(world.engagement_id, snapshot).created
    result = rig.adapter.work(world.engagement_id, created.task_id, snapshot)
    assert result.refusal is True and result.proposal is None and result.action is None


def test_load_policy_is_the_effective_policy_the_control_plane_loads(world):
    policy = make_rig(world).adapter.load_policy(world.engagement_id)
    assert isinstance(policy, EffectivePolicy)


def test_the_enrolled_list_is_the_one_the_reader_gives(world):
    assert make_rig(world).adapter.enrolled() == (world.engagement_id,)


# -- no connection is left checked out ---------------------------------------------------------


def _checked_out() -> int:
    return get_engine().pool.checkedout()


def test_no_port_leaves_a_connection_checked_out(world):
    rig = make_rig(world)
    adapter, eid = rig.adapter, world.engagement_id
    before = _checked_out()
    steps = {}

    def measured(name, call):
        result = call()
        steps[name] = _checked_out() - before
        return result

    measured("enrolled", adapter.enrolled)
    measured("accepts_work", lambda: adapter.accepts_work(eid))
    measured("live_tasks", lambda: adapter.live_tasks(eid))
    snapshot = measured("take_snapshot", lambda: adapter.take_snapshot(eid))
    planned = measured("plan", lambda: adapter.plan(eid, snapshot))
    task_id = measured("claim", lambda: adapter.claim(eid))
    assert task_id == planned.created[0].task_id
    work = measured("work", lambda: adapter.work(eid, task_id, snapshot))
    policy = measured("load_policy", lambda: adapter.load_policy(eid))
    measured("propose", lambda: adapter.propose(eid, task_id, work.proposal, policy,
                                                f"h5:{task_id}:1"))
    measured("complete", lambda: adapter.complete(eid, task_id, "not_run"))

    assert steps == dict.fromkeys(steps, 0), steps
    assert len(steps) == 10


def test_a_port_that_raises_leaves_no_connection_checked_out_either(world):
    rig = make_rig(world, live_task_limit=1)
    from tests.test_harness_h5c1_support import queued_task
    queued_task(world, 21)
    queued_task(world, 22)
    before = _checked_out()
    from harness.loop_adapter import LiveTasksNotReadable
    with pytest.raises(LiveTasksNotReadable):
        rig.adapter.live_tasks(world.engagement_id)
    assert _checked_out() == before


def test_the_connection_count_check_sees_a_leak(db_available):
    """The measure itself: a connection taken and not returned shows in the count."""
    before = _checked_out()
    held = get_engine().connect()
    try:
        assert _checked_out() == before + 1
        held.execute(text("SELECT 1"))
    finally:
        held.close()
    assert _checked_out() == before


def test_the_adapter_is_a_loop_ports_in_the_names_the_loop_uses():
    names = ("enrolled", "accepts_work", "live_tasks", "take_snapshot", "plan", "claim", "work",
             "load_policy", "propose", "complete")
    for name in names:
        assert callable(getattr(LoopAdapter, name)), name
    assert ScriptedSupervisor and ScriptedWorker and FakeSandbox     # (imported for the rig)
