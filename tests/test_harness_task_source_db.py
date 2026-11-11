"""D69 H4: the task source against the test database.

The no-DB file (``test_harness_task_source.py``) says which tasks reach ``create_task``. This one
runs the real ``create_task`` and the real transaction around it and says what is then true of
the database and of the ledger:

* a task that passes both filters has a row in ``tasks`` with its ``identity_key``, a
  ``task.created`` audit event, and its id in the ledger (i);
* a refused task has no row (j);
* an exception from ``create_task`` propagates, the task is not in the ledger, and the tasks
  created before it in the same plan are in the ledger and in the database (k);
* a new ledger starts empty, whatever another one holds and whatever the database holds (l).

The failing input for (k) is a task whose ``goal`` is ``None``: ``create_task`` inserts it and
the ``NOT NULL`` constraint refuses. ``BaseSupervisor._to_tasks`` never produces one, so that
plan comes from a Supervisor subclass that returns its tasks directly -- the only way to put a
task the real ``create_task`` rejects through the real transaction.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from agents.base_agent import ProposedTask
from agents.llm.supervisor_base import BaseSupervisor
from control_plane.audit.query import events_for_subject
from control_plane.state.db import engagement_scope
from harness.action_allowlist import (
    REASON_ACTION_NOT_ALLOWED,
    REASON_CIDR_WITHOUT_PREFIX,
    SIDE_TASK,
    RefusalCounter,
)
from harness.round_snapshot import build_state_summary
from harness.task_source import RunTaskLedger, plan_and_create_tasks
from tests.test_harness_task_source import (
    PlanSupervisor,
    filtered_candidates,
    item,
    payload,
    snapshot,
    unfiltered_candidates,
)

CREATED_BY = "test-harness-supervisor"


def _plan(engagement_id, supervisor, *, ledger, counter=None, candidates=None):
    state = build_state_summary(snapshot()[0], engagement_id=engagement_id, objective="map it")
    return plan_and_create_tasks(
        supervisor=supervisor, state=state,
        candidates=filtered_candidates() if candidates is None else candidates,
        engagement_id=engagement_id, created_by=CREATED_BY, ledger=ledger,
        counter=RefusalCounter() if counter is None else counter,
    )


def _rows(engagement_id) -> dict[str, str]:
    with engagement_scope(engagement_id) as conn:
        return {
            r[0]: r[1]
            for r in conn.execute(text("SELECT task_id, identity_key FROM tasks")).all()
        }


def _event_types(engagement_id, task_id) -> set[str]:
    with engagement_scope(engagement_id) as conn:
        return {e.event_type for e in events_for_subject(conn, subject_id=task_id)}


class DirectSupervisor(BaseSupervisor):
    """Returns the tasks it was given, as they are: no ``_to_tasks`` in between."""

    agent_id = "test-harness-direct-supervisor"

    def __init__(self, tasks):
        super().__init__()
        self._tasks = tasks
        self.plan_calls = 0

    def plan(self, *, state, candidates):
        self.plan_calls += 1
        return list(self._tasks)


def test_i_a_passing_task_has_a_row_an_identity_key_an_audit_event_and_a_ledger_id(engagement_id):
    ledger = RunTaskLedger()
    outcome = _plan(
        engagement_id, PlanSupervisor(payload(item(target_value="10.82.0.0/24"))), ledger=ledger,
    )

    assert len(outcome.created) == 1
    task_id = outcome.created[0].task_id
    rows = _rows(engagement_id)
    assert set(rows) == {task_id}
    assert rows[task_id] == "network.scan\x1fcidr:10.82.0.0/24"
    assert "task.created" in _event_types(engagement_id, task_id)
    assert task_id in ledger
    assert ledger.ids == frozenset({task_id})


def test_i_created_by_is_the_callers(engagement_id):
    outcome = _plan(engagement_id, PlanSupervisor(payload(item())), ledger=RunTaskLedger())
    with engagement_scope(engagement_id) as conn:
        who = conn.execute(
            text("SELECT created_by FROM tasks WHERE task_id = :t"),
            {"t": outcome.created[0].task_id},
        ).scalar_one()
    assert who == CREATED_BY


def test_j_a_refused_task_has_no_row_and_the_others_do(engagement_id):
    reply = payload(
        item(goal="bad action", action="code.secrets"),
        item(goal="no prefix", target_value="10.82.1.0"),
        item(goal="fine", target_value="10.82.0.0/25"),
    )
    counter = RefusalCounter()
    ledger = RunTaskLedger()
    outcome = _plan(
        engagement_id, PlanSupervisor(reply), ledger=ledger, counter=counter,
        candidates=unfiltered_candidates(),
    )

    assert [c.task.goal for c in outcome.created] == ["fine"]
    assert len(_rows(engagement_id)) == 1
    assert counter.entries() == (
        (SIDE_TASK, REASON_ACTION_NOT_ALLOWED),
        (SIDE_TASK, REASON_CIDR_WITHOUT_PREFIX),
    )
    with engagement_scope(engagement_id) as conn:
        goals = {r[0] for r in conn.execute(text("SELECT goal FROM tasks")).all()}
    assert goals == {"fine"}


def test_k_an_exception_from_create_task_propagates_and_earlier_tasks_stay(engagement_id):
    def ok(goal, value):
        return ProposedTask(
            goal=goal, action="network.scan", scope_object_id="so-range",
            target={"logical_identity": {"type": "cidr", "value": value}},
        )

    tasks = [
        ok("first", "10.82.0.0/25"),
        ProposedTask(                       # create_task inserts this and NOT NULL refuses it
            goal=None, action="network.scan", scope_object_id="so-range",       # type: ignore[arg-type]
            target={"logical_identity": {"type": "cidr", "value": "10.82.0.128/25"}},
        ),
        ok("third", "10.82.1.0/25"),
    ]
    supervisor = DirectSupervisor(tasks)
    ledger = RunTaskLedger()

    with pytest.raises(DBAPIError):
        _plan(engagement_id, supervisor, ledger=ledger)

    assert supervisor.plan_calls == 1
    rows = _rows(engagement_id)
    assert len(rows) == 1
    (first_id,) = rows
    assert ledger.ids == frozenset({first_id})
    with engagement_scope(engagement_id) as conn:
        goals = {r[0] for r in conn.execute(text("SELECT goal FROM tasks")).all()}
    assert goals == {"first"}


def test_l_a_new_ledger_starts_empty_whatever_another_holds_and_the_database_holds(engagement_id):
    other = RunTaskLedger()
    outcome = _plan(engagement_id, PlanSupervisor(payload(item())), ledger=other)
    assert other.ids == frozenset({outcome.created[0].task_id})
    assert len(_rows(engagement_id)) == 1

    fresh = RunTaskLedger()
    assert fresh.ids == frozenset()
    assert outcome.created[0].task_id not in fresh
