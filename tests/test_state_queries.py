"""The read-only half of the §2 function API (D17).

``query_findings`` has been in §2 since v0.1 and nothing implemented it, because
until a real Supervisor arrived no component planned anything. ``query_state``
returned five counts, which is enough to assert a scenario ran and not enough to
decide what should happen next.

Two things are being pinned here. The first is that these are *queries*: no
write, no new grant, and the same RLS confinement as the rest of the pipeline.
The second is a characterization — what the Task Manager actually retains about
a task — because D17's finding turns on it and a finding nobody can re-check is
an anecdote.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedTask
from control_plane.api.function_api import (
    FINDING_STATES,
    TASK_STATUSES,
    create_task,
    query_findings,
    query_state,
)
from control_plane.state.db import engagement_scope


def _finding(conn, engagement_id, *, claim, state="candidate", strength="E2",
             finding_id=None):
    """Insert one finding and return its id.

    The id is generated rather than fixed: ``findings_pkey`` is on
    ``finding_id`` alone, across every engagement, so a literal would make two
    tests in the same database collide — and the collision would look like a
    bug in the query rather than in the fixture.
    """
    finding_id = finding_id or f"F-{uuid.uuid4().hex[:12]}"
    conn.execute(
        text("""
            INSERT INTO findings (finding_id, engagement_id, claim, state,
                                  evidence_strength)
            VALUES (:f, :e, :c, :s, :st)
        """),
        {"f": finding_id, "e": engagement_id, "c": claim, "s": state,
         "st": strength},
    )
    return finding_id


def _task(goal, *, target="10.79.0.0/24", action="network.scan",
          scope_object_id="SCOPE-1", target_type="cidr"):
    return ProposedTask(
        goal=goal,
        target={"logical_identity": {"type": target_type, "value": target}},
        action=action, scope_object_id=scope_object_id,
    )


# ---------------------------------------------------------------------------
# query_findings (§2, §4.3)
# ---------------------------------------------------------------------------

def test_query_findings_returns_this_engagement_s_findings(engagement_id):
    with engagement_scope(engagement_id) as conn:
        finding_id = _finding(
            conn, engagement_id,
            claim="redis on 10.79.0.2:6379 accepts unauthenticated commands",
        )
        found = query_findings(conn, engagement_id=engagement_id)

    assert [f["finding_id"] for f in found] == [finding_id]
    assert found[0]["evidence_strength"] == "E2"
    assert found[0]["state"] == "candidate"


def test_query_findings_sees_nothing_from_another_engagement(engagement_id):
    """I4, through the new interface rather than around it.

    A query added for a planner's convenience is exactly the kind of thing that
    acquires a cross-engagement variant later, so the confinement is asserted
    on the function and not only on the table.
    """
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
        _finding(conn, other, claim="not yours")

    with engagement_scope(engagement_id) as conn:
        assert query_findings(conn, engagement_id=engagement_id) == []
        # And naming the other engagement in the argument changes nothing: the
        # argument labels the connection's own scope, it does not select one.
        assert query_findings(conn, engagement_id=other) == []


def test_query_findings_filters_by_state(engagement_id):
    with engagement_scope(engagement_id) as conn:
        _finding(conn, engagement_id, claim="a", state="candidate")
        confirmed = _finding(conn, engagement_id, claim="b", state="verified")

        verified = query_findings(conn, engagement_id=engagement_id,
                                  state=["verified"])
        both = query_findings(conn, engagement_id=engagement_id)

    assert [f["finding_id"] for f in verified] == [confirmed]
    assert len(both) == 2


@pytest.mark.parametrize("state", ["confirmed", "true", "'; DROP TABLE findings--"])
def test_an_unknown_finding_state_is_refused_rather_than_interpolated(
    engagement_id, state
):
    """The filter is an allowlist, not a predicate that becomes SQL.

    §2 writes ``query_findings(engagement_id, filter)``. Spelling ``filter`` as
    a free-form object would make a read interface something a caller could
    widen from the inside; every value that reaches a WHERE clause here is
    either checked against a fixed set or a bound parameter.
    """
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(ValueError) as exc:
            query_findings(conn, engagement_id=engagement_id, state=[state])
    assert "unknown finding state" in str(exc.value)


def test_query_findings_returns_no_confidence_column(engagement_id):
    """§4.3 removed it, and a query that invented one would put it back.

    The strength of a finding is ``evidence_strength`` plus ``verifier_state``.
    A planner that wants to rank findings has to reason about those two discrete
    fields rather than sort by a number nobody computed.
    """
    with engagement_scope(engagement_id) as conn:
        _finding(conn, engagement_id, claim="a")
        found = query_findings(conn, engagement_id=engagement_id)
    assert "confidence" not in found[0]
    assert {"evidence_strength", "verifier_state"} <= set(found[0])


def test_every_documented_finding_state_is_accepted(engagement_id):
    """Control for the refusal test: the allowlist must match §4.3's vocabulary,
    not a subset somebody typed from memory."""
    with engagement_scope(engagement_id) as conn:
        for state in FINDING_STATES:
            assert query_findings(
                conn, engagement_id=engagement_id, state=[state]
            ) == []


# ---------------------------------------------------------------------------
# query_state (§2)
# ---------------------------------------------------------------------------

def test_query_state_returns_the_task_ledger(engagement_id):
    with engagement_scope(engagement_id) as conn:
        create_task(conn, engagement_id=engagement_id,
                    task=_task("Sweep the lab range"), created_by="supervisor")
        state = query_state(conn, engagement_id=engagement_id)

    assert state["counts"]["tasks"] == 1
    assert [t["goal"] for t in state["tasks"]] == ["Sweep the lab range"]
    assert state["tasks"][0]["status"] == "queued"
    assert state["tasks"][0]["created_by"] == "supervisor"


def test_query_state_still_carries_the_counts_it_always_did(engagement_id):
    with engagement_scope(engagement_id) as conn:
        state = query_state(conn, engagement_id=engagement_id)
    assert set(state["counts"]) == {
        "tasks", "proposals", "capabilities", "runs", "evidence"
    }


def test_query_state_filters_tasks_by_status(engagement_id):
    with engagement_scope(engagement_id) as conn:
        create_task(conn, engagement_id=engagement_id, task=_task("one"),
                    created_by="supervisor")
        second = create_task(conn, engagement_id=engagement_id, task=_task("two"),
                             created_by="supervisor")
        conn.execute(
            text("UPDATE tasks SET status = 'completed' WHERE task_id = :t"),
            {"t": second},
        )
        queued = query_state(conn, engagement_id=engagement_id,
                             task_status=["queued"])
        done = query_state(conn, engagement_id=engagement_id,
                           task_status=["completed"])

    assert [t["goal"] for t in queued["tasks"]] == ["one"]
    assert [t["goal"] for t in done["tasks"]] == ["two"]


@pytest.mark.parametrize("status", ["done", "QUEUED", "queued'; DELETE FROM tasks--"])
def test_an_unknown_task_status_is_refused(engagement_id, status):
    with engagement_scope(engagement_id) as conn:
        with pytest.raises(ValueError) as exc:
            query_state(conn, engagement_id=engagement_id, task_status=[status])
    assert "unknown task status" in str(exc.value)


def test_every_documented_task_status_is_accepted(engagement_id):
    with engagement_scope(engagement_id) as conn:
        for status in TASK_STATUSES:
            assert query_state(
                conn, engagement_id=engagement_id, task_status=[status]
            )["tasks"] == []


def test_query_state_sees_no_other_engagement_s_tasks(engagement_id):
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
        create_task(conn, engagement_id=other, task=_task("not yours"),
                    created_by="supervisor")

    with engagement_scope(engagement_id) as conn:
        assert query_state(conn, engagement_id=engagement_id)["tasks"] == []
        assert query_state(conn, engagement_id=other)["tasks"] == []


def test_the_queries_write_nothing(engagement_id):
    """Read-only, asserted rather than asserted-about.

    §2 draws its line at what an agent may *call*. Adding a way to read state
    stays on the right side of that line only while nothing here mutates, and
    the cheapest durable check is that the tables are byte-identical afterwards.
    """
    with engagement_scope(engagement_id) as conn:
        create_task(conn, engagement_id=engagement_id, task=_task("one"),
                    created_by="supervisor")
        _finding(conn, engagement_id, claim="a")

        def snapshot():
            return [
                conn.execute(text(f"SELECT md5(string_agg(t::text, '' ORDER BY t::text)) "
                                  f"FROM {table} t")).scalar_one()
                for table in ("tasks", "findings", "action_proposals",
                              "audit_log", "evidence")
            ]

        before = snapshot()
        query_state(conn, engagement_id=engagement_id)
        query_findings(conn, engagement_id=engagement_id)
        assert snapshot() == before


def test_the_queries_need_no_grant_beyond_the_runtime_role(engagement_id):
    """They run on ``cyberorch_app`` — the role every other component uses.

    ``engagement_scope`` is that connection. If either query had needed a new
    privilege, this test would fail with a permission error rather than passing
    quietly against a role that happened to be able to do more.
    """
    with engagement_scope(engagement_id) as conn:
        role = conn.execute(text("SELECT current_user")).scalar_one()
        assert role == "cyberorch_app"
        query_state(conn, engagement_id=engagement_id)
        query_findings(conn, engagement_id=engagement_id)


# ---------------------------------------------------------------------------
# What the Task Manager retains — D17's finding, pinned (§4.2, §7)
# ---------------------------------------------------------------------------

def test_a_task_keeps_its_prose_and_discards_its_structure(engagement_id):
    """**This documents a gap, it does not endorse one.**

    ``ProposedTask`` carries an action, a canonical target and a scope object
    id. ``create_task`` writes the goal, the creator and the priority, and drops
    the other three on the floor. So the only thing about a task that survives
    into the database is free text — which means any task-level deduplication
    that could exist would necessarily be a comparison of prose.

    Pinned as a test because D17's report rests on it, and because if somebody
    later decides to persist the structured fields this should fail and make
    them say so deliberately.
    """
    with engagement_scope(engagement_id) as conn:
        task_id = create_task(
            conn, engagement_id=engagement_id,
            task=_task("Sweep the lab range", target="10.79.0.0/24",
                       action="network.scan", scope_object_id="SCOPE-1"),
            created_by="supervisor",
        )
        columns = set(conn.execute(
            text("SELECT column_name FROM information_schema.columns "
                 "WHERE table_name = 'tasks'")
        ).scalars())
        row = conn.execute(
            text("SELECT * FROM tasks WHERE task_id = :t"), {"t": task_id}
        ).mappings().one()

    assert "action" not in columns
    assert "target" not in columns
    assert "scope_object_id" not in columns
    assert row["goal"] == "Sweep the lab range"
    # And §4.2's overlap field is there, empty, and written by nothing.
    assert row["overlaps_with"] == []


def test_two_tasks_for_the_same_work_in_different_words_both_get_created(
    engagement_id
):
    """**Also a gap, also pinned rather than fixed.**

    There is no task-level deduplication anywhere in the system: ``create_task``
    inserts unconditionally with a fresh id. §7's fingerprint deduplicates *tool
    executions* — same tool, same version, same normalized target, inside a
    freshness window — and it is consulted at dispatch, several stages after a
    task exists. Nothing consults anything at task creation.

    So two tasks whose structured content is identical and whose prose differs
    are two tasks. This is not a bug that D17 introduced; it is the state a real
    Supervisor is being pointed at, and measuring what that costs is what D17 is
    for. Changing it is a design decision about how tasks are compared, which is
    larger than this deliverable.
    """
    with engagement_scope(engagement_id) as conn:
        first = create_task(
            conn, engagement_id=engagement_id,
            task=_task("Sweep 10.79.0.0/24 for exposed services"),
            created_by="supervisor",
        )
        second = create_task(
            conn, engagement_id=engagement_id,
            task=_task("Enumerate open ports across the 10.79.0.0/24 range"),
            created_by="supervisor",
        )
        # Identical structure, different words.
        state = query_state(conn, engagement_id=engagement_id)

    assert first != second
    assert len(state["tasks"]) == 2
    assert all(t["overlaps_with"] == [] for t in state["tasks"])


def test_even_a_byte_identical_goal_creates_a_second_task(engagement_id):
    """The stronger version: dedup does not exist at all, not merely
    literal-comparison dedup that prose defeats.

    Worth separating, because "the words differed so it slipped through" and
    "nothing is compared" call for different answers, and only the second one
    is true here.
    """
    goal = "Sweep 10.79.0.0/24 for exposed services"
    with engagement_scope(engagement_id) as conn:
        first = create_task(conn, engagement_id=engagement_id, task=_task(goal),
                            created_by="supervisor")
        second = create_task(conn, engagement_id=engagement_id, task=_task(goal),
                             created_by="supervisor")
        state = query_state(conn, engagement_id=engagement_id)

    assert first != second
    assert len(state["tasks"]) == 2
