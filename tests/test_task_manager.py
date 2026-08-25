"""Task claim, lease and overlap — what §6 actually guarantees (D17, §6, §11).

§11 asks for a concurrency test by name: "multiple workers claiming the same
batch of tasks, verifying nothing is executed twice". Until D17 there was none.
Two agents were never run against one queue, and the SQL that makes it safe —
``FOR UPDATE SKIP LOCKED`` plus a status guard — had only ever been read.

The tests here run real connections in real threads against a real PostgreSQL,
because that is the only way this SQL can be wrong: a single-threaded test of
``SKIP LOCKED`` verifies the string, not the behaviour.

What comes out of it is a boundary worth stating precisely, because D17's
report turns on it. §6 guarantees that **one task is claimed by one agent**. It
does not guarantee, and has no way to notice, that **two tasks are the same
work** — those are different questions, and the second one has no implementation
anywhere in the system.
"""

from __future__ import annotations

import threading
import uuid
from collections import Counter

from sqlalchemy import text

from agents.base_agent import ProposedTask
from control_plane.api.function_api import claim_task, create_task
from control_plane.state.db import engagement_scope


def _task(goal, *, target="10.79.0.0/24", action="network.scan",
          scope_object_id="SCOPE-1", priority=0):
    return ProposedTask(
        goal=goal,
        target={"logical_identity": {"type": "cidr", "value": target}},
        action=action, scope_object_id=scope_object_id, priority=priority,
    )


def _seed(engagement_id, goals):
    with engagement_scope(engagement_id) as conn:
        return [
            create_task(conn, engagement_id=engagement_id, task=_task(goal),
                        created_by="supervisor")
            for goal in goals
        ]


# ---------------------------------------------------------------------------
# §6: one task, one agent
# ---------------------------------------------------------------------------

def test_concurrent_agents_never_claim_the_same_task(engagement_id):
    """Eight threads, six tasks, one connection each.

    Each thread claims until the queue is empty. The assertion that matters is
    not the count — it is that no ``task_id`` appears twice across every thread's
    results, because a duplicate there is the same work executed twice by two
    agents, which is what §6 exists to prevent.
    """
    seeded = _seed(engagement_id, [f"task {i}" for i in range(6)])
    claimed: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker(agent_id: str) -> None:
        mine = []
        barrier.wait()
        # Bounded rather than ``while True``. A claim loop that never runs dry
        # is itself the bug — drop the ``status = 'queued'`` guard and every
        # agent claims forever — and a test that hangs on it reports nothing.
        for _ in range(len(seeded) + 1):
            with engagement_scope(engagement_id) as conn:
                task_id = claim_task(conn, engagement_id=engagement_id,
                                     agent_id=agent_id)
            if task_id is None:
                break
            mine.append(task_id)
        with lock:
            claimed.extend(mine)

    threads = [threading.Thread(target=worker, args=(f"agent-{i}",))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert sorted(claimed) == sorted(seeded)
    assert len(set(claimed)) == len(claimed), Counter(claimed).most_common(3)


def test_a_claimed_task_is_not_offered_again(engagement_id):
    """The status guard, on its own, without concurrency.

    Control for the test above: if claiming did not change the status, the
    concurrency test could pass simply because the threads happened not to
    overlap.
    """
    _seed(engagement_id, ["only one"])
    with engagement_scope(engagement_id) as conn:
        first = claim_task(conn, engagement_id=engagement_id, agent_id="a")
        second = claim_task(conn, engagement_id=engagement_id, agent_id="b")
    assert first is not None
    assert second is None


def test_a_claim_takes_a_lease_that_expires(engagement_id):
    """§4.2's ``lease_expires_at`` — the field without which a dead agent
    strands a task forever (§6)."""
    _seed(engagement_id, ["leased"])
    with engagement_scope(engagement_id) as conn:
        task_id = claim_task(conn, engagement_id=engagement_id, agent_id="a")
        row = conn.execute(
            text("SELECT status, owner_agent_id, lease_expires_at, "
                 "lease_expires_at > now() AS still_valid "
                 "FROM tasks WHERE task_id = :t"),
            {"t": task_id},
        ).mappings().one()

    assert row["status"] == "claimed"
    assert row["owner_agent_id"] == "a"
    assert row["lease_expires_at"] is not None
    assert row["still_valid"] is True


def test_priority_then_age_decides_who_is_claimed_first(engagement_id):
    with engagement_scope(engagement_id) as conn:
        low = create_task(conn, engagement_id=engagement_id,
                          task=_task("low", priority=1), created_by="s")
        high = create_task(conn, engagement_id=engagement_id,
                           task=_task("high", priority=9), created_by="s")
        assert claim_task(conn, engagement_id=engagement_id, agent_id="a") == high
        assert claim_task(conn, engagement_id=engagement_id, agent_id="b") == low


def test_an_agent_cannot_claim_another_engagement_s_task(engagement_id):
    """I4 on the claim path. RLS decides this, not the query."""
    other = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(other) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-OTHER', 1)"),
            {"e": other},
        )
        create_task(conn, engagement_id=other, task=_task("not yours"),
                    created_by="s")

    with engagement_scope(engagement_id) as conn:
        assert claim_task(conn, engagement_id=engagement_id, agent_id="a") is None
        # And asking for the other engagement by name changes nothing: the
        # argument names the connection's own scope, it does not select one.
        assert claim_task(conn, engagement_id=other, agent_id="a") is None


# ---------------------------------------------------------------------------
# What §6 does not do, pinned so the report can point at it (D17)
# ---------------------------------------------------------------------------

def test_the_lease_protects_a_task_not_the_work_it_describes(engagement_id):
    """**A gap, documented rather than endorsed.**

    Two tasks describing identical work are two tasks. Two different agents
    claim them, hold two valid leases at once, and each believes it owns work
    nobody else is doing. Nothing in §6 is broken by this — the claim mechanism
    answers "who owns this row", and it answers correctly. The question "is this
    row the same work as that one" is asked nowhere.

    That distinction is the whole of D17's finding, and it is asserted here so
    it can be re-checked rather than taken on the report's word.
    """
    identical = _seed(engagement_id, ["Sweep 10.79.0.0/24 for exposed services"] * 2)
    assert len(identical) == 2

    with engagement_scope(engagement_id) as conn:
        first = claim_task(conn, engagement_id=engagement_id, agent_id="agent-a")
        second = claim_task(conn, engagement_id=engagement_id, agent_id="agent-b")
        rows = conn.execute(
            text("SELECT task_id, goal, owner_agent_id, "
                 "lease_expires_at > now() AS leased FROM tasks "
                 "WHERE task_id = ANY(:ids) ORDER BY task_id"),
            {"ids": identical},
        ).mappings().all()

    assert {first, second} == set(identical)
    assert {r["owner_agent_id"] for r in rows} == {"agent-a", "agent-b"}
    assert all(r["leased"] for r in rows)
    # The same sentence, twice, owned by two agents, both leases live.
    assert len({r["goal"] for r in rows}) == 1


def test_overlapping_work_is_linked_and_distinct_work_is_not(engagement_id):
    """§4.2's ``overlaps_with``, now written (§11.3, ADR_TASK_IDENTITY.md).

    D17 pinned this field as never-written — correct then, and the gap D19
    closed. It is still not a guess (ADR G): it is filled only when the stored,
    canonicalized target-level identity matches exactly. Two tasks that are the
    same work are linked symmetrically; two tasks for different work are not;
    and nothing is dropped in either case.
    """
    with engagement_scope(engagement_id) as conn:
        # Same identity (default target 10.79.0.0/24, action network.scan),
        # different words.
        a = create_task(conn, engagement_id=engagement_id,
                        task=_task("sweep the range"), created_by="supervisor")
        b = create_task(conn, engagement_id=engagement_id,
                        task=_task("enumerate the same /24"), created_by="supervisor")
        # Different work: a different network.
        c = create_task(conn, engagement_id=engagement_id,
                        task=_task("scan the other range", target="10.79.1.0/24"),
                        created_by="supervisor")
        rows = {
            r[0]: r[1]
            for r in conn.execute(
                text("SELECT task_id, overlaps_with FROM tasks "
                     "WHERE task_id = ANY(:ids)"),
                {"ids": [a, b, c]},
            )
        }
    assert set(rows[a]) == {b}   # symmetric
    assert set(rows[b]) == {a}
    assert rows[c] == []         # distinct work is not linked to anything
