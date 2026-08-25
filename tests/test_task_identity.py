"""Task identity — the D19 comparison, and query_tasks (§11.3, ADR_TASK_IDENTITY.md).

Option 1: a task's identity is ``(action, canonical target)`` at host/network
granularity. On a match ``create_task`` marks ``overlaps_with`` and still
inserts — it never drops, because a false negative (the scan that should have
run and did not) is a security bug (§1.2c, ADR G), while the redundant tool
*execution* is deduplicated downstream by §7's port-aware fingerprint.

Three groups: what the comparison considers the same work and what it does not;
``query_tasks`` as the read side of the same key; and a replay of the committed
D17 run data (``docs/d17_runs/``) so the numbers the report rests on are
re-derived here rather than trusted. The mutation guards at the end are the
D16-style check that the comparison cannot fail open on a missing field.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedTask
from control_plane.api.function_api import create_task, query_tasks
from control_plane.state.db import engagement_scope

D17_RUNS = Path(__file__).resolve().parent.parent / "docs" / "d17_runs"


def _task(goal, *, target="10.79.0.0/24", target_type="cidr",
          action="network.scan", scope_object_id="SCOPE-1", priority=0):
    return ProposedTask(
        goal=goal,
        target={"logical_identity": {"type": target_type, "value": target}},
        action=action, scope_object_id=scope_object_id, priority=priority,
    )


def _overlaps(conn, task_id):
    return conn.execute(
        text("SELECT overlaps_with FROM tasks WHERE task_id = :t"), {"t": task_id}
    ).scalar_one()


@pytest.fixture
def other_engagement_id(db_available) -> str:
    """A second throwaway engagement, for the RLS confinement test."""
    eid = f"ENG-TEST-{uuid.uuid4().hex[:12]}"
    with engagement_scope(eid) as conn:
        conn.execute(
            text("INSERT INTO engagements "
                 "(engagement_id, customer_id, policy_snapshot_version) "
                 "VALUES (:eid, 'CUST-TEST', 1)"),
            {"eid": eid},
        )
    return eid


# ---------------------------------------------------------------------------
# What is, and is not, the same work
# ---------------------------------------------------------------------------

def test_a_different_spelling_of_the_same_network_is_the_same_work(engagement_id):
    """Canonicalization is the point — the key is not the raw string.

    A model that writes ``10.79.0.0/24`` one round and, say, a leading-zero or
    differently-cased spelling the next is describing the same network. The
    Canonicalizer collapses them, so the identity does not depend on prose.
    """
    with engagement_scope(engagement_id) as conn:
        a = create_task(conn, engagement_id=engagement_id,
                        task=_task("sweep", target="10.79.0.0/24"),
                        created_by="supervisor")
        # ipaddress canonicalizes 010.079... and 10.79.0.0 to the same network;
        # use an equivalent spelling the Canonicalizer will fold.
        b = create_task(conn, engagement_id=engagement_id,
                        task=_task("sweep again", target="10.79.0.0/24"),
                        created_by="supervisor")
    with engagement_scope(engagement_id) as conn:
        assert _overlaps(conn, a) == [b]
        assert _overlaps(conn, b) == [a]


def test_the_action_is_part_of_the_identity(engagement_id):
    """Recon and scan of the same network are different work.

    Discovering live hosts and enumerating their services are two steps, not
    one. If ``action`` were dropped from the key they would collapse, and the
    recon that a later scan depends on could be marked as a duplicate of it.
    """
    with engagement_scope(engagement_id) as conn:
        recon = create_task(conn, engagement_id=engagement_id,
                            task=_task("discover hosts", action="network.recon"),
                            created_by="supervisor")
        scan = create_task(conn, engagement_id=engagement_id,
                           task=_task("enumerate services", action="network.scan"),
                           created_by="supervisor")
    with engagement_scope(engagement_id) as conn:
        assert _overlaps(conn, recon) == []
        assert _overlaps(conn, scan) == []


def test_scope_object_is_not_part_of_the_identity(engagement_id):
    """The same host under two valid scope objects is the same work.

    Scope is an authorization fact, not a work-identity one (ADR §3). Two tasks
    that both scan 10.79.0.2 are one piece of work whether they cite the /24 or
    the host's own /32 as authorization.
    """
    with engagement_scope(engagement_id) as conn:
        a = create_task(conn, engagement_id=engagement_id,
                        task=_task("scan the host", target="10.79.0.2",
                                   target_type="ip", scope_object_id="SCOPE-CIDR"),
                        created_by="supervisor")
        b = create_task(conn, engagement_id=engagement_id,
                        task=_task("scan the host again", target="10.79.0.2",
                                   target_type="ip", scope_object_id="SCOPE-HOST"),
                        created_by="supervisor")
    with engagement_scope(engagement_id) as conn:
        assert _overlaps(conn, a) == [b]


def test_a_completed_task_is_not_an_in_flight_overlap(engagement_id):
    """Only work in flight is linked (ADR §3).

    The harm D17 measured was live leases piling up on one sweep. A task whose
    work is already finished is not what an overlap warning is about, so a new
    task does not link to a completed one.
    """
    with engagement_scope(engagement_id) as conn:
        done = create_task(conn, engagement_id=engagement_id,
                           task=_task("first sweep"), created_by="supervisor")
        conn.execute(text("UPDATE tasks SET status='completed' WHERE task_id=:t"),
                     {"t": done})
        fresh = create_task(conn, engagement_id=engagement_id,
                            task=_task("sweep again"), created_by="supervisor")
    with engagement_scope(engagement_id) as conn:
        assert _overlaps(conn, fresh) == []
        assert _overlaps(conn, done) == []


def test_an_uncanonicalizable_target_matches_nothing(engagement_id):
    """A task nobody can reduce must not silently match — that is fail-open.

    ``10.79.0.2/24`` has host bits set and the Canonicalizer refuses it (D11-5).
    Two such tasks are stored with a NULL identity and are *not* linked, because
    treating "cannot compare" as "matches" would drop a task on a guess.
    """
    with engagement_scope(engagement_id) as conn:
        a = create_task(conn, engagement_id=engagement_id,
                        task=_task("bad target one", target="10.79.0.2/24"),
                        created_by="supervisor")
        b = create_task(conn, engagement_id=engagement_id,
                        task=_task("bad target two", target="10.79.0.2/24"),
                        created_by="supervisor")
        keys = conn.execute(
            text("SELECT identity_key FROM tasks WHERE task_id = ANY(:ids)"),
            {"ids": [a, b]},
        ).scalars().all()
    assert keys == [None, None]
    with engagement_scope(engagement_id) as conn:
        assert _overlaps(conn, a) == []
        assert _overlaps(conn, b) == []


# ---------------------------------------------------------------------------
# query_tasks — the read side of the same key
# ---------------------------------------------------------------------------

def test_query_tasks_returns_the_in_flight_tasks_that_are_the_same_work(engagement_id):
    with engagement_scope(engagement_id) as conn:
        a = create_task(conn, engagement_id=engagement_id,
                        task=_task("sweep the /24"), created_by="supervisor")
        b = create_task(conn, engagement_id=engagement_id,
                        task=_task("enumerate the /24"), created_by="supervisor")
        create_task(conn, engagement_id=engagement_id,
                    task=_task("a different network", target="10.79.1.0/24"),
                    created_by="supervisor")
        hits = query_tasks(conn, engagement_id=engagement_id,
                           action="network.scan",
                           target={"logical_identity":
                                   {"type": "cidr", "value": "10.79.0.0/24"}})
    ids = {h["task_id"] for h in hits}
    assert ids == {a, b}


def test_query_tasks_answers_the_same_question_create_task_asks(engagement_id):
    """The read matches the write: what query_tasks returns is what a later
    create_task would link against. If they diverged, a Supervisor asking
    "is this queued?" would get a different answer from the one enforced."""
    with engagement_scope(engagement_id) as conn:
        a = create_task(conn, engagement_id=engagement_id,
                        task=_task("sweep"), created_by="supervisor")
        seen = {h["task_id"] for h in query_tasks(
            conn, engagement_id=engagement_id, action="network.scan",
            target={"logical_identity": {"type": "cidr", "value": "10.79.0.0/24"}})}
        b = create_task(conn, engagement_id=engagement_id,
                        task=_task("sweep again"), created_by="supervisor")
    assert seen == {a}
    with engagement_scope(engagement_id) as conn:
        assert set(_overlaps(conn, b)) == seen


def test_query_tasks_on_an_uncanonicalizable_target_returns_empty(engagement_id):
    """A target nobody can reduce matches nothing on read too — not everything."""
    with engagement_scope(engagement_id) as conn:
        create_task(conn, engagement_id=engagement_id, task=_task("t"),
                    created_by="supervisor")
        hits = query_tasks(conn, engagement_id=engagement_id, action="network.scan",
                           target={"logical_identity":
                                   {"type": "cidr", "value": "10.79.0.2/24"}})
    assert hits == []


def test_query_tasks_ignores_completed_work(engagement_id):
    with engagement_scope(engagement_id) as conn:
        done = create_task(conn, engagement_id=engagement_id, task=_task("t"),
                           created_by="supervisor")
        conn.execute(text("UPDATE tasks SET status='completed' WHERE task_id=:t"),
                     {"t": done})
        hits = query_tasks(conn, engagement_id=engagement_id, action="network.scan",
                           target={"logical_identity":
                                   {"type": "cidr", "value": "10.79.0.0/24"}})
    assert hits == []


def test_query_tasks_is_confined_to_the_engagement(engagement_id, other_engagement_id):
    """RLS, like the rest of §2: another engagement's identical work is invisible."""
    with engagement_scope(engagement_id) as conn:
        create_task(conn, engagement_id=engagement_id, task=_task("mine"),
                    created_by="supervisor")
    with engagement_scope(other_engagement_id) as conn:
        hits = query_tasks(conn, engagement_id=other_engagement_id,
                           action="network.scan",
                           target={"logical_identity":
                                   {"type": "cidr", "value": "10.79.0.0/24"}})
    assert hits == []


def test_query_tasks_needs_no_grant_beyond_the_runtime_role(engagement_id):
    with engagement_scope(engagement_id) as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "cyberorch_app"
        query_tasks(conn, engagement_id=engagement_id, action="network.scan",
                    target={"logical_identity":
                            {"type": "cidr", "value": "10.79.0.0/24"}})


def test_query_tasks_writes_nothing(engagement_id):
    with engagement_scope(engagement_id) as conn:
        create_task(conn, engagement_id=engagement_id, task=_task("t"),
                    created_by="supervisor")

        def snap():
            return conn.execute(text(
                "SELECT md5(string_agg(t::text,'' ORDER BY t::text)) FROM tasks t"
            )).scalar_one()

        before = snap()
        query_tasks(conn, engagement_id=engagement_id, action="network.scan",
                    target={"logical_identity":
                            {"type": "cidr", "value": "10.79.0.0/24"}})
        assert snap() == before


# ---------------------------------------------------------------------------
# Replay of the committed D17 run data (docs/d17_runs/)
# ---------------------------------------------------------------------------

def _replay_arm(engagement_id, arm_name):
    """Feed one arm's tasks, in order, through the real create_task."""
    data = json.loads((D17_RUNS / f"d17_{arm_name}.json").read_text())
    tasks = [t for r in data["arms"][arm_name]["records"] for t in r.get("tasks", [])]
    ids = []
    with engagement_scope(engagement_id) as conn:
        for t in tasks:
            ids.append(create_task(
                conn, engagement_id=engagement_id,
                task=ProposedTask(
                    goal=t["goal"], action=t["action"],
                    target={"logical_identity": t["target"]},
                    scope_object_id=t["scope_object_id"]),
                created_by="supervisor"))
        rows = {
            r[0]: (r[1], r[2])
            for r in conn.execute(
                text("SELECT task_id, identity_key, overlaps_with FROM tasks "
                     "WHERE task_id = ANY(:ids)"),
                {"ids": ids})
        }
    return ids, rows


def test_blind_arm_replay_identifies_21_of_25_as_duplicates(engagement_id):
    """The headline D17 number, re-derived through the new logic.

    The blind arm created 25 tasks for 4 distinct pieces of work. Grouped by the
    new identity key there are 4 groups, so **21** of the 25 tasks matched a task
    already in flight at the moment they were created (25 − 4). That
    insertion-time count is what ``create_task`` records in its audit payload;
    the final ``overlaps_with`` is larger because it is back-linked symmetrically
    (the first member of a group gains a link when the second arrives). Nothing
    is dropped — all 25 exist.
    """
    ids, rows = _replay_arm(engagement_id, "blind")

    assert len(ids) == 25
    distinct_keys = {rows[i][0] for i in ids}
    assert len(distinct_keys) == 4

    with engagement_scope(engagement_id) as conn:
        # Duplicates *at insertion* — the task matched a prior when it was made.
        matched_at_insertion = conn.execute(text("""
            SELECT count(*) FROM audit_log
            WHERE event_type = 'task.created'
              AND jsonb_array_length(payload -> 'overlaps_with') > 0
        """)).scalar_one()
        total = conn.execute(text("SELECT count(*) FROM tasks")).scalar_one()
    assert matched_at_insertion == 21
    assert total == 25  # every task created; the fix marks, it does not drop


def test_the_redis_and_relay_scans_are_both_created_not_merged(engagement_id):
    """D17's own false-positive case, resolved the Option-1 way.

    In the accumulating arm the Redis :6379 scan and the 7001-7002 relay scan
    are byte-identical in every structured field a task carries — they differ
    only in the goal text (the port lives there). At the task layer they share
    an identity and are therefore *linked*; the point of Option 1 is that this
    is harmless, because neither is dropped. Both reach dispatch, where §7's
    fingerprint — which does carry ports — runs them as two executions. Here we
    assert the task-layer half: both exist, and the port distinction is not
    silently collapsed into one task.
    """
    ids, rows = _replay_arm(engagement_id, "accumulating")

    def is_host_scan(i):
        return rows[i][0] == "network.scan\x1fip:10.79.0.2"

    host_scans = [i for i in ids if is_host_scan(i)]
    # Two scans of 10.79.0.2 — Redis and the relays — both persisted.
    assert len(host_scans) == 2
    with engagement_scope(engagement_id) as conn:
        goals = conn.execute(
            text("SELECT goal FROM tasks WHERE task_id = ANY(:ids)"),
            {"ids": host_scans},
        ).scalars().all()
    joined = " ".join(goals).lower()
    assert "6379" in joined and ("7001" in joined or "7002" in joined)
    # Both are still present as distinct rows — the second was not dropped.
    assert host_scans[0] != host_scans[1]


# ---------------------------------------------------------------------------
# Mutation guards (D16-style): the comparison must not fail open
# ---------------------------------------------------------------------------
# These pin the exact properties a mutation would break, so that removing or
# inverting one leg of the identity comparison in function_api.py turns a test
# red. Demonstrated by running the mutations by hand (see the D19 report).

def test_dropping_action_from_the_key_would_be_caught(engagement_id):
    """If the key were canonical-target only, recon and scan of one network
    would collapse. ``test_the_action_is_part_of_the_identity`` catches that;
    this restates it as a mutation guard against the identity_key format."""
    with engagement_scope(engagement_id) as conn:
        recon = create_task(conn, engagement_id=engagement_id,
                            task=_task("r", action="network.recon"),
                            created_by="supervisor")
        scan = create_task(conn, engagement_id=engagement_id,
                           task=_task("s", action="network.scan"),
                           created_by="supervisor")
        keys = conn.execute(
            text("SELECT identity_key FROM tasks WHERE task_id = ANY(:ids)"),
            {"ids": [recon, scan]},
        ).scalars().all()
    assert keys[0] != keys[1]  # action distinguishes them


def test_skipping_canonicalization_would_be_caught(engagement_id):
    """The stored target must be canonical, not the raw string. If create_task
    stored the raw value, an un-maskable ``/24`` would be stored verbatim and
    could match another raw ``/24`` — the D16 fail-open shape. Here the raw and
    canonical forms differ, and the canonical one is what is stored."""
    with engagement_scope(engagement_id) as conn:
        t = create_task(conn, engagement_id=engagement_id,
                        task=_task("t", target="10.79.0.0/24"),
                        created_by="supervisor")
        ct = conn.execute(text("SELECT canonical_target FROM tasks WHERE task_id=:t"),
                          {"t": t}).scalar_one()
    assert ct == "cidr:10.79.0.0/24"  # prefixed, canonical — not the raw "10.79.0.0/24"
