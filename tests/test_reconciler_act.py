"""The act half (D64 step 6c): state transitions for real, deletions behind a flag that is off.

* **modes.** A dry run opens no connection and makes no call; the state-only mode moves proposals
  and *skips* every kill, removal and unlink -- the client it is handed is never touched. The flag
  that would let it act is ``Settings.enabled``; it defaults to empty and only a test
  here sets it.
* **a state change is a compare-and-set.** Seven transitions, each from the right stage with the
  right reason; a proposal touched since the plan (even by a transaction still open when the act
  starts) is ``lost_race`` and untouched; another engagement's id moves nothing.
* **verified, then audited.** The hook the audit is written from runs for ``done`` results only, and
  sees the new state when it runs. An action that reports success without doing it is ``failed``.
* **deletions (flag on, tests only).** By full id, after a fresh inspect; the run label, the owner
  label and the kind of object must still be what the plan saw; Docker's refusals are respected;
  afterwards the object must be seen gone. Real Docker for the real cases, a fake that lies for the
  failures.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from types import SimpleNamespace

import docker
import pytest
from docker.errors import APIError, NotFound
from sqlalchemy import text

from control_plane.reconciler import act, flags, vocab
from control_plane.reconciler.act import Mode, Settings, settings_for
from control_plane.reconciler.act import carry_out as run
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import (
    CHANGED,
    DONE,
    DRY_RUN,
    FAILED,
    GONE,
    LOST_RACE,
    SKIPPED_OFF,
)
from control_plane.state.db import engagement_scope
from tests.reconciler_support import _approval, _capability, _proposal, _run

TH = Thresholds(
    stage_grace_s=3600, lease_grace_s=30, approval_grace_s=30, b_cap_s=1800, p_proxy_s=915,
    q_proxy_s=300, kill_margin_s=60, retention_s=86400, network_idle_s=3600,
    network_sweep_period_s=86400, verify_wait_s=10, summary_period_s=3600,
    retry_after_failure_s=1800, max_pages=20, max_actions_per_pass=500,
    backoff_max_s=900, network_conflict_window_s=86400, network_conflict_min_idle_s=3600,
    network_conflict_daily_cap=3)
STATE_ONLY = Settings(Mode.STATE_ONLY)
DELETIONS = Settings(Mode.STATE_ONLY, enabled=flags.EVERYTHING)    # tests only
IMAGE = "python:3.12-slim"


# ---------------------------------------------------------------------------------------------
# modes and the flag
# ---------------------------------------------------------------------------------------------

def test_the_operator_can_choose_two_modes_and_neither_allows_deletions():
    assert set(act.MODE_NAMES) == {"dry-run", "state-only"}
    for name in act.MODE_NAMES:
        try:
            chosen = settings_for(name)
        except ValueError as exc:
            pytest.fail(f"the operator's mode {name!r} was refused: {exc}")
        assert chosen.enabled == frozenset()
    assert settings_for("dry-run").mode is Mode.DRY_RUN
    assert settings_for("state-only").mode is Mode.STATE_ONLY
    for bad in ("full", "delete", "STATE-ONLY", "", "state_only", "deletions"):
        with pytest.raises(ValueError):
            settings_for(bad)


def test_the_flag_defaults_to_off_and_a_dry_run_cannot_carry_it():
    assert Settings(Mode.STATE_ONLY).enabled == frozenset()
    assert Settings(Mode.DRY_RUN).enabled == frozenset()
    with pytest.raises(ValueError):
        Settings(Mode.DRY_RUN, enabled=flags.EVERYTHING)


def action(kind, reason, subject="x" * 64, **kw) -> Action:
    return Action(kind=kind, reason_code=reason, subject_id=subject, **kw)


EVERY_KIND = [
    action(vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE, "P1", engagement_id="E",
           expected_stage="received", planned_stage_updated_us=1),
    action(vocab.CLOSE, vocab.CAPABILITY_NOT_LIVE, "P2", engagement_id="E",
           expected_stage="capability_issued", planned_stage_updated_us=1),
    action(vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME, "P3", engagement_id="E",
           expected_stage="dispatching", planned_stage_updated_us=1),
    action(vocab.KILL_CONTAINER, vocab.OVERRAN_DEADLINE, run_id="R", expected_owner="E"),
    action(vocab.REMOVE_CONTAINER, vocab.RUN_FINISHED, run_id="R", expected_owner="E"),
    action(vocab.REMOVE_PROXY, vocab.OWNER_RUN_ENDED, run_id="R", expected_owner="E"),
    action(vocab.REMOVE_NETWORK, vocab.IDLE_SWEEP, name="cyberorch-allow-x"),
    action(vocab.UNLINK_FILE, "tls_leaf", "cyberorch-tls-abcd1234.pem",
           name="cyberorch-tls-abcd1234.pem", directory="/tmp"),
]


class Untouchable:
    """A Docker client / connection factory that fails the test on any use."""

    def __getattr__(self, name):
        raise AssertionError(f"touched {name}")


def test_a_dry_run_opens_no_connection_makes_no_call_and_says_what_it_would_do(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("a dry run opened a database connection")

    monkeypatch.setattr(act, "engagement_scope", refuse)
    hooked = []
    results = run(EVERY_KIND, Settings(Mode.DRY_RUN), th=TH, client=Untouchable(),
                  directory="/tmp", expected_uid=0, on_verified=hooked.append)
    assert [r.outcome for r in results] == [DRY_RUN] * len(EVERY_KIND)
    assert [r.action for r in results] == EVERY_KIND
    assert hooked == []


def test_state_only_skips_every_deletion_and_never_touches_docker_or_the_filesystem(monkeypatch):
    deletions = EVERY_KIND[3:]
    monkeypatch.setattr(os, "unlink", lambda *a, **kw: pytest.fail("unlinked"))
    hooked = []
    results = run(deletions, STATE_ONLY, th=TH, client=Untouchable(), directory="/tmp",
                  expected_uid=0, on_verified=hooked.append)
    assert [r.outcome for r in results] == [SKIPPED_OFF] * len(deletions)
    assert hooked == []


@pytest.mark.parametrize("bad", [
    action("explode", "because"), action(vocab.CLOSE, "no_such_reason"),
    action(vocab.KILL_CONTAINER, vocab.IDLE_SWEEP)])
def test_an_action_outside_the_vocabulary_is_refused_in_every_mode(bad):
    for settings in (Settings(Mode.DRY_RUN), STATE_ONLY, DELETIONS):
        result = run([bad], settings, th=TH, client=Untouchable())[0]
        assert (result.outcome, result.detail) == (FAILED, "invalid_action")


# ---------------------------------------------------------------------------------------------
# proposals: seven transitions, each a compare-and-set
# ---------------------------------------------------------------------------------------------

def planned_us(eid: str, pid: str) -> int:
    with engagement_scope(eid) as conn:
        return conn.execute(text(
            "SELECT (extract(epoch FROM stage_updated_at) * 1000000)::bigint "
            "FROM action_proposals WHERE proposal_id = :p"), {"p": pid}).scalar_one()


def state(eid: str, pid: str) -> tuple:
    with engagement_scope(eid) as conn:
        return tuple(conn.execute(text(
            "SELECT pipeline_stage, stage_detail, dispatch_state FROM action_proposals "
            "WHERE proposal_id = :p"), {"p": pid}).one())


def move(eid, pid, kind, reason, stage, **kw) -> Action:
    return Action(kind=kind, reason_code=reason, subject_id=pid, engagement_id=eid,
                  expected_stage=stage, planned_stage_updated_us=planned_us(eid, pid), **kw)


def made(eid, stage, kind, reason):
    pid = _proposal(eid, stage)
    return pid, move(eid, pid, kind, reason, stage)


TRANSITIONS = [
    ("received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE, ("abandoned", "undecided_past_grace")),
    ("decided", vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION,
     ("closed", "abandoned_after_decision")),
    ("capability_issued", vocab.CLOSE, vocab.CAPABILITY_NOT_LIVE,
     ("closed", "capability_not_live")),
    ("approved", vocab.CLOSE, vocab.APPROVAL_EXPIRED, ("closed", "approval_expired")),
    ("approved", vocab.CLOSE, vocab.APPROVAL_REVOKED, ("closed", "approval_revoked")),
    ("approved", vocab.CLOSE, vocab.ENGAGEMENT_KILLED, ("closed", "engagement_killed")),
    ("dispatching", vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME,
     ("recorded", "unknown_outcome")),
]


@pytest.mark.parametrize("stage, kind, reason, expected", TRANSITIONS)
def test_each_transition_is_carried_out_verified_and_reported_to_the_hook(
        engagement_id, stage, kind, reason, expected):
    pid, a = made(engagement_id, stage, kind, reason)
    seen = []

    def hook(result):
        seen.append((result.outcome, state(engagement_id, pid)[:2]))      # the new state is there

    (result,) = run([a], STATE_ONLY, on_verified=hook)
    assert (result.outcome, result.detail) == (DONE, None)
    assert state(engagement_id, pid)[:2] == expected
    assert seen == [(DONE, expected)]


def test_a_dispatch_declared_unknown_takes_its_runs_with_it(engagement_id):
    pid = _proposal(engagement_id, "dispatching")
    cid = _capability(engagement_id, pid, '{"max_duration_seconds": 60}')
    live = _run(engagement_id, pid, cid, "running")
    done = _run(engagement_id, pid, cid, "succeeded")
    a = move(engagement_id, pid, vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME, "dispatching")
    assert run([a], STATE_ONLY)[0].outcome == DONE
    assert state(engagement_id, pid) == ("recorded", "unknown_outcome", "unknown_outcome")
    with engagement_scope(engagement_id) as conn:
        statuses = dict(conn.execute(text(
            "SELECT run_id, status FROM tool_runs WHERE proposal_id = :p"), {"p": pid}).all())
    assert statuses == {live: "unknown_outcome", done: "succeeded"}      # only the in-flight one


ANOTHER_STAGE = {"received": "decided", "decided": "capability_issued",
                 "capability_issued": "dispatching", "approved": "dispatching",
                 "dispatching": "recorded"}


@pytest.mark.parametrize("stage, kind, reason, expected", TRANSITIONS)
def test_every_transition_is_a_compare_and_set_on_the_observed_timestamp(
        engagement_id, stage, kind, reason, expected):
    pid, a = made(engagement_id, stage, kind, reason)
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = now() "
                          "WHERE proposal_id = :p"), {"p": pid})
    hooked = []
    (result,) = run([a], STATE_ONLY, on_verified=hooked.append)
    assert result.outcome == LOST_RACE and hooked == []
    assert state(engagement_id, pid)[0] == stage


@pytest.mark.parametrize("stage, kind, reason, expected", TRANSITIONS)
def test_every_transition_needs_the_stage_the_plan_saw(
        engagement_id, stage, kind, reason, expected):
    pid, a = made(engagement_id, stage, kind, reason)
    with engagement_scope(engagement_id) as conn:     # the stage moves; its timestamp does not
        conn.execute(text("UPDATE action_proposals SET pipeline_stage = :s, "
                          "decision = coalesce(decision, 'ALLOW') WHERE proposal_id = :p"),
                     {"p": pid, "s": ANOTHER_STAGE[stage]})
    assert run([a], STATE_ONLY)[0].outcome == LOST_RACE
    assert state(engagement_id, pid)[0] == ANOTHER_STAGE[stage]


def test_the_compare_and_set_matches_the_timestamp_to_the_last_microsecond(engagement_id):
    pid = _proposal(engagement_id, "received")
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = "
                          "TIMESTAMPTZ '2026-01-01 00:00:00.123457+00' WHERE proposal_id = :p"),
                     {"p": pid})
    a = move(engagement_id, pid, vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE, "received")
    assert a.planned_stage_updated_us % 1_000_000 == 123457
    assert run([a], STATE_ONLY)[0].outcome == DONE
    off_by_one = _proposal(engagement_id, "received")
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = "
                          "TIMESTAMPTZ '2026-01-01 00:00:00.123457+00' WHERE proposal_id = :p"),
                     {"p": off_by_one})
    b = move(engagement_id, off_by_one, vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE, "received")
    b = Action(**{**b.__dict__, "planned_stage_updated_us": b.planned_stage_updated_us + 1})
    assert run([b], STATE_ONLY)[0].outcome == LOST_RACE            # one microsecond off is a miss


def test_a_proposal_touched_since_the_plan_is_lost_race_and_left_alone(engagement_id):
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    with engagement_scope(engagement_id) as conn:                         # a live driver touched it
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = now() "
                          "WHERE proposal_id = :p"), {"p": pid})
    hooked = []
    (result,) = run([a], STATE_ONLY, on_verified=hooked.append)
    assert result.outcome == LOST_RACE and hooked == []
    assert state(engagement_id, pid)[0] == "received"


def test_a_proposal_that_moved_to_another_stage_is_lost_race(engagement_id):
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE action_proposals SET pipeline_stage = 'decided', "
                          "decision = 'ALLOW' WHERE proposal_id = :p"), {"p": pid})
    assert run([a], STATE_ONLY)[0].outcome == LOST_RACE
    assert state(engagement_id, pid)[0] == "decided"


def test_the_act_cannot_reach_another_engagements_proposal(engagement_factory):
    (mine, _), (theirs, _) = engagement_factory(), engagement_factory()
    pid, honest = made(theirs, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    wrong = Action(kind=honest.kind, reason_code=honest.reason_code, subject_id=pid,
                   engagement_id=mine, expected_stage="received",
                   planned_stage_updated_us=honest.planned_stage_updated_us)
    assert run([wrong], STATE_ONLY)[0].outcome == LOST_RACE
    assert state(theirs, pid)[0] == "received"
    assert run([honest], STATE_ONLY)[0].outcome == DONE                   # and the right id works


def test_a_transition_the_vocabulary_does_not_name_is_refused(engagement_id):
    pid, good = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    for bad in (
        Action(**{**good.__dict__, "expected_stage": "decided"}),          # not this reason's stage
        Action(**{**good.__dict__, "engagement_id": None}),
        Action(**{**good.__dict__, "planned_stage_updated_us": None}),
        Action(**{**good.__dict__, "kind": vocab.CLOSE}),                  # close for undecided
    ):
        assert run([bad], STATE_ONLY)[0].detail == "invalid_action", bad
    assert state(engagement_id, pid)[0] == "received"


def test_a_row_locked_by_a_live_driver_waits_and_then_loses_the_race(engagement_id):
    """The decision transaction is open and holds the row; the act blocks on it, and when the
    decision commits (which moves ``stage_updated_at``) the compare-and-set matches nothing."""
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    box = {}

    def act_in_thread():
        box["result"] = run([a], STATE_ONLY)[0]

    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = now() "
                          "WHERE proposal_id = :p"), {"p": pid})
        worker = threading.Thread(target=act_in_thread)
        worker.start()
        time.sleep(1.0)
        assert worker.is_alive(), "the act did not wait for the row"
    worker.join(timeout=15)
    assert box["result"].outcome == LOST_RACE
    assert state(engagement_id, pid)[0] == "received"


def test_an_update_that_does_not_stick_is_failed_not_done(engagement_id, monkeypatch):
    pid, a = made(engagement_id, "decided", vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)
    monkeypatch.setattr(act.stages, "stage_of", lambda conn, pid_: ("decided", None))
    hooked = []
    (result,) = run([a], STATE_ONLY, on_verified=hooked.append)
    assert (result.outcome, result.detail) == (FAILED, "not_changed_after_update")
    assert hooked == []


def test_runs_left_in_flight_after_an_unknown_outcome_are_failed_not_done(engagement_id,
                                                                          monkeypatch):
    pid = _proposal(engagement_id, "dispatching")
    cid = _capability(engagement_id, pid, '{"max_duration_seconds": 60}')
    _run(engagement_id, pid, cid, "running")
    a = move(engagement_id, pid, vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME, "dispatching")
    monkeypatch.setattr(act, "RUNS_SQL", "SELECT 1 WHERE CAST(:pid AS text) IS NOT NULL")
    result = run([a], STATE_ONLY)[0]
    assert (result.outcome, result.detail) == (FAILED, "not_changed_after_update")


def test_a_failing_hook_is_logged_and_the_rest_of_the_pass_goes_on(engagement_id, caplog):
    first = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    second = made(engagement_id, "decided", vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)

    def hook(result):
        raise RuntimeError("secret detail that must not be logged")

    with caplog.at_level("ERROR", logger="cyberorch.reconciler"):
        results = run([first[1], second[1]], STATE_ONLY, on_verified=hook)
    assert [r.outcome for r in results] == [DONE, DONE]
    assert state(engagement_id, second[0])[0] == "closed"
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "RuntimeError" in logged and "secret detail" not in logged


def test_one_failing_action_does_not_stop_the_others(engagement_id):
    bad = Action(kind=vocab.CLOSE, reason_code=vocab.CAPABILITY_NOT_LIVE, subject_id="P-none",
                 engagement_id=engagement_id, expected_stage="capability_issued",
                 planned_stage_updated_us=1)
    pid, good = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    results = run([bad, good], STATE_ONLY)
    assert [r.outcome for r in results] == [LOST_RACE, DONE]


# ---------------------------------------------------------------------------------------------
# deletions -- the flag is on only here, in tests
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def client():
    c = docker.from_env()
    try:
        c.ping()
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"Docker is required for this test: {exc}")
    return c


@pytest.fixture
def cleanup(client):
    made_things = []
    yield made_things
    for thing in made_things:
        try:
            thing.remove(force=True) if hasattr(thing, "attrs") and "State" in thing.attrs \
                else thing.remove()
        except (NotFound, APIError):
            pass


def labelled(client, cleanup, *, run_id=None, owner="ENG-ACT", proxy=False,
             command=("sleep", "300"), start=True):
    labels = {"cyberorch.run_id": run_id or f"RUN-{uuid.uuid4().hex[:8]}",
              "cyberorch.owner": owner}
    if proxy:
        labels["cyberorch.egress_proxy"] = "1"
    c = client.containers.create(IMAGE, command=list(command), labels=labels)
    cleanup.append(c)
    if start:
        c.start()
    c.reload()
    return c


def kill_action(c, kind=vocab.KILL_CONTAINER, reason=vocab.OVERRAN_DEADLINE, **kw) -> Action:
    return Action(kind=kind, reason_code=reason, subject_id=c.id,
                  run_id=c.labels["cyberorch.run_id"], expected_owner=c.labels["cyberorch.owner"],
                  engagement_id=c.labels["cyberorch.owner"], **kw)


def test_real_a_running_container_is_killed_verified_and_reported(client, cleanup):
    c = labelled(client, cleanup)
    seen = []

    def hook(result):
        c.reload()
        seen.append((result.outcome, c.attrs["State"]["Running"]))

    (result,) = run([kill_action(c)], DELETIONS, th=TH, client=client, on_verified=hook)
    assert result.outcome == DONE and seen == [(DONE, False)]
    again = run([kill_action(c)], DELETIONS, th=TH, client=client)[0]
    assert (again.outcome, again.detail) == (CHANGED, "not_running")
    assert client.containers.get(c.id)                         # killed, and the corpse is kept


@pytest.mark.parametrize("change", [
    dict(run_id="RUN-someone-else"), dict(expected_owner="ENG-someone-else")])
def test_real_labels_that_are_not_what_the_plan_saw_stop_the_action(client, cleanup, change):
    c = labelled(client, cleanup)
    a = Action(**{**kill_action(c).__dict__, **change})
    result = run([a], DELETIONS, th=TH, client=client)[0]
    assert (result.outcome, result.detail) == (CHANGED, "labels_changed")
    c.reload()
    assert c.attrs["State"]["Running"] is True


def test_real_a_proxy_label_is_part_of_what_the_plan_saw(client, cleanup):
    tool = labelled(client, cleanup)
    wrongly = kill_action(tool, kind=vocab.REMOVE_PROXY, reason=vocab.OWNER_RUN_ENDED)
    assert run([wrongly], DELETIONS, th=TH, client=client)[0].detail == "labels_changed"
    proxy = labelled(client, cleanup, proxy=True)
    wrongly = kill_action(proxy, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    assert run([wrongly], DELETIONS, th=TH, client=client)[0].detail == "labels_changed"
    tool.reload()
    proxy.reload()
    assert tool.status == "running" and proxy.status == "running"


@pytest.mark.parametrize("handle", ["short id", "name", "empty", "upper"])
def test_real_only_a_full_id_is_a_handle(client, cleanup, handle):
    c = labelled(client, cleanup)
    handles = {"short id": c.id[:12], "name": c.name, "empty": "", "upper": c.id.upper()}
    a = Action(**{**kill_action(c).__dict__, "subject_id": handles[handle]})
    result = run([a], DELETIONS, th=TH, client=client)[0]
    assert (result.outcome, result.detail) == (FAILED, "invalid_action")
    c.reload()
    assert c.status == "running"


def test_real_a_container_that_took_over_the_name_is_not_touched(client, cleanup):
    original = labelled(client, cleanup, command=("true",), start=False)
    name, old_id = original.name, original.id
    a = kill_action(original, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    original.remove(force=True)
    newcomer = client.containers.create(IMAGE, command=["sleep", "300"], name=name,
                                        labels={"app": "innocent"})
    cleanup.append(newcomer)
    assert newcomer.name == name and newcomer.id != old_id
    result = run([a], DELETIONS, th=TH, client=client)[0]
    assert result.outcome == GONE                              # by id: not found, so nothing done
    assert client.containers.get(newcomer.id).name == name


def test_real_a_container_at_rest_is_removed_and_seen_gone_a_running_one_is_not(client, cleanup):
    at_rest = labelled(client, cleanup, command=("true",))
    at_rest.wait(timeout=30)
    running = labelled(client, cleanup)
    seen = []
    remove = kill_action(at_rest, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    result = run([remove], DELETIONS, th=TH, client=client, on_verified=seen.append)[0]
    assert result.outcome == DONE and len(seen) == 1
    with pytest.raises(NotFound):
        client.containers.get(at_rest.id)
    started_since = kill_action(running, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    result = run([started_since], DELETIONS, th=TH, client=client)[0]
    assert (result.outcome, result.detail) == (CHANGED, "not_at_rest")
    running.reload()
    assert running.status == "running"


def test_real_an_overdue_proxy_is_removed_even_though_it_is_running(client, cleanup):
    proxy = labelled(client, cleanup, proxy=True)
    a = kill_action(proxy, kind=vocab.REMOVE_PROXY, reason=vocab.OVERRAN_DEADLINE)
    assert run([a], DELETIONS, th=TH, client=client)[0].outcome == DONE
    with pytest.raises(NotFound):
        client.containers.get(proxy.id)


def make_network(client, cleanup, *, label=True, name=None):
    name = name or f"cyberorch-allow-{uuid.uuid4().hex[:12]}"
    net = client.networks.create(name, internal=True,
                                 labels={"cyberorch.allowlist": "10.98.0.0/29"} if label else {})
    cleanup.append(net)
    net.reload()
    return net


def net_action(net) -> Action:
    return Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP, subject_id=net.id,
                  name=net.name)


def test_real_an_idle_network_is_removed_and_seen_gone(client, cleanup):
    net = make_network(client, cleanup)
    seen = []
    assert run([net_action(net)], DELETIONS, th=TH, client=client,
               on_verified=seen.append)[0].outcome == DONE
    assert len(seen) == 1
    with pytest.raises(NotFound):
        client.networks.get(net.id)
    assert run([net_action(net)], DELETIONS, th=TH, client=client)[0].outcome == GONE


def test_real_a_network_with_a_container_of_any_state_is_kept(client, cleanup):
    net = make_network(client, cleanup)
    waiting = client.containers.create(IMAGE, command=["true"], network=net.name)   # created only
    cleanup.insert(0, waiting)
    result = run([net_action(net)], DELETIONS, th=TH, client=client)[0]
    assert (result.outcome, result.detail) == (CHANGED, "in_use")
    assert client.networks.get(net.id)


def test_real_a_lookalike_network_is_not_ours(client, cleanup):
    lookalike = make_network(client, cleanup, label=False)
    result = run([net_action(lookalike)], DELETIONS, th=TH, client=client)[0]
    assert (result.outcome, result.detail) == (CHANGED, "not_ours")
    assert client.networks.get(lookalike.id)
    renamed = Action(**{**net_action(make_network(client, cleanup)).__dict__, "name": "other"})
    assert run([renamed], DELETIONS, th=TH, client=client)[0].detail == "not_ours"


# --- an object that says it is done and is not -------------------------------------------

class Ticker:
    """A clock that only moves when ``sleep`` is called, so a verification wait costs nothing."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = 0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        self.sleeps += 1


class LyingContainer:
    def __init__(self, labels, *, running=True):
        self.id = "a" * 64
        self.labels = labels
        self.attrs = {"State": {"Status": "running" if running else "exited", "Running": running}}
        self.removed = False

    def reload(self):
        return None

    def kill(self):
        return None                                 # says nothing, does nothing

    def remove(self, force=False):
        self.removed = True                         # "removed", and is still there


def fake_client(container=None, network=None):
    containers = SimpleNamespace(
        get=lambda cid: container if container is not None else (_ for _ in ()).throw(NotFound("")),
        list=lambda **kw: [container] if container is not None else [])
    networks = SimpleNamespace(
        get=lambda nid: network if network is not None else (_ for _ in ()).throw(NotFound("")))
    return SimpleNamespace(containers=containers, networks=networks)


LABELS = {"cyberorch.run_id": "R", "cyberorch.owner": "E"}
FAKE_ACTION = dict(subject_id="a" * 64, run_id="R", expected_owner="E", engagement_id="E")


def test_a_kill_that_does_nothing_is_failed_after_the_wait_and_never_reaches_the_hook():
    ticker = Ticker()
    hooked = []
    a = Action(kind=vocab.KILL_CONTAINER, reason_code=vocab.OVERRAN_DEADLINE, **FAKE_ACTION)
    result = run([a], DELETIONS, th=TH, client=fake_client(LyingContainer(LABELS)),
                 sleep=ticker.sleep, clock=ticker.clock, on_verified=hooked.append)[0]
    assert (result.outcome, result.detail) == (FAILED, "still_running_after_kill")
    assert hooked == [] and ticker.now >= TH.verify_wait_s        # it waited the configured time


def test_a_removal_that_leaves_the_container_is_failed_not_done():
    ticker = Ticker()
    c = LyingContainer(LABELS, running=False)
    a = Action(kind=vocab.REMOVE_CONTAINER, reason_code=vocab.RUN_FINISHED, **FAKE_ACTION)
    result = run([a], DELETIONS, th=TH, client=fake_client(c), sleep=ticker.sleep,
                 clock=ticker.clock)[0]
    assert (result.outcome, result.detail) == (FAILED, "not_gone_after_removal")
    assert c.removed is True


def test_a_container_listed_after_get_says_not_found_is_still_not_gone():
    """``get`` raises NotFound but the listing still shows the id: not gone (E14-V2)."""
    ticker = Ticker()
    c = LyingContainer(LABELS, running=False)
    calls = {"get": 0}

    def get(cid):
        calls["get"] += 1
        if c.removed:
            raise NotFound("")
        return c

    client = SimpleNamespace(containers=SimpleNamespace(get=get, list=lambda **kw: [c]))
    a = Action(kind=vocab.REMOVE_CONTAINER, reason_code=vocab.RUN_FINISHED, **FAKE_ACTION)
    result = run([a], DELETIONS, th=TH, client=client, sleep=ticker.sleep, clock=ticker.clock)[0]
    assert (result.outcome, result.detail) == (FAILED, "not_gone_after_removal")


def test_a_network_removal_that_does_nothing_is_failed_not_done():
    ticker = Ticker()

    class Net:
        id = "b" * 64
        name = "cyberorch-allow-abcdef123456"
        attrs = {"Labels": {"cyberorch.allowlist": "10.0.0.0/29"}}

        def reload(self):
            return None

        def remove(self):
            return None

    client = fake_client(network=Net())
    client.containers = SimpleNamespace(list=lambda **kw: [])
    a = Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP, subject_id="b" * 64,
               name=Net.name)
    result = run([a], DELETIONS, th=TH, client=client, sleep=ticker.sleep, clock=ticker.clock)[0]
    assert (result.outcome, result.detail) == (FAILED, "not_gone_after_removal")


def test_dockers_refusal_is_reported_as_in_use_and_the_exception_text_is_not():
    class Net:
        id = "b" * 64
        name = "cyberorch-allow-abcdef123456"
        attrs = {"Labels": {"cyberorch.allowlist": "10.0.0.0/29"}}

        def reload(self):
            return None

        def remove(self):
            raise APIError("has active endpoints: 10.0.0.9 secret-container-name")

    client = fake_client(network=Net())
    client.containers = SimpleNamespace(list=lambda **kw: [])
    a = Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP, subject_id="b" * 64,
               name=Net.name)
    result = run([a], DELETIONS, th=TH, client=client)[0]
    assert (result.outcome, result.detail) == (FAILED, "in_use")
    assert "secret" not in repr(result.detail)


def test_a_daemon_error_is_a_fixed_code_not_its_text():
    class Broken(LyingContainer):
        def kill(self):
            raise APIError("boom: /var/lib/docker/some/secret/path")

    a = Action(kind=vocab.KILL_CONTAINER, reason_code=vocab.OVERRAN_DEADLINE, **FAKE_ACTION)
    result = run([a], DELETIONS, th=TH, client=fake_client(Broken(LABELS)))[0]
    assert (result.outcome, result.detail) == (FAILED, "daemon_error")
    assert "secret" not in repr(result)


def test_the_verification_waits_the_configured_time_and_not_more():
    for wait in (3, 25):
        ticker = Ticker()
        a = Action(kind=vocab.KILL_CONTAINER, reason_code=vocab.OVERRAN_DEADLINE, **FAKE_ACTION)
        th = Thresholds(**{**TH.__dict__, "verify_wait_s": wait})
        run([a], DELETIONS, th=th, client=fake_client(LyingContainer(LABELS)),
            sleep=ticker.sleep, clock=ticker.clock)
        assert wait <= ticker.now < wait + 1, (wait, ticker.now)


# ---------------------------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------------------------

AGE = TH.file_age_s()


def old(path, age_s=AGE + 60):
    t = time.time() - age_s
    os.utime(path, (t, t), follow_symlinks=False)


def file_action(directory, name, reason="credential_mount") -> Action:
    return Action(kind=vocab.UNLINK_FILE, reason_code=reason, subject_id=name, name=name,
                  directory=str(directory))


def files_client(*mounts, status="running"):
    c = SimpleNamespace(attrs={"State": {"Status": status},
                               "Mounts": [{"Source": m} for m in mounts]})
    return SimpleNamespace(containers=SimpleNamespace(list=lambda **kw: [c]))


def unlink_run(tmp_path, a, client=None, uid=None, **kw):
    return run([a], DELETIONS, th=TH, client=client or files_client(), directory=str(tmp_path),
               expected_uid=os.getuid() if uid is None else uid, **kw)[0]


@pytest.mark.parametrize("name, reason", [
    ("cyberorch-cred-ab12_xyz", "credential_mount"), ("cyberorch-tls-ab12_xyz.pem", "tls_leaf")])
def test_an_old_unmounted_file_of_ours_is_unlinked_and_seen_gone(tmp_path, name, reason):
    path = tmp_path / name
    path.write_text("secret")
    old(path)
    seen = []
    result = unlink_run(tmp_path, file_action(tmp_path, name, reason), on_verified=seen.append)
    assert result.outcome == DONE and len(seen) == 1 and not path.exists()


def test_a_file_is_judged_again_on_the_spot(tmp_path):
    name = "cyberorch-cred-ab12_xyz"
    path = tmp_path / name
    path.write_text("secret")
    a = file_action(tmp_path, name)
    assert unlink_run(tmp_path, a).detail == "too_young"                  # younger than the bound
    old(path)
    assert unlink_run(tmp_path, a, client=files_client(str(path))).detail == "mounted"
    assert unlink_run(tmp_path, a, client=files_client(str(path), status="created")
                      ).detail == "mounted"
    assert unlink_run(tmp_path, a, client=files_client(str(path), status="exited")
                      ).outcome == DONE                                     # an exited one is done
    path.write_text("again")
    old(path)
    assert unlink_run(tmp_path, a, uid=os.getuid() + 1).detail == "foreign_owner"
    assert path.exists()


def test_a_symlink_is_not_unlinked_and_its_target_is_untouched(tmp_path):
    target = tmp_path / "victim"
    target.write_text("do not touch")
    link = tmp_path / "cyberorch-cred-linkxxxx"
    link.symlink_to(target)
    old(link)
    result = unlink_run(tmp_path, file_action(tmp_path, link.name))
    assert (result.outcome, result.detail) == (CHANGED, "not_a_regular_file")
    assert link.is_symlink() and target.read_text() == "do not touch"


@pytest.mark.parametrize("name, directory_ok", [
    ("cyberorch-cred-AB12_XYZ", True), ("cyberorch-cred-ab12_xyz.pem", True),
    ("cyberorch-tls-ab12_xyz", True), ("../cyberorch-cred-ab12_xyz", True),
    ("cyberorch-cred-ab12_xyz", False)])
def test_a_name_or_a_directory_that_is_not_the_configured_one_is_refused(
        tmp_path, name, directory_ok):
    (tmp_path / "keep").write_text("x")
    other = tmp_path / "other"
    other.mkdir()
    a = file_action(tmp_path if directory_ok else other, name)
    reason = "tls_leaf" if "tls" in name else "credential_mount"
    a = Action(**{**a.__dict__, "reason_code": reason})
    result = unlink_run(tmp_path, a)
    assert (result.outcome, result.detail) == (FAILED, "invalid_action")
    assert (tmp_path / "keep").exists()


def test_a_file_that_vanished_is_already_gone(tmp_path):
    assert unlink_run(tmp_path, file_action(tmp_path, "cyberorch-cred-ab12_xyz")).outcome == GONE


def test_an_unlink_that_leaves_the_file_is_failed_not_done(tmp_path, monkeypatch):
    path = tmp_path / "cyberorch-cred-ab12_xyz"
    path.write_text("secret")
    old(path)
    monkeypatch.setattr(os, "unlink", lambda *a, **kw: None)
    hooked = []
    result = unlink_run(tmp_path, file_action(tmp_path, path.name), on_verified=hooked.append)
    assert (result.outcome, result.detail) == (FAILED, "not_gone_after_removal")
    assert hooked == [] and path.exists()


# ---------------------------------------------------------------------------------------------
# plan -> act, end to end
# ---------------------------------------------------------------------------------------------

def test_plan_then_act_moves_the_real_rows_and_a_second_pass_finds_nothing_left(
        engagement_id, tmp_path):
    from control_plane.reconciler import observe
    from control_plane.reconciler.plan import plan
    from control_plane.state.db import reconciler_reader_scope
    received = _proposal(engagement_id, "received")
    decided = _proposal(engagement_id, "decided")
    lapsed = _proposal(engagement_id, "capability_issued")
    _capability(engagement_id, lapsed, '{"max_duration_seconds": 60}',
                lease="TIMESTAMPTZ '1970-01-02 01:00:00+00'")
    approved = _proposal(engagement_id, "approved")
    _approval(engagement_id, approved, valid="TIMESTAMPTZ '1970-01-03 00:00:00+00'")
    dispatching = _proposal(engagement_id, "dispatching")
    cap = _capability(engagement_id, dispatching, '{"max_duration_seconds": 120}')
    _run(engagement_id, dispatching, cap, "running")

    class Docker:
        containers = SimpleNamespace(list=lambda **kw: [])
        networks = SimpleNamespace(list=lambda: [])

    def one_pass():
        with reconciler_reader_scope() as conn:
            obs = observe.observe(conn, Docker, directory=str(tmp_path), expected_uid=os.getuid(),
                                  clock_us=lambda: time.time_ns() // 1000)
        mine = [a for a in plan(obs, TH).actions if a.engagement_id == engagement_id]
        return mine, run(mine, STATE_ONLY)

    actions, results = one_pass()
    assert {a.subject_id for a in actions} == {received, decided, lapsed, approved, dispatching}
    assert [r.outcome for r in results] == [DONE] * 5
    assert state(engagement_id, received)[:2] == ("abandoned", "undecided_past_grace")
    assert state(engagement_id, decided)[:2] == ("closed", "abandoned_after_decision")
    assert state(engagement_id, lapsed)[:2] == ("closed", "capability_not_live")
    assert state(engagement_id, approved)[:2] == ("closed", "approval_expired")
    assert state(engagement_id, dispatching)[:2] == ("recorded", "unknown_outcome")
    again, _ = one_pass()
    assert again == []                                          # nothing is left to do
