"""The order of change and record (D64 pre-deletion item 4, ACCEPTANCE 5.86).

Two rules, each shown where it can fail:

* **A proposal transition and its audit record are one transaction.** Both exist or neither does:
  seen from a second connection while the change is open, rolled back when the record cannot be
  written (a hook that raises, and a record the database itself refuses), never called for a lost
  race, and -- with a real ``kill -9`` of a child process at three points -- either both rows or
  neither after the process is gone.
* **An irreversible act on a Docker object or a host file is announced first.** The intent is
  written after the last check that can decline and right before the call: never for an action
  that was declined, never after the call, and if it cannot be written no call is made. An intent
  with no result, because the process died between the call and its verification, is listed by
  ``unresolved_reconciler_intents`` -- and is not listed when the result, or a failure, followed.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import docker
import pytest
from docker.errors import APIError, NotFound
from sqlalchemy import text

from control_plane.audit.logger import AuditWriteError, record_audit_in_transaction
from control_plane.audit.query import unresolved_reconciler_intents
from control_plane.reconciler import emit, vocab
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.act import carry_out as run
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import CHANGED, DONE, FAILED, GONE, LOST_RACE, SKIPPED_OFF
from control_plane.state.db import engagement_scope
from tests.helpers import committing_scope
from tests.test_reconciler_act import (  # helpers shared with the act tests
    DELETIONS,
    FAKE_ACTION,
    LABELS,
    STATE_ONLY,
    TH,
    LyingContainer,
    Ticker,
    fake_client,
    files_client,
    kill_action,
    labelled,
    made,
    make_network,
    net_action,
    old,
    state,
)

REPO = Path(__file__).resolve().parents[1]


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


def events_of(eid, *types):
    with committing_scope(eid) as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT audit_id, event_type, payload, subject_id FROM audit_log "
            "WHERE engagement_id = :e AND event_type = ANY(:t) ORDER BY audit_id"),
            {"e": eid, "t": list(types) or list(emit.EVENTS)}).mappings()]


def record_hook(conn, action):
    """What the service's ``_record`` does, without the service."""
    event_type, payload, engagement_id, subject_type, subject_id = emit.for_proposal_action(action)
    emit.emit_in_transaction(conn, event_type, payload, engagement_id=engagement_id,
                             subject_type=subject_type, subject_id=subject_id)


# ---------------------------------------------------------------------------------------------
# a transition and its record: one transaction
# ---------------------------------------------------------------------------------------------

def test_the_record_is_written_inside_the_transition_and_is_visible_only_with_it(engagement_id):
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    seen = {}

    def hook(conn, action):
        seen["inside"] = tuple(conn.execute(text(
            "SELECT pipeline_stage, stage_detail FROM action_proposals WHERE proposal_id = :p"),
            {"p": pid}).one())
        seen["elsewhere"] = state(engagement_id, pid)[:2]           # another connection
        record_hook(conn, action)
        with committing_scope(engagement_id) as other:                # ... and the record, too
            seen["record_elsewhere"] = other.execute(text(
                "SELECT count(*) FROM audit_log WHERE subject_id = :p AND event_type = :t"),
                {"p": pid, "t": emit.PROPOSAL_ABANDONED}).scalar_one()

    (result,) = run([a], STATE_ONLY, record=hook)
    assert (result.outcome, result.audited) == (DONE, True)
    assert seen["inside"] == ("abandoned", "undecided_past_grace")
    assert seen["elsewhere"] == ("received", None)                  # not committed yet
    assert seen["record_elsewhere"] == 0
    assert state(engagement_id, pid)[:2] == ("abandoned", "undecided_past_grace")
    (event,) = events_of(engagement_id, emit.PROPOSAL_ABANDONED)
    assert event["subject_id"] == pid
    assert event["payload"] == {"proposal_id": pid, "reason_code": "undecided_past_grace"}


@pytest.mark.parametrize("stage, kind, reason", [
    ("received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE),
    ("decided", vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION),
    ("dispatching", vocab.MARK_UNKNOWN_OUTCOME, vocab.UNKNOWN_OUTCOME)])
def test_a_record_that_raises_rolls_the_transition_back(engagement_id, stage, kind, reason, caplog):
    pid, a = made(engagement_id, stage, kind, reason)

    def hook(conn, action):
        raise RuntimeError("text that must not reach the log: 10.0.0.5")

    with caplog.at_level("ERROR", logger="cyberorch.reconciler"):
        (result,) = run([a], STATE_ONLY, record=hook)
    assert (result.outcome, result.detail, result.audited) == (FAILED, "audit_failed", False)
    assert state(engagement_id, pid)[0] == stage                     # nothing changed
    assert events_of(engagement_id) == []
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "RuntimeError" in logged and "10.0.0.5" not in logged


def test_a_record_the_database_itself_refuses_rolls_the_transition_back(engagement_id):
    """Not a hook that raises: an insert that row-level security rejects (another engagement's id),
    which aborts the transaction -- the transition must not survive it."""
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)

    def hook(conn, action):
        record_audit_in_transaction(
            conn, engagement_id="ENG-NOT-THE-BOUND-ONE", actor="reconciler",
            event_type=emit.PROPOSAL_ABANDONED, payload={"proposal_id": pid})

    with pytest.raises(AuditWriteError):                              # the writer's own contract
        with engagement_scope(engagement_id) as conn:
            hook(conn, a)
    (result,) = run([a], STATE_ONLY, record=hook)
    assert (result.outcome, result.detail) == (FAILED, "audit_failed")
    assert state(engagement_id, pid)[0] == "received"
    assert events_of(engagement_id) == []


def test_the_record_is_not_written_for_a_lost_race_a_dry_run_or_a_deletion(engagement_id):
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    with engagement_scope(engagement_id) as conn:
        conn.execute(text("UPDATE action_proposals SET stage_updated_at = now() "
                          "WHERE proposal_id = :p"), {"p": pid})
    called = []

    def hook(conn, action):
        called.append(action)

    assert run([a], STATE_ONLY, record=hook)[0].outcome == LOST_RACE
    assert run([a], Settings(Mode.DRY_RUN), record=hook)[0].outcome == "dry_run"
    deletion = Action(kind=vocab.KILL_CONTAINER, reason_code=vocab.OVERRAN_DEADLINE,
                      subject_id="a" * 64, run_id="R", expected_owner="E")
    assert run([deletion], STATE_ONLY, record=hook)[0].outcome == SKIPPED_OFF
    assert called == []


def test_without_a_record_hook_a_transition_still_works_and_says_it_was_not_audited(engagement_id):
    pid, a = made(engagement_id, "decided", vocab.CLOSE, vocab.ABANDONED_AFTER_DECISION)
    (result,) = run([a], STATE_ONLY)
    assert (result.outcome, result.audited) == (DONE, False)
    assert events_of(engagement_id) == []


KILL_CHILD = r"""
import json, os, signal, sys
from control_plane.config import load_dotenv
load_dotenv()
from control_plane.reconciler import act, emit
from control_plane.reconciler.model import Action

spec = json.loads(sys.argv[1])
action = Action(**spec["action"])
point = spec["point"]


def die():
    os.kill(os.getpid(), signal.SIGKILL)


def record(conn, a):
    if point == "before_the_record":
        die()
    event_type, payload, engagement_id, subject_type, subject_id = emit.for_proposal_action(a)
    emit.emit_in_transaction(conn, event_type, payload, engagement_id=engagement_id,
                             subject_type=subject_type, subject_id=subject_id)
    if point == "after_the_record_before_the_commit":
        die()


def after_commit(result):
    if point == "after_the_commit":
        die()


act.carry_out([action], act.Settings(act.Mode.STATE_ONLY), record=record, on_verified=after_commit)
"""


@pytest.mark.parametrize("point, both", [
    ("before_the_record", False), ("after_the_record_before_the_commit", False),
    ("after_the_commit", True)])
def test_a_kill_9_leaves_the_change_and_its_record_together_or_neither(engagement_id, point, both):
    """The window the 6d design could only bound ("at most the number of kills"): there is none now.
    The three points are where the old order had a gap, plus the one after it."""
    pid, a = made(engagement_id, "received", vocab.ABANDON, vocab.UNDECIDED_PAST_GRACE)
    spec = json.dumps({"point": point, "action": dict(a.__dict__)})
    child = subprocess.run([sys.executable, "-c", KILL_CHILD, spec], cwd=REPO, timeout=120,
                           env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True,
                           text=True)
    assert child.returncode == -signal.SIGKILL, (child.returncode, child.stderr[-300:])
    moved = state(engagement_id, pid)[0] == "abandoned"
    recorded = len(events_of(engagement_id, emit.PROPOSAL_ABANDONED))
    assert moved is both and recorded == (1 if both else 0), (point, moved, recorded)


# ---------------------------------------------------------------------------------------------
# an irreversible act: announced first, only once it can go ahead
# ---------------------------------------------------------------------------------------------

def test_real_the_intent_is_written_after_the_checks_and_before_the_call(client, cleanup):
    c = labelled(client, cleanup, command=("true",))
    c.wait(timeout=30)
    a = kill_action(c, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    seen = []

    def intend(action):
        seen.append(("intend", client.containers.get(c.id).status))       # still there

    (result,) = run([a], DELETIONS, th=TH, client=client, intend=intend)
    assert result.outcome == DONE
    assert seen == [("intend", "exited")]
    with pytest.raises(NotFound):
        client.containers.get(c.id)


def test_real_every_kind_of_irreversible_action_calls_intend_once_right_before_its_call(
        client, cleanup):
    running, proxy = labelled(client, cleanup), labelled(client, cleanup, proxy=True)
    at_rest = labelled(client, cleanup, command=("true",))
    at_rest.wait(timeout=30)
    net = make_network(client, cleanup)
    for action, probe in [
        (kill_action(running), lambda: client.containers.get(running.id).status == "running"),
        (kill_action(at_rest, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED),
         lambda: client.containers.get(at_rest.id) is not None),
        (kill_action(proxy, kind=vocab.REMOVE_PROXY, reason=vocab.OWNER_RUN_ENDED),
         lambda: client.containers.get(proxy.id) is not None),
        (net_action(net), lambda: client.networks.get(net.id) is not None),
    ]:
        order = []
        run([action], DELETIONS, th=TH, client=client,
            intend=lambda a, probe=probe, order=order: order.append(probe()))
        assert order == [True], action.kind


@pytest.mark.parametrize("why", ["gone", "labels_changed", "not_at_rest", "not_running",
                                 "in_use", "skipped_off", "invalid"])
def test_real_an_action_that_is_declined_writes_no_intent(client, cleanup, why):
    called = []

    def intend(action):
        called.append(action)

    if why == "gone":
        c = labelled(client, cleanup, command=("true",), start=False)
        a = kill_action(c, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
        c.remove(force=True)
        expected = GONE
    elif why == "labels_changed":
        c = labelled(client, cleanup)
        a = Action(**{**kill_action(c).__dict__, "expected_owner": "ENG-someone-else"})
        expected = CHANGED
    elif why == "not_at_rest":
        c = labelled(client, cleanup)
        a = kill_action(c, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
        expected = CHANGED
    elif why == "not_running":
        c = labelled(client, cleanup, command=("true",))
        c.wait(timeout=30)
        a = kill_action(c)
        expected = CHANGED
    elif why == "in_use":
        net = make_network(client, cleanup)
        waiting = client.containers.create("python:3.12-slim", command=["true"], network=net.name)
        cleanup.insert(0, waiting)
        a = net_action(net)
        expected = CHANGED
    elif why == "skipped_off":
        c = labelled(client, cleanup)
        a = kill_action(c)
        assert run([a], STATE_ONLY, th=TH, client=client, intend=intend)[0].outcome == SKIPPED_OFF
        assert called == []
        return
    else:
        c = labelled(client, cleanup)
        a = Action(**{**kill_action(c).__dict__, "subject_id": c.id[:12]})
        expected = FAILED
    assert run([a], DELETIONS, th=TH, client=client, intend=intend)[0].outcome == expected
    assert called == []


@pytest.mark.parametrize("kind", ["kill", "remove_container", "remove_proxy", "remove_network"])
def test_real_an_intent_that_cannot_be_written_means_no_call_is_made(client, cleanup, kind):
    def intend(action):
        raise AuditWriteError("cannot write: secret detail")

    if kind == "kill":
        c = labelled(client, cleanup)
        a = kill_action(c)
    elif kind == "remove_container":
        c = labelled(client, cleanup, command=("true",))
        c.wait(timeout=30)
        a = kill_action(c, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    elif kind == "remove_proxy":
        c = labelled(client, cleanup, proxy=True)
        a = kill_action(c, kind=vocab.REMOVE_PROXY, reason=vocab.OWNER_RUN_ENDED)
    else:
        net = make_network(client, cleanup)
        result = run([net_action(net)], DELETIONS, th=TH, client=client, intend=intend)[0]
        assert (result.outcome, result.detail) == (FAILED, "audit_failed")
        assert client.networks.get(net.id)
        return
    hooked = []
    result = run([a], DELETIONS, th=TH, client=client, intend=intend, on_verified=hooked.append)[0]
    assert (result.outcome, result.detail) == (FAILED, "audit_failed")
    assert "secret" not in repr(result) and hooked == []
    c.reload()
    assert c.status in ("running", "exited")                          # still there, still as it was


def test_an_intent_that_cannot_be_written_means_no_unlink(tmp_path):
    name = "cyberorch-cred-ab12_xyz"
    path = tmp_path / name
    path.write_text("secret")
    old(path)
    a = Action(kind=vocab.UNLINK_FILE, reason_code="credential_mount", subject_id=name, name=name,
               directory=str(tmp_path))

    def intend(action):
        raise AuditWriteError("cannot write")

    result = run([a], DELETIONS, th=TH, client=files_client(), directory=str(tmp_path),
                 expected_uid=os.getuid(), intend=intend)[0]
    assert (result.outcome, result.detail) == (FAILED, "audit_failed")
    assert path.exists()


def test_a_file_is_announced_before_it_is_unlinked_and_not_when_it_is_declined(tmp_path):
    name = "cyberorch-cred-ab12_xyz"
    path = tmp_path / name
    path.write_text("secret")
    a = Action(kind=vocab.UNLINK_FILE, reason_code="credential_mount", subject_id=name, name=name,
               directory=str(tmp_path))
    order = []

    def intend(action):
        order.append(("intend", path.exists()))

    kwargs = dict(th=TH, client=files_client(), directory=str(tmp_path), expected_uid=os.getuid(),
                  intend=intend)
    assert run([a], DELETIONS, **kwargs)[0].detail == "too_young"        # declined: no intent
    assert order == []
    old(path)
    assert run([a], DELETIONS, **kwargs)[0].outcome == DONE
    assert order == [("intend", True)] and not path.exists()


def test_an_intent_is_written_even_when_the_call_then_fails_to_verify():
    """The intent says the call was about to be made; what came of it is the result's business."""
    ticker, calls = Ticker(), []
    a = Action(kind=vocab.KILL_CONTAINER, reason_code=vocab.OVERRAN_DEADLINE, **FAKE_ACTION)
    result = run([a], DELETIONS, th=TH, client=fake_client(LyingContainer(LABELS)),
                 sleep=ticker.sleep, clock=ticker.clock, intend=calls.append)[0]
    assert (result.outcome, result.detail) == (FAILED, "still_running_after_kill")
    assert calls == [a]


# ---------------------------------------------------------------------------------------------
# the service's hooks write the real events, in the right order, and pair them
# ---------------------------------------------------------------------------------------------

def _reconciler(engagement_id, **kw):
    from control_plane.reconciler.service import Reconciler
    from tests.test_reconciler_service import MADE, FakeDocker
    r = Reconciler(settings=kw.pop("settings", DELETIONS), th=kw.pop("th", TH),
                   client=kw.pop("client", FakeDocker()), directory="/tmp",
                   expected_uid=os.getuid(), only_engagements=frozenset({engagement_id}), **kw)
    MADE.append(r)
    return r


def test_real_a_removal_is_two_events_the_intent_then_the_result_and_nothing_is_unresolved(
        client, cleanup, engagement_id):
    c = labelled(client, cleanup, command=("true",), owner=engagement_id)
    c.wait(timeout=30)
    a = kill_action(c, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    r = _reconciler(engagement_id, client=client)
    (result,) = run([a], DELETIONS, th=TH, client=client, intend=r._intend, on_verified=r._audit)
    assert result.outcome == DONE
    written = events_of(engagement_id, emit.ACTION_INTENDED, emit.CONTAINER_REMOVED)
    assert [e["event_type"] for e in written] == [emit.ACTION_INTENDED, emit.CONTAINER_REMOVED]
    run_id = c.labels["cyberorch.run_id"]
    assert written[0]["payload"] == {"kind": "remove_container", "subject_id": run_id,
                                     "reason_code": "run_finished"}
    assert written[1]["payload"] == {"run_id": run_id, "reason_code": "run_finished"}
    assert written[0]["subject_id"] == written[1]["subject_id"] == run_id
    with committing_scope(engagement_id) as conn:
        assert unresolved_reconciler_intents(conn) == []


def test_an_intent_alone_is_unresolved_and_a_result_or_a_failure_after_it_closes_it(engagement_id):
    def intent(kind, subject, reason):
        emit.emit(emit.ACTION_INTENDED, {"kind": kind, "subject_id": subject,
                                         "reason_code": reason}, engagement_id=engagement_id,
                  subject_type="tool_run", subject_id=subject)

    def listed():
        with committing_scope(engagement_id) as conn:
            return [(u.kind, u.subject_id, u.reason_code)
                    for u in unresolved_reconciler_intents(conn)]

    intent("remove_container", "RUN-A", "run_finished")                       # nothing follows
    intent("remove_container", "RUN-B", "run_finished")                       # a result follows
    emit.emit(emit.CONTAINER_REMOVED, {"run_id": "RUN-B", "reason_code": "run_finished"},
              engagement_id=engagement_id, subject_type="tool_run", subject_id="RUN-B")
    intent("kill_container", "RUN-C", "overran_deadline")                     # a failure follows
    emit.emit(emit.ACTION_FAILED, {"kind": "kill_container", "subject_id": "RUN-C",
                                   "reason_code": "still_running_after_kill"},
              engagement_id=engagement_id, subject_type="reconciler_action", subject_id="RUN-C")
    intent("kill_container", "RUN-D", "overran_deadline")                     # wrong kind follows
    emit.emit(emit.CONTAINER_REMOVED, {"run_id": "RUN-D", "reason_code": "run_finished"},
              engagement_id=engagement_id, subject_type="tool_run", subject_id="RUN-D")
    intent("remove_proxy", "RUN-E", "owner_run_ended")                        # a kill follows
    emit.emit(emit.CONTAINER_KILLED, {"run_id": "RUN-E", "reason_code": "overran_deadline"},
              engagement_id=engagement_id, subject_type="tool_run", subject_id="RUN-E")
    assert listed() == [("remove_container", "RUN-A", "run_finished"),
                        ("kill_container", "RUN-D", "overran_deadline"),
                        ("remove_proxy", "RUN-E", "owner_run_ended")]


CRASH_CHILD = r"""
import json, os, signal, sys
import docker
from control_plane.config import load_dotenv
load_dotenv()
from control_plane.reconciler import act, emit, flags
from control_plane.reconciler.config import Thresholds
from control_plane.reconciler.model import Action

spec = json.loads(sys.argv[1])
real = docker.from_env()
action = Action(**spec["action"])


class Container:
    def __init__(self, c):
        self._c = c
    def __getattr__(self, name):
        return getattr(self._c, name)
    def remove(self, force=False):
        self._c.remove(force=force)
        os.kill(os.getpid(), signal.SIGKILL)      # the call happened; nothing after it will


class Containers:
    def get(self, cid):
        return Container(real.containers.get(cid))
    def list(self, **kw):
        return real.containers.list(**kw)


def intend(a):
    event_type, payload, engagement_id, subject_type, subject_id = emit.intent_for(a)
    emit.emit(event_type, payload, engagement_id=engagement_id, subject_type=subject_type,
              subject_id=subject_id)


th = Thresholds(**spec["th"])
act.carry_out([action], act.Settings(act.Mode.STATE_ONLY, enabled=flags.EVERYTHING), th=th,
              client=type("C", (), {"containers": Containers()})(), intend=intend)
"""


def test_real_a_process_that_dies_after_the_call_leaves_a_visible_unresolved_intent(
        client, cleanup, engagement_id):
    """Before this change the same crash left nothing: the container was gone, and no record said
    so."""
    c = labelled(client, cleanup, command=("true",), owner=engagement_id)
    c.wait(timeout=30)
    a = kill_action(c, kind=vocab.REMOVE_CONTAINER, reason=vocab.RUN_FINISHED)
    spec = json.dumps({"action": dict(a.__dict__), "th": dict(TH.__dict__)})
    child = subprocess.run([sys.executable, "-c", CRASH_CHILD, spec], cwd=REPO, timeout=120,
                           env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True,
                           text=True)
    assert child.returncode == -signal.SIGKILL, (child.returncode, child.stderr[-400:])
    with pytest.raises(NotFound):
        client.containers.get(c.id)                                  # the removal did happen
    written = events_of(engagement_id, emit.ACTION_INTENDED, emit.CONTAINER_REMOVED,
                        emit.ACTION_FAILED)
    assert [e["event_type"] for e in written] == [emit.ACTION_INTENDED]    # and only the intent
    with committing_scope(engagement_id) as conn:
        (unresolved,) = unresolved_reconciler_intents(conn)
    assert (unresolved.kind, unresolved.subject_id, unresolved.reason_code) == (
        "remove_container", c.labels["cyberorch.run_id"], "run_finished")


# ---------------------------------------------------------------------------------------------
# a failing object is not attempted every pass
# ---------------------------------------------------------------------------------------------

def test_a_failed_irreversible_action_is_not_attempted_again_until_the_wait_has_passed(
        engagement_id, monkeypatch):
    from control_plane.reconciler.config import Thresholds
    from control_plane.reconciler.model import Plan
    th = Thresholds(**{**TH.__dict__, "verify_wait_s": 1, "retry_after_failure_s": 600})
    labels = {"cyberorch.run_id": "R", "cyberorch.owner": engagement_id}
    a = Action(kind=vocab.KILL_CONTAINER, reason_code=vocab.OVERRAN_DEADLINE, subject_id="a" * 64,
               run_id="R", expected_owner=engagement_id, engagement_id=engagement_id)
    clock = SimpleNamespace(now=1000.0)
    calls = {"kill": 0}

    class Stubborn(LyingContainer):
        def kill(self):
            calls["kill"] += 1                       # says nothing, does nothing

    r = _reconciler(engagement_id, th=th, client=fake_client(Stubborn(labels)),
                    monotonic=lambda: clock.now)
    monkeypatch.setattr("control_plane.reconciler.service.make_plan",
                        lambda obs, t: Plan(actions=(a,)))
    monkeypatch.setattr(r, "_observe", lambda: None)
    monkeypatch.setattr(r, "_assert_lock", lambda: None)
    r.started = True

    first = r.pass_once()
    assert first.outcomes == {"failed": 1} and first.held_back == 0 and calls["kill"] == 1
    clock.now += 599
    second = r.pass_once()                                   # inside the wait: nothing is done
    assert second.outcomes == {} and second.held_back == 1 and calls["kill"] == 1
    clock.now += 2
    third = r.pass_once()                                    # the wait is over: a new attempt
    assert third.outcomes == {"failed": 1} and third.held_back == 0 and calls["kill"] == 2
    # two attempts, two intents; the failure is reported once per object and reason
    assert len(events_of(engagement_id, emit.ACTION_INTENDED)) == 2
    assert len(events_of(engagement_id, emit.ACTION_FAILED)) == 1


def test_an_attempt_key_is_the_object_not_the_pass():
    from control_plane.reconciler.service import Reconciler
    a = Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP, subject_id="b" * 64,
               name="cyberorch-allow-0123456789ab")
    b = Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP, subject_id="c" * 64,
               name="cyberorch-allow-0123456789ab")
    assert Reconciler._attempt_key(a) == Reconciler._attempt_key(b) == (
        "remove_network", "0123456789ab")
    proposal = Action(kind=vocab.CLOSE, reason_code=vocab.APPROVAL_EXPIRED, subject_id="P-1")
    assert Reconciler._attempt_key(proposal) == ("close", "P-1")
