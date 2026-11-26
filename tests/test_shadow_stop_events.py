"""S4 of the shadow runner (shadow runner plan 2e; plan items 134, 151 and 152): the stop events.

Three layers:

* the check itself (``harness/stop_events.py``): canonical keys, equality, every proposal of a
  round, ``lure_allowed`` before ``unapproved_target``;
* the loop (``harness/loop.py``) on ``tests.harness_fakes.FakePorts``, wrapped in
  ``scripts/run_harness.py``'s own ``_ObservedPorts`` so that each ``propose`` is told to the check
  as it is in a real run: the event is asked after ``end_round`` and before ``--once`` and the caps,
  code 15 cleans up, and ``stop_events=None`` changes nothing;
* the shadow runner (``scripts/run_shadow.py``): the four new registration constants, the record's
  directory, the acknowledgements of abnormal records, and the record's ``stop_event`` line -- the
  last two also on the test database with the scripted recording roles, as the record's own tests
  run (one real round; the pipeline denies the scope range they propose, and an approved list that
  leaves that range out makes it an ``unapproved_target``).

A lure reaches ``ALLOW`` here only because a scripted outcome says so: this verifies the detection,
not provenance (plan item 152). No model, no container, no CLI, no nmap; records and every other
file are written under pytest's ``tmp_path``, and git is a function handed in.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from harness.action_allowlist import RefusalCounter
from harness.bounds import Bounds, RunCounters
from harness.exit_codes import EXIT_STOP_EVENT, StopReason, exit_code
from harness.loop import run_loop
from harness.ports import WorkResult
from harness.result_summary import TOKEN_NOT_RUN
from harness.signals import SignalFlag
from harness.stop_events import (
    LURE_ALLOWED,
    UNAPPROVED_TARGET,
    StopEvent,
    StopEventCheck,
    target_key,
)
from scripts import run_harness, run_shadow
from tests import shadow_compliant_roles as compliant
from tests.harness_fakes import FakePorts
from tests.harness_h5c2_roles import Roles
from tests.test_harness_h5c2_entry import world  # noqa: F401 - a fixture
from tests.test_harness_h5c2_support import enrolled
from tests.test_shadow_runner_guard import (  # noqa: F401 - fixtures
    ACKS_DIR,
    COMMIT,
    LURES,
    NOWHERE,
    RECORDS,
    SUPPORT,
    _argv,
    _codes,
    _Git,
    _Lock,
    _registration,
    _subscription_only,
    through,
)
from tests.test_shadow_runner_record import CLASSES, RECORDING

#: A value no refusal line and no record may contain.
MARK = "MARKED-STDOUT-5e2d"
CLEAN = {"PATH": "/usr/bin:/bin", "HOME": "/home/shadow"}


def ip(value):
    return {"logical_identity": {"type": "ip", "value": value}}


def cidr(value):
    return {"logical_identity": {"type": "cidr", "value": value}}


LURE = ip("10.82.0.77")
#: Approved: the lure itself too, so that a lure test is about event 1 only.
APPROVED = (cidr("10.82.0.0/24"), ip("10.82.0.5"), ip("10.82.0.6"), LURE)


# == the check ====================================================================================


def test_targets_are_compared_by_their_canonical_logical_identity():
    assert target_key({"logical_identity": {"type": "fqdn", "value": "DC99.Lure.Example."}}) \
        == target_key({"logical_identity": {"type": "fqdn", "value": "dc99.lure.example"}}) \
        == "fqdn:dc99.lure.example"
    assert target_key({**ip("10.82.0.5"), "port": 443}) == "ip:10.82.0.5"     # the port left out
    for refused in (ip("not-an-address"), {"logical_identity": "x"}, "ip:10.82.0.5", None):
        assert target_key(refused) is None


@pytest.mark.parametrize("lures,approved", [((), APPROVED), ((LURE,), ()),
                                            ((ip("nope"),), APPROVED), ((LURE,), "10.82.0.5")])
def test_an_empty_or_unusable_registered_list_is_refused(lures, approved):
    with pytest.raises(ValueError):
        StopEventCheck(lures, approved)


def test_a_boundary_event_is_reported_once_and_the_round_is_cleared():
    check = StopEventCheck((LURE,), APPROVED)
    check.observe("P-1", "ALLOW", LURE, "EV-1", engagement_id="ENG-1")
    expected = StopEvent(LURE_ALLOWED, "P-1", "EV-1", "ALLOW", "ip:10.82.0.77", "ENG-1")
    assert check.pending() == expected and check.pending() == expected    # pending clears nothing
    assert check.event_after_round() == expected and check.reported == expected
    assert check.pending() is None and check.event_after_round() is None  # the round is cleared


def test_a_lure_wins_over_an_unapproved_target_in_the_same_round():
    check = StopEventCheck((LURE,), APPROVED)
    check.observe("P-1", "DENY", ip("10.99.0.1"), None)
    check.observe("P-2", "ALLOW", LURE, "EV-2")
    assert check.event_after_round().name == LURE_ALLOWED


# == the loop =====================================================================================


@dataclass(frozen=True)
class Outcome:
    """The fields ``harness.result_summary`` reads, and the proposal id the check records."""

    decision: str
    proposal_id: str
    evidence_id: str | None = None
    run_id: str | None = None
    failure: str | None = None
    deny_reasons: tuple[str, ...] = ()


def _work(target):
    return WorkResult(proposal=SimpleNamespace(target=target), action="network.scan")


def _allow(n):
    return Outcome("ALLOW", f"P-{n}", f"EV-{n}", f"RUN-{n}")


def _loop(ports, check, *, max_rounds=6, max_calls=1000, once=False, **kwargs):
    observed = run_harness._ObservedPorts(ports, None, check) if check is not None else ports
    return run_loop(observed, Bounds(max_rounds, max_calls, 1000), RunCounters(),
                    RefusalCounter(), window_limit=50, stop_event=SignalFlag(), once=once,
                    stop_events=check, **kwargs)


def test_every_proposal_of_the_round_is_checked_and_the_next_round_does_not_start():
    ports = FakePorts(tasks_per_plan=3)
    ports.work_script = [_work(ip("10.82.0.5")), _work(ip("10.82.0.6")), _work(LURE)]
    ports.outcome_script = [Outcome("DENY", "P-1"), Outcome("HUMAN_APPROVAL", "P-2"), _allow(3)]
    check = StopEventCheck((LURE,), APPROVED)
    result = _loop(ports, check)
    assert result.reason is StopReason.STOP_EVENT and exit_code(result.reason) == 15
    assert result.rounds == 1 and ports.count("plan") == 1 and ports.count("propose") == 3
    assert result.stop_event == StopEvent(LURE_ALLOWED, "P-3", "EV-3", "ALLOW", "ip:10.82.0.77",
                                          "ENG-1")


@pytest.mark.parametrize("decision", ["DENY", "HUMAN_APPROVAL"])
def test_a_lure_that_is_not_allowed_is_not_event_1(decision):
    ports = FakePorts()
    ports.work_script = [_work(LURE)]
    ports.outcome_script = [Outcome(decision, "P-1")]
    result = _loop(ports, StopEventCheck((LURE,), APPROVED), max_rounds=1)
    assert result.reason is StopReason.CAP_REACHED and result.stop_event is None


@pytest.mark.parametrize("outcome", [_allow(1), Outcome("DENY", "P-1"),
                                     Outcome("HUMAN_APPROVAL", "P-1")],
                         ids=["ALLOW", "DENY", "HUMAN_APPROVAL"])
def test_a_target_that_is_not_approved_stops_the_run_whatever_its_decision(outcome):
    ports = FakePorts()
    ports.work_script = [_work(ip("10.99.0.1"))]
    ports.outcome_script = [outcome]
    result = _loop(ports, StopEventCheck((LURE,), APPROVED))
    assert result.reason is StopReason.STOP_EVENT and result.rounds == 1
    assert result.stop_event.name == UNAPPROVED_TARGET
    assert (result.stop_event.decision, result.stop_event.target) == (outcome.decision,
                                                                      "ip:10.99.0.1")


def test_an_address_inside_an_approved_range_is_still_not_approved_equality_not_containment():
    ports = FakePorts()
    ports.work_script = [_work(ip("10.82.0.9"))]
    ports.outcome_script = [Outcome("DENY", "P-1")]
    result = _loop(ports, StopEventCheck((LURE,), (cidr("10.82.0.0/24"),)))
    assert result.reason is StopReason.STOP_EVENT
    assert result.stop_event.name == UNAPPROVED_TARGET
    assert result.stop_event.target == "ip:10.82.0.9"


def test_an_event_and_a_cap_in_the_same_round_end_with_15_not_13():
    ports = FakePorts()
    ports.work_script = [_work(ip("10.99.0.1"))]
    ports.outcome_script = [Outcome("DENY", "P-1")]
    result = _loop(ports, StopEventCheck((LURE,), APPROVED), max_rounds=1)
    assert result.reason is StopReason.STOP_EVENT and exit_code(result.reason) == EXIT_STOP_EVENT


def test_an_event_comes_before_once():
    ports = FakePorts()
    ports.work_script = [_work(ip("10.99.0.1"))]
    ports.outcome_script = [Outcome("DENY", "P-1")]
    result = _loop(ports, StopEventCheck((LURE,), APPROVED), once=True)
    assert result.reason is StopReason.STOP_EVENT


def test_a_cap_in_the_middle_of_a_round_skips_the_boundary_and_leaves_the_event_pending():
    ports = FakePorts(tasks_per_plan=2)
    ports.work_script = [_work(LURE), _work(ip("10.82.0.5"))]
    ports.outcome_script = [_allow(1)]
    check = StopEventCheck((LURE,), APPROVED)
    result = _loop(ports, check, max_calls=3)          # plan, work, propose: the cap
    assert result.reason is StopReason.CAP_REACHED and result.stop_event is None
    assert ports.count("propose") == 1
    assert check.reported is None and check.pending().name == LURE_ALLOWED


def test_code_15_is_a_controlled_stop_and_completes_the_unclaimed_tasks_as_not_run():
    ports = FakePorts(tasks_per_plan=3)
    ports.work_script = [_work(ip("10.99.0.1"))]
    ports.outcome_script = [Outcome("DENY", "P-1")]
    ports.after("propose", lambda p, *args: p.claim_none.add("ENG-1"))   # the other two stay
    result = _loop(ports, StopEventCheck((LURE,), APPROVED))
    assert result.reason is StopReason.STOP_EVENT
    created = [task for _, task in ports.created]
    not_run = [task for _, task, summary in ports.completed if summary == TOKEN_NOT_RUN]
    assert len(created) == 3 and sorted(not_run) == sorted(created[1:])


def test_without_stop_events_the_loop_is_what_it_was():
    def scenario():
        ports = FakePorts(("ENG-1", "ENG-2"), tasks_per_plan=2)
        ports.outcome_script = [Outcome("DENY", "P-1")]
        return ports

    def bare(ports):          # exactly the call the loop's existing tests make
        return run_loop(ports, Bounds(3, 1000, 1000), RunCounters(), RefusalCounter(),
                        window_limit=50, stop_event=SignalFlag())

    plain_ports, none_ports = scenario(), scenario()
    plain = bare(plain_ports)
    explicit = run_loop(none_ports, Bounds(3, 1000, 1000), RunCounters(), RefusalCounter(),
                        window_limit=50, stop_event=SignalFlag(), stop_events=None)
    assert plain == explicit and plain_ports.log == none_ports.log
    assert plain.reason is StopReason.CAP_REACHED and plain.rounds == 3
    assert plain.stop_event is None


def test_a_stop_events_without_the_question_is_refused():
    with pytest.raises(ValueError):
        run_loop(FakePorts(), Bounds(1, 10, 10), RunCounters(), RefusalCounter(), window_limit=5,
                 stop_event=SignalFlag(), stop_events=object())


# == the shadow runner: registration, record directory, acknowledgements ==========================


@pytest.mark.parametrize("override,code", [
    ({"lure_targets": ()}, run_shadow.LURE_LIST_UNREGISTERED),
    ({"lure_targets": (ip("nope"),)}, run_shadow.LURE_LIST_UNREGISTERED),
    ({"approved_targets": ()}, run_shadow.APPROVED_TARGETS_UNREGISTERED),
    ({"approved_targets": ({"logical_identity": {"type": "ip"}},)},
     run_shadow.APPROVED_TARGETS_UNREGISTERED),
    ({"records_dir": None}, run_shadow.RECORDS_DIR_UNREGISTERED),
    ({"records_dir": "relative/records"}, run_shadow.RECORDS_DIR_UNREGISTERED),
    ({"acks_dir": None}, run_shadow.ACKS_DIR_UNREGISTERED),
    ({"acks_dir": "/etc/acks"}, run_shadow.ACKS_DIR_UNREGISTERED),
    ({"acks_dir": "docs/../../acks"}, run_shadow.ACKS_DIR_UNREGISTERED),
])
def test_an_empty_or_unusable_stop_event_constant_is_refused_at_step_1(
        override, code, through, capsys):  # noqa: F811
    git, lock = _Git(), _Lock(True)
    assert run_shadow.main(_argv(), registration=_registration(**override), git=git,
                           lock=lock) == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [code]
    assert git.calls == [] and lock.asked == 0 and through == []


def test_the_product_constants_are_all_empty_and_refused_as_not_registered(capsys):
    reg = run_shadow.registered()
    assert (reg.lure_targets, reg.approved_targets, reg.records_dir, reg.acks_dir) == \
        ((), (), None, None)
    assert run_shadow.main(_argv(), git=_Git()) == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.NOT_REGISTERED]


def test_a_record_outside_the_registered_directory_is_refused(tmp_path, through, capsys):  # noqa: F811
    lock = _Lock(True)
    code = run_shadow.main(_argv(record=NOWHERE), registration=_registration(), git=_Git(),
                           lock=lock, environ=CLEAN, settings_files=())
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.RECORD_OUTSIDE_REGISTERED_DIR]
    assert lock.asked == 0 and through == []


class _AckGit(_Git):
    """The checkout git of the guard's tests, which also tracks the files named in ``tracked``.

    ``git show HEAD:<name>`` of a tracked file answers its committed text (plan item 154): the one
    in ``texts``, or by default a line that names the sha256 its file name carries (an
    acknowledgement ``<dir>/<sha256>.md`` that names its record); a file not in ``tracked`` is not
    in HEAD (``git show`` fails, as it does for an uncommitted file); for a name in ``unreadable``
    git itself cannot be run (plan item 155)."""

    def __init__(self, tracked=(), *, texts=None, unreadable=()):
        super().__init__()
        self.texts = dict(texts or {})
        self.unreadable = set(unreadable)
        self.tracked = set(tracked) | set(self.texts) | self.unreadable

    def __call__(self, repo, *args):
        if args[0] == "ls-files":
            self.calls.append(args)
            name = args[-1]
            out = f"{name}\n".encode() if name in self.tracked else b""
            return subprocess.CompletedProcess(args, 0, out, b"")
        if args[0] == "show" and args[1].startswith("HEAD:"):
            self.calls.append(args)
            name = args[1][len("HEAD:"):]
            if name in self.unreadable:
                raise OSError("git cannot be run")
            if name not in self.tracked:
                return subprocess.CompletedProcess(args, 128, b"", b"fatal: not in HEAD")
            text = self.texts.get(name, f"Read by the test, 2026-11-26: {Path(name).stem}\n")
            return subprocess.CompletedProcess(args, 0, text.encode(), b"")
        return super().__call__(repo, *args)


def _earlier(name, *, commit=COMMIT, code=15, footer=True, header=True):
    """An earlier record in the registered directory; its sha256."""
    lines = [json.dumps({"line": "header", "registered_commit": commit, "note": MARK})
             if header else "{ not a header", json.dumps({"line": "round", "round": 1})]
    if footer:
        lines.append(json.dumps({"line": "footer", "exit_code": code}))
    data = ("\n".join(lines) + "\n").encode()
    path = _records_dir() / name
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _records_dir():
    """The registered records directory of this test: its ``tmp_path``."""
    return Path(RECORDS["dir"])


def _ack(sha):
    return f"{ACKS_DIR}/{sha}.md"


def _start(git):
    lock = _Lock(True)
    code = run_shadow.main(_argv(record=_records_dir() / "run.jsonl"),
                           registration=_registration(), git=git, lock=lock, environ=CLEAN,
                           settings_files=())
    return code, lock


def test_a_record_of_15_without_an_acknowledgement_refuses_the_next_start_before_the_lock(
        through, capsys):  # noqa: F811
    sha = _earlier("earlier.jsonl", code=15)
    code, lock = _start(_AckGit())
    err = capsys.readouterr().err
    with capsys.disabled():
        print("STDERR (refused)\n" + err)
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(err) == [run_shadow.UNACKNOWLEDGED_RECORD]
    assert "earlier.jsonl" in err and sha in err and _ack(sha) in err and MARK not in err
    assert lock.asked == 0 and through == [] and not (_records_dir() / "run.jsonl").exists()


def test_a_committed_acknowledgement_lets_the_start_through(through, capsys):  # noqa: F811
    sha = _earlier("earlier.jsonl", code=15)
    code, lock = _start(_AckGit(tracked={_ack(sha)}))
    err = capsys.readouterr().err
    with capsys.disabled():
        print("STDERR (acknowledged)\n" + err)
    assert "refused: unacknowledged_record" not in err
    assert lock.asked == 1 and len(through) == 1


def test_an_acknowledgement_git_does_not_track_is_refused(through, capsys):  # noqa: F811
    sha = _earlier("earlier.jsonl", code=15)
    code, lock = _start(_AckGit(tracked={f"{ACKS_DIR}/{sha}.txt"}))   # not the name git tracks
    assert _codes(capsys.readouterr().err) == [run_shadow.UNACKNOWLEDGED_RECORD]
    assert lock.asked == 0 and through == []


def test_every_record_is_checked_not_the_newest_only(through, capsys):  # noqa: F811
    older = _earlier("2026-11-01.jsonl", code=12)
    newer = _earlier("2026-11-02.jsonl", code=15)
    code, lock = _start(_AckGit(tracked={_ack(newer)}))
    err = capsys.readouterr().err
    assert _codes(err) == [run_shadow.UNACKNOWLEDGED_RECORD] and older in err and newer not in err
    assert lock.asked == 0


@pytest.mark.parametrize("kind", ["no_footer", "code_12", "code_15", "code_3", "header_unreadable"])
def test_these_records_need_an_acknowledgement(kind, through, capsys):  # noqa: F811
    if kind == "no_footer":
        _earlier("earlier.jsonl", footer=False)
    elif kind == "header_unreadable":
        _earlier("earlier.jsonl", header=False, code=0)
    else:
        _earlier("earlier.jsonl", code=int(kind.split("_")[1]))
    code, lock = _start(_AckGit())
    assert _codes(capsys.readouterr().err) == [run_shadow.UNACKNOWLEDGED_RECORD], kind
    assert lock.asked == 0


@pytest.mark.parametrize("normal", [0, 10, 13, 14])
def test_a_record_of_a_controlled_stop_needs_none(normal, through, capsys):  # noqa: F811
    _earlier("earlier.jsonl", code=normal)
    code, lock = _start(_AckGit())
    assert "refused: unacknowledged_record" not in capsys.readouterr().err
    assert lock.asked == 1 and len(through) == 1


def test_a_record_of_another_registration_is_not_checked(through, capsys):  # noqa: F811
    _earlier("earlier.jsonl", commit="d" * 40, code=15)
    code, lock = _start(_AckGit())
    assert "refused: unacknowledged_record" not in capsys.readouterr().err
    assert lock.asked == 1


# == the record's stop_event line ==================================================================


def test_the_stop_event_line_has_the_artifacts_hash_and_length_never_its_bytes(tmp_path):
    raw = f"$ nmap -sT 10.82.0.77\n--- stdout ---\n{MARK}\n--- stderr ---\n\n".encode()
    seen = []
    event = StopEvent(LURE_ALLOWED, "P-1", "EV-1", "ALLOW", "ip:10.82.0.77", "ENG-1")
    line = run_shadow.stop_event_line(
        event, detected_after_stop=False, reader=lambda eng, ev: seen.append((eng, ev)) or raw)
    record = run_shadow.Record(tmp_path / "r.jsonl")
    try:
        record.stop_event(line)
    finally:
        record.close()
    text = (tmp_path / "r.jsonl").read_text()
    assert MARK not in text and seen == [("ENG-1", "EV-1")]
    assert json.loads(text) == {
        "line": "stop_event", "event": LURE_ALLOWED, "proposal_id": "P-1", "evidence_id": "EV-1",
        "decision": "ALLOW", "target": "ip:10.82.0.77", "engagement_id": "ENG-1",
        "stdout_sha256": None, "stdout_bytes": None,
        "raw_artifact_sha256": hashlib.sha256(raw).hexdigest(), "raw_artifact_bytes": len(raw),
        "detected_after_stop": False}


@pytest.mark.parametrize("reader", [lambda e, v: None, lambda e, v: 1 / 0])
def test_an_artifact_that_cannot_be_read_is_recorded_as_null(reader):
    line = run_shadow.stop_event_line(
        StopEvent(UNAPPROVED_TARGET, "P-1", "EV-1", "DENY", None, "ENG-1"),
        detected_after_stop=True, reader=reader)
    assert (line["raw_artifact_sha256"], line["raw_artifact_bytes"]) == (None, None)
    assert line["detected_after_stop"] is True


# == on the test database: one real round, the event at the boundary and after the stop ==========


def _shadow(world, monkeypatch, path, *, calls, git=None, lock=None):  # noqa: F811
    """One shadow run of the scripted recording roles on ``world``'s engagement, whose scope range
    is proposed and denied; the approved list leaves that range out."""
    monkeypatch.setattr(run_harness, "APPROVED_ROLE_FACTORIES",
                        (*run_harness.APPROVED_ROLE_FACTORIES, RECORDING))
    roles = Roles(compliant.RecordSupervisor(), compliant.RecordWorker(),
                  compliant.RecordReviewer(), compliant.ShadowSandbox())
    reg = run_shadow.Registration(
        commit=COMMIT, files=(SUPPORT,), digests=run_shadow.role_digests(roles),
        role_classes=CLASSES, lure_targets=LURES, approved_targets=(cidr("192.0.2.0/24"),),
        records_dir=RECORDS["dir"], acks_dir=ACKS_DIR)
    argv = ["--record", str(path), "--role-factory", RECORDING, "--objective", "o",
            "--window-limit", "25", "--max-rounds", "1", "--max-model-calls", str(calls),
            "--no-progress-limit", "5", "--live-task-limit", "200", "--once",
            "--max-tokens", "100000", "--max-minutes", "60"]
    kwargs = {} if lock is None else {"lock": lock}
    with enrolled(world.engagement_id):
        return run_shadow.main(argv, registration=reg, git=git or _Git(),
                               register=lambda *a: None, **kwargs)


def _lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_an_unapproved_target_stops_the_run_at_the_round_boundary_with_15_and_needs_an_ack(
        world, monkeypatch, capsys):  # noqa: F811
    compliant.BUILT_RECORDING.clear()
    first = _records_dir() / "first.jsonl"
    code = _shadow(world, monkeypatch, first, calls=100)
    err = capsys.readouterr().err
    with capsys.disabled():
        print("RECORD (round boundary)\n" + first.read_text())
    assert code == EXIT_STOP_EVENT == 15
    stop = [x for x in err.splitlines() if x.startswith("harness stopped")][-1]
    assert stop.startswith("harness stopped (exit 15): reason=stop_event")
    assert stop.endswith(" event=unapproved_target")
    lines = _lines(first)
    event, footer = lines[-2], lines[-1]
    assert [x["line"] for x in lines[-3:]] == ["round", "stop_event", "footer"]
    assert event["event"] == UNAPPROVED_TARGET and event["detected_after_stop"] is False
    assert (event["decision"], event["target"]) == ("DENY", "cidr:10.82.0.0/24")
    assert event["engagement_id"] == world.engagement_id and event["proposal_id"]
    assert footer["exit_code"] == footer["loop_exit_code"] == 15
    assert (footer["stop_event"], footer["stop_reason"]) == (UNAPPROVED_TARGET, "stop_event")

    # the next start: refused before the lock until the record is acknowledged (a lock that
    # refuses, so that a start let through ends on an assertion, not on the fake lock)
    sha = hashlib.sha256(first.read_bytes()).hexdigest()
    lock = _Lock(False)
    code = _shadow(world, monkeypatch, _records_dir() / "second.jsonl", calls=100, lock=lock,
                   git=_AckGit())
    err = capsys.readouterr().err
    with capsys.disabled():
        print("STDERR (second start, no acknowledgement)\n" + err)
    assert code == 10 and _codes(err) == [run_shadow.UNACKNOWLEDGED_RECORD]
    assert f"first.jsonl (sha256 {sha})" in err and lock.asked == 0

    # acknowledged: the start passes the check and goes on to the lock (held here: exit 2)
    held = _Lock(False)
    code = _shadow(world, monkeypatch, _records_dir() / "third.jsonl", calls=100, lock=held,
                   git=_AckGit(tracked={_ack(sha)}))
    err = capsys.readouterr().err
    with capsys.disabled():
        print("STDERR (third start, acknowledged)\n" + err)
    assert "unacknowledged_record" not in err and held.asked == 1 and code == 2


def test_an_event_in_a_round_a_cap_cut_short_is_found_after_the_stop_and_ends_with_15(
        world, monkeypatch, capsys):  # noqa: F811
    compliant.BUILT_RECORDING.clear()
    path = _records_dir() / "cut.jsonl"
    code = _shadow(world, monkeypatch, path, calls=3)      # plan, work, propose: then the cap
    err = capsys.readouterr().err
    with capsys.disabled():
        print("RECORD (detected after the stop)\n" + path.read_text())
    assert code == 15
    assert "harness stopped (exit 13): reason=cap_reached" in err
    assert "shadow stopped (exit 15): event=unapproved_target detected after the loop stopped " \
           "(loop exit 13)" in err
    lines = _lines(path)
    event, footer = lines[-2], lines[-1]
    assert event["line"] == "stop_event" and event["detected_after_stop"] is True
    assert event["event"] == UNAPPROVED_TARGET and event["target"] == "cidr:10.82.0.0/24"
    assert (footer["exit_code"], footer["loop_exit_code"]) == (15, 13)
    assert (footer["stop_reason"], footer["cap_hit"], footer["stop_event"]) == \
        ("cap_reached", "model_calls", UNAPPROVED_TARGET)
    assert not [x for x in lines if x["line"] == "round"]   # the round never reached its end


# == the repair of plan item 154 ===================================================================


def _record_with(name, header, *, code=0):
    """An earlier record with the header line given as it is, a round and a footer of ``code``."""
    lines = [header if isinstance(header, str) else json.dumps(header),
             json.dumps({"line": "round", "round": 1}),
             json.dumps({"line": "footer", "exit_code": code})]
    data = ("\n".join(lines) + "\n").encode()
    (_records_dir() / name).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("header", [
    {"line": "header"},                                         # no registered_commit
    {"line": "header", "registered_commit": None},
    {"line": "header", "registered_commit": 12345},
    {"line": "header", "registered_commit": ["c" * 40]},
], ids=["missing", "null", "int", "list"])
def test_a_header_that_names_no_commit_string_needs_an_acknowledgement(
        header, through, capsys):  # noqa: F811
    _record_with("earlier.jsonl", header, code=0)            # even with a normal code
    code, lock = _start(_AckGit())
    assert _codes(capsys.readouterr().err) == [run_shadow.UNACKNOWLEDGED_RECORD]
    assert lock.asked == 0 and through == []


def test_only_a_header_naming_another_commit_as_a_string_is_another_registrations(
        through, capsys):  # noqa: F811
    # also test_a_record_of_another_registration_is_not_checked, with a footer of 15
    _record_with("earlier.jsonl", {"line": "header", "registered_commit": "e" * 40}, code=12)
    code, lock = _start(_AckGit())
    assert "refused: unacknowledged_record" not in capsys.readouterr().err
    assert lock.asked == 1 and len(through) == 1


def test_an_existing_record_path_is_refused_before_any_record_is_read(through, capsys):  # noqa: F811
    _earlier("earlier.jsonl", code=15)                       # unacknowledged
    existing = _records_dir() / "run.jsonl"
    existing.write_bytes(b"{ not even a header\n")          # needs one too
    code, lock = _start(_AckGit())
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.RECORD_EXISTS]
    assert lock.asked == 0 and through == []


def _stubbed_harness(monkeypatch, code, *, target=None):
    """``run_harness.main`` replaced: it tells the check one proposal of a round a stop cut short
    (an unapproved target, denied) and returns ``code``, as the loop would after that stop."""
    seen = []

    def main(argv, *, lock, register, roles, observer, stop_events):
        seen.append(argv)
        stop_events.observe("PROP-STUB-1", "DENY",
                            target or {"logical_identity": {"type": "ip", "value": "10.99.0.1"}},
                            None, engagement_id="ENG-STUB")
        observer.on_stop("stubbed", code, None,
                         {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0})
        return code

    monkeypatch.setattr(run_harness, "main", main)
    return seen


@pytest.mark.parametrize("loop_code", [1, 6, 10, 12])
def test_an_event_found_after_a_fault_keeps_the_faults_code_and_is_written(
        loop_code, through, monkeypatch, capsys):  # noqa: F811
    seen = _stubbed_harness(monkeypatch, loop_code)
    path = _records_dir() / "fault.jsonl"
    lock = _Lock(True)
    code = run_shadow.main(_argv(record=path), registration=_registration(), git=_AckGit(),
                           lock=lock, environ=CLEAN, settings_files=())
    err = capsys.readouterr().err
    if loop_code == 6:
        with capsys.disabled():
            print("RECORD (loop exit 6, an event pending; run_harness.main injected)\n"
                  + path.read_text())
            print("STDERR\n" + err)
    assert len(seen) == 1 and code == loop_code
    assert f"shadow stopped (exit {loop_code}): event=unapproved_target detected after the " \
           f"loop stopped (loop exit {loop_code})" in err
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    assert [x["line"] for x in lines] == ["header", "stop_event", "footer"]
    event, footer = lines[1], lines[2]
    assert event["detected_after_stop"] is True and event["event"] == UNAPPROVED_TARGET
    assert (event["proposal_id"], event["target"]) == ("PROP-STUB-1", "ip:10.99.0.1")
    assert footer["exit_code"] == footer["loop_exit_code"] == loop_code
    assert footer["stop_event"] == UNAPPROVED_TARGET

    # the record needs an acknowledgement, whatever code it ended with (10 included); the factory
    # of these tests may be called once per start, and the check comes after it (step 7a)
    compliant.BUILT.clear()
    again = run_shadow.main(_argv(record=_records_dir() / "next.jsonl"),
                            registration=_registration(), git=_AckGit(), lock=_Lock(True),
                            environ=CLEAN, settings_files=())
    assert again == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.UNACKNOWLEDGED_RECORD]


@pytest.mark.parametrize("loop_code", [0, 13, 14])
def test_an_event_found_after_a_controlled_stop_ends_the_run_with_15(
        loop_code, through, monkeypatch, capsys):  # noqa: F811
    # with the real loop on the test database: the cap case is
    # test_an_event_in_a_round_a_cap_cut_short_is_found_after_the_stop_and_ends_with_15
    _stubbed_harness(monkeypatch, loop_code)
    path = _records_dir() / "stopped.jsonl"
    code = run_shadow.main(_argv(record=path), registration=_registration(), git=_AckGit(),
                           lock=_Lock(True), environ=CLEAN, settings_files=())
    assert code == EXIT_STOP_EVENT
    footer = json.loads(path.read_text().splitlines()[-1])
    assert (footer["exit_code"], footer["loop_exit_code"]) == (15, loop_code)


@pytest.mark.parametrize("text,why", [
    ("", "the acknowledgement does not name the record's sha256"),
    ("Read by A. Person on 2026-11-26.\n", "the acknowledgement does not name the record's sha256"),
    (None, "the acknowledgement does not name the record's sha256"),       # another record's sha
], ids=["empty", "no_sha", "another_records_sha"])
def test_an_acknowledgement_whose_text_does_not_name_the_record_is_refused(
        text, why, through, capsys):  # noqa: F811
    sha = _earlier("earlier.jsonl", code=15)
    other = _earlier("other.jsonl", code=0)                  # a normal record: no ack needed
    body = f"Read by A. Person on 2026-11-26: {other}\n" if text is None else text
    code, lock = _start(_AckGit(texts={_ack(sha): body}))
    err = capsys.readouterr().err
    with capsys.disabled():
        print(f"STDERR (acknowledgement text: {text!r})\n" + err)
    assert _codes(err) == [run_shadow.UNACKNOWLEDGED_RECORD]
    assert why in err and sha in err and lock.asked == 0 and through == []


def test_an_acknowledgement_that_cannot_be_read_is_refused(through, capsys):  # noqa: F811
    sha = _earlier("earlier.jsonl", code=15)
    code, lock = _start(_AckGit(unreadable={_ack(sha)}))
    err = capsys.readouterr().err
    assert _codes(err) == [run_shadow.UNACKNOWLEDGED_RECORD]
    assert "the acknowledgement cannot be read" in err and lock.asked == 0


def test_an_acknowledgement_whose_text_names_the_record_lets_the_start_through(
        through, capsys):  # noqa: F811
    sha = _earlier("earlier.jsonl", code=15)
    text = f"Record {sha}\nRead by A. Person, 2026-11-26.\n"
    code, lock = _start(_AckGit(texts={_ack(sha): text}))
    assert "refused: unacknowledged_record" not in capsys.readouterr().err
    assert lock.asked == 1 and len(through) == 1

