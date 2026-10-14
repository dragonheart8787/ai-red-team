"""A container whose run's outcome is unknown is removed only after its evidence is kept
(D64 completion 4, item 2; ACCEPTANCE 5.97).

What the tests hold:

* **retention binds an ``unknown_outcome`` container exactly as it binds a finished one**: nothing
  is planned a microsecond before the bound, the removal is planned at it (the plan's own table
  shows the same edge for every reason; here it is shown for this reason code);
* **the archive**: ``<id>.inspect.json`` and ``<id>.logs`` in a private directory, mode 0600, with
  the SHA-256 of the file as it is on disk; nothing replaced; no partial file left behind;
* **fail closed**: no directory, a directory other people can use, a log that breaks half-way, a
  log too large, a file that cannot be synced, a different file already there -- the container is
  not removed, no intent is written, the result is ``failed / evidence_not_saved``;
* **the order**: archive, then intent, then ``evidence_saved``, then the removal; and an intent or
  an ``evidence_saved`` record that cannot be written stops the removal;
* **the audit trail** carries the container id and two hashes -- never a path, never a line of the
  output -- and both the daemon-less fake and a real Docker container go through the same code.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import uuid
from types import SimpleNamespace

import docker
import pytest
from docker.errors import APIError, NotFound

from control_plane.reconciler import act, emit, evidence, flags, vocab
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.act import carry_out as run
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import (
    AUDIT_FAILED,
    CHANGED,
    DONE,
    EVIDENCE_NOT_SAVED,
    FAILED,
)
from tests.test_reconciler_act import TH, Ticker
from tests.test_reconciler_service import TH as SERVICE_TH
from tests.test_reconciler_service import (
    _locks_are_let_go,  # noqa: F401  (an autouse fixture)
    events,
    reconciler,
)

CID = "c" * 64
LABELS = {"cyberorch.run_id": "RUN-U", "cyberorch.owner": "ENG-U"}
LOGS = b"2026-10-14T10:00:00.000000000Z line one\n2026-10-14T10:00:01.000000000Z line two\n"


@pytest.fixture
def vault(tmp_path):
    path = tmp_path / "evidence"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return str(path)


class Ct:
    """A container at rest whose output and inspect are scripted."""

    def __init__(self, *, labels=LABELS, status="exited", logs=LOGS, log_error=None, cid=CID):
        self.id = cid
        self.labels = dict(labels)
        self.attrs = {"Id": cid, "State": {"Status": status, "Running": status == "running"},
                      "Config": {"Labels": dict(labels)}}
        self._logs, self._log_error = logs, log_error
        self.removed = False
        self.log_calls: list[dict] = []

    def reload(self):
        return None

    def logs(self, **kw):
        self.log_calls.append(kw)

        def stream():
            yield self._logs[: len(self._logs) // 2]
            if self._log_error is not None:
                raise self._log_error
            yield self._logs[len(self._logs) // 2:]
        return stream()

    def remove(self, force=False):
        self.removed = True


def client_for(ct):
    def get(cid):
        if ct.removed or cid != ct.id:
            raise NotFound("")
        return ct
    return SimpleNamespace(containers=SimpleNamespace(
        get=get, list=lambda **kw: [] if ct.removed else [ct]))


def removal(reason=vocab.RUN_UNKNOWN_OUTCOME) -> Action:
    return Action(kind=vocab.REMOVE_CONTAINER, reason_code=reason, subject_id=CID, run_id="RUN-U",
                  expected_owner="ENG-U", engagement_id="ENG-U")


def settings(vault_dir) -> Settings:
    return Settings(Mode.STATE_ONLY, enabled=frozenset({flags.CONTAINER}), evidence_dir=vault_dir)


class Journal:
    """The hooks the service gives the act half, recording the order they were called in."""

    def __init__(self, ct, vault_dir):
        self.ct, self.vault, self.calls = ct, vault_dir, []
        self.fail_intent = self.fail_saved = False

    def intend(self, action):
        self.calls.append(("intend", sorted(os.listdir(self.vault)), self.ct.removed))
        if self.fail_intent:
            raise RuntimeError("audit down")

    def saved(self, action, kept):
        self.calls.append(("saved", kept, self.ct.removed))
        if self.fail_saved:
            raise RuntimeError("audit down")


def carry(ct, vault_dir, journal=None, action=None, **kw):
    journal = journal or Journal(ct, vault_dir)
    ticker = Ticker()
    result = run([action or removal()], settings(vault_dir), th=TH, client=client_for(ct),
                 intend=journal.intend, saved=journal.saved, sleep=ticker.sleep,
                 clock=ticker.clock, **kw)[0]
    return result, journal


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


# ---------------------------------------------------------------------------------------------
# retention binds an unknown_outcome container
# ---------------------------------------------------------------------------------------------

def test_retention_binds_an_unknown_outcome_container_to_the_microsecond():
    from tests.test_reconciler_plan import NOW, RETENTION, container, observe, plan, s, th
    states = {"RUN-1": "unknown_outcome"}
    young = container(status="exited", started_us=NOW - s(RETENTION - 0.000001),
                      finished_us=NOW - s(RETENTION - 0.000001), created_us=0)
    due = container(status="exited", started_us=NOW - s(RETENTION),
                    finished_us=NOW - s(RETENTION), created_us=0)
    assert plan(observe(containers=[young], run_states=states), th()).actions == ()
    (a,) = plan(observe(containers=[due], run_states=states), th()).actions
    assert (a.kind, a.reason_code) == (vocab.REMOVE_CONTAINER, vocab.RUN_UNKNOWN_OUTCOME)
    # a longer retention moves the bound with it: the number is the argument's
    assert plan(observe(containers=[due], run_states=states),
                th(retention_s=RETENTION + 1)).actions == ()


def test_only_a_run_of_unknown_outcome_carries_that_reason():
    from tests.test_reconciler_plan import NOW, RETENTION, container, observe, plan, s, th
    old = container(status="exited", started_us=NOW - s(RETENTION * 2),
                    finished_us=NOW - s(RETENTION * 2), created_us=0)
    reasons = {}
    for run_state in ("succeeded", "failed", "unknown_outcome", None):
        states = {} if run_state is None else {"RUN-1": run_state}
        (a,) = plan(observe(containers=[old], run_states=states), th()).actions
        reasons[run_state] = a.reason_code
    assert reasons == {"succeeded": vocab.RUN_FINISHED, "failed": vocab.RUN_FINISHED,
                       "unknown_outcome": vocab.RUN_UNKNOWN_OUTCOME,
                       None: vocab.NO_RUN_ROW_PAST_GRACE}


def test_a_proxy_has_no_such_reason_and_a_forged_one_is_refused():
    assert vocab.RUN_UNKNOWN_OUTCOME not in vocab.REASONS[vocab.REMOVE_PROXY]
    assert vocab.RUN_UNKNOWN_OUTCOME not in vocab.REASONS[vocab.KILL_CONTAINER]
    forged = Action(kind=vocab.REMOVE_PROXY, reason_code=vocab.RUN_UNKNOWN_OUTCOME,
                    subject_id=CID, run_id="RUN-U", expected_owner="ENG-U")
    result = run([forged], Settings(Mode.STATE_ONLY, enabled=flags.EVERYTHING), th=TH,
                 client=SimpleNamespace())[0]
    assert (result.outcome, result.detail) == (FAILED, "invalid_action")


# ---------------------------------------------------------------------------------------------
# the archive
# ---------------------------------------------------------------------------------------------

def test_the_archive_is_two_private_files_named_by_the_id_and_hashed_as_they_are_on_disk(vault):
    ct = Ct()
    kept = evidence.save(ct, vault)
    inspect_path = os.path.join(vault, CID + ".inspect.json")
    logs_path = os.path.join(vault, CID + ".logs")
    assert sorted(os.listdir(vault)) == sorted([CID + ".inspect.json", CID + ".logs"])
    assert open(logs_path, "rb").read() == LOGS                       # both halves of the stream
    assert json.load(open(inspect_path)) == ct.attrs
    assert (kept.container_id, kept.inspect_sha256, kept.logs_sha256) == (
        CID, sha(inspect_path), sha(logs_path))
    for path in (inspect_path, logs_path):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert ct.log_calls == [{"stdout": True, "stderr": True, "timestamps": True, "stream": True}]


def test_saving_the_same_container_twice_is_the_same_evidence_and_replaces_nothing(vault):
    first = evidence.save(Ct(), vault)
    inode = os.stat(os.path.join(vault, CID + ".logs")).st_ino
    assert evidence.save(Ct(), vault) == first
    assert os.stat(os.path.join(vault, CID + ".logs")).st_ino == inode
    assert sorted(os.listdir(vault)) == sorted([CID + ".inspect.json", CID + ".logs"])


def test_a_different_file_already_there_is_never_replaced_and_is_a_refusal(vault):
    path = os.path.join(vault, CID + ".logs")
    with open(path, "wb") as handle:
        handle.write(b"somebody else's")
    with pytest.raises(evidence.EvidenceError):
        evidence.save(Ct(), vault)
    assert open(path, "rb").read() == b"somebody else's"
    assert not [n for n in os.listdir(vault) if n.endswith(".partial")]


@pytest.mark.parametrize("how", ["missing", "none", "empty", "file", "link", "group", "world",
                                 "other_owner"])
def test_a_directory_that_is_not_private_and_ours_is_refused(tmp_path, monkeypatch, how):
    good = tmp_path / "good"
    good.mkdir(mode=0o700)
    target = {"missing": str(tmp_path / "nowhere"), "none": None, "empty": "",
              "file": str(tmp_path / "plain"), "link": str(tmp_path / "link"),
              "group": str(tmp_path / "group"), "world": str(tmp_path / "world"),
              "other_owner": str(good)}[how]
    (tmp_path / "plain").write_text("x")
    os.symlink(good, tmp_path / "link")
    for name, mode in (("group", 0o770), ("world", 0o707)):
        (tmp_path / name).mkdir()
        os.chmod(tmp_path / name, mode)
    if how == "other_owner":
        monkeypatch.setattr(os, "getuid", lambda: os.stat(good).st_uid + 1)
    with pytest.raises(evidence.EvidenceError):
        evidence.check_directory(target)
    with pytest.raises(evidence.EvidenceError):
        evidence.save(Ct(), target)
    assert os.listdir(good) == []


def test_a_private_directory_of_ours_is_accepted(vault):
    assert evidence.check_directory(vault) == vault


def test_a_log_that_breaks_half_way_leaves_no_file_of_it_and_no_partial(vault):
    ct = Ct(log_error=APIError("the daemon went away"))
    with pytest.raises(evidence.EvidenceError):
        evidence.save(ct, vault)
    assert not os.path.exists(os.path.join(vault, CID + ".logs"))
    assert not [n for n in os.listdir(vault) if n.endswith(".partial")]


def test_a_log_too_large_to_keep_is_refused_not_cut(vault, monkeypatch):
    monkeypatch.setattr(evidence, "MAX_LOG_BYTES", len(LOGS) - 1)
    with pytest.raises(evidence.EvidenceError):
        evidence.save(Ct(), vault)
    assert not os.path.exists(os.path.join(vault, CID + ".logs"))
    monkeypatch.setattr(evidence, "MAX_LOG_BYTES", len(LOGS))
    assert evidence.save(Ct(), vault).container_id == CID               # the edge itself is kept


@pytest.mark.parametrize("what", ["the file", "the directory"])
def test_a_file_or_directory_that_cannot_be_synced_is_not_evidence(vault, monkeypatch, what):
    real = os.fsync
    wanted = stat.S_ISREG if what == "the file" else stat.S_ISDIR

    def broken(fd):
        if wanted(os.fstat(fd).st_mode):
            raise OSError("no space left on device")
        return real(fd)
    monkeypatch.setattr(os, "fsync", broken)
    with pytest.raises(evidence.EvidenceError):
        evidence.save(Ct(), vault)


def test_the_hash_is_that_of_the_file_in_place_not_of_what_was_meant_to_be_written(
        vault, monkeypatch):
    real_link = os.link

    def link_then_damage(source, target):
        real_link(source, target)
        with open(target, "ab") as handle:               # something else touched it on the way
            handle.write(b"?")
    monkeypatch.setattr(os, "link", link_then_damage)
    kept = evidence.save(Ct(), vault)
    assert kept.logs_sha256 == sha(os.path.join(vault, CID + ".logs"))
    assert kept.logs_sha256 != hashlib.sha256(LOGS).hexdigest()


def test_an_id_that_is_not_a_full_container_id_is_refused(vault):
    with pytest.raises(evidence.EvidenceError):
        evidence.save(Ct(cid="../../etc/passwd"), vault)
    with pytest.raises(evidence.EvidenceError):
        evidence.save(Ct(cid="c" * 12), vault)
    assert os.listdir(vault) == []


# ---------------------------------------------------------------------------------------------
# the removal: evidence first, then the intent, then the record of it, then the call
# ---------------------------------------------------------------------------------------------

def test_the_order_is_archive_then_intent_then_evidence_record_then_removal(vault):
    ct = Ct()
    result, journal = carry(ct, vault)
    assert result.outcome == DONE and ct.removed
    kinds = [c[0] for c in journal.calls]
    assert kinds == ["intend", "saved"]
    intent, saved = journal.calls
    assert intent[1] == sorted([CID + ".inspect.json", CID + ".logs"])    # already on disk
    assert intent[2] is False and saved[2] is False                       # not yet removed
    kept = saved[1]
    assert kept.inspect_sha256 == sha(os.path.join(vault, CID + ".inspect.json"))
    assert kept.logs_sha256 == sha(os.path.join(vault, CID + ".logs"))


@pytest.mark.parametrize("breakage", ["no_directory", "bad_directory", "log_error", "too_large",
                                      "cannot_sync", "other_file_there"])
def test_no_evidence_no_intent_no_removal(vault, tmp_path, monkeypatch, breakage):
    ct = Ct(log_error=APIError("gone") if breakage == "log_error" else None)
    target = {"no_directory": None, "bad_directory": str(tmp_path / "nowhere")}.get(breakage, vault)
    if breakage == "too_large":
        monkeypatch.setattr(evidence, "MAX_LOG_BYTES", 5)
    if breakage == "cannot_sync":
        monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("full")))
    if breakage == "other_file_there":
        open(os.path.join(vault, CID + ".inspect.json"), "w").write("{}")
    result, journal = carry(ct, target)
    assert (result.outcome, result.detail) == (FAILED, EVIDENCE_NOT_SAVED)
    assert ct.removed is False
    assert journal.calls == []                      # neither the intent nor the evidence record


def test_a_container_that_started_since_the_plan_is_left_and_nothing_is_archived(vault):
    ct = Ct(status="running")
    result, journal = carry(ct, vault)
    assert (result.outcome, result.detail) == (CHANGED, "not_at_rest")
    assert os.listdir(vault) == [] and journal.calls == [] and ct.removed is False


def test_a_container_whose_labels_changed_is_left_and_nothing_is_archived(vault):
    ct = Ct(labels={"cyberorch.run_id": "RUN-OTHER", "cyberorch.owner": "ENG-U"})
    result, journal = carry(ct, vault)
    assert (result.outcome, result.detail) == (CHANGED, "labels_changed")
    assert os.listdir(vault) == [] and journal.calls == [] and ct.removed is False


def test_an_intent_that_cannot_be_written_stops_the_removal(vault):
    ct = Ct()
    journal = Journal(ct, vault)
    journal.fail_intent = True
    result, journal = carry(ct, vault, journal)
    assert (result.outcome, result.detail) == (FAILED, AUDIT_FAILED)
    assert ct.removed is False and [c[0] for c in journal.calls] == ["intend"]


def test_an_evidence_record_that_cannot_be_written_stops_the_removal(vault):
    ct = Ct()
    journal = Journal(ct, vault)
    journal.fail_saved = True
    result, _ = carry(ct, vault, journal)
    assert (result.outcome, result.detail) == (FAILED, AUDIT_FAILED)
    assert ct.removed is False


def test_a_finished_run_needs_no_evidence_and_leaves_none(vault):
    ct = Ct()
    result, journal = carry(ct, vault, action=removal(vocab.RUN_FINISHED))
    assert result.outcome == DONE and ct.removed
    assert os.listdir(vault) == [] and ct.log_calls == []
    assert [c[0] for c in journal.calls] == ["intend"]


def test_without_the_container_switch_nothing_is_archived_and_nothing_removed(vault):
    ct = Ct()
    off = Settings(Mode.STATE_ONLY, evidence_dir=vault)
    result = run([removal()], off, th=TH, client=client_for(ct))[0]
    assert result.outcome == "skipped_deletions_off"
    assert os.listdir(vault) == [] and ct.removed is False and ct.log_calls == []


def test_a_dry_run_archives_nothing(vault):
    ct = Ct()
    result = run([removal()], Settings(Mode.DRY_RUN), th=TH, client=client_for(ct))[0]
    assert result.outcome == "dry_run"
    assert os.listdir(vault) == [] and ct.log_calls == []


# ---------------------------------------------------------------------------------------------
# the operator's door
# ---------------------------------------------------------------------------------------------

def test_container_cannot_be_enabled_without_a_private_directory(vault, tmp_path):
    with pytest.raises(ValueError, match="evidence-dir"):
        act.settings_for("state-only", ["container"])
    with pytest.raises(ValueError, match="evidence-dir"):
        act.settings_for("state-only", ["container"], str(tmp_path / "nowhere"))
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o755)
    with pytest.raises(ValueError, match="evidence-dir"):
        act.settings_for("state-only", ["container"], str(open_dir))
    chosen = act.settings_for("state-only", ["container"], vault)
    assert chosen.enabled == {flags.CONTAINER} and chosen.evidence_dir == vault
    # the other switches need no directory
    assert act.settings_for("state-only", ["kill", "proxy"]).evidence_dir is None


# ---------------------------------------------------------------------------------------------
# the audit trail: ids and hashes, nothing else
# ---------------------------------------------------------------------------------------------

def test_the_evidence_event_is_an_id_and_two_hashes_and_nothing_else(vault):
    kept = evidence.save(Ct(), vault)
    event_type, payload, engagement, subject_type, subject_id = emit.evidence_for(removal(), kept)
    assert event_type == emit.EVIDENCE_SAVED == "reconciler.evidence_saved"
    assert payload == {"run_id": "RUN-U", "container_id": CID,
                       "inspect_sha256": kept.inspect_sha256, "logs_sha256": kept.logs_sha256}
    assert (engagement, subject_type, subject_id) == ("ENG-U", "tool_run", "RUN-U")
    assert emit.validate(event_type, payload) == payload
    text = json.dumps(payload)
    assert vault not in text and "line one" not in text and ".logs" not in text


@pytest.mark.parametrize("key, bad", [
    ("inspect_sha256", "abc"), ("inspect_sha256", "G" * 64), ("inspect_sha256", "A" * 64),
    ("logs_sha256", None), ("logs_sha256", 7), ("logs_sha256", "a" * 63),
    ("container_id", "/tmp/evidence/" + CID), ("container_id", ""), ("run_id", "x y")])
def test_the_evidence_event_refuses_anything_else(vault, key, bad):
    kept = evidence.save(Ct(), vault)
    payload = emit.evidence_for(removal(), kept)[1]
    payload[key] = bad
    with pytest.raises(emit.PayloadRejected):
        emit.validate(emit.EVIDENCE_SAVED, payload)
    payload = emit.evidence_for(removal(), kept)[1]
    with pytest.raises(emit.PayloadRejected):
        emit.validate(emit.EVIDENCE_SAVED, {**payload, "path": vault})
    del payload["logs_sha256"]
    with pytest.raises(emit.PayloadRejected):
        emit.validate(emit.EVIDENCE_SAVED, payload)


# ---------------------------------------------------------------------------------------------
# a real daemon
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def real_client():
    c = docker.from_env()
    try:
        c.ping()
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"Docker is required for this test: {exc}")
    return c


def test_real_a_container_with_output_is_kept_and_then_removed(real_client, vault):
    run_id = f"RUN-{uuid.uuid4().hex[:8]}"
    ct = real_client.containers.create(
        "python:3.12-slim", command=["sh", "-c", "echo out-line; echo err-line 1>&2"],
        labels={"cyberorch.run_id": run_id, "cyberorch.owner": "ENG-U"})
    try:
        ct.start()
        ct.wait(timeout=30)
        ct.reload()
        action = Action(kind=vocab.REMOVE_CONTAINER, reason_code=vocab.RUN_UNKNOWN_OUTCOME,
                        subject_id=ct.id, run_id=run_id, expected_owner="ENG-U",
                        engagement_id="ENG-U")
        saved = []
        order = []
        result = run([action], settings(vault), th=TH, client=real_client,
                     intend=lambda a: order.append(("intend", sorted(os.listdir(vault)))),
                     saved=lambda a, kept: (order.append("saved"), saved.append(kept)))[0]
        assert result.outcome == DONE
        with pytest.raises(NotFound):
            real_client.containers.get(ct.id)
        assert sorted(os.listdir(vault)) == sorted([ct.id + ".inspect.json", ct.id + ".logs"])
        assert len(saved) == 1 and order[-1] == "saved"
        logs = open(os.path.join(vault, ct.id + ".logs"), "rb").read()
        assert b"out-line" in logs and b"err-line" in logs
        assert logs.startswith(b"20")                                   # Docker's timestamps
        attrs = json.load(open(os.path.join(vault, ct.id + ".inspect.json")))
        assert attrs["Id"] == ct.id and attrs["Config"]["Labels"]["cyberorch.run_id"] == run_id
        (kept,) = saved
        assert kept.logs_sha256 == sha(os.path.join(vault, ct.id + ".logs"))
        assert order[0] == ("intend", sorted([ct.id + ".inspect.json", ct.id + ".logs"]))
    finally:
        try:
            ct.remove(force=True)
        except (NotFound, APIError):
            pass


def test_real_a_container_that_cannot_be_archived_is_still_there_after(real_client, tmp_path):
    run_id = f"RUN-{uuid.uuid4().hex[:8]}"
    ct = real_client.containers.create(
        "python:3.12-slim", command=["true"],
        labels={"cyberorch.run_id": run_id, "cyberorch.owner": "ENG-U"})
    try:
        ct.start()
        ct.wait(timeout=30)
        action = Action(kind=vocab.REMOVE_CONTAINER, reason_code=vocab.RUN_UNKNOWN_OUTCOME,
                        subject_id=ct.id, run_id=run_id, expected_owner="ENG-U",
                        engagement_id="ENG-U")
        intents = []
        result = run([action], settings(str(tmp_path / "nowhere")), th=TH, client=real_client,
                     intend=intents.append)[0]
        assert (result.outcome, result.detail) == (FAILED, EVIDENCE_NOT_SAVED)
        assert intents == []
        assert real_client.containers.get(ct.id).id == ct.id
    finally:
        try:
            ct.remove(force=True)
        except (NotFound, APIError):
            pass


# ---------------------------------------------------------------------------------------------
# through the service: the database, the audit trail and a real daemon
# ---------------------------------------------------------------------------------------------

def _exited_container(real_client, run_id, owner, made):
    ct = real_client.containers.create(
        "python:3.12-slim", command=["sh", "-c", "echo kept-line"],
        labels={"cyberorch.run_id": run_id, "cyberorch.owner": owner})
    made.append(ct)
    ct.start()
    ct.wait(timeout=30)
    ct.reload()
    return ct


@pytest.fixture
def made_containers():
    things: list = []
    yield things
    for thing in things:
        try:
            thing.remove(force=True)
        except (NotFound, APIError):
            pass


def _pass(engagement_id, tmp_path, real_client, vault_dir, retention_s):
    import dataclasses

    r = reconciler(engagement_id, settings=settings(vault_dir),
                   th=dataclasses.replace(SERVICE_TH, retention_s=retention_s),
                   client=real_client, tmp_path=tmp_path)
    r.begin()
    try:
        return r.pass_once()
    finally:
        r.finish("signal")


def _unknown_run(engagement_id):
    from tests.reconciler_support import _capability, _proposal, _run
    pid = _proposal(engagement_id, "recorded")
    cid = _capability(engagement_id, pid, '{"max_duration_seconds": 600}')
    return _run(engagement_id, pid, cid, "unknown_outcome")


def test_service_the_trail_has_intent_evidence_and_removal_in_that_order_with_hashes_only(
        engagement_id, tmp_path, real_client, vault, made_containers):
    run_id = _unknown_run(engagement_id)
    ct = _exited_container(real_client, run_id, engagement_id, made_containers)
    time.sleep(1.2)
    report = _pass(engagement_id, tmp_path, real_client, vault, retention_s=1)
    assert report.outcomes.get("done", 0) >= 1
    with pytest.raises(NotFound):
        real_client.containers.get(ct.id)
    written = [e for e in events(engagement_id, emit.ACTION_INTENDED, emit.EVIDENCE_SAVED,
                                 emit.CONTAINER_REMOVED) if e["subject_id"] == run_id]
    assert [e["event_type"] for e in written] == [
        emit.ACTION_INTENDED, emit.EVIDENCE_SAVED, emit.CONTAINER_REMOVED]
    assert written[0]["payload"]["reason_code"] == vocab.RUN_UNKNOWN_OUTCOME
    saved = written[1]["payload"]
    assert saved == {"run_id": run_id, "container_id": ct.id,
                     "inspect_sha256": sha(os.path.join(vault, ct.id + ".inspect.json")),
                     "logs_sha256": sha(os.path.join(vault, ct.id + ".logs"))}
    assert written[2]["payload"]["reason_code"] == vocab.RUN_UNKNOWN_OUTCOME
    trail = json.dumps([e["payload"] for e in written])
    assert vault not in trail and "kept-line" not in trail
    assert b"kept-line" in open(os.path.join(vault, ct.id + ".logs"), "rb").read()


def test_service_inside_the_retention_nothing_is_archived_and_nothing_removed(
        engagement_id, tmp_path, real_client, vault, made_containers):
    run_id = _unknown_run(engagement_id)
    ct = _exited_container(real_client, run_id, engagement_id, made_containers)
    report = _pass(engagement_id, tmp_path, real_client, vault, retention_s=3600)
    assert not [r for r in report.results if r.action.subject_id == ct.id]
    assert real_client.containers.get(ct.id).id == ct.id
    assert os.listdir(vault) == []
    assert not events(engagement_id, emit.ACTION_INTENDED, emit.EVIDENCE_SAVED)


def test_service_when_the_evidence_cannot_be_kept_the_container_stays_and_it_is_said_once(
        engagement_id, tmp_path, real_client, vault, made_containers):
    run_id = _unknown_run(engagement_id)
    ct = _exited_container(real_client, run_id, engagement_id, made_containers)
    time.sleep(1.2)
    os.chmod(vault, 0o755)                         # the directory stopped being private
    report = _pass(engagement_id, tmp_path, real_client, vault, retention_s=1)
    mine = [r for r in report.results if r.action.subject_id == ct.id]
    assert [(r.outcome, r.detail) for r in mine] == [(FAILED, EVIDENCE_NOT_SAVED)]
    assert real_client.containers.get(ct.id).id == ct.id
    assert os.listdir(vault) == []
    written = events(engagement_id, emit.ACTION_INTENDED, emit.EVIDENCE_SAVED,
                     emit.CONTAINER_REMOVED, emit.ACTION_FAILED)
    assert [(e["event_type"], e["payload"]["reason_code"]) for e in written
            if e["subject_id"] == run_id] == [(emit.ACTION_FAILED, EVIDENCE_NOT_SAVED)]
