"""D69 shadow runner, stage S2 (plan item 140; shadow runner plan 2b, way b3): the run's record.

One real round on the test database, the way H5c2's entry tests run one (``world``, ``enrolled``):
``scripts/run_shadow.py`` with the registration handed in (the product constants stay empty), the
scripted recording roles of ``tests/shadow_compliant_roles.py`` -- whose Supervisor plans a task
the harness refuses and writes a marked ``assessment_note``, and whose Worker fails once with a
marked reason -- and ``run_harness`` handing the record every event as it happens. The record is
written under pytest's ``tmp_path``. No model, no container, no sandbox reached (the neutral
baseline denies the one proposal).
"""

from __future__ import annotations

import json

import pytest

from scripts import run_harness, run_shadow
from tests import shadow_compliant_roles as compliant
from tests.harness_h5c2_roles import Roles
from tests.test_harness_h5c2_entry import world  # noqa: F401 - a fixture
from tests.test_harness_h5c2_support import enrolled
from tests.test_shadow_runner_guard import COMMIT, SUPPORT, _codes, _Git

RECORDING = "tests.shadow_compliant_roles:build_recording"
CLASSES = {"worker": (compliant.RecordWorker,), "supervisor": (compliant.RecordSupervisor,),
           "reviewer": (compliant.RecordReviewer,), "sandbox": (compliant.ShadowSandbox,)}
HEADER_KEYS = {"line", "format", "started_at", "registered_commit", "head", "registered_sha256",
               "code_sha256", "digests", "supervisor_warn_about_duplicates", "role_factory",
               "role_classes", "bounds", "once"}


def _registration():
    roles = Roles(compliant.RecordSupervisor(), compliant.RecordWorker(),
                  compliant.RecordReviewer(), compliant.ShadowSandbox())
    return run_shadow.Registration(commit=COMMIT, files=(SUPPORT,),
                                   digests=run_shadow.role_digests(roles), role_classes=CLASSES)


def _argv(record):
    return ["--record", str(record), "--role-factory", RECORDING, "--objective", "o",
            "--window-limit", "25", "--max-rounds", "1", "--max-model-calls", "100",
            "--no-progress-limit", "5", "--live-task-limit", "200", "--once"]


@pytest.fixture
def run(world, monkeypatch, tmp_path):  # noqa: F811
    """A function that runs the shadow runner for one round on ``world``'s engagement and returns
    (exit code, the record's lines, the roles that ran, the adapter that ran them)."""
    compliant.BUILT_RECORDING.clear()
    monkeypatch.setattr(run_harness, "APPROVED_ROLE_FACTORIES",
                        (*run_harness.APPROVED_ROLE_FACTORIES, RECORDING))
    adapters = []
    real = run_harness.LoopAdapter

    def capture(**kwargs):
        adapters.append(real(**kwargs))
        return adapters[-1]

    monkeypatch.setattr(run_harness, "LoopAdapter", capture)
    path = tmp_path / "run.jsonl"

    def go():
        with enrolled(world.engagement_id):
            code = run_shadow.main(_argv(path), registration=_registration(), git=_Git(),
                                   register=lambda *a: None)
        lines = [json.loads(x) for x in path.read_text().splitlines()]
        return code, lines, compliant.BUILT_RECORDING[-1], adapters[-1], path

    go.path = path
    yield go
    compliant.BUILT_RECORDING.clear()


def _of(lines, kind):
    return [x for x in lines if x["line"] == kind]


def _fields(call):
    return {"model": call.model, "latency_seconds": call.latency_seconds,
            "input_tokens": call.input_tokens, "output_tokens": call.output_tokens,
            "failed": call.failed}


def test_one_round_is_recorded_line_by_line_without_any_model_text(run):
    code, lines, roles, adapter, path = run()
    print("RECORD\n" + path.read_text())
    assert [x["line"] for x in (lines[0], lines[1], lines[-1])] == ["header", "banner", "footer"]

    header = lines[0]
    assert set(header) == HEADER_KEYS
    checked = run_shadow.integrity(repo=run_shadow.REPO_ROOT, registered_commit=COMMIT,
                                   files=(SUPPORT,), git=_Git())
    digests = run_shadow.role_digests(roles)
    assert header["registered_commit"] == COMMIT and header["head"] == checked.head
    assert header["registered_sha256"] == checked.registered_sha256
    assert header["code_sha256"] == checked.code_sha256
    assert header["digests"] == {role: digests[role] for role in run_shadow.ROLES}
    assert header["supervisor_warn_about_duplicates"] is False
    assert header["role_factory"] == RECORDING and header["once"] is True
    assert header["bounds"] == {"window_limit": 25, "max_rounds": 1, "max_model_calls": 100,
                                "no_progress_limit": 5, "live_task_limit": 200}

    refusals = [(x["side"], x["reason"]) for x in _of(lines, "refusal")]
    assert refusals and refusals == list(adapter.refusals.entries())

    calls = _of(lines, "call")
    for role in run_shadow.ROLES:
        written = [{k: x[k] for k in ("model", "latency_seconds", "input_tokens",
                                      "output_tokens", "failed")}
                   for x in calls if x["role"] == role]
        kept = getattr(roles, role).calls
        assert kept and written == [_fields(c) for c in kept], role
    assert all(x["failure_kind"] == ("unknown" if x["failed"] else None) for x in calls)
    assert any(x["failed"] for x in calls)

    # the marked texts exist in the roles' own records, and nowhere in the run record
    assert roles.supervisor.calls[0].assessment_note == compliant.NOTE_MARK
    assert any(compliant.FAILURE_MARK in (c.failure or "") for c in roles.worker.calls)
    text = path.read_text()
    assert compliant.NOTE_MARK not in text and compliant.FAILURE_MARK not in text

    assert _of(lines, "round") == [{"line": "round", "round": 1, "progress": True}]
    footer = lines[-1]
    assert footer["exit_code"] == code == 0 and footer["stop_reason"] == "signal_or_once"


def test_every_line_is_on_disk_before_the_next_event(run, monkeypatch):
    on_disk = []
    original = run_shadow.Record.on_round

    def spy(self, number, progress):
        on_disk.append(self.path.read_text().splitlines())
        original(self, number, progress)

    monkeypatch.setattr(run_shadow.Record, "on_round", spy)
    _, lines, _, _, path = run()
    (before_round,) = on_disk
    everything = path.read_text().splitlines()
    first_round = next(i for i, x in enumerate(lines) if x["line"] == "round")
    assert before_round == everything[:first_round] and len(before_round) >= 4


def test_an_existing_record_is_refused_and_left_as_it_was(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_harness, "APPROVED_ROLE_FACTORIES",
                        (*run_harness.APPROVED_ROLE_FACTORIES, RECORDING))
    path = tmp_path / "run.jsonl"
    path.write_bytes(b'{"line": "header", "earlier": true}\n')
    before = path.read_bytes()
    code = run_shadow.main(_argv(path), registration=_registration(), git=_Git(),
                           register=lambda *a: None)
    assert code == run_shadow.EXIT_STARTUP_REFUSED
    assert _codes(capsys.readouterr().err) == [run_shadow.RECORD_EXISTS]
    assert path.read_bytes() == before


def test_a_record_that_cannot_take_an_event_stops_the_run_with_3(run, monkeypatch, capsys):
    def full(self, role, call):
        raise OSError("no space left on device")

    monkeypatch.setattr(run_shadow.Record, "on_call", full)
    code, lines, roles, _, _ = run()
    err = capsys.readouterr().err
    assert code == run_shadow.EXIT_AUDIT_FAILED == 3
    assert "the run record could not be written (OSError)" in err
    assert [x["line"] for x in lines[:3]] == ["header", "banner", "refusal"]
    assert _of(lines, "call") == [] and _of(lines, "round") == []
    assert roles.worker.calls == []                   # the loop stopped after the planning call
    assert lines[-1]["line"] == "footer" and lines[-1]["exit_code"] == 3


def test_an_abnormal_end_leaves_every_written_line_and_no_footer(run, monkeypatch):
    def interrupted(self, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(compliant.RecordWorker, "propose", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run()
    lines = [json.loads(x) for x in run.path.read_text().splitlines()]
    kinds = [x["line"] for x in lines]
    assert kinds[:3] == ["header", "banner", "refusal"]
    assert [x["role"] for x in _of(lines, "call")] == ["supervisor"]   # written before the end
    assert "footer" not in kinds and "round" not in kinds
