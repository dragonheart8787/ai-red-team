"""D69-NC-1 (plan item 142): the three real headless role adapters keep the kind of a failed call.

Each real adapter (``ClaudeCodeHeadlessWorker``, ``ClaudeCodeHeadlessSupervisor``,
``ClaudeCodeHeadlessReviewer``) is built with its injectable ``runner``: a function that plays the
CLI -- a timeout, a non-zero exit with text on stderr, an overloaded service, a reply that is not
JSON, a safety stop -- so no model is called and no process is started (``mkdtemp`` returns a path
that is never created, as in ``tests/test_shadow_runner_pins.py``). The kind each failure gets is
the kind ``control_plane/plan_fit/failure_kind.py`` gives it; the shadow runner's record writes that
kind and never the failure's free text. Each record is written under pytest's ``tmp_path``.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from agents.base_agent import ProposedAction
from agents.llm import headless
from agents.llm.claude_code_headless_reviewer import ClaudeCodeHeadlessReviewer
from agents.llm.claude_code_headless_supervisor import ClaudeCodeHeadlessSupervisor
from agents.llm.claude_code_headless_worker import ClaudeCodeHeadlessWorker
from agents.llm.supervisor_base import StateSummary
from agents.llm.worker_base import WorkerCall
from control_plane.canonicalizer.target import normalize_target
from control_plane.plan_fit import failure_kind
from control_plane.plan_fit.failure_kind import REFUSAL, TRANSPORT, UNCLASSIFIED
from scripts import run_shadow
from tests.test_shadow_runner_pins import CANDIDATES, SCOPE, TASK

#: Text a target or a model could have put on stderr: it may be in ``failure``, never in a record.
STDERR_MARK = "TARGET-STDERR-5be1"


@pytest.fixture(autouse=True)
def _no_working_directory(monkeypatch):
    monkeypatch.setattr(headless.tempfile, "mkdtemp",
                        lambda prefix="": "/nonexistent/cyberorch-headless-kinds")


def _completed(returncode, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _timeout(command, **kwargs):
    raise subprocess.TimeoutExpired(command, 30)


#: Each form of failure, as the CLI shows it, and the kind failure_kind.py gives it.
FORMS = {
    "timeout": (_timeout, TRANSPORT),
    "cli_exit": (lambda command, **kwargs: _completed(1, stderr=f"broke: {STDERR_MARK}"),
                 UNCLASSIFIED),
    "overloaded": (lambda command, **kwargs: _completed(1, stdout=json.dumps(
        {"is_error": True, "api_error_status": 529, "result": STDERR_MARK})), TRANSPORT),
    "unparseable": (lambda command, **kwargs: _completed(0, stdout=f"not json {STDERR_MARK}"),
                    UNCLASSIFIED),
    "refusal": (lambda command, **kwargs: _completed(1, stdout=json.dumps(
        {"duration_api_ms": 3000, "stop_reason": "refusal", "is_error": True, "result": ""})),
                REFUSAL),
}


def _call(role, runner):
    """One call of the real adapter of ``role`` over ``runner``; the adapter's last call record."""
    if role == "worker":
        adapter = ClaudeCodeHeadlessWorker(runner=runner)
        adapter.propose(task=TASK, candidates=CANDIDATES, task_id="TASK-KIND")
    elif role == "supervisor":
        adapter = ClaudeCodeHeadlessSupervisor(runner=runner)
        adapter.plan(state=StateSummary(engagement_id="ENG-KIND", objective="o"),
                     candidates=CANDIDATES)
    else:
        adapter = ClaudeCodeHeadlessReviewer(runner=runner)
        proposal = ProposedAction(
            action="network.scan",
            target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
            authorization={"source": "engagement_scope", "scope_object_id": SCOPE},
            discovery={"source": "explicit_scope"}, task_id="TASK-KIND")
        adapter.review(proposal=proposal, canonical_target=normalize_target(proposal.target))
    assert len(adapter.calls) == 1
    return adapter.calls[-1]


def _recorded(call, role, tmp_path):
    """The line the shadow runner's record writes for ``call``, as text and as an object."""
    record = run_shadow.Record(tmp_path / f"{role}.jsonl")
    try:
        record.on_call(role, call)
    finally:
        record.close()
    text = (tmp_path / f"{role}.jsonl").read_text()
    return text, json.loads(text)


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("role", ["worker", "supervisor", "reviewer"])
def test_a_failed_call_keeps_its_kind_and_the_record_writes_the_kind_not_the_text(
        role, form, tmp_path):
    runner, kind = FORMS[form]
    call = _call(role, runner)
    print("KIND", role, form, call.failure_kind)
    assert call.failed and call.failure_kind == kind
    text, line = _recorded(call, role, tmp_path)
    assert line["failed"] is True and line["failure_kind"] == kind
    assert call.failure and call.failure not in text and STDERR_MARK not in text


def _usable_envelope(payload):
    return json.dumps({"result": payload, "usage": {"input_tokens": 13, "output_tokens": 17}})


@pytest.mark.parametrize("role", ["worker", "supervisor"])
def test_an_unusable_reply_is_unclassified_and_keeps_its_tokens(role, tmp_path):
    payload = {"scope_object_id": "SCOPE-NOT-OFFERED", "action": "network.scan",
               "target_type": "ip", "target_value": "10.82.0.5", "scan_type": "connect",
               "reason": "x", "status_assessment": "work_remains", "assessment_note": "x",
               "tasks": [{"scope_object_id": "SCOPE-NOT-OFFERED", "action": "network.scan",
                          "target_type": "ip", "target_value": "10.82.0.5", "goal": "g",
                          "priority": 1}]}
    call = _call(role, lambda command, **kwargs: _completed(0, stdout=_usable_envelope(payload)))
    print("KIND", role, "unusable", call.failure_kind)
    assert call.failed and call.failure.startswith("unusable ")
    assert call.failure_kind == UNCLASSIFIED
    assert (call.input_tokens, call.output_tokens) == (13, 17)  # the reply's tokens were spent
    text, line = _recorded(call, role, tmp_path)
    assert line["failure_kind"] == UNCLASSIFIED and call.failure not in text


def test_the_record_uses_failure_kind_py_s_vocabulary_and_writes_unknown_outside_it(tmp_path):
    assert run_shadow.FAILURE_KINDS is failure_kind.FAILURE_KINDS
    assert set(failure_kind.FAILURE_KINDS) == {REFUSAL, TRANSPORT, UNCLASSIFIED}
    for given, written in ((None, "unknown"), ("made-up", "unknown"), ("timed out", "unknown"),
                           (TRANSPORT, TRANSPORT)):
        call = WorkerCall(latency_seconds=0.0, failed=True, failure="x", failure_kind=given)
        _, line = _recorded(call, f"worker-{written}-{given}", tmp_path)
        assert line["failure_kind"] == written, given
    _, line = _recorded(WorkerCall(latency_seconds=0.0, failure_kind=TRANSPORT), "ok", tmp_path)
    assert line["failed"] is False and line["failure_kind"] is None
