"""D69-NC-1a (plan item 147): a failed call's tokens, when its envelope carries them.

``agents/llm/headless.py`` reads a failed call's envelope for a ``usage`` object the way it reads a
successful call's (a missing or ill-typed field is 0, and nothing raises), and hands it on as
``HeadlessError.usage``; the three real adapters pass it to ``_refuse`` / ``_escalate``, so the call
record has the tokens and ``run_harness.tokens_spent`` counts them. A failure whose envelope has no
``usage`` keeps 0 tokens, and the shadow runner's record counts it in the footer as
``failed_calls_without_tokens``. The real adapters run on a fake runner: no process, no model;
``mkdtemp`` returns a path that is never created. Records are written under pytest's ``tmp_path``.
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
from scripts import run_harness, run_shadow
from tests.test_shadow_runner_pins import CANDIDATES, SCOPE, TASK

ROLES = ("worker", "supervisor", "reviewer")


@pytest.fixture(autouse=True)
def _no_working_directory(monkeypatch):
    monkeypatch.setattr(headless.tempfile, "mkdtemp",
                        lambda prefix="": "/nonexistent/cyberorch-headless-usage")


def _cli(returncode, envelope):
    stdout = envelope if isinstance(envelope, str) else json.dumps(envelope)

    def run(command, **kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
    return run


def _adapter(role, runner):
    """The real adapter of ``role``, after one call over ``runner``."""
    if role == "worker":
        adapter = ClaudeCodeHeadlessWorker(runner=runner)
        adapter.propose(task=TASK, candidates=CANDIDATES, task_id="TASK-USAGE")
    elif role == "supervisor":
        adapter = ClaudeCodeHeadlessSupervisor(runner=runner)
        adapter.plan(state=StateSummary(engagement_id="ENG-USAGE", objective="o"),
                     candidates=CANDIDATES)
    else:
        adapter = ClaudeCodeHeadlessReviewer(runner=runner)
        proposal = ProposedAction(
            action="network.scan",
            target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
            authorization={"source": "engagement_scope", "scope_object_id": SCOPE},
            discovery={"source": "explicit_scope"}, task_id="TASK-USAGE")
        adapter.review(proposal=proposal, canonical_target=normalize_target(proposal.target))
    assert len(adapter.calls) == 1 and adapter.calls[0].failed
    return adapter


#: Failed envelopes that carry a usage object: a safety stop with exit 1, and an error with exit 0.
WITH_USAGE = {
    "refusal_exit_1": (1, {"is_error": True, "stop_reason": "refusal", "result": "",
                           "usage": {"input_tokens": 21, "output_tokens": 4}}),
    "error_exit_0": (0, {"is_error": True, "result": "boom",
                         "usage": {"input_tokens": 21, "output_tokens": 4}}),
}


@pytest.mark.parametrize("case", list(WITH_USAGE))
@pytest.mark.parametrize("role", ROLES)
def test_a_failed_envelope_with_usage_keeps_its_tokens_and_the_cap_counts_them(role, case):
    adapter = _adapter(role, _cli(*WITH_USAGE[case]))
    call = adapter.calls[0]
    assert (call.input_tokens, call.output_tokens) == (21, 4), (role, case)
    roles = SimpleNamespace(**{r: SimpleNamespace(calls=[]) for r in ROLES})
    setattr(roles, role, adapter)
    assert run_harness.tokens_spent(roles) == 25


@pytest.mark.parametrize("envelope", [
    {"is_error": True, "result": "boom"},                                    # no usage object
    {"is_error": True, "result": "boom", "usage": "lots"},                   # not an object
    {"is_error": True, "result": "boom", "usage": {"input_tokens": "many", "output_tokens": [1]}},
    {"is_error": True, "result": "boom", "usage": {}},
    "not an envelope",
])
@pytest.mark.parametrize("role", ROLES)
def test_a_failed_envelope_without_usable_tokens_records_zero_and_raises_nothing(role, envelope):
    call = _adapter(role, _cli(1, envelope)).calls[0]
    assert (call.input_tokens, call.output_tokens) == (0, 0)


def test_the_error_carries_the_usage_read_as_a_successful_calls_and_none_without_one():
    def run(envelope, returncode=1):
        with pytest.raises(headless.HeadlessError) as raised:
            headless.run_headless(command=["claude"], timeout_seconds=5,
                                  runner=_cli(returncode, envelope))
        return raised.value.usage

    assert run({"is_error": True, "usage": {"input_tokens": 3, "output_tokens": 9}}) == \
        headless.HeadlessUsage(input_tokens=3, output_tokens=9)
    assert run({"is_error": True, "usage": {"input_tokens": None}}) == \
        headless.HeadlessUsage(input_tokens=0, output_tokens=0)
    assert run({"is_error": True}) is None
    assert run("garbage") is None

    def slow(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 5)

    with pytest.raises(headless.HeadlessError) as raised:
        headless.run_headless(command=["claude"], timeout_seconds=5, runner=slow)
    assert raised.value.usage is None and raised.value.timed_out


def test_the_footer_counts_the_failed_calls_without_tokens(tmp_path):
    record = run_shadow.Record(tmp_path / "run.jsonl")
    try:
        for call in (WorkerCall(0.0, failed=True, failure="x"),                   # counted
                     WorkerCall(0.0, input_tokens=21, output_tokens=4, failed=True, failure="x"),
                     WorkerCall(0.0, output_tokens=1, failed=True, failure="x"),
                     WorkerCall(0.0),                                             # not failed
                     WorkerCall(0.0, failed=True, failure="y")):                  # counted
            record.on_call("worker", call)
        record.on_stop("signal_or_once", 0, None, {"input_tokens": 21, "output_tokens": 5,
                                                   "cache_read_tokens": 0})
        record.footer(0)
    finally:
        record.close()
    footer = json.loads((tmp_path / "run.jsonl").read_text().splitlines()[-1])
    assert footer["line"] == "footer" and footer["failed_calls_without_tokens"] == 2
