"""D69 shadow runner, stage S1 (plan item 137): the real Worker's ``propose`` makes its
``discovery`` through ``BaseWorker._to_proposal``, and the real Supervisor's ``plan`` makes its
tasks through ``BaseSupervisor._to_tasks``.

The real classes (``ClaudeCodeHeadlessWorker``, ``ClaudeCodeHeadlessSupervisor``) are built with
their injectable ``runner``, which here is a function that returns the CLI's result envelope
around a fixed payload: no model is called and no process is started. ``run_headless`` makes and
removes a working directory around each call (``agents/llm/headless.py``); here ``mkdtemp`` returns
a path that is never created, so the tests write nothing. The Worker is shown one observation built
by the real builder (``harness.observations``) from the real nmap adapter's view of H7's sample 1
(``tests/test_harness_h7_528.py``): the responder is 10.82.0.5 and a banner names 10.82.0.77.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agents.base_agent import ProposedAction, ProposedTask
from agents.llm import headless
from agents.llm.claude_code_headless_reviewer import ClaudeCodeHeadlessReviewer
from agents.llm.claude_code_headless_supervisor import ClaudeCodeHeadlessSupervisor
from agents.llm.claude_code_headless_worker import ClaudeCodeHeadlessWorker
from agents.llm.reviewer_base import SYSTEM_PROMPT as REVIEWER_SYSTEM_PROMPT
from agents.llm.reviewer_base import BaseReviewer
from agents.llm.supervisor_base import BaseSupervisor, StateSummary
from agents.llm.worker_base import WORKER_SYSTEM_PROMPT, BaseWorker, ScopeCandidate
from control_plane.canonicalizer.target import normalize_target
from harness.observations import EvidenceWindowRow, observation_from_evidence
from tests.test_harness_h7_528 import STDOUT
from tool_gateway.adapters import nmap

SCOPE = "SCOPE-PIN"
CANDIDATES = (ScopeCandidate(SCOPE, "cidr", "10.82.0.0/24", ("network.scan",)),)
OBSERVATIONS = (observation_from_evidence(EvidenceWindowRow(
    evidence_id="EV-PIN-1", run_id="RUN-PIN-1", tool="nmap",
    derived_view=nmap.derive_view(STDOUT[1], ""), scan_type="ping",
    requested_target="10.82.0.250")),)
TASK = ProposedTask(goal="Find out which hosts in 10.82.0.0/24 are up",
                    target={"logical_identity": {"type": "cidr", "value": "10.82.0.0/24"}},
                    action="network.scan", scope_object_id=SCOPE)


@pytest.fixture(autouse=True)
def _no_working_directory(monkeypatch):
    monkeypatch.setattr(headless.tempfile, "mkdtemp",
                        lambda prefix="": "/nonexistent/cyberorch-headless-pin")


def _runner(payload, seen):
    """The CLI, as a function: records the argv and answers with one envelope."""
    def run(command, **kwargs):
        seen.append(command)
        envelope = {"result": payload, "usage": {"input_tokens": 1, "output_tokens": 1}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")
    return run


def _worker_payload(target_value):
    return {"scope_object_id": SCOPE, "action": "network.scan", "target_type": "ip",
            "target_value": target_value, "scan_type": "connect", "reason": "pin"}


def _propose(target_value, monkeypatch):
    seen = []
    worker = ClaudeCodeHeadlessWorker(runner=_runner(_worker_payload(target_value), seen))
    proposal = worker.propose(task=TASK, candidates=CANDIDATES, observations=OBSERVATIONS,
                              task_id="TASK-PIN")
    print("OBSERVED", target_value, "discovery", proposal.discovery if proposal else None)
    return proposal, seen


def test_the_real_worker_inherits_the_boundary_methods():
    for method in ("build_prompt", "_to_proposal", "_refuse"):
        assert getattr(ClaudeCodeHeadlessWorker, method) is getattr(BaseWorker, method)


def test_a_lure_named_in_the_evidence_is_introduced_by_the_real_worker(monkeypatch):
    proposal, seen = _propose("10.82.0.77", monkeypatch)
    assert len(seen) == 1                                       # one "model call", no process
    assert seen[0][seen[0].index("--system-prompt") + 1] == WORKER_SYSTEM_PROMPT
    assert proposal is not None
    assert proposal.discovery["introduced_by_untrusted"] is True
    assert proposal.discovery["evidence_id"] == "EV-PIN-1"


def test_the_observed_responder_is_not_introduced_by_the_real_worker(monkeypatch):
    proposal, seen = _propose("10.82.0.5", monkeypatch)
    assert len(seen) == 1 and proposal is not None
    assert proposal.discovery["introduced_by_untrusted"] is False


def _plan(scope_object_id):
    seen = []
    payload = {"status_assessment": "work_remains", "assessment_note": "pin",
               "tasks": [{"scope_object_id": scope_object_id, "action": "network.scan",
                          "target_type": "ip", "target_value": "10.82.0.5",
                          "goal": "scan 10.82.0.5", "priority": 1}]}
    supervisor = ClaudeCodeHeadlessSupervisor(runner=_runner(payload, seen))
    tasks = supervisor.plan(state=StateSummary(engagement_id="ENG-PIN", objective="o"),
                            candidates=CANDIDATES)
    return supervisor, tasks, seen


def test_the_real_supervisor_inherits_the_boundary_methods():
    for method in ("build_prompt", "_to_tasks", "_refuse"):
        assert getattr(ClaudeCodeHeadlessSupervisor, method) is getattr(BaseSupervisor, method)


def test_the_real_supervisor_makes_its_tasks_through_to_tasks():
    _, tasks, seen = _plan(SCOPE)
    assert len(seen) == 1
    assert [(t.scope_object_id, t.target["logical_identity"]["value"]) for t in tasks] == [
        (SCOPE, "10.82.0.5")]


def test_the_real_supervisor_refuses_a_plan_that_to_tasks_refuses():
    supervisor, tasks, seen = _plan("SCOPE-NOT-OFFERED")
    assert len(seen) == 1 and tasks is None
    assert supervisor.calls[-1].failed and "was not among" in supervisor.calls[-1].failure


# -- the real Reviewer (S2, plan item 140): the system prompt the Reviewer's digest assumes --------


def _review(risk_hint):
    seen = []
    reviewer = ClaudeCodeHeadlessReviewer(runner=_runner({"risk_hint": risk_hint}, seen))
    proposal = ProposedAction(
        action="network.scan", target={"logical_identity": {"type": "ip", "value": "10.82.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": SCOPE},
        discovery={"source": "explicit_scope"}, task_id="TASK-PIN")
    opinion = reviewer.review(proposal=proposal,
                              canonical_target=normalize_target(proposal.target))
    return reviewer, opinion, seen


def test_the_real_reviewer_inherits_the_boundary_methods():
    for method in ("build_prompt", "_to_opinion", "_escalate"):
        assert getattr(ClaudeCodeHeadlessReviewer, method) is getattr(BaseReviewer, method)


def test_the_real_reviewer_sends_the_reviewer_system_prompt():
    _, _, seen = _review("medium")
    assert len(seen) == 1                                       # one "model call", no process
    assert seen[0][seen[0].index("--system-prompt") + 1] == REVIEWER_SYSTEM_PROMPT


def test_the_real_reviewer_makes_its_opinion_through_to_opinion():
    reviewer, opinion, _ = _review("medium")
    assert opinion.reviewer_id == reviewer.reviewer_id and opinion.risk_hint == "medium"
    _, coerced, _ = _review("not-a-risk-level")                 # _to_opinion's own coercion
    assert coerced.risk_hint == "high"
