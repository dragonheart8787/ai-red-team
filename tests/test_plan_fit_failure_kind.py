"""The kind of a failed Q1 call (D68 DP-15): ``refusal``, ``transport`` or ``unclassified``.

What the exit rule counts depends on it (a service outage must not suspend a class), so the
classification is tested as a table, through each of the three real transports, and through the
control plane's own reading of a validator that raises. No database here: the rule over the
recorded kinds is in ``test_plan_fit_class_store.py``.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
from types import SimpleNamespace

import pytest

from agents.failure_kind import (
    FAILURE_KINDS,
    REFUSAL,
    TRANSPORT,
    UNCLASSIFIED,
    classify_failure,
    status_is_transport,
)
from agents.fake.fake_plan_fit import ScriptedPlanFit, UnavailableFakePlanFit
from agents.llm.headless import HeadlessError, run_headless
from control_plane.plan_fit import goal_fit as gf
from control_plane.plan_fit import relation as r
from tests.test_plan_fit_validator import answer, api, asked, cli, cli_envelope, local


class StatusError(Exception):
    def __init__(self, status):
        super().__init__("status")
        self.status_code = status


class RateLimitError(Exception):
    """Named as the Anthropic client names it; no import of the package is needed."""


class AuthenticationError(Exception):
    pass


# -- the classification, as a table ---------------------------------------------------------------

@pytest.mark.parametrize("status,expected", [
    (500, True), (502, True), (503, True), (529, True), (599, True),
    (401, True), (402, True), (403, True), (408, True), (429, True),
    (400, False), (404, False), (413, False), (422, False), (499, False), (600, False),
    (200, False), (0, False), (None, False), ("500", False), (True, False), (503.0, False),
])
def test_which_statuses_belong_to_the_service(status, expected):
    assert status_is_transport(status) is expected


@pytest.mark.parametrize("kwargs,kind", [
    ({"stop_reason": "refusal"}, REFUSAL),
    ({"stop_reason": "refusal", "timed_out": True}, REFUSAL),          # a refusal is a refusal
    ({"stop_reason": "refusal", "api_error_status": 503}, REFUSAL),
    ({"stop_reason": "end_turn"}, UNCLASSIFIED),
    ({"stop_reason": "Refusal"}, UNCLASSIFIED),                       # exact, not "close to"
    ({"timed_out": True}, TRANSPORT),
    ({"api_error_status": 529}, TRANSPORT),
    ({"api_error_status": 401}, TRANSPORT),
    ({"api_error_status": 429}, TRANSPORT),
    ({"api_error_status": 400}, UNCLASSIFIED),
    ({"api_error_status": "529"}, UNCLASSIFIED),
    ({}, UNCLASSIFIED),
    ({"exception": TimeoutError("slow")}, TRANSPORT),
    ({"exception": subprocess.TimeoutExpired("cmd", 3)}, TRANSPORT),
    ({"exception": TimeoutError()}, TRANSPORT),
    ({"exception": ConnectionResetError()}, TRANSPORT),
    ({"exception": ConnectionRefusedError()}, TRANSPORT),
    ({"exception": BrokenPipeError()}, TRANSPORT),
    ({"exception": urllib.error.URLError("no route")}, TRANSPORT),
    ({"exception": urllib.error.HTTPError("u", 503, "m", {}, None)}, TRANSPORT),
    ({"exception": urllib.error.HTTPError("u", 429, "m", {}, None)}, TRANSPORT),
    ({"exception": urllib.error.HTTPError("u", 400, "m", {}, None)}, UNCLASSIFIED),
    ({"exception": StatusError(503)}, TRANSPORT),
    ({"exception": StatusError(401)}, TRANSPORT),
    ({"exception": StatusError(400)}, UNCLASSIFIED),
    ({"exception": RateLimitError("x")}, TRANSPORT),
    ({"exception": AuthenticationError("x")}, TRANSPORT),
    ({"exception": HeadlessError("m", timed_out=True)}, TRANSPORT),
    ({"exception": HeadlessError("m", api_error_status=502)}, TRANSPORT),
    ({"exception": HeadlessError("m", stop_reason="refusal")}, REFUSAL),
    ({"exception": HeadlessError("m")}, UNCLASSIFIED),
    ({"exception": ValueError("x")}, UNCLASSIFIED),
    ({"exception": KeyError("x")}, UNCLASSIFIED),
    ({"exception": RuntimeError("x")}, UNCLASSIFIED),
    ({"exception": json.JSONDecodeError("m", "d", 0)}, UNCLASSIFIED),
    ({"exception": OSError("no such file")}, UNCLASSIFIED),     # plain OSError: not "the network"
    ({"exception": FileNotFoundError("claude")}, UNCLASSIFIED),
])
def test_the_kind_of_each_failure(kwargs, kind):
    assert classify_failure(**kwargs) == kind
    assert kind in FAILURE_KINDS


@pytest.mark.parametrize("message", [
    "timed out after 30s", "503 Service Unavailable", "rate limit exceeded", "connection reset",
    "stop_reason: refusal", "401 unauthorized"])
def test_words_in_a_message_never_choose_a_kind(message):
    """The kind comes from what the service or the transport said -- a status, a stop reason, a
    flag, an exception's type -- and never from the text of a message, so wording (a goal, a
    target, anything echoed back) cannot choose ``transport`` or ``refusal``."""
    for exc in (RuntimeError(message), ValueError(message), HeadlessError(message),
                OSError(message)):
        assert classify_failure(exception=exc) == UNCLASSIFIED


# -- through the three transports -----------------------------------------------------------------

def kind_of(validator, q=None):
    got = asked(validator, q)
    assert (got.goal_fit, got.cause) == ("not_assessed", "failed")
    (call,) = validator.calls
    assert call.failed and call.failure_kind in FAILURE_KINDS
    return call.failure_kind


def refusal_envelope(**extra):
    return json.dumps({"duration_api_ms": 3000, "stop_reason": "refusal", "is_error": True,
                       "result": "", **extra})


def test_the_api_validators_failures():
    assert kind_of(api(answer("plausible"), stop_reason="refusal")) == REFUSAL
    assert kind_of(api(raises=TimeoutError("slow"))) == TRANSPORT
    assert kind_of(api(raises=StatusError(503))) == TRANSPORT
    assert kind_of(api(raises=StatusError(429))) == TRANSPORT
    assert kind_of(api(raises=AuthenticationError("bad key"))) == TRANSPORT
    assert kind_of(api(raises=StatusError(400))) == UNCLASSIFIED
    assert kind_of(api("not json at all")) == UNCLASSIFIED
    assert kind_of(api("[1, 2]")) == UNCLASSIFIED
    assert kind_of(api(no_text=True)) == UNCLASSIFIED
    assert kind_of(api(json.dumps({"goal_fit": "plausible", "why": "x"}))) == UNCLASSIFIED


def test_the_claude_code_validators_failures():
    # the safety stop that S7 and S8b measured: exit 1 with the envelope on stdout
    assert kind_of(cli(refusal_envelope(), returncode=1)) == REFUSAL
    # ... and the same stop reported with exit 0 and an empty result
    assert kind_of(cli(json.dumps({"stop_reason": "refusal", "result": ""}))) == REFUSAL
    assert kind_of(cli(json.dumps({"stop_reason": "refusal", "is_error": True}))) == REFUSAL
    assert kind_of(cli(raises=subprocess.TimeoutExpired("claude", 30))) == TRANSPORT
    assert kind_of(cli(json.dumps({"is_error": True, "api_error_status": 529,
                                   "result": "overloaded"}), returncode=1)) == TRANSPORT
    assert kind_of(cli(json.dumps({"is_error": True, "api_error_status": 401}))) == TRANSPORT
    assert kind_of(cli(json.dumps({"is_error": True, "api_error_status": 429}),
                       returncode=1)) == TRANSPORT
    assert kind_of(cli(json.dumps({"is_error": True, "api_error_status": 400}),
                       returncode=1)) == UNCLASSIFIED
    assert kind_of(cli(returncode=1, stderr="something broke")) == UNCLASSIFIED
    assert kind_of(cli("not json")) == UNCLASSIFIED
    assert kind_of(cli(raises=OSError("no such file"))) == UNCLASSIFIED
    assert kind_of(cli(cli_envelope({"goal_fit": "plausible", "x": 1}))) == UNCLASSIFIED


def test_the_local_validators_failures():
    assert kind_of(local(raises=urllib.error.URLError("refused"))) == TRANSPORT
    assert kind_of(local(raises=TimeoutError("slow"))) == TRANSPORT
    assert kind_of(local(raises=ConnectionResetError())) == TRANSPORT
    assert kind_of(local(raises=urllib.error.HTTPError("u", 502, "bad gateway", {}, None))
                   ) == TRANSPORT
    assert kind_of(local(raises=urllib.error.HTTPError("u", 400, "bad", {}, None))
                   ) == UNCLASSIFIED
    assert kind_of(local({"choices": []})) == UNCLASSIFIED
    assert kind_of(local("junk")) == UNCLASSIFIED


def test_the_headless_error_keeps_its_message_and_adds_what_the_cli_said():
    def run(stdout, returncode=1):
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, returncode, stdout, "")
        return run_headless(command=["claude"], timeout_seconds=5, runner=runner)

    with pytest.raises(HeadlessError) as raised:
        run(refusal_envelope())
    assert str(raised.value).startswith("cli exited 1: no stderr; stdout: ")
    assert raised.value.stop_reason == "refusal" and not raised.value.timed_out
    with pytest.raises(HeadlessError) as raised:
        run("not an envelope")
    assert (raised.value.stop_reason, raised.value.api_error_status) == (None, None)

    def slow(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 5)

    with pytest.raises(HeadlessError) as raised:
        run_headless(command=["claude"], timeout_seconds=5, runner=slow)
    assert str(raised.value) == "timed out after 5s" and raised.value.timed_out is True


# -- the control plane's reading ------------------------------------------------------------------

def relation():
    return r.TaskRelation(r.MATCHES_TASK)


def fit(validator):
    return gf.assess_goal_fit(
        validator=validator, relation=relation(),
        task_context={"goal": "Scan the host", "action": "network.scan",
                      "canonical_target": "ip:10.0.0.5"},
        proposal_action="network.scan", proposal_target="ip:10.0.0.5",
        enabled_actions=frozenset({"network.scan"}))


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_a_failed_call_carries_its_kind_into_the_assessment_and_the_audit(kind):
    got = fit(UnavailableFakePlanFit(kind))
    assert got.outcome == "failed" and got.failure_kind == kind
    assert got.audit_payload()["failure_kind"] == kind
    assert got.audit_payload()["goal_fit_cause"] == "failed"   # fails closed the same way


def test_a_validator_that_raises_is_classified_by_its_exception():
    class Raises:
        validator_id = "raises"

        def __init__(self, exc):
            self.exc = exc

        def assess(self, *, query):
            raise self.exc

    assert fit(Raises(TimeoutError("slow"))).failure_kind == TRANSPORT
    assert fit(Raises(StatusError(503))).failure_kind == TRANSPORT
    assert fit(Raises(HeadlessError("m", stop_reason="refusal"))).failure_kind == REFUSAL
    assert fit(Raises(RuntimeError("503 timed out"))).failure_kind == UNCLASSIFIED


def test_an_answer_outside_the_contract_is_unclassified():
    class Garbage:
        validator_id = "garbage"

        def assess(self, *, query):
            return "plausible"

    got = fit(Garbage())
    assert got.outcome == "failed" and got.failure_kind == UNCLASSIFIED


def test_a_kind_a_call_record_should_not_hold_is_read_as_unclassified():
    class Liar:
        validator_id = "liar"

        def __init__(self):
            self.calls = []

        def assess(self, *, query):
            from agents.base_agent import GoalFitAssessment
            self.calls.append(SimpleNamespace(
                latency_seconds=0.0, input_tokens=0, output_tokens=0, failed=True,
                failure_kind="transport; DROP TABLE"))
            return GoalFitAssessment(self.validator_id, "not_assessed", "failed")

    assert fit(Liar()).failure_kind == UNCLASSIFIED


def test_an_answered_call_and_a_call_not_asked_have_no_kind():
    assert fit(ScriptedPlanFit("implausible")).failure_kind is None
    not_asked = gf.assess_goal_fit(
        validator=ScriptedPlanFit("plausible"), relation=relation(), task_context=None,
        proposal_action="network.scan", proposal_target=None)
    assert not_asked.failure_kind is None and not_asked.outcome is None
