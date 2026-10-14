"""A run that timed out and a run that never started are told apart by their reason codes (5.77).

Both end ``failed`` and both are, for the caller, "it did not complete" -- and they are opposites
for everything that follows. A run that **timed out** started, ran, and left output; what it did
before it was ended is part of the record, and running it again is a decision. A run that was
**never started** (Docker unreachable, the image missing, the in-container deadline helper missing
or altered, the tool's command not executable) ran nothing and is safe to retry. D65-A made the two
easier to confuse: the helper's exit 124 is now a timeout, its "cannot execute" line is a refusal,
and a refused helper is a refusal that *looks* like an infrastructure fault.

So each has its own code, in every place a reader looks:

========================  ==================================  ======================  =========
                          audit event                         reasons                 outcome
========================  ==================================  ======================  =========
timed out                 ``tool_run.failed`` (with output)   ``tool_run_timed_out``  ``failure``
never started             ``tool_run.refused``                ``sandbox_not_started``,  ``failure``
                                                              then the exception's code
========================  ==================================  ======================  =========

and the two vocabularies share no code.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.orchestrator import dispatch, stages
from control_plane.state.db import engagement_scope
from tests.test_pipeline_stages import (
    CIDR,
    CountingReviewer,
    FakeSandbox,
    assert_coherent,
    go,
    only,
    snapshot,
)
from tool_gateway import deadline_helper as dh
from tool_gateway import sandbox as sandbox_module
from tool_gateway.sandbox import (
    ContainerStartRefused,
    DeadlineHelperUnavailable,
    NotStarted,
    SandboxResult,
    ToolNotExecutable,
)


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id,
            "key": f"key-{uuid.uuid4().hex[:8]}"}


class TimedOut(FakeSandbox):
    def run(self, **kwargs):
        self.calls += 1
        return SandboxResult(-1, "partial output", "", True, 5.2, (CIDR,), "fake")


def _audit(eid: str) -> dict[str, list[list[str]]]:
    with engagement_scope(eid) as conn:
        out: dict[str, list[list[str]]] = {}
        for event, reasons in conn.execute(text(
                "SELECT event_type, reasons FROM audit_log WHERE event_type LIKE 'tool_run.%' "
                "ORDER BY audit_id")).all():
            out.setdefault(event, []).append(list(reasons))
        return out


def _runs(eid: str):
    with engagement_scope(eid) as conn:
        return conn.execute(text("SELECT status, exit_code FROM tool_runs")).all()


# ---------------------------------------------------------------------------
# the vocabularies
# ---------------------------------------------------------------------------

def _not_started_classes():
    found, todo = [], [NotStarted]
    while todo:
        cls = todo.pop()
        for sub in cls.__subclasses__():
            found.append(sub)
            todo.append(sub)
    return [NotStarted, *found]


def _helper_codes() -> set[str]:
    source = Path(dh.__file__).read_text() + Path(sandbox_module.__file__).read_text()
    return set(re.findall(r'"(deadline_helper_[a-z_]+)"', source)) - {"deadline_helper_unavailable"}


def test_every_not_started_class_has_its_own_reason_and_none_is_the_timeout_code():
    classes = _not_started_classes()
    reasons = [c.reason for c in classes]
    assert len(classes) >= 8, "the scan found too few classes: it is broken"
    assert len(set(reasons)) == len(reasons), f"two NotStarted classes share a code: {reasons}"
    assert dispatch.TIMED_OUT not in reasons
    assert ToolNotExecutable.reason == "tool_command_not_executable" and issubclass(
        ToolNotExecutable, ContainerStartRefused)


def test_the_helper_refusal_codes_are_their_own_and_are_not_the_timeout_code():
    codes = _helper_codes()
    assert len(codes) >= 7, codes
    assert dispatch.TIMED_OUT not in codes
    assert not codes & {c.reason for c in _not_started_classes()}
    assert dispatch.TIMED_OUT == "tool_run_timed_out" and dispatch.SANDBOX_NOT_STARTED not in codes


# ---------------------------------------------------------------------------
# a run that timed out
# ---------------------------------------------------------------------------

def test_a_timed_out_run_is_failed_with_its_output_and_its_own_code(world):
    eid = world["engagement_id"]
    outcome = go(world, sandbox=TimedOut())

    assert outcome.decision == "ALLOW" and outcome.run_id and outcome.evidence_id
    assert outcome.failure == dispatch.TIMED_OUT
    snap = snapshot(eid)
    p = only(snap)
    assert (p["stage"], p["detail"], p["dispatch_state"]) == (stages.RECORDED, "failed", "failed")
    assert _runs(eid) == [("failed", -1)] and snap["evidence"] == 1
    audit = _audit(eid)
    assert audit["tool_run.failed"] == [[dispatch.TIMED_OUT]]
    assert "tool_run.refused" not in audit
    assert_coherent(snap)


def test_a_timed_out_run_asked_again_is_told_the_same_way_and_nothing_runs(world):
    eid = world["engagement_id"]
    first = go(world, sandbox=TimedOut())
    sandbox, reviewer = TimedOut(), CountingReviewer()
    again = go(world, sandbox=sandbox, reviewer=reviewer)
    assert again.run_id == first.run_id and again.failure == dispatch.TIMED_OUT
    assert sandbox.calls == 0 and reviewer.calls == 0
    assert len(_runs(eid)) == 1


def test_an_ordinary_failure_is_neither(world):
    class Fails(FakeSandbox):
        def run(self, **kwargs):
            self.calls += 1
            return SandboxResult(3, "", "boom", False, 0.4, (CIDR,), "fake")

    eid = world["engagement_id"]
    outcome = go(world, sandbox=Fails())
    assert outcome.failure not in (dispatch.TIMED_OUT, dispatch.SANDBOX_NOT_STARTED)
    assert _audit(eid)["tool_run.failed"] == [[]]
    assert _runs(eid) == [("failed", 3)]


def test_a_deadline_ended_by_the_in_container_helper_is_recorded_as_the_same_timeout(
    world, monkeypatch,
):
    """The real helper, a real container, the control plane alive but not acting: the helper's
    deadline (budget - 3 s here) ends the run and the pipeline records exactly what it records for
    the control plane's own timeout."""
    from tool_gateway.sandbox import DockerSandbox

    monkeypatch.setattr(dh, "SLACK_SECONDS", -3)
    eid = world["engagement_id"]

    class RealHelperRun(FakeSandbox):
        def run(self, **kwargs):
            self.calls += 1
            return DockerSandbox(image="python:3.12-slim").run(
                command=["sleep", "120"], network_allowlist=[CIDR], max_duration_seconds=6,
                no_network=True, engagement_id=eid)

    outcome = go(world, sandbox=RealHelperRun())
    assert outcome.failure == dispatch.TIMED_OUT
    assert _audit(eid)["tool_run.failed"] == [[dispatch.TIMED_OUT]]
    assert _runs(eid) == [("failed", -1)]
    with engagement_scope(eid) as conn:
        stderr_has_the_helpers_line = conn.execute(text(
            "SELECT count(*) FROM evidence")).scalar_one()
    assert stderr_has_the_helpers_line == 1


# ---------------------------------------------------------------------------
# a run that never started
# ---------------------------------------------------------------------------

REFUSALS = [
    DeadlineHelperUnavailable("the helper is missing", "deadline_helper_missing"),
    DeadlineHelperUnavailable("the helper was altered", "deadline_helper_hash_mismatch"),
    DeadlineHelperUnavailable("not executable", "deadline_helper_not_executable"),
    ToolNotExecutable("the tool's command could not be executed"),
    ContainerStartRefused("docker refused to start"),
]


@pytest.mark.parametrize("refusal", REFUSALS, ids=lambda e: e.reason)
def test_a_run_that_never_started_is_refused_with_the_exceptions_code_and_no_output(world, refusal):
    eid = world["engagement_id"]
    outcome = go(world, sandbox=FakeSandbox(error=refusal))

    assert outcome.failure == refusal.reason and outcome.run_id is None
    assert outcome.failure != dispatch.TIMED_OUT
    snap = snapshot(eid)
    p = only(snap)
    assert (p["stage"], p["detail"]) == (stages.CLOSED, refusal.reason)
    assert _runs(eid) == [("failed", None)] and snap["evidence"] == 0
    audit = _audit(eid)
    assert audit["tool_run.refused"] == [[dispatch.SANDBOX_NOT_STARTED, refusal.reason]]
    assert "tool_run.failed" not in audit
    assert_coherent(snap)


def test_the_two_are_told_apart_by_code_in_the_same_engagement(world):
    """One of each, one engagement: nothing a reader sees is the same between them."""
    eid = world["engagement_id"]
    timed_out = go(world, sandbox=TimedOut(), key="k-timeout", target="10.82.0.5")
    refused = go(world, sandbox=FakeSandbox(error=DeadlineHelperUnavailable(
        "altered", "deadline_helper_hash_mismatch")), key="k-refused", target="10.82.0.6")
    assert timed_out.failure == dispatch.TIMED_OUT
    assert refused.failure == "deadline_helper_hash_mismatch"
    assert timed_out.run_id and refused.run_id is None
    audit = _audit(eid)
    assert audit["tool_run.failed"] == [[dispatch.TIMED_OUT]]
    assert audit["tool_run.refused"] == [["sandbox_not_started", "deadline_helper_hash_mismatch"]]
