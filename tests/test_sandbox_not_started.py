"""A sandbox that never started is "failed", not "unknown outcome" (D58-7).

D58 found two defects in how dispatch records a failure of the sandbox itself:

* **Mislabel.** Every ``SandboxUnavailable`` was recorded as ``unknown_outcome`` ("the tool may or
  may not have run", §8.8) -- including "Docker could not be reached", where the tool *provably did
  not run*. A Docker outage then turned every dispatch in its window into a proposal only a human
  could clear. (The same was true of the network refusals until D59 typed them.)
* **Escape (X5).** A cached client whose daemon has since died raises a raw
  ``requests.exceptions.ConnectionError``, which is not a ``SandboxUnavailable`` and so escaped the
  typed path altogether.

The fix is a type, not a message match: ``NotStarted`` marks the failures that are provable
pre-start (daemon unreachable, image absent, network unobtainable, container not created), and
dispatch records exactly those as ``failed``/retryable. A plain ``SandboxUnavailable`` still means
"cannot tell" and is still ``unknown_outcome``; nothing from ``start()`` onwards is retyped.

These tests use the real Docker SDK against a daemon address that is not there, and against the
real daemon with an image that does not exist -- not a stub that raises what the fix expects.
"""

from __future__ import annotations

import uuid

import docker
import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.orchestrator.dispatch import reconcile_stale_dispatches
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from tests.helpers import committing_scope as engagement_scope
from tool_gateway.sandbox import (
    DaemonUnreachable,
    DockerSandbox,
    ImageNotPresent,
    NetworkNotAvailable,
    NotStarted,
    SandboxResult,
    SandboxUnavailable,
)

CIDR = "10.84.0.0/24"
DEAD = "tcp://127.0.0.1:1"      # nothing listens here


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", actions={"network.scan": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


@pytest.fixture
def world(engagement_id, registry):
    scope_id = f"SCOPE-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=CIDR,
                   allowed_actions=["network.scan"])
    return {"engagement_id": engagement_id, "scope_id": scope_id}


def go(world, sandbox):
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.84.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": world["scope_id"]},
        discovery={"source": "explicit_scope"},
    )
    return propose_action(
        engagement_id=world["engagement_id"], proposal=proposal,
        reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="w",
        sandbox=sandbox, network_allowlist=[CIDR],
    )


def recorded(world):
    with engagement_scope(world["engagement_id"]) as conn:
        p = conn.execute(text(
            "SELECT dispatch_state, pipeline_stage, stage_detail FROM action_proposals"
        )).mappings().one()
        runs = [r[0] for r in conn.execute(text("SELECT status FROM tool_runs")).all()]
        events = [(r[0], list(r[1])) for r in conn.execute(text(
            "SELECT event_type, reasons FROM audit_log WHERE event_type LIKE 'tool_run.%' "
            "OR event_type LIKE 'dispatch.%' ORDER BY audit_id")).all()]
        evidence = conn.execute(text("SELECT count(*) FROM evidence")).scalar_one()
    return dict(p), runs, events, evidence


def _dead_cached_client():
    """A client that was built against a daemon and now finds none (an explicit API version skips
    the eager version probe, which is what a client constructed while the daemon was up never
    needed to repeat)."""
    return docker.DockerClient(base_url=DEAD, version="1.43")


class _GoodSandbox:
    def __init__(self):
        self.calls = 0

    def run(self, **kwargs):
        self.calls += 1
        return SandboxResult(0, "Nmap done: 1 host up", "", False, 0.1, (CIDR,), "fake")


# ---------------------------------------------------------------------------
# 1. The types
# ---------------------------------------------------------------------------

def test_the_not_started_family_is_still_caught_by_the_old_handlers():
    for kind in (DaemonUnreachable, ImageNotPresent, NetworkNotAvailable):
        assert issubclass(kind, NotStarted) and issubclass(kind, SandboxUnavailable)
    assert not issubclass(SandboxUnavailable, NotStarted), (
        "a plain SandboxUnavailable makes no claim about whether anything started")


# ---------------------------------------------------------------------------
# 2. The daemon cannot be reached -- the mislabel itself
# ---------------------------------------------------------------------------

def test_an_unreachable_daemon_is_a_typed_refusal(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", DEAD)
    box = DockerSandbox()
    with pytest.raises(DaemonUnreachable):
        box.run(command=["true"], network_allowlist=[CIDR], max_duration_seconds=5)
    assert box._client is None, "a client that failed its ping must not be cached"


def test_an_unreachable_daemon_is_failed_and_retryable_not_unknown_outcome(world, monkeypatch):
    """Through the real entry point, the real SDK, an address with no daemon behind it."""
    monkeypatch.setenv("DOCKER_HOST", DEAD)
    outcome = go(world, DockerSandbox())

    assert outcome.decision == "ALLOW" and outcome.run_id is None
    assert outcome.failure == DaemonUnreachable.reason
    proposal, runs, events, evidence = recorded(world)
    assert proposal["dispatch_state"] == "failed", proposal
    assert (proposal["pipeline_stage"], proposal["stage_detail"]) == (
        "closed", "docker_unreachable")
    assert runs == ["failed"] and evidence == 0
    kinds = [e[0] for e in events]
    assert "tool_run.unknown_outcome" not in kinds
    refused = next(e for e in events if e[0] == "tool_run.refused")
    assert refused[1] == ["sandbox_not_started", "docker_unreachable"]
    # nothing waits for a human or for the reconciler
    with engagement_scope(world["engagement_id"]) as conn:
        assert reconcile_stale_dispatches(
            conn, engagement_id=world["engagement_id"], older_than_seconds=0,
            actor="sweeper") == []


def test_the_same_proposal_runs_once_the_daemon_is_back(world, monkeypatch):
    """Retryable means retryable: a fresh proposal for the same target goes through."""
    with monkeypatch.context() as m:
        m.setenv("DOCKER_HOST", DEAD)
        assert go(world, DockerSandbox()).failure == "docker_unreachable"
    good = _GoodSandbox()
    again = go(world, good)
    assert again.executed and good.calls == 1


# ---------------------------------------------------------------------------
# 3. X5: a cached client whose daemon died
# ---------------------------------------------------------------------------

def test_a_cached_client_with_a_dead_daemon_raises_the_typed_error_not_a_raw_one():
    """The state D58's E6 produced by killing dockerd: a client that had connected, then nothing
    answering. A client built for an address with no daemon, installed as the cache, raises the same
    raw ``requests`` error without needing the real daemon killed."""
    box = DockerSandbox()
    box._client = _dead_cached_client()
    with pytest.raises(DaemonUnreachable):
        box.run(command=["true"], network_allowlist=[CIDR], max_duration_seconds=5)


def test_a_cached_client_with_a_dead_daemon_is_failed_through_propose_action(world):
    box = DockerSandbox()
    box._client = _dead_cached_client()
    outcome = go(world, box)             # used to raise ConnectionError out of propose_action
    assert outcome.failure == "docker_unreachable"
    proposal, runs, _events, _ev = recorded(world)
    assert proposal["dispatch_state"] == "failed" and runs == ["failed"]


# ---------------------------------------------------------------------------
# 4. The image is absent (real daemon)
# ---------------------------------------------------------------------------

def test_a_missing_tool_image_is_failed_not_unknown_outcome(world):
    box = DockerSandbox(image=f"cyberorch/no-such-image-{uuid.uuid4().hex[:6]}:none")
    outcome = go(world, box)
    assert outcome.failure == "tool_image_missing" and outcome.run_id is None
    proposal, runs, events, _ev = recorded(world)
    assert proposal["dispatch_state"] == "failed" and runs == ["failed"]
    assert "tool_run.unknown_outcome" not in [e[0] for e in events]


# ---------------------------------------------------------------------------
# 5. What must NOT change: "cannot tell" is still unknown_outcome
# ---------------------------------------------------------------------------

class _UntypedFailure:
    def run(self, **kwargs):
        raise SandboxUnavailable("something went wrong at a point nobody can place")


def test_an_untyped_sandbox_failure_is_still_unknown_outcome(world):
    """The fix retypes provable pre-start failures. It does not turn every sandbox error into a
    retry: where nothing says the tool did not run, §8.8 still says it might have."""
    outcome = go(world, _UntypedFailure())
    assert outcome.run_id is not None
    proposal, runs, events, _ev = recorded(world)
    assert proposal["dispatch_state"] == "unknown_outcome"
    assert runs == ["unknown_outcome"]
    assert "tool_run.unknown_outcome" in [e[0] for e in events]
    assert (proposal["pipeline_stage"], proposal["stage_detail"]) == (
        "recorded", "unknown_outcome")


# ---------------------------------------------------------------------------
# 6. The exit D58-7 first missed: container.start() refused by the daemon
# ---------------------------------------------------------------------------
#
# Found while designing the scheduler: a network.scan on a single IP with no allowlist builds a
# one-address Docker network; ``containers.create`` succeeds and ``container.start()`` then fails
# with "no available IPv4 addresses". That is an ``APIError`` out of ``start()`` -- after the
# position D58-7 typed, before any process existed -- and it escaped dispatch raw, leaving the
# proposal at ``dispatching`` for a run that provably never executed.

from tool_gateway.sandbox import ContainerStartRefused  # noqa: E402

ONE_ADDRESS = "10.211.7.5/32"       # a pool Docker cannot give a container an address from


def test_a_start_refused_by_the_daemon_is_typed_when_the_container_never_ran():
    """Real Docker, real refusal: the one-address network from the field."""
    # The sandbox's own tool image: it is the one CI builds and the one every dispatch uses, so the
    # only thing that can refuse this start is the network.
    box = DockerSandbox()
    with pytest.raises(ContainerStartRefused) as refused:
        box.run(command=["nmap", "--version"], network_allowlist=[ONE_ADDRESS],
                max_duration_seconds=5)
    assert isinstance(refused.value, NotStarted) and isinstance(refused.value, SandboxUnavailable)
    assert refused.value.reason == "container_start_refused"
    # the message is fixed text: nothing of the daemon's reply (network ids, names) reaches an audit
    assert "10.211.7.5" not in str(refused.value) and "cyberorch-allow" not in str(refused.value)


def test_a_refused_start_through_propose_action_is_failed_and_closed_not_stuck_dispatching(
    world, caplog,
):
    """The proposal used to stay at ``dispatching`` with a ``running`` row and the exception
    escaped propose_action. Now it is a known outcome. The real tool image is used so that the
    refusal can only be the network one (a wrong image would also be refused at start, for an
    unrelated reason), and the daemon's own explanation -- logged for the operator, never put in
    the audit trail -- is asserted to say so."""
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.84.0.5"}},
        authorization={"source": "engagement_scope", "scope_object_id": world["scope_id"]},
        discovery={"source": "explicit_scope"},
    )
    with caplog.at_level("WARNING", logger="cyberorch.sandbox"):
        outcome = propose_action(
            engagement_id=world["engagement_id"], proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="w",
            sandbox=DockerSandbox(), network_allowlist=["10.84.0.5/32"],
        )
    assert any("failed to set up container networking" in r.getMessage() for r in caplog.records)
    assert outcome.failure == "container_start_refused" and outcome.run_id is None
    proposal_row, runs, events, evidence = recorded(world)
    assert proposal_row["dispatch_state"] == "failed", proposal_row
    assert (proposal_row["pipeline_stage"], proposal_row["stage_detail"]) == (
        "closed", "container_start_refused")
    assert runs == ["failed"] and evidence == 0
    assert "tool_run.unknown_outcome" not in [e[0] for e in events]
    refused = next(e for e in events if e[0] == "tool_run.refused")
    assert refused[1] == ["sandbox_not_started", "container_start_refused"]
    with engagement_scope(world["engagement_id"]) as conn:
        assert reconcile_stale_dispatches(
            conn, engagement_id=world["engagement_id"], older_than_seconds=0,
            actor="sweeper") == [], "nothing is left for the reconciler"


class _FakeContainer:
    """Just enough container for DockerSandbox._start_container."""

    short_id = "fake"

    def __init__(self, state, *, reload_error=None):
        self.attrs = {"State": state}
        self._reload_error = reload_error

    def start(self):
        raise docker.errors.APIError("daemon said no", explanation="start failed")

    def reload(self):
        if self._reload_error:
            raise self._reload_error


NEVER = {"Status": "created", "Running": False, "Pid": 0, "StartedAt": "0001-01-01T00:00:00Z"}


def test_a_refusal_is_typed_only_on_proof_the_container_never_ran():
    with pytest.raises(ContainerStartRefused):
        DockerSandbox._start_container(_FakeContainer(NEVER))

    for state in (
        {**NEVER, "Status": "running", "Running": True, "Pid": 4242,
         "StartedAt": "2026-10-08T03:00:00Z"},                       # it did run
        {**NEVER, "Status": "exited", "StartedAt": "2026-10-08T03:00:00Z"},   # ran and ended
        {**NEVER, "Pid": 77},                                         # a process existed
    ):
        with pytest.raises(docker.errors.APIError):
            DockerSandbox._start_container(_FakeContainer(state))


def test_a_refusal_whose_inspection_fails_stays_unplaced():
    """If Docker cannot be asked what happened, nothing is proven: the original error propagates
    (the proposal stays ``dispatching``, the reconciler's) rather than "not started"."""
    box = _FakeContainer(NEVER, reload_error=docker.errors.DockerException("daemon went away"))
    with pytest.raises(docker.errors.APIError):
        DockerSandbox._start_container(box)
