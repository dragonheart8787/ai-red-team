"""Two dispatches for one allowlist can race on creating its network (ACCEPTANCE 5.108).

``DockerSandbox.ensure_network`` is ``networks.get`` and, on ``NotFound``, ``networks.create``; a
second creator that arrives between the two gets Docker's 409 ("network with name ... already
exists"). What the product promises about that loser, and what these tests pin:

* it is refused with a **typed ``NotStarted``** -- ``NetworkNotAvailable``, reason
  ``network_unavailable`` -- before any container of the run exists, so the outcome is *known* (the
  run failed and never ran), never ``unknown_outcome``;
* it is **retryable**: the same request, made again, goes through once the network is there;
* on a real daemon, with the two creators released together, every outcome is one of "has the
  network" or "``NetworkNotAvailable``" -- never another exception -- 40 times over; and a retry
  of every loser succeeds.

The race itself is not removed (the loser is refused, as designed in D58-7); it is shown to be a
refusal and not a loss.
"""

from __future__ import annotations

import threading

import docker
import pytest
import requests
from docker.errors import APIError, NotFound
from sqlalchemy import text

from tests.helpers import committing_scope as engagement_scope
from tests.test_sandbox_not_started import CIDR, _GoodSandbox, go, recorded, world  # noqa: F401
from tool_gateway.sandbox import DockerSandbox, NetworkNotAvailable, NotStarted

ROUNDS = 40


def _conflict() -> APIError:
    response = requests.Response()
    response.status_code = 409
    return APIError("409 Client Error: Conflict", response,
                    "network with name cyberorch-allow-x already exists")


class _LosesTheRace:
    """The real client, except that the network is not there to be got and cannot be created."""

    def __init__(self, real):
        self._real = real
        self.created_containers = 0

        class Networks:
            def get(self, name):
                raise NotFound("no such network")

            def create(self, *args, **kwargs):
                raise _conflict()

        self.networks = Networks()

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_the_loser_of_the_race_is_a_typed_not_started_refusal_with_a_stable_reason():
    box = DockerSandbox()
    box._client = _LosesTheRace(docker.from_env())
    with pytest.raises(NetworkNotAvailable) as refused:
        box.ensure_network(["10.99.77.0/29"])
    assert isinstance(refused.value, NotStarted)
    assert refused.value.reason == "network_unavailable"
    assert "10.99.77.0/29" in str(refused.value) or "cyberorch-allow" in str(refused.value)


def test_through_propose_action_it_is_failed_closed_and_never_unknown_outcome(world):  # noqa: F811
    box = DockerSandbox()
    box._client = _LosesTheRace(docker.from_env())
    outcome = go(world, box)
    assert outcome.decision == "ALLOW" and outcome.run_id is None
    assert outcome.failure == "network_unavailable"
    proposal, runs, events, evidence = recorded(world)
    assert proposal["dispatch_state"] == "failed"
    assert (proposal["pipeline_stage"], proposal["stage_detail"]) == (
        "closed", "network_unavailable")
    assert runs == ["failed"] and evidence == 0
    assert "tool_run.unknown_outcome" not in [e[0] for e in events]
    with engagement_scope(world["engagement_id"]) as conn:
        code = conn.execute(text("SELECT refusal_code FROM tool_runs")).scalar_one()
    assert code == "network_unavailable"                     # (0025: it never ran)


def test_the_same_request_goes_through_after_a_refusal(world):  # noqa: F811
    box = DockerSandbox()
    box._client = _LosesTheRace(docker.from_env())
    assert go(world, box).failure == "network_unavailable"
    good = _GoodSandbox()
    again = go(world, good)
    assert again.executed and good.calls == 1


def test_on_a_real_daemon_two_creators_released_together_are_never_anything_but_a_refusal():
    real = docker.from_env()
    real.ping()
    outcomes: list[str] = []
    losers_retried = 0
    for round_ in range(ROUNDS):
        allowlist = [f"10.{60 + round_ // 200}.{(round_ % 200) + 20}.0/29"]
        boxes = [DockerSandbox(), DockerSandbox()]
        results: list[object] = [None, None]
        barrier = threading.Barrier(2)

        def creator(i, boxes=boxes, results=results, barrier=barrier, allowlist=allowlist):
            barrier.wait()
            try:
                results[i] = boxes[i].ensure_network(allowlist)
            except NetworkNotAvailable as exc:
                results[i] = exc
            except BaseException as exc:  # noqa: BLE001
                results[i] = exc

        threads = [threading.Thread(target=creator, args=(i,)) for i in (0, 1)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        try:
            for result in results:
                if isinstance(result, NetworkNotAvailable):
                    outcomes.append("refused")
                    assert isinstance(result, NotStarted) and result.reason == "network_unavailable"
                    retry = boxes[0].ensure_network(allowlist)         # retryable
                    assert retry is not None
                    losers_retried += 1
                else:
                    assert not isinstance(result, BaseException), (round_, repr(result))
                    outcomes.append("has the network")
        finally:
            name = boxes[0].network_name(allowlist)
            try:
                real.networks.get(name).remove()
            except NotFound:
                pass
    assert len(outcomes) == 2 * ROUNDS
    assert losers_retried == outcomes.count("refused")
    print(f"\nreal race: {outcomes.count('refused')} of {ROUNDS} rounds had a loser")
