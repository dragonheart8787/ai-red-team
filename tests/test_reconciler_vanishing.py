"""An object that is gone between two calls is gone; a daemon that does not answer is lost (5.107).

The soak's first pilots stopped the reconciler with exit 5, "Docker unreachable", while the daemon
was healthy: a container removed between the two calls a listing is made of (the daemon's list of
ids, then an inspect of each) raised ``NotFound``, and ``service._translate`` took every
``DockerException`` for a lost daemon. The rule, now stated in ``_translate`` and pinned here:

* ``NotFound`` (HTTP 404) for an object whose id we hold -- *that object is gone*; handled where the
  call is made (a listing drops it, an action says ``gone``), never an exit;
* the daemon refuses the connection, resets it, or times out; an HTTP answer of 5xx; an error of
  the SDK that carries no HTTP answer -- *the daemon is lost*, ``docker_lost``, exit 5;
* an HTTP answer of 4xx that reaches the top -- *the daemon is there and this is a defect*,
  ``unexpected_error``, exit 1.

Both sides on a real daemon. *Gone:* for each place that reads Docker and then asks about what it
found, the object is removed **between the two calls, deterministically, 40 times** (the SDK's own
inspect is made to find the object already removed by Docker itself, so the ``NotFound`` is
Docker's); the read returns what is left and does not raise. *Lost:* a client pointed at a port
nothing listens on, the SDK's real connection error, through the reconciler's own ``serve``, ends
with exit 5.
"""

from __future__ import annotations

import os
import tempfile
import threading
import uuid

import docker
import pytest
import requests
from docker.errors import APIError, DockerException, NotFound
from docker.models.containers import ContainerCollection
from docker.models.networks import NetworkCollection

from control_plane.reconciler import act_docker, emit, observe
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.service import Reconciler, _translate
from control_plane.scheduler.lock import SingletonLock
from tests.test_reconciler_concurrency import TH
from tool_gateway.sandbox import DockerSandbox

ROUNDS = 40
IMAGE = "python:3.12-slim"
DEAD = "tcp://127.0.0.1:1"          # nothing listens here


def _api_error(status: int) -> APIError:
    response = requests.Response()
    response.status_code = status
    return APIError(f"{status}", response, "explanation")


# ---------------------------------------------------------------------------------------------
# the rule
# ---------------------------------------------------------------------------------------------

def _not_found() -> NotFound:
    return NotFound("No such container", _api_error(404))


RULE = [
    ("a container that is not there", _not_found(), emit.STOP_UNEXPECTED, 1),
    ("a conflict the daemon answered", _api_error(409), emit.STOP_UNEXPECTED, 1),
    ("a bad request the daemon answered", _api_error(400), emit.STOP_UNEXPECTED, 1),
    ("a server error of the daemon", _api_error(500), emit.STOP_DOCKER_LOST, 5),
    ("a bad gateway", _api_error(502), emit.STOP_DOCKER_LOST, 5),
    ("the connection refused", requests.exceptions.ConnectionError("refused"),
     emit.STOP_DOCKER_LOST, 5),
    ("a read that timed out", requests.exceptions.ReadTimeout("slow"), emit.STOP_DOCKER_LOST, 5),
    ("the SDK found no daemon to ask",
     DockerException("Error while fetching server API version"), emit.STOP_DOCKER_LOST, 5),
    ("a socket that is not there", ConnectionRefusedError(111, "refused"),
     emit.STOP_DOCKER_LOST, 5),
]


@pytest.mark.parametrize("what, exc, reason, code", RULE, ids=[r[0] for r in RULE])
def test_the_classification_rule(what, exc, reason, code):
    stop = _translate(exc)
    assert (stop.reason, stop.exit_code) == (reason, code), what


def test_a_notfound_is_a_defect_if_it_reaches_the_top_never_a_lost_daemon():
    assert isinstance(_not_found(), DockerException)                    # that was the bug
    assert _translate(_not_found()).reason != emit.STOP_DOCKER_LOST


# ---------------------------------------------------------------------------------------------
# lost: a real client, a real connection error
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def real():
    c = docker.from_env()
    try:
        c.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"Docker is required for this test: {exc}")
    return c


def dead_client() -> docker.DockerClient:
    # (an explicit API version skips the probe a constructor would make)
    return docker.DockerClient(base_url=DEAD, version="1.43", timeout=3)


def test_lost_every_read_of_a_daemon_that_is_not_there_is_docker_lost():
    client = dead_client()
    for read in (observe.list_containers, observe.list_networks, observe.live_mount_sources,
                 act_docker.live_mount_sources):
        with pytest.raises(Exception) as raised:  # noqa: B017 -- what it is is the point
            read(client)
        stop = _translate(raised.value)
        assert (stop.reason, stop.exit_code) == (emit.STOP_DOCKER_LOST, 5), (read, raised.value)


def test_lost_the_reconcilers_own_serve_ends_with_exit_5_when_the_daemon_is_gone(engagement_id):
    r = Reconciler(settings=Settings(Mode.STATE_ONLY), th=TH, client=dead_client(),
                   directory=tempfile.gettempdir(), expected_uid=os.getuid(),
                   lock=SingletonLock(), watchdog_interval=0.2,
                   only_engagements=frozenset({engagement_id}))
    assert r.serve(interval=1, max_passes=1, stop_event=threading.Event()) == 5


# ---------------------------------------------------------------------------------------------
# gone: 40 deterministic races per place that reads and then asks
# ---------------------------------------------------------------------------------------------

class Remover:
    """Make Docker itself answer ``NotFound`` to the SDK's inspect of ``victims``: the first time an
    inspect of one of them is asked, it is removed (by another connection) just before."""

    def __init__(self, monkeypatch, victims: set[str]):
        self.victims, self.removed = set(victims), []
        other = docker.from_env()
        real_get = ContainerCollection.get
        owner = self

        def get(collection, container_id):
            if container_id in owner.victims:
                owner.victims.discard(container_id)
                other.containers.get(container_id).remove(force=True)
                owner.removed.append(container_id)
            return real_get(collection, container_id)

        monkeypatch.setattr(ContainerCollection, "get", get)


def make(client, made, *, mount: str | None = None, network: str | None = None):
    kwargs = {}
    if mount:
        kwargs["volumes"] = {mount: {"bind": "/probe", "mode": "ro"}}
    if network:
        kwargs["network"] = network
    c = client.containers.create(
        IMAGE, command=["true"], labels={"cyberorch.run_id": f"RUN-{uuid.uuid4().hex[:8]}",
                                         "cyberorch.owner": "ENG-VANISH"}, **kwargs)
    made.append(c)
    return c


@pytest.fixture
def made(real):
    items: list = []
    yield items
    for item in items:
        try:
            item.remove(force=True)
        except (NotFound, APIError):
            pass


def test_gone_a_container_removed_between_the_list_and_the_inspect_is_not_listed_40_times(
        real, made, monkeypatch):
    for _ in range(ROUNDS):
        victim, survivor = make(real, made), make(real, made)
        remover = Remover(monkeypatch, {victim.id})
        seen = {o.container_id for o in observe.list_containers(real)}
        assert remover.removed == [victim.id], "the race did not happen"
        assert victim.id not in seen and survivor.id in seen
        monkeypatch.undo()
        survivor.remove(force=True)


@pytest.mark.parametrize("reader", [observe.live_mount_sources, act_docker.live_mount_sources],
                         ids=["observe", "act_docker"])
def test_gone_a_container_removed_while_mount_sources_are_read_is_not_a_mount_40_times(
        real, made, monkeypatch, tmp_path, reader):
    for i in range(ROUNDS):
        gone_file, kept_file = tmp_path / f"gone{i}", tmp_path / f"kept{i}"
        gone_file.write_text("x")
        kept_file.write_text("x")
        victim = make(real, made, mount=str(gone_file))
        survivor = make(real, made, mount=str(kept_file))
        remover = Remover(monkeypatch, {victim.id})
        sources = reader(real)
        assert remover.removed == [victim.id]
        assert str(kept_file) in sources and str(gone_file) not in sources
        monkeypatch.undo()
        survivor.remove(force=True)


def make_network(client, made_networks):
    net = client.networks.create(f"cyberorch-allow-{uuid.uuid4().hex[:12]}", internal=True,
                                 labels={"cyberorch.allowlist": "10.98.0.0/29"})
    made_networks.append(net)
    return net


def test_gone_a_network_removed_between_the_list_and_its_inspect_is_not_listed_40_times(
        real, monkeypatch):
    nets: list = []
    real_list = NetworkCollection.list
    try:
        for _ in range(ROUNDS):
            victim, survivor = make_network(real, nets), make_network(real, nets)

            def list_then_remove(collection, *args, victim=victim, **kwargs):
                found = real_list(collection, *args, **kwargs)
                # (after the list, before the inspect)
                docker.from_env().networks.get(victim.id).remove()
                return found

            monkeypatch.setattr(NetworkCollection, "list", list_then_remove)
            listed = {n.network_id for n in observe.list_networks(real)}
            monkeypatch.undo()
            assert victim.id not in listed and survivor.id in listed
            survivor.remove()
    finally:
        for net in nets:
            try:
                net.remove()
            except (NotFound, APIError):
                pass


def test_gone_a_container_attached_to_a_network_that_vanishes_while_its_members_are_read_40_times(
        real, made, monkeypatch):
    nets: list = []
    try:
        for _ in range(ROUNDS):
            net = make_network(real, nets)
            victim = make(real, made, network=net.name)
            survivor = make(real, made, network=net.name)
            remover = Remover(monkeypatch, {victim.id})
            listed = {n.network_id: n for n in observe.list_networks(real)}
            assert remover.removed == [victim.id]
            attached = {c.container_id for c in listed[net.id].attached}
            assert attached == {survivor.id}
            monkeypatch.undo()
            survivor.remove(force=True)
            net.remove()
    finally:
        for net in nets:
            try:
                net.remove()
            except (NotFound, APIError):
                pass


def test_gone_a_container_that_vanishes_while_the_sandbox_checks_exclusivity_40_times(
        real, made, monkeypatch):
    """``DockerSandbox._assert_exclusive`` lists the containers of other owners on a network and
    inspects each; one that is removed in between is not on the network."""
    nets: list = []
    box = DockerSandbox()
    try:
        for _ in range(ROUNDS):
            net = make_network(real, nets)
            mine = real.containers.create(IMAGE, command=["true"], network=net.name,
                                          labels={"cyberorch.run_id": "R", "cyberorch.owner": "A"})
            other = real.containers.create(IMAGE, command=["true"], network=net.name,
                                           labels={"cyberorch.run_id": "S", "cyberorch.owner": "B"})
            made.extend([mine, other])
            real_list = ContainerCollection.list
            removed = []

            def list_then_remove(collection, *args, other=other, real_list=real_list,
                                 removed=removed, **kwargs):
                found = real_list(collection, *args, **kwargs)
                docker.from_env().containers.get(other.id).remove(force=True)   # after the list
                removed.append(other.id)
                return found

            monkeypatch.setattr(ContainerCollection, "list", list_then_remove)
            mine.reload()
            box._assert_exclusive(mine, [net.name], "A")           # must not raise NotFound
            assert removed == [other.id]
            monkeypatch.undo()
            mine.remove(force=True)
            net.remove()
    finally:
        for net in nets:
            try:
                net.remove()
            except (NotFound, APIError):
                pass


def test_gone_a_container_on_a_network_that_vanishes_while_the_network_is_removed_40_times(
        real, made, monkeypatch):
    """``act_docker._remove_network`` refuses a network that has a container of any state on it;
    one that is removed while that is looked at is not on it, and the network goes."""
    from control_plane.reconciler import act
    from control_plane.reconciler.outcome import DONE
    from tests.test_reconciler_act import DELETIONS, net_action

    nets: list = []
    try:
        for _ in range(ROUNDS):
            net = make_network(real, nets)
            net.reload()
            victim = make(real, made, network=net.name)
            remover = Remover(monkeypatch, {victim.id})
            result = act.carry_out([net_action(net)], DELETIONS, th=TH, client=real)[0]
            assert remover.removed == [victim.id]
            assert (result.outcome, result.detail) == (DONE, None), result
            monkeypatch.undo()
    finally:
        for net in nets:
            try:
                net.remove()
            except (NotFound, APIError):
                pass
