"""Someone else moved first: a proxy, a file and a network, forty times each (pre-deletion item 4;
ACCEPTANCE 5.90).

The control plane tears down what it made -- a proxy container (``remove(force=True)``), a network
(``remove_network``) -- and a temporary file may be unlinked by whoever made it. The reconciler
plans from a listing that is up to a minute old, so by the time it acts the object may already be
gone, or may go at the very moment it acts. The rule is the same for all three: **an object that is
gone is ``gone`` (or ``done``, if the reconciler's own call removed it) -- never ``failed``**,
because a failure writes an ``action_failed`` event, holds the object back for
``retry_after_failure_s`` and would be a lie about something that simply no longer exists.

Each object is shown two ways, 40 rounds each, on a real Docker daemon and the real filesystem:

* **after** -- the other party finishes first, then the reconciler acts on its stale plan;
* **during** -- both start together on a barrier, and the round ends in whichever order it ends in.

Forty real rounds did not reach two branches that exist: a file that vanishes between ``lstat`` and
``unlink`` (``FileNotFoundError``, classified ``failed / file_error``), and a network whose removal
Docker refused because someone else was removing it (``failed / in_use``, a false claim that
something is attached). The ``scripted`` tests pin each branch deterministically -- found by writing
them, fixed in ``act_files`` and ``act_docker``; ``D64-P7-f`` was likewise missed by 12 real rounds.
"""

from __future__ import annotations

import os
import threading
import uuid
from types import SimpleNamespace

import docker
import pytest
from docker.errors import APIError, NotFound

from control_plane.reconciler import act, vocab
from control_plane.reconciler.act import Mode, Settings
from control_plane.reconciler.model import Action
from control_plane.reconciler.outcome import CHANGED, DONE, FAILED, GONE
from tests.test_reconciler_act import DELETIONS, TH, kill_action, net_action
from tests.test_reconciler_concurrency import labelled, run_threads

ROUNDS = 40


@pytest.fixture
def docker_client():
    c = docker.from_env()
    try:
        c.ping()
    except Exception as exc:                                         # noqa: BLE001
        pytest.fail(f"Docker is required for this test: {exc}")
    return c


@pytest.fixture
def made():
    things: list = []
    yield things
    for thing in things:
        try:
            thing.remove(force=True) if hasattr(thing, "attrs") and "State" in thing.attrs \
                else thing.remove()
        except (NotFound, APIError):
            pass


def carry_out(action, *, client=None, directory=None, uid=None):
    return act.carry_out([action], DELETIONS, th=TH, client=client or docker.from_env(),
                         directory=directory, expected_uid=uid)[0]


def summary(outcomes):
    from collections import Counter
    return dict(Counter(outcomes))


# ---------------------------------------------------------------------------------------------
# a proxy
# ---------------------------------------------------------------------------------------------

def test_proxy_the_control_plane_removed_it_first_40_times_each_is_gone(docker_client, made):
    outcomes = []
    for _ in range(ROUNDS):
        proxy = labelled(docker_client, made, proxy=True)
        action = kill_action(proxy, kind=vocab.REMOVE_PROXY, reason=vocab.OWNER_RUN_ENDED)
        proxy.remove(force=True)                       # the control plane's teardown, first
        result = carry_out(action, client=docker_client)
        outcomes.append((result.outcome, result.detail))
    assert outcomes == [(GONE, None)] * ROUNDS, summary(outcomes)


def test_proxy_both_at_once_40_times_is_never_a_failure(docker_client, made):
    outcomes = []
    for _ in range(ROUNDS):
        proxy = labelled(docker_client, made, proxy=True)
        action = kill_action(proxy, kind=vocab.REMOVE_PROXY, reason=vocab.OWNER_RUN_ENDED)
        barrier, box = threading.Barrier(2), {}

        def reconciler_side(action=action, barrier=barrier, box=box):
            barrier.wait(10)
            box["r"] = carry_out(action)

        def control_plane_side(proxy_id=proxy.id, barrier=barrier):
            barrier.wait(10)
            try:
                docker.from_env().containers.get(proxy_id).remove(force=True)
            except (NotFound, APIError):
                pass

        run_threads(reconciler_side, control_plane_side)
        outcomes.append(box["r"].outcome)
        with pytest.raises(NotFound):
            docker_client.containers.get(proxy.id)
    assert set(outcomes) <= {DONE, GONE}, summary(outcomes)


# ---------------------------------------------------------------------------------------------
# a file
# ---------------------------------------------------------------------------------------------

def old_file(directory, name=None) -> str:
    name = name or f"cyberorch-cred-{uuid.uuid4().hex[:8]}"
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        handle.write("x")
    os.utime(path, (1, 1))                             # long past B_cap + P + Q
    return name


def file_action(directory, name) -> Action:
    return Action(kind=vocab.UNLINK_FILE, reason_code="credential_mount", subject_id=name,
                  name=name, directory=directory)


class NoMounts:
    containers = SimpleNamespace(list=lambda **kw: [])


def sweep(directory, name):
    return act.carry_out([file_action(directory, name)], DELETIONS, th=TH, client=NoMounts(),
                         directory=directory, expected_uid=os.getuid())[0]


def test_file_the_owner_unlinked_it_first_40_times_each_is_gone(tmp_path):
    outcomes = []
    for _ in range(ROUNDS):
        name = old_file(tmp_path)
        action = file_action(str(tmp_path), name)
        os.unlink(tmp_path / name)                     # whoever made it, first
        outcomes.append(act.carry_out([action], DELETIONS, th=TH, client=NoMounts(),
                                      directory=str(tmp_path), expected_uid=os.getuid())[0].outcome)
    assert outcomes == [GONE] * ROUNDS, summary(outcomes)


def test_file_both_at_once_40_times_is_never_a_failure(tmp_path):
    outcomes = []
    for _ in range(ROUNDS):
        name = old_file(tmp_path)
        action = file_action(str(tmp_path), name)
        barrier, box = threading.Barrier(2), {}

        def reconciler_side(action=action, barrier=barrier, box=box):
            barrier.wait(10)
            box["r"] = act.carry_out([action], DELETIONS, th=TH, client=NoMounts(),
                                     directory=str(tmp_path), expected_uid=os.getuid())[0]

        def owner_side(name=name, barrier=barrier):
            barrier.wait(10)
            try:
                os.unlink(tmp_path / name)
            except FileNotFoundError:
                pass

        run_threads(reconciler_side, owner_side)
        outcomes.append(box["r"].outcome)
        assert not (tmp_path / name).exists()
    assert set(outcomes) <= {DONE, GONE}, summary(outcomes)


def test_file_scripted_the_name_vanishes_between_the_look_and_the_unlink(tmp_path, monkeypatch):
    """The branch a real race reaches only sometimes: ``lstat`` saw the file, the owner unlinks it,
    and ``unlink`` finds nothing."""
    name = old_file(tmp_path)
    real = os.unlink

    def the_owner_got_there_first(path, *, dir_fd=None):
        real(path, dir_fd=dir_fd)
        raise FileNotFoundError(path)

    monkeypatch.setattr("control_plane.reconciler.act_files.os.unlink", the_owner_got_there_first)
    result = sweep(str(tmp_path), name)
    assert (result.outcome, result.detail) == (GONE, None)


def test_file_scripted_a_real_failure_to_unlink_is_still_a_failure(tmp_path, monkeypatch):
    name = old_file(tmp_path)

    def refused(path, *, dir_fd=None):
        raise PermissionError(path)

    monkeypatch.setattr("control_plane.reconciler.act_files.os.unlink", refused)
    result = sweep(str(tmp_path), name)
    assert (result.outcome, result.detail) == (FAILED, "file_error")


def test_file_a_file_that_was_replaced_by_something_else_is_not_removed(tmp_path):
    """Someone else moved first and put something there: not a regular file, so not ours."""
    name = old_file(tmp_path)
    action = file_action(str(tmp_path), name)
    os.unlink(tmp_path / name)
    os.mkdir(tmp_path / name)
    result = act.carry_out([action], DELETIONS, th=TH, client=NoMounts(),
                           directory=str(tmp_path), expected_uid=os.getuid())[0]
    assert (result.outcome, result.detail) == (CHANGED, "not_a_regular_file")
    assert (tmp_path / name).is_dir()


# ---------------------------------------------------------------------------------------------
# a network
# ---------------------------------------------------------------------------------------------

def make_network(client, made):
    net = client.networks.create(f"cyberorch-allow-{uuid.uuid4().hex[:12]}", internal=True,
                                 labels={"cyberorch.allowlist": "10.98.0.0/29"})
    made.append(net)
    net.reload()
    return net


def test_network_the_control_plane_removed_it_first_40_times_each_is_gone(docker_client, made):
    outcomes = []
    for _ in range(ROUNDS):
        net = make_network(docker_client, made)
        action = net_action(net)
        net.remove()                                   # DockerSandbox.remove_network, first
        result = carry_out(action, client=docker_client)
        outcomes.append((result.outcome, result.detail))
    assert outcomes == [(GONE, None)] * ROUNDS, summary(outcomes)


def test_network_both_at_once_40_times_is_never_a_failure(docker_client, made):
    outcomes = []
    for _ in range(ROUNDS):
        net = make_network(docker_client, made)
        action = net_action(net)
        barrier, box = threading.Barrier(2), {}

        def reconciler_side(action=action, barrier=barrier, box=box):
            barrier.wait(10)
            box["r"] = carry_out(action)

        def control_plane_side(net_id=net.id, barrier=barrier):
            barrier.wait(10)
            try:
                docker.from_env().networks.get(net_id).remove()
            except (NotFound, APIError):
                pass

        run_threads(reconciler_side, control_plane_side)
        outcomes.append((box["r"].outcome, box["r"].detail))
        with pytest.raises(NotFound):
            docker_client.networks.get(net.id)
    assert not [o for o in outcomes if o[0] == FAILED], summary(outcomes)
    assert {o[0] for o in outcomes} <= {DONE, GONE}, summary(outcomes)


def test_network_a_network_re_created_under_the_same_name_is_not_touched(docker_client, made):
    """Someone else moved first and made a new one with the old name: by id, so nothing is done."""
    net = make_network(docker_client, made)
    action = net_action(net)
    name = net.name
    net.remove()
    newcomer = docker_client.networks.create(name, internal=True,
                                             labels={"cyberorch.allowlist": "10.98.0.8/29"})
    made.append(newcomer)
    result = carry_out(action, client=docker_client)
    assert result.outcome == GONE
    assert docker_client.networks.get(newcomer.id).name == name


class FakeNetwork:
    def __init__(self, *, remove_raises, vanished_after_remove):
        self.id, self.name = "a" * 64, "cyberorch-allow-aaaaaaaaaaaa"
        self.attrs = {"Labels": {"cyberorch.allowlist": "x"}}
        self._raises, self._vanished = remove_raises, vanished_after_remove
        self.removed = False

    def reload(self):
        pass

    def remove(self):
        if self._raises is not None:
            self.removed = self._vanished
            raise self._raises


class FakeNetworks:
    def __init__(self, network):
        self.network = network
        self.containers = SimpleNamespace(list=lambda **kw: [])
        self.networks = SimpleNamespace(get=self._get)

    def _get(self, _id):
        if self.network.removed:
            raise NotFound("gone")
        return self.network


def test_network_scripted_a_refusal_while_someone_else_removes_it_is_gone_not_in_use():
    """Docker answers the loser of a removal race with an error and the network is gone by the next
    look. Before the fix this was ``failed / in_use``: a false claim that something is attached."""
    network = FakeNetwork(remove_raises=APIError("being removed",
                                                 response=SimpleNamespace(status_code=403,
                                                                          reason="x", content=b"")),
                          vanished_after_remove=True)
    action = Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP,
                    subject_id=network.id, name=network.name)
    result = act.carry_out([action], Settings(Mode.STATE_ONLY, allow_deletions=True), th=TH,
                           client=FakeNetworks(network))[0]
    assert (result.outcome, result.detail) == (GONE, None)


def test_network_scripted_a_refusal_that_is_real_is_still_in_use():
    network = FakeNetwork(remove_raises=APIError("has active endpoints",
                                                 response=SimpleNamespace(status_code=403,
                                                                          reason="x", content=b"")),
                          vanished_after_remove=False)
    action = Action(kind=vocab.REMOVE_NETWORK, reason_code=vocab.IDLE_SWEEP,
                    subject_id=network.id, name=network.name)
    result = act.carry_out([action], Settings(Mode.STATE_ONLY, allow_deletions=True), th=TH,
                           client=FakeNetworks(network))[0]
    assert (result.outcome, result.detail) == (FAILED, "in_use")
