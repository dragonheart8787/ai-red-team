"""The end-of-session residue check (tests/residue.py) sees what it is there to see (D63).

A check that has never been shown to fail is a claim. Each kind of residue is created for real --
a global layer on the real database, a container and a network on the real daemon -- and the
comparison against a snapshot taken before is shown to report it; then everything is taken back,
and a snapshot compared with itself is clean.
"""

from __future__ import annotations

import uuid

import pytest

from tests import residue
from tests.helpers import deactivate_global_layer, publish_global_layer

docker = pytest.importorskip("docker")

#: Any image with ``sleep`` will do. CI has this one (the Semgrep and BloodHound image builds pull
#: it); a workstation has it from the same builds. Pulled if missing, and a failure to get it fails
#: the test -- a residue check that could not create the residue has shown nothing.
BASE_IMAGE = "python:3.12-slim"


@pytest.fixture
def client(db_available):
    c = residue._docker()
    if c is None:
        pytest.skip("no Docker daemon")
    try:
        c.images.get(BASE_IMAGE)
    except docker.errors.ImageNotFound:
        try:
            c.images.pull(BASE_IMAGE)
        except docker.errors.DockerException as exc:
            pytest.fail(f"{BASE_IMAGE} is neither present nor pullable: {exc}")
    return c


def test_a_snapshot_compared_with_itself_is_clean(client):
    before = residue.snapshot()
    found = residue.leftovers(before)
    assert found.failures() == [] and found.networks_removed == []


def test_an_active_global_layer_is_residue_and_is_not_cleaned_up(db_available):
    before = residue.snapshot()
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    try:
        found = residue.leftovers(before)
        assert [row[0] for row in found.layers] == [layer_id]
        assert found.failures() and "policy layers" in found.failures()[0]
    finally:
        deactivate_global_layer(layer_id)
    assert residue.leftovers(before).layers == []                # retired: no longer residue


def test_a_retired_global_layer_is_not_residue(db_available):
    before = residue.snapshot()
    layer_id = publish_global_layer(
        layer="emergency_overlay", version=uuid.uuid4().int % 2_000_000_000, document={})
    deactivate_global_layer(layer_id)
    assert residue.leftovers(before).failures() == []


def test_a_container_is_residue_even_if_it_never_started(client):
    before = residue.snapshot()
    container = client.containers.create(BASE_IMAGE, name=f"residue-{uuid.uuid4().hex[:8]}")
    try:
        found = residue.leftovers(before)
        assert any(container.name in entry for entry in found.containers)
        assert found.failures() and "containers" in found.failures()[0]
    finally:
        container.remove(force=True)
    assert residue.leftovers(before).containers == []


def test_a_sandbox_network_is_removed_and_counted_not_failed(client):
    before = residue.snapshot()
    name = f"cyberorch-allow-residue{uuid.uuid4().hex[:6]}"
    client.networks.create(name)
    try:
        found = residue.leftovers(before)
        assert found.networks_removed == [name] and found.failures() == []
    finally:
        for n in client.networks.list(names=[name]):
            n.remove()
    assert not client.networks.list(names=[name])


def test_a_network_with_something_attached_is_a_failure(client):
    before = residue.snapshot()
    name = f"cyberorch-allow-residue{uuid.uuid4().hex[:6]}"
    network = client.networks.create(name)
    container = client.containers.run(BASE_IMAGE, ["sleep", "60"], detach=True,
                                      name=f"residue-{uuid.uuid4().hex[:8]}", network=name)
    try:
        found = residue.leftovers(before)
        assert found.networks_stuck == [name]
        assert any("could not be removed" in f for f in found.failures())
    finally:
        container.remove(force=True)
        network.remove()
