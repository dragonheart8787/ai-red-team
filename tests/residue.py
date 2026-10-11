"""What a test session must not leave behind (D63).

A suite that leaves state behind makes the next run depend on the last one: a global ``DENY``
overlay made every scheduler test fail on a second local run (D63 closeout 2); a graph fixture
that was never taken back grew the tables until the planner changed its mind about a query
(ACCEPTANCE 5.23); Docker networks of earlier sessions were still there days later. CI starts empty
and never sees any of it.

Three kinds of thing are compared, **before** the session and **after** it:

* **global policy layers** -- an active layer with no engagement applies to every engagement, so
  one left active is the worst kind of residue. Not cleaned up: the test that published it is
  wrong, and the run fails so that it is found;
* **containers** -- any container, running or not, that did not exist at the start. Not cleaned up,
  for the same reason;
* **networks** -- ``cyberorch-*`` networks that did not exist at the start. The sandbox keeps one
  network per allowlist and removes it only on request (``remove_network``, ADR D58-13): it is
  designed to persist, so a test that makes a sandbox run leaves one. Those are removed here, and
  counted, and the run fails only if one cannot be removed (something is still attached to it).

What was there *before* the session is never touched: a development database keeps its real
baseline, and a Docker host keeps its other containers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import text

from control_plane.state.db import global_policy_admin_scope

NETWORK_PREFIX = "cyberorch-"


@dataclass(frozen=True)
class Snapshot:
    layers: frozenset[int]
    containers: frozenset[str] | None            # None: no Docker daemon to look at
    networks: frozenset[str] | None


@dataclass
class Leftovers:
    layers: list[tuple[int, str, int]] = field(default_factory=list)      # (id, layer, version)
    containers: list[str] = field(default_factory=list)                   # "name (id) status"
    networks_removed: list[str] = field(default_factory=list)
    networks_stuck: list[str] = field(default_factory=list)

    def failures(self) -> list[str]:
        out = []
        if self.layers:
            out.append(f"active policy layers with no engagement left behind: {self.layers}")
        if self.containers:
            out.append(f"containers left behind: {self.containers}")
        if self.networks_stuck:
            out.append(f"networks that could not be removed (something is attached): "
                       f"{self.networks_stuck}")
        return out


def _docker():
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return client
    except Exception:
        return None


def _active_unbound_layers() -> list[tuple[int, str, int]]:
    """Active layers that are not an engagement's own: the global ones and each customer's."""
    with global_policy_admin_scope() as conn:
        return [tuple(r) for r in conn.execute(text(
            "SELECT id, layer, version FROM policy_layers "
            "WHERE engagement_id IS NULL AND active IS TRUE ORDER BY id")).all()]


def snapshot() -> Snapshot:
    client = _docker()
    return Snapshot(
        layers=frozenset(row[0] for row in _active_unbound_layers()),
        containers=None if client is None else frozenset(
            c.id for c in client.containers.list(all=True)),
        networks=None if client is None else frozenset(
            n.name for n in client.networks.list() if n.name.startswith(NETWORK_PREFIX)),
    )


def leftovers(before: Snapshot) -> Leftovers:
    """Compare with ``before``; remove the sandbox networks the session made and say which."""
    found = Leftovers(layers=[
        row for row in _active_unbound_layers() if row[0] not in before.layers])
    client = _docker()
    if client is None or before.containers is None:
        return found
    found.containers = [f"{c.name} ({c.short_id}) {c.status}"
                        for c in client.containers.list(all=True) if c.id not in before.containers]
    for network in client.networks.list():
        if network.name.startswith(NETWORK_PREFIX) and network.name not in (before.networks or ()):
            try:
                network.remove()
                found.networks_removed.append(network.name)
            except Exception:
                found.networks_stuck.append(network.name)
    return found
