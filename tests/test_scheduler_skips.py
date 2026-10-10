"""What the scheduler does with an approved proposal it cannot run (D62, D58-1/D-9).

A *skip* leaves the proposal in ``approved`` -- the scheduler does not close it and does not touch
it -- so it is picked up again on every tick. That has two consequences these tests pin:

* the "still ``approved`` after ``dispatch_approved`` => stop the service (exit 7)" rule applies
  only to a proposal that was actually handed to ``dispatch_approved``; a skip never reaches it;
* a skip is recorded **once** (an audit event and a state row), not once per tick.

Then one test per way a network proposal can be un-runnable (design note §1): a ``cidr`` scope
narrower than the /29 Docker needs for a scanner plus a target; an ``ip`` scope (always skipped,
never widened); and a target that is the network, gateway or broadcast address of its block. The
last two are checked against a **real Docker daemon**: the premise ("no container can have that
address") is demonstrated there, and the scheduler is shown to leave the proposal alone without
creating a run, a capability, a container or a network.
"""

from __future__ import annotations

import uuid

import docker
import pytest
from docker.types import IPAMConfig, IPAMPool
from sqlalchemy import text

from control_plane.orchestrator import stages
from control_plane.scheduler import vocab
from control_plane.scheduler.service import Scheduler
from control_plane.state.db import scheduler_reader_scope
from tests import scheduler_support as sup
from tests.helpers import committing_scope
from tool_gateway.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxResult


class RecordingSandbox:
    """Stands in for the container and remembers what the dispatch asked of it."""

    def __init__(self):
        self.allowlists: list[list[str]] = []

    def run(self, **kwargs):
        self.allowlists.append(list(kwargs["network_allowlist"]))
        return SandboxResult(0, "Nmap done: 1 host up", "", False, 0.5,
                             tuple(kwargs["network_allowlist"]), "fake")

    @property
    def calls(self) -> int:
        return len(self.allowlists)


@pytest.fixture
def enrolled(engagement_id, registry):
    sup.publish_engagement_policy(engagement_id, actions=("network.scan", "web.get"))
    sup.enroll(engagement_id)
    yield engagement_id, registry
    sup.withdraw(engagement_id)


def _stage(eid, pid):
    with committing_scope(eid) as conn:
        return stages.stage_of(conn, pid)


def _state(eid, pid):
    with scheduler_reader_scope(eid) as conn:
        return conn.execute(text(
            "SELECT disposition, reason_code FROM scheduler_state WHERE proposal_id = :p"),
            {"p": pid}).one_or_none()


# ---------------------------------------------------------------------------------------------
# a skipped proposal and the "stop the service" rule do not interact
# ---------------------------------------------------------------------------------------------

def test_a_skipped_proposal_over_many_ticks_does_not_stop_the_service_and_is_recorded_once(
    enrolled,
):
    eid, registry = enrolled
    scope_id = sup.register_scope(registry, type="cidr", value="10.96.65.0/30")
    pid = sup.approved_proposal(eid, scope_id, host="10.96.65.2")
    sandbox = RecordingSandbox()

    sched = Scheduler(sandbox=sandbox, watchdog_interval=0.2)
    exit_code = sched.run(interval=0, max_ticks=12)

    assert exit_code == vocab.EXIT_OK          # twelve ticks, each of which found the proposal
    assert sandbox.calls == 0
    assert _stage(eid, pid)[0] == stages.APPROVED       # waiting, untouched, still approved
    (skipped,) = sup.audit(eid, "scheduler.skipped")
    assert skipped["payload"] == {"proposal_id": pid, "reason_code": vocab.SCOPE_TOO_NARROW}
    assert tuple(_state(eid, pid)) == (vocab.SKIPPED_STATE, vocab.SCOPE_TOO_NARROW)
    assert sup.audit(eid, "scheduler.dispatched", "scheduler.deferred") == []
    assert sup.rows(eid, "SELECT 1 FROM capabilities") == []


def test_a_skip_does_not_hide_a_dispatchable_proposal_beside_it(enrolled):
    """One un-runnable proposal does not block the one next to it, tick after tick."""
    eid, registry = enrolled
    narrow = sup.register_scope(registry, type="cidr", value="10.96.65.16/30")
    wide = sup.register_scope(registry, type="cidr", value="10.96.65.64/26")
    stuck = sup.approved_proposal(eid, narrow, host="10.96.65.18")
    fine = sup.approved_proposal(eid, wide, host="10.96.65.70")
    sandbox = RecordingSandbox()

    with sup.running(sandbox) as sched:
        first = sched.tick()
        second = sched.tick()

    assert (first.skipped, first.dispatched) == ([stuck], [fine])
    assert (second.skipped, second.dispatched) == ([], [])
    assert sandbox.allowlists == [["10.96.65.64/26"]]
    assert _stage(eid, stuck)[0] == stages.APPROVED
    assert _stage(eid, fine) == (stages.RECORDED, "succeeded")


def test_an_action_the_scheduler_does_not_dispatch_is_skipped_once_and_never_stops_it(enrolled):
    eid, registry = enrolled
    scope_id = sup.register_scope(registry, type="cidr", value="10.96.65.128/26",
                                  actions=("network.scan", "web.get"))
    pid = sup.approved_proposal(eid, scope_id, host="10.96.65.130", action="web.get")
    sched = Scheduler(sandbox=RecordingSandbox(), watchdog_interval=0.2)
    assert sched.run(interval=0, max_ticks=6) == vocab.EXIT_OK
    (skipped,) = sup.audit(eid, "scheduler.skipped")
    assert skipped["payload"]["reason_code"] == vocab.ACTION_NOT_SUPPORTED
    assert _stage(eid, pid)[0] == stages.APPROVED


# ---------------------------------------------------------------------------------------------
# tier 1 -- a cidr scope narrower than /29
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cidr,host,outcome", [
    ("10.96.66.0/30", "10.96.66.2", vocab.SCOPE_TOO_NARROW),
    ("10.96.66.8/31", "10.96.66.9", vocab.SCOPE_TOO_NARROW),
    ("10.96.66.16/32", "10.96.66.16", vocab.SCOPE_TOO_NARROW),
    ("10.96.66.24/29", "10.96.66.27", None),          # the boundary: /29 is the smallest that works
])
def test_a_cidr_scope_narrower_than_a_slash_29_is_skipped_and_a_slash_29_is_not(
    enrolled, cidr, host, outcome,
):
    eid, registry = enrolled
    scope_id = sup.register_scope(registry, type="cidr", value=cidr)
    pid = sup.approved_proposal(eid, scope_id, host=host)
    sandbox = RecordingSandbox()

    with sup.running(sandbox) as sched:
        report = sched.tick()

    if outcome:
        assert report.skipped == [pid] and report.dispatched == []
        assert tuple(_state(eid, pid)) == (vocab.SKIPPED_STATE, outcome)
        assert sandbox.calls == 0 and _stage(eid, pid)[0] == stages.APPROVED
    else:
        assert report.dispatched == [pid] and report.skipped == []
        assert sandbox.allowlists == [[cidr]]


# ---------------------------------------------------------------------------------------------
# tier 2 -- an ip scope (never dispatched)
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("address", ["10.96.67.9", "10.96.67.0", "10.96.67.20", "10.96.67.31"])
def test_an_ip_scope_is_skipped_whatever_the_address_and_never_widened(enrolled, address):
    """One authorized address cannot hold a scanner and a target, and widening it would run the
    tool against more than was authorized: an ``ip`` scope is not dispatched."""
    eid, registry = enrolled
    scope_id = sup.register_scope(registry, type="ip", value=address)
    pid = sup.approved_proposal(eid, scope_id, host=address)
    sandbox = RecordingSandbox()

    sched = Scheduler(sandbox=sandbox, watchdog_interval=0.2)
    assert sched.run(interval=0, max_ticks=6) == vocab.EXIT_OK       # skipped, not a stop

    assert sandbox.calls == 0 and sandbox.allowlists == []
    assert _stage(eid, pid)[0] == stages.APPROVED
    assert tuple(_state(eid, pid)) == (vocab.SKIPPED_STATE, vocab.SCOPE_TOO_NARROW)
    (event,) = sup.audit(eid, "scheduler.skipped")                    # once, not once per tick
    assert event["payload"] == {"proposal_id": pid, "reason_code": vocab.SCOPE_TOO_NARROW}
    assert sup.rows(eid, "SELECT 1 FROM capabilities") == []


def test_an_ip_scope_with_a_real_docker_daemon_starts_nothing(enrolled):
    """Same, against the scheduler's own DockerSandbox: no capability, no run, no container, no
    network -- and the daemon's container and network lists are exactly what they were."""
    eid, registry = enrolled
    scope_id = sup.register_scope(registry, type="ip", value="10.96.67.20")
    pid = sup.approved_proposal(eid, scope_id, host="10.96.67.20")
    client = _docker()
    containers = {c.id for c in client.containers.list(all=True)}
    networks = {n.id for n in client.networks.list()}

    with sup.running() as sched:
        first = sched.tick()
        later = [sched.tick() for _ in range(4)]

    assert first.skipped == [pid] and first.dispatched == []
    assert all(r.skipped == [] and r.dispatched == [] for r in later)
    assert _stage(eid, pid)[0] == stages.APPROVED
    assert tuple(_state(eid, pid)) == (vocab.SKIPPED_STATE, vocab.SCOPE_TOO_NARROW)
    assert len(sup.audit(eid, "scheduler.skipped")) == 1
    assert sup.rows(eid, "SELECT 1 FROM capabilities") == []
    assert sup.rows(eid, "SELECT 1 FROM tool_runs") == []
    assert {c.id for c in client.containers.list(all=True)} == containers
    assert {n.id for n in client.networks.list()} == networks


# ---------------------------------------------------------------------------------------------
# tier 3 -- a target on a reserved address, against a real Docker daemon
# ---------------------------------------------------------------------------------------------

RESERVED = [("network", "10.96.68.0"), ("gateway", "10.96.68.1"), ("broadcast", "10.96.68.255")]
#: The probe uses a subnet of its own, so a sandbox network a run left on 10.96.68.0/24 (the
#: sandbox keeps and reuses them) cannot make it fail with "pool overlaps".
PROBE_SUBNET, PROBE_PREFIX = "10.96.75.0/24", "10.96.75."


def _docker():
    return DockerSandbox().client()


def _try_to_start_at(client, network_name: str, address: str) -> str | None:
    """Start a container pinned at ``address``; the daemon's refusal text, or None if it started."""
    config = client.api.create_networking_config({
        network_name: client.api.create_endpoint_config(ipv4_address=address)})
    container_id = client.api.create_container(
        DEFAULT_IMAGE, command=["nmap", "--version"],
        host_config=client.api.create_host_config(network_mode=network_name),
        networking_config=config)["Id"]
    try:
        client.api.start(container_id)
    except docker.errors.APIError as exc:
        return getattr(exc, "explanation", None) or str(exc)
    finally:
        client.api.remove_container(container_id, force=True)
    return None


def test_docker_really_has_no_container_at_the_network_gateway_or_broadcast_address():
    """The premise of ``target_is_reserved_address``, demonstrated rather than assumed."""
    client = _docker()
    name = f"probe-reserved-{uuid.uuid4().hex[:8]}"
    network = client.networks.create(
        name, driver="bridge", internal=True,
        ipam=IPAMConfig(pool_configs=[IPAMPool(subnet=PROBE_SUBNET)]))
    try:
        for label, tail in (("network", "0"), ("gateway", "1"), ("broadcast", "255")):
            address = PROBE_PREFIX + tail
            refusal = _try_to_start_at(client, name, address)
            assert refusal and "Address already in use" in refusal, (label, address, refusal)
        assert _try_to_start_at(client, name, PROBE_PREFIX + "9") is None     # control: a host
    finally:
        network.remove()


@pytest.mark.parametrize("label,address", RESERVED)
def test_a_target_on_a_reserved_address_is_skipped_and_nothing_is_started(
    enrolled, label, address,
):
    eid, registry = enrolled
    scope_id = sup.register_scope(registry, type="cidr", value="10.96.68.0/24")
    pid = sup.approved_proposal(eid, scope_id, host=address)
    client = _docker()
    before = {c.id for c in client.containers.list(all=True)}

    with sup.running() as sched:                         # a real DockerSandbox, not a stand-in
        report = sched.tick()
        again = sched.tick()

    assert report.skipped == [pid] and again.skipped == []
    assert tuple(_state(eid, pid)) == (vocab.SKIPPED_STATE, vocab.TARGET_RESERVED)
    (event,) = sup.audit(eid, "scheduler.skipped")
    assert event["payload"] == {"proposal_id": pid, "reason_code": vocab.TARGET_RESERVED}
    assert _stage(eid, pid)[0] == stages.APPROVED
    assert sup.rows(eid, "SELECT 1 FROM capabilities") == []
    assert sup.rows(eid, "SELECT 1 FROM tool_runs") == []
    assert {c.id for c in client.containers.list(all=True)} - before == set()
    assert sup.audit(eid, "scheduler.dispatched") == []
