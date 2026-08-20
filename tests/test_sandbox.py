"""Sandbox network isolation (§8.3).

The point of these tests is the negative one. §8.3 calls network isolation the
last physical boundary — the layer that has to hold when the Policy Gate, the
Capability Broker and the infrastructure ACL have all been bypassed. So the
important test does not ask whether a capability was issued; it grants a
perfectly valid capability naming a target outside the sandbox allowlist and
requires the kernel to refuse anyway.

Nothing here is mocked. A mocked sandbox tests the mock's idea of routing, and
the property under test is precisely that the real kernel has no route. If
Docker or the tool image is unavailable these tests fail rather than skip: a
green run that never started a container has verified nothing about isolation,
and would be worse than a red one because it looks the same as success.
"""

from __future__ import annotations

import subprocess
import uuid

import pytest

from tool_gateway.adapters import nmap
from tool_gateway.sandbox import (
    DockerSandbox,
    SandboxUnavailable,
    target_within_allowlist,
    validate_allowlist,
)

# A range with no route to anywhere real, so an escape attempt cannot reach a
# third party even if the boundary failed.
ALLOWED_CIDR = "10.77.0.0/24"
TARGET_IP = "10.77.0.10"
OUTSIDE_IP = "10.99.0.10"


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox()
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "These tests verify the last physical boundary in the design (§8.3) "
            "and are not meaningful without a real container. Build the image "
            "with tool_gateway/images/build_nmap_image.sh and ensure the Docker "
            "daemon is running.",
            pytrace=False,
        )
    return box


@pytest.fixture(scope="module")
def scan_target(sandbox):
    """A container inside the allowlisted range with one open port.

    Started on its own internal network at a fixed address so the positive
    control has something real to find. Without it, "no route" would be
    indistinguishable from "nothing listening".
    """
    name = f"cyberorch-test-target-{uuid.uuid4().hex[:8]}"
    network = sandbox.ensure_network([ALLOWED_CIDR])
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", network.name,
         "--ip", TARGET_IP, sandbox.image, "/usr/bin/ncat", "-l", "8080", "-k"],
        check=True, capture_output=True,
    )
    yield TARGET_IP
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    sandbox.remove_network([ALLOWED_CIDR])


# ---------------------------------------------------------------------------
# Allowlist validation — §8.3 rejects hostnames by construction
# ---------------------------------------------------------------------------

def test_allowlist_accepts_cidrs():
    assert validate_allowlist(["10.20.0.0/24", "10.20.1.5"]) == (
        "10.20.0.0/24", "10.20.1.5/32",
    )


@pytest.mark.parametrize("bad", ["app.customer-a.com", "*.example.com", "not-an-ip"])
def test_allowlist_refuses_hostnames(bad):
    """§8.3: binding egress to a resolved name is the design that was rejected.

    One name maps to many addresses, they change when the TTL lapses, and DNS
    rebinding makes the gap attacker-controlled. The allowlist never resolves.
    """
    with pytest.raises(ValueError, match="CIDR"):
        validate_allowlist([bad])


def test_allowlist_refuses_everything():
    with pytest.raises(ValueError, match="allowlist"):
        validate_allowlist(["0.0.0.0/0"])


def test_allowlist_cannot_be_empty():
    with pytest.raises(ValueError):
        validate_allowlist([])


@pytest.mark.parametrize("target,inside", [
    ("10.20.0.7", True), ("10.20.0.0/25", True),
    ("10.20.1.7", False), ("10.20.0.0/16", False), ("app.example.com", False),
])
def test_containment(target, inside):
    assert target_within_allowlist(target, ["10.20.0.0/24"]) is inside


# ---------------------------------------------------------------------------
# The boundary itself
# ---------------------------------------------------------------------------

def test_scan_inside_the_allowlist_reaches_the_target(sandbox, scan_target):
    """The positive control. Without it, a sandbox that blocks everything
    would pass every negative test in this file."""
    plan = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "connect"},
        budget={"max_duration_seconds": 60}, target=scan_target,
    )
    result = sandbox.run(
        command=plan.command, network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=60,
    )

    assert result.exit_code == 0, result.stderr
    assert result.timed_out is False
    view = nmap.derive_view(result.stdout, result.stderr)
    assert any(p["port"] == 8080 and p["state"] == "open" for p in view["open_ports"]), (
        f"expected 8080 open, got {view['ports']}\n{result.stdout}"
    )


def test_target_outside_the_allowlist_has_no_route(sandbox):
    """§8.3's last physical boundary, asked of the kernel.

    Everything upstream is assumed already bypassed: no policy is consulted, no
    capability is checked, and the target is an ordinary address. The container
    simply has no route off the allowlisted range, so connect() fails with
    ENETUNREACH and no packet is ever built.
    """
    assert sandbox.probe_egress(
        target=OUTSIDE_IP, port=8080, network_allowlist=[ALLOWED_CIDR],
    ) == "network_unreachable"


def test_an_absent_host_inside_the_allowlist_is_not_confused_with_confinement(sandbox):
    """The distinction the previous test depends on.

    An unused address *inside* the allowlist yields EHOSTUNREACH or a timeout:
    there was a route, traffic left the namespace, and nothing answered. Only
    ENETUNREACH means the packet was never built. Collapsing the two — they
    both read as "no route" in English — would make the confinement test pass
    whenever the target simply happened to be absent.
    """
    assert sandbox.probe_egress(
        target="10.77.0.99", port=8080, network_allowlist=[ALLOWED_CIDR],
    ) in ("host_unreachable", "no_answer")


def test_a_valid_capability_does_not_widen_the_sandbox(sandbox):
    """Defence in depth, stated as a test.

    The scan is well formed and its constraints name a target outside the
    allowlist — as though the Policy Gate and the Capability Broker had both
    been fooled. The sandbox is configured from the allowlist, never from the
    capability, so the kernel refuses regardless.

    Note what is *not* asserted: nmap's own report. Under -Pn it calls this
    target "up" with a "filtered" port, which is what a firewall in front of a
    reachable host looks like. Believing the scanner here would have produced a
    test that passed while proving nothing.
    """
    plan = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "connect"},
        budget={"max_duration_seconds": 30}, target=OUTSIDE_IP,
    )
    result = sandbox.run(
        command=plan.command, network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=30,
    )
    view = nmap.derive_view(result.stdout, result.stderr)
    assert view["open_ports"] == [], "the sandbox reached outside its allowlist"

    # The kernel is the authority on whether anything left the namespace.
    assert sandbox.probe_egress(
        target=OUTSIDE_IP, port=8080, network_allowlist=[ALLOWED_CIDR],
    ) == "network_unreachable"


def test_ping_scan_surfaces_the_routing_failure(sandbox):
    """A scan type that does its own routing does report the failure.

    Kept to document that the signal exists for -sn and is simply unavailable
    under -Pn with a connect scan — the reason probe_egress has to exist.
    """
    plan = nmap.build_plan(
        constraints={"scan_type": "ping"},
        budget={"max_duration_seconds": 15}, target=OUTSIDE_IP,
    )
    result = sandbox.run(
        command=plan.command, network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=15,
    )
    assert nmap.derive_view(result.stdout, result.stderr)["nmap_reported_no_route"] is True


def test_duration_budget_kills_a_long_run(sandbox):
    """§4.6: the budget has to stop execution, not just sit in the database."""
    result = sandbox.run(
        command=["/usr/bin/sleep", "60"], network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=3,
    )
    assert result.timed_out is True
    assert result.duration_seconds < 20, "the container outlived its budget"


def test_sandbox_leaves_no_container_or_network_behind(sandbox):
    """A leaked container keeps its namespace, and a namespace keeps its route."""
    client = sandbox.client()
    run_id = uuid.uuid4().hex[:12]
    sandbox.run(
        command=["/usr/bin/nmap", "--version"], network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=30, run_id=run_id,
    )
    assert client.containers.list(
        all=True, filters={"label": f"cyberorch.run_id={run_id}"}
    ) == []
    # The allowlist network is shared and outlives individual runs by design;
    # only the container is per-run.
