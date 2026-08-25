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


@pytest.mark.parametrize("scan_type", sorted(nmap.SCAN_TYPES))
def test_every_scan_type_can_actually_execute_in_the_sandbox(
    sandbox, scan_target, scan_type
):
    """Every entry in SCAN_TYPES runs, against a live host, and exits clean.

    The test the D11 live run showed was missing, and the reason it is
    parametrized over the whole table rather than written once per type: the
    suite executed ``connect`` and nothing else, so two of the three scan types
    the adapter advertises had never been run at all. Both failed — nmap picked
    a raw-socket technique it had no NET_RAW for and quit with exit 1 — after
    the pipeline had already canonicalized, resolved, decided, issued a
    capability and dispatched. A configuration that passes every check upstream
    and cannot execute is worse than one that is rejected.

    Exit code and a parsed host, not just "it produced output": the broken
    runs printed nmap's banner to stdout before dying, so anything weaker than
    this would have passed.
    """
    plan = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": scan_type},
        budget={"max_duration_seconds": 60}, target=scan_target,
    )
    result = sandbox.run(
        command=plan.command, network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=60,
    )

    assert result.exit_code == 0, (
        f"{scan_type} scan failed: {' '.join(plan.command)}\n{result.stderr}"
    )
    assert "QUITTING!" not in result.stderr
    view = nmap.derive_view(result.stdout, result.stderr)
    assert view["hosts"] == [scan_target], (
        f"{scan_type} produced no host report\n{result.stdout}"
    )


def test_version_scan_names_its_own_technique():
    """-sV is service detection layered on a scan, not a scan.

    Emitted alone it left nmap free to choose, and nmap chooses by uid rather
    than by capability. Asserted on the command rather than only through the
    sandbox so the reason survives as a statement about the flag.
    """
    plan = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "version"},
        budget={"max_duration_seconds": 60}, target=TARGET_IP,
    )
    assert "-sT" in plan.command and "-sV" in plan.command
    assert "--unprivileged" in plan.command


def test_ping_scan_no_longer_reports_a_routing_failure(sandbox):
    """What --unprivileged cost, recorded rather than quietly dropped.

    Before D11, ``-sn`` against an address outside the allowlist printed
    "failed to determine route" while planning a raw packet, and
    ``derive_view`` surfaced it as ``nmap_reported_no_route``. Unprivileged
    nmap does not plan a route — it calls connect(), gets ENETUNREACH, and
    says "host seems down" — so that string is gone and the flag is now
    permanently False.

    Nothing security-relevant was lost, and this test is where that claim is
    checked rather than asserted: the scanner's account was never evidence of
    confinement in the first place (under -Pn it calls an unroutable target
    "up, filtered"), so the kernel is asked directly here, as it always was.
    """
    plan = nmap.build_plan(
        constraints={"scan_type": "ping"},
        budget={"max_duration_seconds": 15}, target=OUTSIDE_IP,
    )
    result = sandbox.run(
        command=plan.command, network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=15,
    )
    view = nmap.derive_view(result.stdout, result.stderr)
    assert view["nmap_reported_no_route"] is False
    assert view["open_ports"] == []

    # The authority on whether anything left the namespace, unchanged.
    assert sandbox.probe_egress(
        target=OUTSIDE_IP, port=8080, network_allowlist=[ALLOWED_CIDR],
    ) == "network_unreachable"


def test_the_tool_is_asked_to_stop_before_the_sandbox_kills_it():
    """The two deadlines are ordered, not simultaneous.

    ``--host-timeout`` exists so a long scan ends with a partial report instead
    of a destroyed container. Set to the same second as the kill it never got
    the chance: D11 watched a -sV scan of a silent listener get killed at the
    deadline with its output discarded, which is the failure the flag was added
    to prevent.

    The margin comes off the tool's deadline. The sandbox still kills at
    exactly the budgeted duration, because that number is an authorization
    (I3) and not a target to overshoot.
    """
    plan = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "connect"},
        budget={"max_duration_seconds": 60}, target=TARGET_IP,
    )
    assert plan.max_duration_seconds == 60, "the sandbox's kill must not move"
    timeout = plan.command[plan.command.index("--host-timeout") + 1]
    assert int(timeout.rstrip("s")) < plan.max_duration_seconds

    # A budget smaller than the margin still yields a usable positive timeout
    # rather than zero or a negative one.
    tiny = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "connect"},
        budget={"max_duration_seconds": 2}, target=TARGET_IP,
    )
    assert int(tiny.command[tiny.command.index("--host-timeout") + 1].rstrip("s")) >= 1


def test_a_scan_that_outlives_its_tool_deadline_still_reports(sandbox, scan_target):
    """The behaviour the ordering buys, against a real unresponsive service.

    ``-sV`` against a listener that accepts and then says nothing walks its
    whole probe sequence, so this genuinely exceeds a short budget. With the
    deadlines ordered, nmap stops itself and prints what it has; with them
    equal, the container was killed and ``stdout`` held nothing but the banner.
    """
    plan = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "version"},
        budget={"max_duration_seconds": 25}, target=scan_target,
    )
    result = sandbox.run(
        command=plan.command, network_allowlist=[ALLOWED_CIDR],
        max_duration_seconds=plan.max_duration_seconds,
    )

    assert result.timed_out is False, "the sandbox had to kill it after all"
    assert result.exit_code == 0, result.stderr
    view = nmap.derive_view(result.stdout, result.stderr)
    assert view["hosts"] == [scan_target], result.stdout


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
