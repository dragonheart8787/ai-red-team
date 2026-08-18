"""Shared scaffolding for the §10 MVP-Kernel scenarios."""

from __future__ import annotations

import subprocess
import uuid

import pytest

from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

ALLOWED_CIDR = "10.79.0.0/24"
TARGET_IP = "10.79.0.10"
DENIED_TARGET_IP = "10.79.0.20"


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class RecordingSandbox:
    """Counts calls and delegates to the real sandbox.

    A spy rather than a stub. Scenario A needs the container to actually run —
    §10 asks for evidence from a real tool — while Scenario B needs to prove
    the sandbox was never reached. One object does both, and the call count is
    direct evidence rather than the absence of a side effect.
    """

    def __init__(self, inner: DockerSandbox) -> None:
        self._inner = inner
        self.run_calls: list[dict] = []
        self.image = inner.image

    def run(self, **kwargs):
        self.run_calls.append(kwargs)
        return self._inner.run(**kwargs)

    def probe_egress(self, **kwargs):
        return self._inner.probe_egress(**kwargs)

    def ensure_network(self, allowlist):
        return self._inner.ensure_network(allowlist)

    def remove_network(self, allowlist):
        return self._inner.remove_network(allowlist)

    @property
    def call_count(self) -> int:
        return len(self.run_calls)


class RecordingBroker:
    """Wraps issue_capability to count calls (§10 Scenario B).

    Scenario B requires proof that the broker was never called, not that it was
    called and declined. Checking for the absence of a capability row cannot
    tell those apart.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls: list[dict] = []

    def __call__(self, conn, **kwargs):
        self.calls.append(kwargs)
        return self._inner(conn, **kwargs)

    @property
    def call_count(self) -> int:
        return len(self.calls)


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox()
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "§10's scenarios run a real scan through a real container. Build the "
            "image with tool_gateway/images/build_nmap_image.sh.",
            pytrace=False,
        )
    return box


@pytest.fixture(scope="module")
def scan_target(sandbox):
    """A live host inside the allowlist, so Scenario A finds something real."""
    name = f"cyberorch-scenario-target-{uuid.uuid4().hex[:8]}"
    network = sandbox.ensure_network([ALLOWED_CIDR])
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", network.name,
         "--ip", TARGET_IP, sandbox.image, "/usr/bin/ncat", "-l", "8080", "-k"],
        check=True, capture_output=True,
    )
    yield TARGET_IP
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    sandbox.remove_network([ALLOWED_CIDR])


@pytest.fixture
def effective_policy():
    """Baseline policy: network.scan allowed, PII and customer data denied."""
    return merge_policy(
        PolicyLayer(
            name="baseline_global",
            data_deny=frozenset({"PII", "customer_database"}),
            actions={"network.scan": ALLOW},
        ),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )
