"""D49 §三-1: independent, kernel-level evidence that ``dns_server`` really
sends a query, and only to the authorized address -- never trusting
bloodhound-python's own report (D6's rigor standard, reused: "confirmed
with the kernel, never with the tool").

A second, unrelated process (a bare Python UDP socket, not part of this
system's own code) is started at a fixed address inside the sandbox's own
allowlisted network and simply records whatever arrives on port 53. It has
no opinion about bloodhound-python and cannot be fooled by anything that
tool prints to stdout. The real, unmodified adapter command
(``ad_collector.build_plan``) is then run through the real
``DockerSandbox``, and the listener's own capture -- not the tool's exit
code or output -- is what this file asserts against.

**A real, adjacent finding surfaced while building this, reported here
rather than worked around silently:** ``ad_collector.build_plan``'s
*uncredentialed* command (no ``domain_username``) can never reach DNS
resolution against the real ``bloodhound==1.9.0`` binary this project's own
image installs -- confirmed by reading ``bloodhound.__init__.main`` directly
(inside ``cyberorch/bloodhound:local``): with no ``-u``/``--hashes``/
``-aesKey``/``-k``, it prints its own usage text and calls ``sys.exit(1)``
*before* ever constructing the ``AD`` object ``dns_resolve`` is a method of.
Every credentialed-vs-uncredentialed adapter test in this suite
(``tests/test_ad_collector_adapter.py``, ``tests/test_dispatch_collection.py``)
uses ``StubSandbox``/fixture output and so never executes the real binary,
which is exactly why this was not caught before. It does not block D49 (this
file authorizes and uses a synthetic credential purely to reach the DNS
phase; real ``ad.collect`` capabilities issued through this system already
carry a ``domain_username`` far more often than not, D44's own credential
vault existing for exactly that case) and fixing it is out of this
deliverable's stated scope (unblock DNS, not re-verify the credentialed
collection flow task #42/#44/#45 cover) -- recorded here rather than glossed
over, per this project's standing discipline.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import dns.message
import pytest

from tool_gateway.adapters import ad_collector
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

ALLOWED_CIDR = "10.91.0.0/24"
LISTENER_IP = "10.91.0.53"
FAKE_DOMAIN = "fake.internal.test"

# A bare, dependency-free UDP:53 listener -- not this project's code, and
# not bloodhound-python's -- run inside the same image only because the
# image already has python3, not because it shares any code path with the
# adapter under test. Records the first datagram's source and raw bytes,
# then exits; NO_PACKET after the timeout is an equally meaningful result.
_LISTENER_SCRIPT = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    "s.bind(('0.0.0.0',53))\n"
    "s.settimeout(20)\n"
    "try:\n"
    "    data,addr=s.recvfrom(4096)\n"
    "    sys.stdout.write('RECEIVED src=%s hex=%s\\n' % (addr[0], data.hex()))\n"
    "except socket.timeout:\n"
    "    sys.stdout.write('NO_PACKET\\n')\n"
    "sys.stdout.flush()\n"
)


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox(image=ad_collector.IMAGE)
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "This file verifies the D49 DNS mechanism against the real "
            "bloodhound-python binary and a real socket listener, and is not "
            "meaningful without a real container (§8.3's own convention, "
            "tests/test_sandbox.py) -- build cyberorch/bloodhound:local and "
            "ensure the Docker daemon is running.",
            pytrace=False,
        )
    return box


def _start_listener(network_name: str, name: str) -> None:
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", network_name,
         "--ip", LISTENER_IP, ad_collector.IMAGE, "python3", "-c", _LISTENER_SCRIPT],
        check=True, capture_output=True,
    )


def _listener_output(name: str, wait_seconds: int) -> str:
    deadline = time.monotonic() + wait_seconds
    out = ""
    while time.monotonic() < deadline:
        out = subprocess.run(
            ["docker", "logs", name], capture_output=True, text=True,
        ).stdout
        if "RECEIVED" in out or "NO_PACKET" in out:
            return out
        time.sleep(1)
    return out


def test_dns_server_sends_a_real_srv_query_to_only_the_authorized_address(sandbox):
    """The positive case: an independent socket, not bloodhound-python's own
    report, observes a real DNS SRV query for the AD locator record arriving
    from the sandboxed container, addressed to the authorized dns_server.
    """
    network = sandbox.ensure_network([ALLOWED_CIDR])
    listener_name = f"cyberorch-dns-evidence-{uuid.uuid4().hex[:8]}"
    try:
        _start_listener(network.name, listener_name)

        # A synthetic credential, used only to get the real binary past its
        # own auth-presence check (module docstring above) and into
        # dns_resolve -- authentication is never attempted against anything
        # here, and nothing about D49's DNS mechanism depends on whether it
        # would succeed.
        plan = ad_collector.build_plan(
            constraints={
                "collection_methods": ["Group"], "dns_server": LISTENER_IP,
                "domain_username": "fake-probe-account",
            },
            budget={"max_duration_seconds": 20}, target=FAKE_DOMAIN,
        )
        assert plan.dns_server == LISTENER_IP
        # The credentialed branch reads the password from CONTAINER_CRED_PATH
        # at run time (D44) -- mount a throwaway one, read-only, the same
        # shape dispatch_collection's own vault.mount_for_run produces.
        with tempfile.TemporaryDirectory() as tmp:
            cred_file = Path(tmp) / "secret"
            cred_file.write_text("fake-probe-password")
            sandbox.run(
                command=plan.command, network_allowlist=[ALLOWED_CIDR],
                max_duration_seconds=20,
                source_mounts={str(cred_file): ad_collector.CONTAINER_CRED_PATH},
            )

        output = _listener_output(listener_name, wait_seconds=22)
        assert "RECEIVED" in output, (
            f"no UDP:53 packet reached the authorized dns_server; listener log: {output!r}"
        )
        src_ip = output.split("src=")[1].split(" ")[0]
        raw_hex = output.split("hex=")[1].strip()

        # The only other container on this isolated, internal, two-node
        # network is the collector itself -- the address independently
        # confirms where the packet actually came from, rather than assuming
        # it because nothing else was listening.
        assert src_ip != LISTENER_IP

        message = dns.message.from_wire(bytes.fromhex(raw_hex))
        assert len(message.question) == 1
        question_name = str(message.question[0].name).rstrip(".")
        question_type = message.question[0].rdtype
        # dns.rdatatype.SRV == 33 -- the exact locator record the module
        # docstring names (bloodhound.ad.domain.AD.dns_resolve's own query).
        assert question_type == 33, f"expected an SRV query, got rdtype {question_type}"
        assert question_name == f"_ldap._tcp.pdc._msdcs.{FAKE_DOMAIN}"
    finally:
        subprocess.run(["docker", "rm", "-f", listener_name], capture_output=True)
        sandbox.remove_network([ALLOWED_CIDR])


def test_no_dns_server_constraint_means_no_query_reaches_that_address(sandbox):
    """The negative control the positive case needs to mean anything:
    identical credentialed command, identical listener at the identical
    address, the *only* difference being no ``dns_server`` constraint -- so
    bloodhound-python still reaches ``dns_resolve`` (same auth shape as the
    positive case) and still fires a real SRV query, just against whatever
    ambient resolver the container has (Docker's own embedded one), never
    against our listener. This is what proves the packet captured above is
    caused by the ``-ns`` flag D49 added, not some coincidence of the
    two-container network that would have reached the same listener
    regardless of whether dns_server were ever wired through.
    """
    network = sandbox.ensure_network([ALLOWED_CIDR])
    listener_name = f"cyberorch-dns-evidence-control-{uuid.uuid4().hex[:8]}"
    try:
        _start_listener(network.name, listener_name)

        plan = ad_collector.build_plan(
            constraints={
                "collection_methods": ["Group"], "domain_username": "fake-probe-account",
            },
            budget={"max_duration_seconds": 8}, target=FAKE_DOMAIN,
        )
        assert plan.dns_server is None

        with tempfile.TemporaryDirectory() as tmp:
            cred_file = Path(tmp) / "secret"
            cred_file.write_text("fake-probe-password")
            sandbox.run(
                command=plan.command, network_allowlist=[ALLOWED_CIDR],
                max_duration_seconds=10,
                source_mounts={str(cred_file): ad_collector.CONTAINER_CRED_PATH},
            )

        # The listener's own internal socket timeout is 20s -- wait_seconds
        # here must exceed that, or this would only ever observe "still
        # waiting", which is not the same fact as "confirmed nothing arrived".
        output = _listener_output(listener_name, wait_seconds=22)
        assert "NO_PACKET" in output, (
            f"a query reached the control listener despite no dns_server "
            f"constraint being set: {output!r}"
        )
    finally:
        subprocess.run(["docker", "rm", "-f", listener_name], capture_output=True)
        sandbox.remove_network([ALLOWED_CIDR])
