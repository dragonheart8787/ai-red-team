"""Container sandbox with a network-namespace CIDR allowlist (§8.3).

§8.3 splits egress enforcement by protocol. HTTP goes through a policy-aware
egress proxy that can check Host headers per request; raw TCP/UDP goes through
a network namespace whose egress is bound to an explicit CIDR allowlist. Only
the second is in scope here — the egress proxy is explicitly deferred (§10),
and Nmap needs the namespace path anyway.

The allowlist is a list of CIDRs, never a hostname. §8.3 rejected the
"resolve the hostname, then write an iptables rule for the address" design
because the rule and the intention come apart: one name can map to many
addresses, they change when the TTL lapses, and DNS rebinding makes the gap
attacker-controlled. A CIDR does not move.

**How the boundary is enforced.** The container joins a Docker network created
with ``internal=True`` and the allowlisted CIDR as its subnet. Docker attaches
no default gateway to an internal network, so the container's namespace has a
route to the allowlisted range and to nothing else. Traffic to any other
address fails in the kernel with "network is unreachable" before a packet is
built. There is no filter to misconfigure and no rule ordering to get wrong —
the route simply does not exist.

The network is named deterministically from the allowlist and reused across
runs rather than created per run. That is not an optimization: a network
created fresh for one container has nothing else on it, so the allowlist would
describe a range containing only the scanner. The allowlisted network is
provisioned once and each run attaches to it, which is also how a real
deployment works — the range exists because the customer's assets are in it.

That is also why the tool container drops every capability. A tool holding
NET_ADMIN could add the missing route itself, which would make the boundary
advisory. The sandbox is what the design calls the last physical boundary,
and it has to hold even when the three layers above it have been bypassed.

DEFERRED — enforcement against a non-Docker network
---------------------------------------------------
The allowlisted CIDR is realized as a Docker-managed bridge subnet, so targets
have to live inside it. That is enough for MVP-Kernel, where the targets are
containers, and it is genuinely namespace-level enforcement: the tests confirm
the kernel returns ENETUNREACH for anything outside the range.

It is not enough for a real engagement, where the allowlist describes a
customer's actual network. Such a deployment would attach a routed or macvlan
network restricted to the same CIDR. **This has never been exercised, and no
test here covers it.** The enforcement mechanism should be unchanged — the
namespace holds a route to the allowlist and no default route, which is a
property of the routing table rather than of the driver — but "should be" is
the honest phrasing, and the difference between a bridge and a macvlan is
exactly the sort of place where a boundary quietly stops holding.

If it is implemented, three things are not negotiable:

1. **The confinement tests must run against the new driver.** The existing
   suite proves a bridge network confines; it says nothing about a macvlan.
   Passing tests on the old driver is not evidence about the new one.
2. **Confinement is confirmed with the kernel, never with the tool.** Under
   -Pn a scanner reports an unroutable target as "host up, port filtered",
   identical to a firewall in front of a reachable host. probe_egress asks
   connect() instead, and ENETUNREACH is the only answer that means nothing
   left the namespace — EHOSTUNREACH means traffic did leave.
3. **No capability may widen the allowlist.** The sandbox is configured from
   the engagement's allowlist and never from the capability being executed.
   A routed setup makes it tempting to derive the network from the target,
   which would delete the §8.3 boundary while appearing to preserve it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - import guard
    import docker
    from docker.errors import DockerException, ImageNotFound, NotFound
except ImportError:  # pragma: no cover
    docker = None
    DockerException = ImageNotFound = NotFound = Exception

DEFAULT_IMAGE = "cyberorch/nmap:local"


class SandboxUnavailable(RuntimeError):
    """Docker is not usable, or the tool image is missing.

    Raised rather than degraded into a skip or a simulated run. A sandbox that
    silently does not sandbox is worse than one that refuses to start.
    """


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    network_allowlist: tuple[str, ...]
    image: str

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def as_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_seconds": round(self.duration_seconds, 3),
            "network_allowlist": list(self.network_allowlist),
            "image": self.image,
        }


def validate_allowlist(cidrs: Sequence[str]) -> tuple[str, ...]:
    """Normalize the allowlist, refusing anything that is not a real CIDR.

    A hostname here would be the §8.3 mistake wearing different clothes, so
    values that do not parse as networks are rejected outright rather than
    resolved.
    """
    if not cidrs:
        raise ValueError("a sandbox requires an explicit CIDR allowlist (§8.3)")
    normalized = []
    for entry in cidrs:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"{entry!r} is not a CIDR. §8.3 binds egress to address ranges, "
                "never to names that have to be resolved first."
            ) from exc
        if network.prefixlen == 0:
            raise ValueError(f"{entry!r} allows every address; that is not an allowlist")
        normalized.append(str(network))
    return tuple(normalized)


def target_within_allowlist(target: str, allowlist: Sequence[str]) -> bool:
    """Whether an address or range falls inside the allowlist."""
    try:
        candidate = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return any(
        candidate.subnet_of(ipaddress.ip_network(entry, strict=False))
        for entry in allowlist
        if ipaddress.ip_network(entry, strict=False).version == candidate.version
    )


@dataclass
class DockerSandbox:
    """Runs one command in a network-confined container."""

    image: str = DEFAULT_IMAGE
    memory_limit: str = "512m"
    pids_limit: int = 256
    _client: Any = field(default=None, repr=False)

    def client(self):
        if self._client is not None:
            return self._client
        if docker is None:
            raise SandboxUnavailable("the docker SDK is not installed")
        try:
            self._client = docker.from_env()
            self._client.ping()
        except DockerException as exc:
            raise SandboxUnavailable(f"docker is not reachable: {exc}") from exc
        return self._client

    def network_name(self, allowlist: Sequence[str]) -> str:
        """Deterministic name for the network backing one allowlist."""
        digest = hashlib.sha256("|".join(sorted(allowlist)).encode()).hexdigest()[:12]
        return f"cyberorch-allow-{digest}"

    def ensure_network(self, allowlist: Sequence[str]):
        """Get or create the internal network for this allowlist.

        Idempotent, because several runs share one allowlist and Docker refuses
        two networks over the same subnet. Reuse is also what makes the
        allowlist meaningful: the range has to contain the targets.
        """
        allowlist = validate_allowlist(allowlist)
        client = self.client()
        name = self.network_name(allowlist)
        try:
            return client.networks.get(name)
        except NotFound:
            pass
        try:
            return client.networks.create(
                name=name,
                driver="bridge",
                # No default gateway is attached to an internal network, so the
                # namespace has no route off the allowlisted range. This one
                # flag is the boundary.
                internal=True,
                ipam=docker.types.IPAMConfig(
                    pool_configs=[docker.types.IPAMPool(subnet=cidr)
                                  for cidr in allowlist]
                ),
                labels={"cyberorch.allowlist": ",".join(allowlist)},
            )
        except DockerException as exc:
            raise SandboxUnavailable(
                f"could not create the confined network for {allowlist}: {exc}"
            ) from exc

    def remove_network(self, allowlist: Sequence[str]) -> None:
        """Tear down an allowlist network. Used by tests and engagement teardown."""
        try:
            self.client().networks.get(
                self.network_name(validate_allowlist(allowlist))
            ).remove()
        except (DockerException, NotFound, ValueError):
            pass

    def probe_egress(
        self, *, target: str, port: int, network_allowlist: Sequence[str],
        timeout_seconds: int = 5,
    ) -> str:
        """Ask the kernel whether the sandbox can reach an address.

        Returns one of:

        ``network_unreachable``
            ENETUNREACH. The namespace holds no route for that network, so no
            packet was built. This is the §8.3 boundary holding.
        ``host_unreachable``
            EHOSTUNREACH. There *is* a route — the address is on a network the
            sandbox can use — and the host did not answer ARP. Traffic left the
            namespace.
        ``no_answer``
            A connection was attempted and timed out or was refused.
        ``reachable``
            A connection succeeded.

        The distinction between the first two carries the whole result, and it
        is easy to lose: both read as "no route" in English, and collapsing
        them makes a confinement test pass whenever the target simply happens
        to be absent. Only ENETUNREACH means nothing left the namespace.

        This exists because the scanner's own report cannot answer the
        question. Run with -Pn, nmap describes a target it has no route to as
        "host up, port filtered" — indistinguishable from a firewall in front
        of a reachable host.
        """
        result = self.run(
            command=["/usr/bin/ncat", "-w", str(timeout_seconds), "-v",
                     target, str(port)],
            network_allowlist=network_allowlist,
            max_duration_seconds=timeout_seconds + 10,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        if "Network is unreachable" in combined:
            return "network_unreachable"
        if "No route to host" in combined:
            return "host_unreachable"
        if "TIMEOUT" in combined or "Connection refused" in combined:
            return "no_answer"
        return "reachable"

    def ensure_image(self) -> None:
        """Confirm the tool image exists locally.

        Never pulls. The image is built from the operator's own installation by
        tool_gateway/images/build_nmap_image.sh, so what runs in the sandbox is
        pinned to what was installed rather than to a tag that can move.
        """
        try:
            self.client().images.get(self.image)
        except ImageNotFound as exc:
            raise SandboxUnavailable(
                f"image {self.image!r} is not present. Build it with "
                "tool_gateway/images/build_nmap_image.sh"
            ) from exc

    def run(
        self,
        *,
        command: Sequence[str],
        network_allowlist: Sequence[str],
        max_duration_seconds: int,
        run_id: str | None = None,
    ) -> SandboxResult:
        """Execute ``command`` confined to ``network_allowlist``.

        ``max_duration_seconds`` is enforced by killing the container, not by
        asking the tool to stop. A budget the tool could ignore is a number in
        a database, not a limit.
        """
        allowlist = validate_allowlist(network_allowlist)
        self.ensure_image()
        client = self.client()

        run_id = run_id or uuid.uuid4().hex[:12]
        network = self.ensure_network(allowlist)
        container = None
        started = time.monotonic()

        try:
            container = client.containers.create(
                image=self.image,
                command=list(command),
                network=network.name,
                # The tool must not be able to widen its own confinement.
                cap_drop=["ALL"],
                privileged=False,
                security_opt=["no-new-privileges:true"],
                read_only=True,
                mem_limit=self.memory_limit,
                pids_limit=self.pids_limit,
                labels={"cyberorch.run_id": run_id},
            )
            container.start()

            timed_out = False
            try:
                status = container.wait(timeout=max_duration_seconds)
                exit_code = int(status.get("StatusCode", -1))
            except Exception:
                # wait() raises on timeout (and on a lost connection). Either
                # way the container is still running and must not be left that
                # way: kill first, decide afterwards.
                timed_out = True
                exit_code = -1
                try:
                    container.kill()
                except (DockerException, NotFound):
                    pass

            duration = time.monotonic() - started
            stdout = container.logs(stdout=True, stderr=False).decode(errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode(errors="replace")

            return SandboxResult(
                exit_code=exit_code, stdout=stdout, stderr=stderr,
                timed_out=timed_out, duration_seconds=duration,
                network_allowlist=allowlist, image=self.image,
            )
        finally:
            # Teardown runs even when the run failed. A leaked container keeps
            # its namespace, and a leaked namespace keeps its route. The
            # network is shared and outlives the run by design, so it is left
            # for remove_network().
            if container is not None:
                try:
                    container.remove(force=True)
                except (DockerException, NotFound):
                    pass
