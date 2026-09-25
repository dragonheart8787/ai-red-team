"""Container sandbox with a network-namespace CIDR allowlist (§8.3).

§8.3 splits egress enforcement by protocol. HTTP goes through a policy-aware
egress proxy that can check Host headers per request; raw TCP/UDP goes through
a network namespace whose egress is bound to an explicit CIDR allowlist. D6
built the second; D34 added the first, and both live here because both are
realized the same way — by what routes exist in a namespace.

**The two-network topology (D34).** A web.* run no longer puts the tool on the
network its targets are on. Two internal networks are created instead:

    tool container ──[ tool-side network ]── egress proxy ──[ target-side ]── target

The proxy is the only thing on both. The tool container's namespace therefore
holds a route to the proxy and to nothing else, so a tool that ignored its
``--proxy`` flag and addressed the target directly gets ENETUNREACH from the
kernel — the same fact ``probe_egress`` already knows how to establish, reused
rather than reasoned about again. That is the kernel-level half of D34's
evidence; the other half is the target's own access log, which is outside the
proxy's control and is where a refusal is actually proven.

Nmap keeps the single-network path: §8.3 routes raw TCP through the namespace
precisely because there is no application protocol for a proxy to read.

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
import json
import os
import socket
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - import guard
    import docker
    from docker.errors import DockerException, ImageNotFound, NotFound
except ImportError:  # pragma: no cover
    docker = None
    DockerException = ImageNotFound = NotFound = Exception

DEFAULT_IMAGE = "cyberorch/nmap:local"

#: Image for the policy-aware egress proxy (§8.3, D34).
PROXY_IMAGE = "cyberorch/egress-proxy:local"

#: Port the proxy listens on inside its container.
PROXY_PORT = 3128

#: Fixed in-container paths for the TLS material delivered by read-only bind
#: mount (D35). Paths, not contents: the private keys never pass through argv
#: or the environment, where `docker inspect` and the process table would
#: expose them. The tool reads the CA at TOOL_CA_PATH via curl --cacert; the
#: proxy reads its leaf at the two PROXY_LEAF_* paths.
TOOL_CA_PATH = "/etc/cyberorch/engagement-ca.pem"
PROXY_LEAF_CERT_PATH = "/etc/cyberorch/leaf-cert.pem"
PROXY_LEAF_KEY_PATH = "/etc/cyberorch/leaf-key.pem"


def _write_pem_tempfile(pem: str, mode: int) -> str:
    """Write PEM to a host temp file with ``mode`` and return its path.

    The file is bind-mounted read-only into a container; it must outlive the
    container, so the caller removes it on teardown rather than here.
    """
    fd, path = tempfile.mkstemp(suffix=".pem", prefix="cyberorch-tls-")
    try:
        os.write(fd, pem.encode())
    finally:
        os.close(fd)
    os.chmod(path, mode)
    return path


def _write_secret_tempfile(pem: str) -> str:
    """A private key: 0600, readable only by the uid that wrote it.

    Whoever reads it inside a container must *be* that uid. Every container
    here runs with ``cap_drop=["ALL"]``, so container root has no
    CAP_DAC_OVERRIDE and is refused a 0600 file it does not own — which is why
    :meth:`DockerSandbox.start_egress_proxy` runs the proxy as the host uid
    rather than loosening the mode (D35; CI's runner is not uid 0, the dev
    container is, and that difference is how this was found).
    """
    return _write_pem_tempfile(pem, 0o600)


def _write_public_tempfile(pem: str) -> str:
    """A certificate: 0644. It is public; hiding it protects nothing."""
    return _write_pem_tempfile(pem, 0o644)


def _host_user() -> str:
    """``uid:gid`` of this process, the owner of every file it writes."""
    return f"{os.getuid()}:{os.getgid()}"


def _unlink_all(paths: Sequence[str]) -> None:
    """Remove host temp files, ignoring ones already gone."""
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass


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


@dataclass(frozen=True)
class ProxyEndpoint:
    """A running egress proxy, and the two networks it bridges (D34)."""

    container_id: str
    name: str
    url: str
    tool_side: tuple[str, ...]
    target_side: tuple[str, ...]
    #: Host temp files (leaf cert + key) bind-mounted into the proxy, removed
    #: by stop_egress_proxy. Empty when the proxy is HTTP-only (no TLS).
    secret_files: tuple[str, ...] = ()
    #: Whether the proxy was given a leaf and can terminate TLS.
    tls: bool = False


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

    def start_egress_proxy(
        self, *, grant: Mapping[str, Any], tool_side: Sequence[str],
        target_side: Sequence[str], run_id: str | None = None,
        leaf_cert_pem: str | None = None, leaf_key_pem: str | None = None,
    ) -> ProxyEndpoint:
        """Start the proxy bridging the tool-side and target-side networks.

        The grant is passed as one JSON argument at start time and cannot be
        changed afterwards: the proxy's life is one capability's life. There is
        no control socket, no reload, and no flag that widens it — a proxy that
        could be reconfigured while running would be a second place where
        authorization is decided, and §8.3 puts that decision upstream.

        The tool-side network is the *only* one the tool container joins, so
        the proxy is the only address it can reach. That is what makes the
        kernel the witness for "the tool cannot go around the proxy": the
        route is absent, not filtered.

        ``leaf_cert_pem`` / ``leaf_key_pem`` enable TLS termination (D35). They
        are written to 0600 host files and bind-mounted read-only, and only
        their *paths* are passed as arguments — the key never enters argv. The
        proxy runs as the host uid so it owns, and can read, that 0600 key. With
        neither, the proxy is HTTP-only and refuses CONNECT, the honest D34
        answer for "cannot inspect this tunnel". Both or neither: a cert
        without a key is a misconfiguration, not a mode.
        """
        if bool(leaf_cert_pem) != bool(leaf_key_pem):
            raise ValueError("leaf_cert_pem and leaf_key_pem must be given together")
        tool_side = validate_allowlist(tool_side)
        target_side = validate_allowlist(target_side)
        if set(tool_side) & set(target_side):
            raise ValueError(
                "the tool-side and target-side networks must be different "
                "ranges; sharing one would put the tool back on the target's "
                "network and leave the proxy advisory"
            )

        client = self.client()
        try:
            client.images.get(PROXY_IMAGE)
        except ImageNotFound as exc:
            raise SandboxUnavailable(
                f"image {PROXY_IMAGE!r} is not present. Build it with "
                "tool_gateway/images/build_egress_proxy_image.sh"
            ) from exc

        tool_network = self.ensure_network(tool_side)
        target_network = self.ensure_network(target_side)
        name = f"cyberorch-egress-{run_id or uuid.uuid4().hex[:12]}"

        proxy_args = [
            "--grant", json.dumps(grant, sort_keys=True),
            "--bind", "0.0.0.0", "--port", str(PROXY_PORT),
        ]
        volumes: dict[str, dict[str, str]] = {}
        secret_files: list[str] = []
        if leaf_cert_pem and leaf_key_pem:
            cert_path = _write_secret_tempfile(leaf_cert_pem)
            key_path = _write_secret_tempfile(leaf_key_pem)
            secret_files = [cert_path, key_path]
            volumes[cert_path] = {"bind": PROXY_LEAF_CERT_PATH, "mode": "ro"}
            volumes[key_path] = {"bind": PROXY_LEAF_KEY_PATH, "mode": "ro"}
            proxy_args += ["--leaf-cert", PROXY_LEAF_CERT_PATH,
                           "--leaf-key", PROXY_LEAF_KEY_PATH]

        container = client.containers.create(
            image=PROXY_IMAGE,
            # Arguments only. The image sets an ENTRYPOINT of
            # ["/usr/bin/python3", "-u", "/opt/egress_proxy.py"], so `command`
            # is *appended* to it rather than replacing it -- passing the
            # interpreter and script again put them in the proxy's own argv,
            # argparse refused them, and the container exited before binding.
            # The tests then reported an unreachable proxy, which is a true
            # statement about the wrong thing.
            command=proxy_args,
            volumes=volumes,
            # The uid that wrote the leaf key, so the key can stay 0600. Not
            # root: with every capability dropped, container root cannot read
            # another uid's 0600 file, and the fix that keeps the key private
            # is for the proxy to be its owner, not for the key to be readable
            # by everyone. The proxy binds a high port and writes nothing, so
            # it needs nothing root has.
            user=_host_user(),
            name=name,
            network=tool_network.name,
            # The proxy is confined exactly as the tool is. It holds no
            # credential and owns no decision the control plane did not
            # already make, so there is nothing it needs that the tool does
            # not, and a privileged proxy would be a way around the boundary
            # it exists to enforce.
            cap_drop=["ALL"],
            privileged=False,
            security_opt=["no-new-privileges:true"],
            read_only=True,
            mem_limit=self.memory_limit,
            pids_limit=self.pids_limit,
            labels={"cyberorch.egress_proxy": "1",
                    "cyberorch.run_id": run_id or ""},
        )
        try:
            target_network.connect(container)
            container.start()
            container.reload()
            networks = container.attrs["NetworkSettings"]["Networks"]
            address = networks[tool_network.name]["IPAddress"]
        except Exception:
            try:
                container.remove(force=True)
            except (DockerException, NotFound):
                pass
            _unlink_all(secret_files)
            raise

        if not address:
            try:
                container.remove(force=True)
            except (DockerException, NotFound):
                pass
            _unlink_all(secret_files)
            raise SandboxUnavailable(
                "the egress proxy has no address on the tool-side network"
            )

        try:
            self._wait_until_listening(container)
        except Exception:
            _unlink_all(secret_files)
            raise

        return ProxyEndpoint(
            container_id=container.id, name=name,
            url=f"http://{address}:{PROXY_PORT}",
            tool_side=tool_side, target_side=target_side,
            secret_files=tuple(secret_files), tls=bool(leaf_cert_pem),
        )

    @staticmethod
    def _wait_until_listening(container, timeout_seconds: float = 15.0) -> None:
        """Block until the proxy says it has bound its socket.

        ``start()`` returns when the container is created, not when the process
        inside it is listening, so without this the first request races the
        interpreter and the caller sees a connection refused. D31 learned this
        with the web target; the same gate is applied here rather than
        rediscovered.

        More importantly it makes a proxy that *never* starts report itself as
        that, with its own output attached. The alternative was what CI showed:
        four tests failing with "no_answer", which is a true statement about
        an unreachable address and says nothing about why.
        """
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
            if "egress proxy listening" in logs:
                return
            container.reload()
            if container.status != "running":
                break
            time.sleep(0.2)

        logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
        try:
            container.remove(force=True)
        except (DockerException, NotFound):
            pass
        raise SandboxUnavailable(
            "the egress proxy never started listening. Its output was:\n" + logs
        )

    def proxy_logs(self, endpoint: ProxyEndpoint) -> str:
        """The proxy container's output.

        Provided for operators and for diagnosing a failing run. Deliberately
        *not* what any test asserts a refusal with: a proxy reporting that it
        refused something is a proxy reporting on itself. The refusal is proven
        with the target's log, where the request is absent.
        """
        try:
            container = self.client().containers.get(endpoint.container_id)
            return container.logs(stdout=True, stderr=True).decode(errors="replace")
        except (DockerException, NotFound):
            return ""

    def stop_egress_proxy(self, endpoint: ProxyEndpoint) -> None:
        """Remove the proxy container and its leaf files. Networks outlive it."""
        try:
            self.client().containers.get(endpoint.container_id).remove(force=True)
        except (DockerException, NotFound):
            pass
        # The leaf key file is short-lived by design; do not leave it on the
        # host after the proxy that used it is gone.
        _unlink_all(endpoint.secret_files)

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
        stdin: str | None = None,
        ca_cert_pem: str | None = None,
    ) -> SandboxResult:
        """Execute ``command`` confined to ``network_allowlist``.

        ``max_duration_seconds`` is enforced by killing the container, not by
        asking the tool to stop. A budget the tool could ignore is a number in
        a database, not a limit.

        ``stdin`` feeds a request body to the tool without it appearing in
        argv (D34). web.post needs this: a body on the command line is visible
        in the process table and in the ``tool_run.started`` audit payload,
        argv has a length limit a legitimate body can exceed, and curl's
        ``--data-binary @<value>`` reads a *file* unless the value is exactly
        ``-``. Feeding stdin lets the sigil stay fixed at ``@-``, so no body
        value can ever name a path.

        ``ca_cert_pem`` is the per-engagement CA the egress proxy signs its
        leaf with (D35). It is bind-mounted read-only at ``TOOL_CA_PATH`` so the
        tool can trust the proxy's TLS termination — the adapter passes
        ``--cacert TOOL_CA_PATH``. It is the *public* certificate only; no
        private key reaches the tool. Left off for a plain-HTTP or nmap run.
        """
        allowlist = validate_allowlist(network_allowlist)
        self.ensure_image()
        client = self.client()

        run_id = run_id or uuid.uuid4().hex[:12]
        network = self.ensure_network(allowlist)
        container = None
        started = time.monotonic()
        ca_file: str | None = None
        volumes: dict[str, dict[str, str]] = {}
        if ca_cert_pem:
            # Public, so 0644: the tool runs as cap-dropped container root and
            # could not read a 0600 file owned by the host uid.
            ca_file = _write_public_tempfile(ca_cert_pem)
            volumes[ca_file] = {"bind": TOOL_CA_PATH, "mode": "ro"}

        try:
            container = client.containers.create(
                image=self.image,
                command=list(command),
                network=network.name,
                volumes=volumes,
                # Only opened when there is something to write. A container
                # with an open stdin nobody closes is a container waiting.
                stdin_open=stdin is not None,
                # The tool must not be able to widen its own confinement.
                cap_drop=["ALL"],
                privileged=False,
                security_opt=["no-new-privileges:true"],
                read_only=True,
                mem_limit=self.memory_limit,
                pids_limit=self.pids_limit,
                labels={"cyberorch.run_id": run_id},
            )
            # Attached before start, not after: a container that runs to
            # completion between start() and attach() leaves the write with
            # nowhere to go, and the tool waits on a stdin that never closes
            # until the sandbox kills it.
            payload_socket = None
            if stdin is not None:
                payload_socket = container.attach_socket(
                    params={"stdin": 1, "stream": 1}
                )

            container.start()

            if payload_socket is not None:
                raw = payload_socket._sock  # noqa: SLF001 - the SDK exposes no other handle
                try:
                    raw.sendall(stdin.encode("utf-8", "surrogatepass"))
                    # Without the shutdown the tool blocks reading a stdin that
                    # is never going to end, and the run dies on its deadline
                    # looking like a slow target.
                    raw.shutdown(socket.SHUT_WR)
                finally:
                    payload_socket.close()

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
            # The CA is public, but there is no reason to leave a copy of it on
            # the host after the run that mounted it is gone.
            if ca_file is not None:
                _unlink_all([ca_file])
