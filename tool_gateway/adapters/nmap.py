"""Nmap adapter — Capability constraints to scan arguments (§4.6, §7).

Nmap rather than Nuclei for MVP-Kernel: §4.1.5's scope types are fqdn and cidr,
and a network scan exercises the CIDR allowlist directly. Nuclei's budget is
HTTP-shaped, and §8.3 routes HTTP through the egress proxy that §10 defers.

The adapter owns the tool-specific half of §4.6's budget. The control plane
knows about duration, targets and concurrency; what a port range means is the
adapter's business, and stays here so a second tool does not have to be
generalized for before it exists.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

TOOL = "nmap"

# Scan techniques the adapter will emit. -sT (TCP connect) is the default
# because the sandbox drops every capability including NET_RAW: a SYN scan
# would need the container to hold a capability that also lets it reshape its
# own network namespace, which would make the §8.3 boundary advisory. A slower
# scan is the right trade.
SCAN_TYPES = {
    "connect": "-sT",
    "ping": "-sn",
    "version": "-sV",
}

_PORT_SPEC = re.compile(r"^[0-9,\-]+$")
_OPEN_PORT = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S*)", re.MULTILINE)
_HOST_LINE = re.compile(r"Nmap scan report for (\S+)")


class AdapterError(ValueError):
    """The capability cannot be turned into a scan."""


@dataclass(frozen=True)
class NmapPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    target: str
    ports: str | None
    scan_type: str
    max_duration_seconds: int

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint."""
        return {
            "target": self.target,
            "ports": self.ports,
            "scan_type": self.scan_type,
        }


def tool_version() -> str:
    """The installed nmap version, for the fingerprint (§7).

    §7 puts tool_version in the fingerprint so a scan is not treated as
    already-done after the tool changes underneath it.
    """
    binary = shutil.which("nmap")
    if binary is None:
        return "unknown"
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return "unknown"
    match = re.search(r"Nmap version (\S+)", out)
    return match.group(1) if match else "unknown"


def validate_ports(spec: str | None) -> str | None:
    if spec is None or spec == "":
        return None
    if not _PORT_SPEC.match(spec):
        raise AdapterError(
            f"invalid port specification {spec!r}: digits, commas and hyphens only"
        )
    return spec


def build_plan(
    *,
    constraints: Mapping[str, Any],
    budget: Mapping[str, Any],
    target: str,
) -> NmapPlan:
    """Turn a capability into a concrete scan.

    ``max_duration_seconds`` reaches nmap twice over. ``--host-timeout`` asks
    it to stop, and the sandbox kills the container at the same deadline. The
    sandbox is the one that counts — a tool that has stopped responding will
    not honour its own timeout — but passing it in as well means a well-behaved
    run ends cleanly with partial output rather than being killed mid-write.
    """
    if not target:
        raise AdapterError("no target")

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    tool_budget = budget.get("tool") or {}
    ports = validate_ports(constraints.get("ports") or tool_budget.get("allowed_ports"))

    scan_type = constraints.get("scan_type", "connect")
    if scan_type not in SCAN_TYPES:
        raise AdapterError(
            f"unsupported scan_type {scan_type!r}; expected one of {sorted(SCAN_TYPES)}"
        )

    command: list[str] = ["/usr/bin/nmap", SCAN_TYPES[scan_type]]
    command.append("-n")
    if scan_type != "ping":
        # -Pn: the sandbox has no route off the allowlist, so an unanswered
        # ping says nothing useful and skipping discovery keeps the run inside
        # budget. Not added to -sn, whose entire job is that discovery.
        command.append("-Pn")
    if ports and scan_type != "ping":
        command += ["-p", ports]
    command += ["--host-timeout", f"{max_duration}s"]
    command.append(target)

    return NmapPlan(
        command=tuple(command), target=target, ports=ports,
        scan_type=scan_type, max_duration_seconds=max_duration,
    )


def derive_view(stdout: str, stderr: str, *, truncated_at: int = 4000) -> dict[str, Any]:
    """Build the §4.4 derived view — the only thing an LLM is shown.

    Everything here is marked untrusted, because all of it came from the
    target. §5 renamed this tier OBSERVED for the same reason: nmap parsed the
    banner honestly, which says nothing about whether the banner is true. A
    service claiming to be "nginx 1.18" is a claim by the scanned host.
    """
    scanned = [
        {"port": int(port), "protocol": proto, "state": state, "service": service or None}
        for port, proto, state, service in _OPEN_PORT.findall(stdout)
    ]
    open_ports = [p for p in scanned if p["state"] == "open"]
    filtered_ports = [p for p in scanned if p["state"] == "filtered"]
    hosts = _HOST_LINE.findall(stdout)

    return {
        "untrusted_content": True,
        "hosts": hosts,
        "ports": scanned,
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "port_count": len(open_ports),
        # Nmap's own words for "I could not route to this address". Present
        # only for scan types that do their own routing (-sn, raw scans).
        #
        # Not a security signal, and named so nobody reads it as one. Under -Pn
        # with a connect scan, a target the namespace has no route to is
        # reported as "host up, port filtered" -- the same thing a firewall in
        # front of a reachable host produces. Confirming that the §8.3 boundary
        # held requires DockerSandbox.probe_egress, which asks the kernel
        # instead of the scanner.
        "nmap_reported_no_route": "failed to determine route" in f"{stdout}{stderr}",
        "stdout_excerpt": stdout[:truncated_at],
        "stderr_excerpt": stderr[:truncated_at],
        "stdout_truncated": len(stdout) > truncated_at,
    }
