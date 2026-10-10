"""From an authorizing scope object to a Docker-acceptable ``network_allowlist`` (D62, D-9).

Pure functions: no database, no Docker. What they encode was *measured* on a real daemon (and
``tests/test_scheduler_allowlist.py`` re-measures it): on an internal bridge a ``/32`` fits 0
containers, ``/31`` 1, ``/30`` 1, ``/29`` 5. Docker reserves the network address, the gateway (the
first host) and the broadcast address, and a target must be a container attached to the same
network, so the scanner plus the target need at least a ``/29``.

A skip is a *reason*, never a guess: the operator's only explanation for a proposal that did not run
is the code returned here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from control_plane.scheduler import vocab

#: Largest prefix length (smallest block) Docker can use for a scanner and a target.
MIN_BLOCK_PREFIX = 29


@dataclass(frozen=True)
class Derived:
    """An allowlist, or the reason there is none."""

    allowlist: tuple[str, ...] | None = None
    skip: str | None = None


def _reserved(address, block) -> bool:
    """Network, gateway (first host) or broadcast address of ``block``: no container can have it."""
    return address in (block.network_address, block.network_address + 1, block.broadcast_address)


def derive_network_allowlist(
    *, action: str, scope_type: str, scope_value: str, target_type: str, target_value: str,
) -> Derived:
    """The allowlist the execution step passes to ``dispatch_approved``, or the skip reason."""
    if action in vocab.CODE_ACTIONS:
        return Derived()                       # code scans join no network
    if action not in vocab.NETWORK_ACTIONS:
        return Derived(skip=vocab.ACTION_NOT_SUPPORTED)

    if scope_type == "ip":
        # One address cannot hold a scanner and a target. Widening it to a block would grant more
        # than was authorized (design note, D-9), so it is not run: a single-IP authorization needs
        # the sandbox to separate "what is authorized" from "the Docker network range".
        return Derived(skip=vocab.SCOPE_TOO_NARROW)
    if scope_type != "cidr":
        return Derived(skip=vocab.SCOPE_TYPE_NO_RANGE)
    try:
        scope = ipaddress.ip_network(scope_value, strict=False)
    except ValueError:
        return Derived(skip=vocab.SCOPE_TYPE_NO_RANGE)
    if scope.version != 4:
        return Derived(skip=vocab.IPV6_UNSUPPORTED)

    if scope.prefixlen > MIN_BLOCK_PREFIX:
        return Derived(skip=vocab.SCOPE_TOO_NARROW)
    block = scope

    if target_type == "ip":
        try:
            target = ipaddress.ip_address(target_value)
        except ValueError:
            return Derived(skip=vocab.SCOPE_TYPE_NO_RANGE)
        if target.version != 4:
            return Derived(skip=vocab.IPV6_UNSUPPORTED)
        if _reserved(target, block):
            return Derived(skip=vocab.TARGET_RESERVED)
    return Derived(allowlist=(str(block),))
