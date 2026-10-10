"""From an authorizing scope object to a network allowlist Docker accepts (D62, D-9).

The unit tests fix the derivation table: every skip code is reachable, and each boundary is on the
right side. The Docker tests re-measure what the derivation rests on -- how many containers an
internal bridge of each size actually holds -- on a real daemon, so a change in Docker's behaviour
turns this red instead of silently turning dispatches into failures.
"""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from docker.types import IPAMConfig, IPAMPool

from control_plane.scheduler import allowlist, vocab
from tests.test_scheduler_skips import _docker, _try_to_start_at
from tool_gateway.registry import ADAPTERS


def derive(action="network.scan", scope=("cidr", "10.1.0.0/24"), target=("ip", "10.1.0.9")):
    return allowlist.derive_network_allowlist(
        action=action, scope_type=scope[0], scope_value=scope[1],
        target_type=target[0], target_value=target[1])


@pytest.mark.parametrize("action", ["network.scan", "network.recon"])
def test_a_cidr_scope_is_its_own_allowlist(action):
    assert derive(action=action) == allowlist.Derived(allowlist=("10.1.0.0/24",))


@pytest.mark.parametrize("action", ["code.scan", "code.secrets"])
def test_a_code_action_joins_no_network(action):
    assert derive(action=action, scope=("repo", "https://example.invalid/x.git"),
                  target=("repo", "https://example.invalid/x.git")) == allowlist.Derived()


@pytest.mark.parametrize("action", sorted(set(ADAPTERS) - set(vocab.SUPPORTED_ACTIONS)))
def test_every_other_registered_action_is_not_supported_in_v0(action):
    assert derive(action=action).skip == vocab.ACTION_NOT_SUPPORTED


@pytest.mark.parametrize("cidr,expected", [
    ("10.1.0.0/24", None), ("10.1.0.0/28", None), ("10.1.0.0/29", None),
    ("10.1.0.0/30", vocab.SCOPE_TOO_NARROW), ("10.1.0.0/31", vocab.SCOPE_TOO_NARROW),
    ("10.1.0.0/32", vocab.SCOPE_TOO_NARROW),
])
def test_a_cidr_narrower_than_a_slash_29_is_skipped(cidr, expected):
    got = derive(scope=("cidr", cidr), target=("ip", "10.1.0.4"))
    assert got.skip == expected
    assert (got.allowlist is None) == (expected is not None)


@pytest.mark.parametrize("address", ["10.1.0.0", "10.1.0.4", "10.1.0.9", "10.1.0.16", "10.1.0.31",
                                     "2001:db8::9"])
@pytest.mark.parametrize("target", ["10.1.0.4", "10.1.0.255", "2001:db8::9"])
def test_an_ip_scope_is_always_skipped_never_widened(address, target):
    got = derive(scope=("ip", address), target=("ip", target))
    assert got == allowlist.Derived(skip=vocab.SCOPE_TOO_NARROW)


def test_nothing_derives_a_block_wider_than_the_authorized_scope():
    """The allowlist is the scope itself or nothing; the derivation has no way to enlarge it."""
    assert not hasattr(allowlist, "block_for_address")
    assert not hasattr(allowlist, "MAX_BLOCK_PREFIX")
    for value in ("10.1.0.0/24", "10.1.0.8/29", "10.1.0.64/26"):
        assert derive(scope=("cidr", value), target=("ip", "10.1.0.70")).allowlist in (
            (value,), None)


@pytest.mark.parametrize("scope,target,code", [
    (("fqdn", "example.invalid"), ("ip", "10.1.0.9"), vocab.SCOPE_TYPE_NO_RANGE),
    (("url", "http://10.1.0.9/"), ("ip", "10.1.0.9"), vocab.SCOPE_TYPE_NO_RANGE),
    (("cidr", "not-a-network"), ("ip", "10.1.0.9"), vocab.SCOPE_TYPE_NO_RANGE),
    (("cidr", "2001:db8::/64"), ("ip", "2001:db8::9"), vocab.IPV6_UNSUPPORTED),
    (("cidr", "10.1.0.0/24"), ("ip", "2001:db8::9"), vocab.IPV6_UNSUPPORTED),
])
def test_the_remaining_skip_codes_are_reachable(scope, target, code):
    assert derive(scope=scope, target=target).skip == code


@pytest.mark.parametrize("target", ["10.1.0.0", "10.1.0.1", "10.1.0.255"])
def test_a_target_on_the_network_gateway_or_broadcast_address_is_skipped(target):
    assert derive(target=("ip", target)).skip == vocab.TARGET_RESERVED


@pytest.mark.parametrize("target", ["10.1.0.2", "10.1.0.254"])
def test_the_first_and_last_usable_host_are_not(target):
    assert derive(target=("ip", target)).allowlist == ("10.1.0.0/24",)


def test_every_skip_code_the_derivation_can_return_is_in_the_closed_vocabulary():
    seen = set()
    for scope, target in [
        (("cidr", "10.1.0.0/30"), ("ip", "10.1.0.2")), (("ip", "10.1.0.9"), ("ip", "10.1.0.9")),
        (("fqdn", "x"), ("ip", "10.1.0.2")), (("cidr", "2001:db8::/64"), ("ip", "2001:db8::2")),
        (("cidr", "10.1.0.0/24"), ("ip", "10.1.0.1")),
    ]:
        seen.add(derive(scope=scope, target=target).skip)
    seen.add(derive(action="web.get").skip)
    assert seen == set(vocab.SKIP_REASONS)


# ---------------------------------------------------------------------------------------------
# what the table rests on, measured on a real daemon
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("prefix,capacity", [(32, 0), (31, 1), (30, 1), (29, 5), (28, 13)])
def test_an_internal_bridge_holds_this_many_containers(prefix, capacity):
    """Containers that start on an internal /N bridge, taking addresses in turn until the pool is
    exhausted. /29 holds 5: network, gateway and broadcast are not available to a container."""
    client = _docker()
    octet = {32: 80, 31: 82, 30: 84, 29: 88, 28: 96}[prefix]
    subnet = f"10.96.74.{octet}/{prefix}"
    name = f"probe-cap-{prefix}-{uuid.uuid4().hex[:6]}"
    try:
        network = client.networks.create(
            name, driver="bridge", internal=True,
            ipam=IPAMConfig(pool_configs=[IPAMPool(subnet=subnet)]))
    except Exception as exc:                                  # a /32 may be refused outright
        assert capacity == 0, exc
        return
    candidates = [str(a) for a in ipaddress.ip_network(subnet)]
    started = 0
    try:
        for address in candidates:
            if _try_to_start_at(client, name, address) is None:
                started += 1
        assert started == capacity, (subnet, started)
    finally:
        network.remove()
