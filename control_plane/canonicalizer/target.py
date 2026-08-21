"""Target normalization (§4.1, §5).

Turns the ``target`` block of an Action Proposal into a canonical form that the
resolvers and the execution fingerprint (§7) can both rely on.

Two rules shape this module:

* **It never resolves anything.** No DNS, no connections, no enrichment. A
  normalizer that resolved names would be manufacturing ``network_binding``
  values, and §8.9/I8 is explicit that finding out where packets go is not the
  same as being authorized to send them. Whatever binding the proposal carries
  is passed through untouched and is never consulted for authorization.
* **Ambiguity is an error, not a guess.** A target that cannot be normalized
  raises :class:`CanonicalizationError` rather than being normalized to
  something plausible; I10 wants authorization-critical attributes to fail
  closed when they are unclear.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Identity types accepted here mirror the scope object types in §4.1.5.
IDENTITY_TYPES = frozenset({"fqdn", "ip", "cidr", "url", "repo", "ad_domain"})

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class CanonicalizationError(ValueError):
    """The target cannot be normalized, so no action may proceed on it."""


@dataclass(frozen=True)
class LogicalIdentity:
    """What the target *is* — the thing authorization is granted against."""

    type: str
    value: str


@dataclass(frozen=True)
class NetworkBinding:
    """Where packets would go. Routing information only (§8.9).

    Deliberately not part of :attr:`CanonicalTarget.normalized`: two proposals
    against the same host are the same execution even if DNS handed back a
    different address in between.
    """

    ip: str | None = None
    resolved_at: str | None = None
    dns_ttl: int | None = None


@dataclass(frozen=True)
class CanonicalTarget:
    logical_identity: LogicalIdentity
    network_binding: NetworkBinding | None
    port: int | None
    path: str | None

    @property
    def normalized(self) -> str:
        """Stable string form, used in the §7 execution fingerprint."""
        base = f"{self.logical_identity.type}:{self.logical_identity.value}"
        if self.port is not None:
            base += f":{self.port}"
        if self.path:
            base += self.path
        return base

    @property
    def address_count(self) -> int:
        """How many addresses this target names (§4.6 ``max_targets``, I3).

        The number the policy compares against the requested budget. It exists
        because D11 watched a capability recording ``max_targets: 1`` execute a
        scan against 256 addresses: a ``cidr`` target is one *identity* and one
        proposal, and the count of things it touches was nowhere in the input.

        A property rather than a stored field, so it cannot drift from the
        identity it describes.

        **Everything that is not a cidr counts as one, and that is a statement
        about the identity, not about reachability.** An fqdn may resolve to
        any number of addresses; this module never resolves anything (§8.9/I8),
        so it does not know and must not pretend to. One name is one target.
        A budget meant to bound how many *hosts* a name reaches is not a thing
        this field can provide, and reading it that way would be the v0.2 bug
        where discovery quietly widened scope.
        """
        if self.logical_identity.type != "cidr":
            return 1
        return ipaddress.ip_network(self.logical_identity.value).num_addresses

    def as_dict(self) -> dict[str, Any]:
        return {
            "logical_identity": {
                "type": self.logical_identity.type,
                "value": self.logical_identity.value,
            },
            "network_binding": (
                {
                    "ip": self.network_binding.ip,
                    "resolved_at": self.network_binding.resolved_at,
                    "dns_ttl": self.network_binding.dns_ttl,
                }
                if self.network_binding
                else None
            ),
            "port": self.port,
            "path": self.path,
            "normalized": self.normalized,
            "address_count": self.address_count,
        }


def normalize_fqdn(value: str) -> str:
    """Lowercase, drop the root dot, punycode any non-ASCII labels.

    Rejects anything that parses as an IP literal: an address reached through
    a name is still an address, and §4.1.5 keeps those two authorization types
    apart.
    """
    host = value.strip().rstrip(".").lower()
    if not host:
        raise CanonicalizationError("empty fqdn")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise CanonicalizationError(f"{value!r} is an IP literal, not an fqdn")

    labels = host.split(".")
    out = []
    for label in labels:
        if not label:
            raise CanonicalizationError(f"empty label in fqdn {value!r}")
        if not label.isascii():
            try:
                label = label.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise CanonicalizationError(f"cannot encode label {label!r}: {exc}") from exc
        if not _LABEL.match(label):
            raise CanonicalizationError(f"invalid label {label!r} in fqdn {value!r}")
        out.append(label)
    return ".".join(out)


def normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise CanonicalizationError(f"invalid ip {value!r}: {exc}") from exc


def normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise CanonicalizationError(f"invalid cidr {value!r}: {exc}") from exc


def normalize_path(path: str | None) -> str | None:
    """Collapse duplicate slashes and resolve dot segments.

    ``/api/../admin`` and ``/admin`` must not be two different targets, or a
    path-scoped constraint could be sidestepped by spelling it differently.
    """
    if path is None or path == "":
        return None
    raw = path if path.startswith("/") else "/" + path
    trailing = raw.endswith("/") and raw != "/"
    segments: list[str] = []
    for segment in raw.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    out = "/" + "/".join(segments)
    if trailing and out != "/":
        out += "/"
    return out


def normalize_url(value: str) -> tuple[str, int | None, str | None]:
    """Return (canonical url, port, path)."""
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise CanonicalizationError(f"unsupported url scheme {parts.scheme!r}")
    if not parts.hostname:
        raise CanonicalizationError(f"url {value!r} has no host")

    try:
        host = normalize_ip(parts.hostname)
        host_repr = f"[{host}]" if ":" in host else host
    except CanonicalizationError:
        host = normalize_fqdn(parts.hostname)
        host_repr = host

    try:
        port = parts.port
    except ValueError as exc:
        raise CanonicalizationError(f"invalid port in url {value!r}: {exc}") from exc
    if port == _DEFAULT_PORTS[scheme]:
        port = None

    path = normalize_path(parts.path)
    netloc = host_repr if port is None else f"{host_repr}:{port}"
    canonical = urlunsplit((scheme, netloc, path or "/", "", ""))
    return canonical, port or _DEFAULT_PORTS[scheme], path


def normalize_target(target: Mapping[str, Any]) -> CanonicalTarget:
    """Normalize a §4.1 ``target`` block."""
    identity = target.get("logical_identity")
    if not isinstance(identity, Mapping):
        raise CanonicalizationError("target.logical_identity is missing")

    itype = identity.get("type")
    ivalue = identity.get("value")
    if itype not in IDENTITY_TYPES:
        raise CanonicalizationError(f"unknown logical_identity.type {itype!r}")
    if not isinstance(ivalue, str) or not ivalue.strip():
        raise CanonicalizationError("logical_identity.value must be a non-empty string")

    port = target.get("port")
    if port is not None:
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            raise CanonicalizationError(f"invalid port {port!r}")
    path = normalize_path(target.get("path"))

    if itype == "fqdn":
        value = normalize_fqdn(ivalue)
    elif itype == "ip":
        value = normalize_ip(ivalue)
    elif itype == "cidr":
        value = normalize_cidr(ivalue)
    elif itype == "url":
        value, url_port, url_path = normalize_url(ivalue)
        port = port if port is not None else url_port
        path = path if path is not None else url_path
    else:  # repo, ad_domain — opaque identifiers, compared verbatim
        value = ivalue.strip()

    binding_raw = target.get("network_binding")
    binding = None
    if isinstance(binding_raw, Mapping):
        ip = binding_raw.get("ip")
        binding = NetworkBinding(
            # Normalized for readability only; nothing reads this for a decision.
            ip=normalize_ip(ip) if isinstance(ip, str) and ip else None,
            resolved_at=binding_raw.get("resolved_at"),
            dns_ttl=binding_raw.get("dns_ttl"),
        )

    return CanonicalTarget(
        logical_identity=LogicalIdentity(type=itype, value=value),
        network_binding=binding,
        port=port,
        path=path,
    )
