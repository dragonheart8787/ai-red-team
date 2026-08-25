"""Target normalizer tests (§4.1, §5)."""

from __future__ import annotations

import pytest

from control_plane.canonicalizer.target import (
    CanonicalizationError,
    normalize_path,
    normalize_target,
)


def _fqdn(value: str, **kw):
    return normalize_target({"logical_identity": {"type": "fqdn", "value": value}, **kw})


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("APP.Customer-A.com", "app.customer-a.com"),
        ("app.customer-a.com.", "app.customer-a.com"),
        ("  app.customer-a.com  ", "app.customer-a.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("Bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_fqdn_normalization(raw, expected):
    assert _fqdn(raw).logical_identity.value == expected


@pytest.mark.parametrize("raw", ["", "  ", "a..b.com", "-bad.example.com", "a b.com"])
def test_malformed_fqdn_is_an_error_not_a_guess(raw):
    """I10: an unparseable target fails closed rather than being repaired."""
    with pytest.raises(CanonicalizationError):
        _fqdn(raw)


def test_ip_literal_is_not_an_fqdn():
    """§4.1.5 keeps name authorization and address authorization apart."""
    with pytest.raises(CanonicalizationError):
        _fqdn("203.0.113.17")


@pytest.mark.parametrize(
    "raw,expected",
    [("203.0.113.17", "203.0.113.17"), ("2001:0db8::0001", "2001:db8::1")],
)
def test_ip_normalization(raw, expected):
    target = normalize_target({"logical_identity": {"type": "ip", "value": raw}})
    assert target.logical_identity.value == expected


def _cidr(value: str):
    return normalize_target({"logical_identity": {"type": "cidr", "value": value}})


@pytest.mark.parametrize(
    "raw", ["10.20.0.5/24", "10.20.0.1/8", "192.168.1.100/16", "2001:db8::1/32"]
)
def test_cidr_with_host_bits_is_an_error_not_a_widening(raw):
    """The replacement for a test that asserted the opposite (D11-5).

    This used to be ``test_cidr_normalization_masks_host_bits``, and the
    masking it pinned was a real hole rather than a tidy-up. ``10.20.0.5/24``
    reads as one host; masking turns it into 256 addresses, and D11 followed
    that all the way to ``nmap ... 10.20.0.0/24``. Two readings, and the
    normalizer silently took the wider one — in a module whose stated rule is
    that ambiguity is an error, not a guess (I10).
    """
    with pytest.raises(CanonicalizationError, match="host bits"):
        _cidr(raw)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("10.20.0.0/24", "10.20.0.0/24"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("10.20.0.5/32", "10.20.0.5/32"),
        ("  10.20.0.0/24  ", "10.20.0.0/24"),
        ("2001:db8::/32", "2001:db8::/32"),
    ],
)
def test_a_properly_written_network_still_normalizes(raw, expected):
    """The control. Without it, refusing every cidr would pass the test above.

    ``/32`` is in the list on purpose: a single host written as a network has
    no host bits set, so it stays legal — that is how a caller says "this one
    address" in cidr form, and the strict rule must not take it away.
    """
    target = _cidr(raw)
    assert target.logical_identity.value == expected


def test_a_malformed_cidr_says_so_rather_than_blaming_host_bits():
    """The two failures are different problems and read differently."""
    with pytest.raises(CanonicalizationError, match="invalid cidr") as excinfo:
        _cidr("10.20.0.0/99")
    assert "host bits" not in str(excinfo.value)


def test_address_count_is_what_the_policy_will_compare():
    """§4.6/I3: the field the budget check reads, at the source.

    A cidr counts its addresses; everything else counts one, and for an fqdn
    that is a statement about the identity rather than about how many hosts
    the name reaches — this module never resolves anything.
    """
    assert _cidr("10.20.0.0/24").address_count == 256
    assert _cidr("10.20.0.5/32").address_count == 1
    assert normalize_target(
        {"logical_identity": {"type": "ip", "value": "10.20.0.5"}}
    ).address_count == 1
    assert _fqdn("app.customer-a.com").address_count == 1


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/api//profile", "/api/profile"),
        ("/api/../admin", "/admin"),
        ("/api/./profile", "/api/profile"),
        ("api/profile", "/api/profile"),
        ("/api/profile/", "/api/profile/"),
        ("/", "/"),
    ],
)
def test_path_normalization(raw, expected):
    """Two spellings of one path must not become two targets."""
    assert normalize_path(raw) == expected


def test_url_normalization_drops_default_port_and_resolves_dot_segments():
    target = normalize_target(
        {"logical_identity": {"type": "url",
                              "value": "HTTPS://App.Customer-A.com:443/api/../profile"}}
    )
    assert target.logical_identity.value == "https://app.customer-a.com/profile"
    assert target.port == 443
    assert target.path == "/profile"


def test_normalizer_does_not_resolve_anything():
    """§8.9: normalization must not manufacture a network binding.

    A target with no binding keeps none — the normalizer has no DNS in it, so
    there is no path by which discovery could produce routing information that
    later reads as authorization.
    """
    assert _fqdn("app.customer-a.com").network_binding is None


def test_network_binding_is_carried_but_not_part_of_identity():
    target = normalize_target({
        "logical_identity": {"type": "fqdn", "value": "app.customer-a.com"},
        "network_binding": {"ip": "203.0.113.17", "dns_ttl": 300},
    })
    assert target.network_binding.ip == "203.0.113.17"
    assert "203.0.113.17" not in target.normalized


def test_normalized_form_is_stable_across_spellings():
    a = normalize_target({
        "logical_identity": {"type": "fqdn", "value": "APP.Customer-A.com."},
        "port": 443, "path": "/api/../profile",
    })
    b = normalize_target({
        "logical_identity": {"type": "fqdn", "value": "app.customer-a.com"},
        "port": 443, "path": "/profile",
    })
    assert a.normalized == b.normalized == "fqdn:app.customer-a.com:443/profile"


@pytest.mark.parametrize("port", [0, 65536, -1, "443", 4.5, True])
def test_invalid_port_is_rejected(port):
    with pytest.raises(CanonicalizationError):
        _fqdn("app.customer-a.com", port=port)


def test_unknown_identity_type_is_rejected():
    with pytest.raises(CanonicalizationError):
        normalize_target({"logical_identity": {"type": "mainframe", "value": "x"}})
