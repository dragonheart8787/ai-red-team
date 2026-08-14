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


def test_cidr_normalization_masks_host_bits():
    target = normalize_target(
        {"logical_identity": {"type": "cidr", "value": "10.20.0.5/24"}}
    )
    assert target.logical_identity.value == "10.20.0.0/24"


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
