"""Per-engagement CA and per-host leaf certificates (D35).

The proxy's TLS termination rests on this: a CA the tool trusts, scoped to one
engagement, whose private key never leaves the control plane. The tests hold
three properties:

1. the crypto is real — a leaf chains to the CA and carries the right SAN;
2. the CA is persisted once per engagement and isolated by RLS, so one
   engagement cannot read another's;
3. the CA key is as unreachable to the read roles as ``credentials`` is, and
   never appears in an audit record.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from control_plane.state.db import (
    engagement_scope,
    global_auditor_scope,
    registry_admin_scope,
    ui_reader_scope,
)
from control_plane.tls.engagement_ca import (
    CA_TTL_DAYS,
    LEAF_TTL_HOURS,
    ensure_engagement_ca,
    generate_ca,
    mint_leaf_for_host,
    sign_leaf,
)


def _make_engagement(conn, eid: str) -> None:
    conn.execute(
        text("INSERT INTO engagements (engagement_id, customer_id, "
             "policy_snapshot_version) VALUES (:e, 'CUST-TEST', 1)"),
        {"e": eid},
    )


# ---------------------------------------------------------------------------
# 1. The crypto is real
# ---------------------------------------------------------------------------

def test_a_leaf_chains_to_the_ca_that_signed_it():
    ca = generate_ca("ENG-1")
    leaf = sign_leaf(ca, "10.78.0.10")
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    leaf_cert = x509.load_pem_x509_certificate(leaf.leaf_cert_pem.encode())

    # The CA's public key verifies the leaf's signature — a real chain, not two
    # unrelated certs that merely share a name.
    ca_cert.public_key().verify(
        leaf_cert.signature, leaf_cert.tbs_certificate_bytes,
        ec.ECDSA(leaf_cert.signature_hash_algorithm),
    )
    assert leaf_cert.issuer == ca_cert.subject


def test_the_ca_is_a_ca_and_the_leaf_is_not():
    ca = generate_ca("ENG-1")
    leaf = sign_leaf(ca, "10.78.0.10")
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    leaf_cert = x509.load_pem_x509_certificate(leaf.leaf_cert_pem.encode())
    assert ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert not leaf_cert.extensions.get_extension_for_class(
        x509.BasicConstraints).value.ca


@pytest.mark.parametrize("host,kind", [
    ("10.78.0.10", x509.IPAddress),
    ("app.staging.example.com", x509.DNSName),
])
def test_the_san_matches_the_host_kind(host, kind):
    """An IP host needs an IPAddress SAN and a name needs a DNSName.

    curl verifies the leaf's SAN against the host it dialled; the wrong kind
    fails the handshake with a name-mismatch that reads like a proxy bug.
    """
    leaf = sign_leaf(generate_ca("E"), host)
    cert = x509.load_pem_x509_certificate(leaf.leaf_cert_pem.encode())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert len(list(sans)) == 1
    assert isinstance(list(sans)[0], kind)


def test_the_leaf_lives_hours_and_the_ca_lives_longer():
    """A leaf is minted per run and thrown away; a long life buys nothing."""
    ca = generate_ca("E")
    leaf = sign_leaf(ca, "10.78.0.10")
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    leaf_cert = x509.load_pem_x509_certificate(leaf.leaf_cert_pem.encode())
    ca_span = ca_cert.not_valid_after_utc - ca_cert.not_valid_before_utc
    leaf_span = leaf_cert.not_valid_after_utc - leaf_cert.not_valid_before_utc
    assert leaf_span.total_seconds() < ca_span.total_seconds()
    assert leaf_span.total_seconds() <= (LEAF_TTL_HOURS + 1) * 3600
    assert ca_span.days >= CA_TTL_DAYS - 1


def test_the_leaf_carries_the_ca_cert_but_not_the_ca_key():
    """What the proxy is handed: the leaf, and the CA's *public* cert only."""
    ca = generate_ca("E")
    leaf = sign_leaf(ca, "10.78.0.10")
    assert leaf.ca_cert_pem == ca.cert_pem
    assert leaf.leaf_key_pem != ca.key_pem
    # The CA private key is nowhere in what the proxy receives.
    assert "PRIVATE KEY" in leaf.leaf_key_pem
    assert ca.key_pem not in (leaf.leaf_cert_pem + leaf.ca_cert_pem)


# ---------------------------------------------------------------------------
# 2. Persistence and engagement isolation
# ---------------------------------------------------------------------------

def test_the_ca_is_generated_once_and_then_stable(engagement_id):
    with engagement_scope(engagement_id) as conn:
        first = ensure_engagement_ca(conn, engagement_id)
        second = ensure_engagement_ca(conn, engagement_id)
    assert first.cert_pem == second.cert_pem
    assert first.key_pem == second.key_pem


def test_one_engagements_ca_cannot_be_read_from_another(engagement_factory):
    """I4: the CA is engagement-scoped like every other secret.

    A connection bound to engagement B sees no row for engagement A — the same
    RLS boundary that isolates credentials, applied to the signing key.
    """
    eid_a, _ = engagement_factory()
    eid_b, _ = engagement_factory()
    with engagement_scope(eid_a) as conn:
        ensure_engagement_ca(conn, eid_a)

    with engagement_scope(eid_b) as conn:
        # B's own row does not exist yet, and A's is invisible to B.
        rows = conn.execute(
            text("SELECT engagement_id FROM engagement_ca")
        ).scalars().all()
        assert eid_a not in rows


def test_minting_a_leaf_gives_the_engagements_own_ca(engagement_id):
    with engagement_scope(engagement_id) as conn:
        ca = ensure_engagement_ca(conn, engagement_id)
        leaf = mint_leaf_for_host(conn, engagement_id, "10.78.0.10")
    assert leaf.ca_cert_pem == ca.cert_pem
    assert leaf.host == "10.78.0.10"


# ---------------------------------------------------------------------------
# 3. Least privilege — the CA key is as protected as credentials
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scope_factory", [
    ui_reader_scope, registry_admin_scope, global_auditor_scope,
])
def test_no_read_role_can_reach_the_ca_key(engagement_id, scope_factory):
    """None of the read roles was granted engagement_ca (§8.6, D35).

    The CA private key is the most sensitive value in the schema; it is reached
    only by cyberorch_app, RLS-scoped to its own engagement. The read roles
    grant SELECT on named tables and this is not one of them, so a new table is
    invisible to them by construction — the same standard as ``credentials``.
    """
    with engagement_scope(engagement_id) as conn:
        ensure_engagement_ca(conn, engagement_id)

    # global_auditor takes no engagement; the others do. Both call styles land
    # in a context manager, so normalise on that.
    def opened():
        try:
            return scope_factory(engagement_id)
        except TypeError:
            return scope_factory()

    with pytest.raises(ProgrammingError, match="permission denied"):
        with opened() as conn:
            conn.execute(text("SELECT ca_key_pem FROM engagement_ca"))


def test_the_provisioning_audit_record_does_not_carry_the_key(engagement_id):
    """Auditing the key would be the leak the audit is meant to detect."""
    with engagement_scope(engagement_id) as conn:
        ca = ensure_engagement_ca(conn, engagement_id)

    with engagement_scope(engagement_id) as conn:
        payloads = conn.execute(
            text("SELECT payload::text FROM audit_log "
                 "WHERE event_type = 'egress_ca.provisioned' "
                 "AND engagement_id = :e"),
            {"e": engagement_id},
        ).scalars().all()

    assert payloads, "provisioning was not audited"
    key_body = ca.key_pem.split("\n")[1]  # a chunk of the base64 key
    for payload in payloads:
        assert key_body not in payload
        assert "PRIVATE KEY" not in payload
