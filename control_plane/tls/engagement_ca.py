"""Per-engagement CA, and per-host leaf certificates for the egress proxy (D35).

D34 built the egress proxy but refused TLS: inside a TLS session it could see
only the hostname the tool asked to connect to, which is a self-report, and D31
established that a check the tool can narrate is not a check. D35 removes the
refusal by terminating TLS at the proxy — which needs a certificate the tool
will trust for the host it is talking to.

The shape of the trust, and why
--------------------------------
**One CA per engagement, never a global one.** A global signing CA would be a
single key whose leak lets an attacker impersonate any host in any engagement
— it would sit above the I4 engagement boundary the whole system is built to
hold. So each engagement gets its own CA, stored in an RLS-scoped table that
`cyberorch_app` can read only while bound to that engagement. One engagement's
CA cannot be read from inside another, by the same mechanism that keeps every
other per-engagement secret apart.

**The CA private key never enters the sandbox.** This is the same judgement
D34 recorded as 5.12 — the in-container proxy has no database connection. The
control plane holds the CA key and signs; the proxy is handed only a leaf
certificate and its key, for the single host the capability names, valid for
hours. A compromised proxy container leaks one short-lived leaf for one host,
not the power to mint certs.

**One leaf, minted once, per proxy launch — no on-the-fly signing, no cache.**
D34 established that one capability authorises exactly one host. So the proxy
never faces a second host and never needs to sign on demand: the control plane
mints the single leaf when it builds the grant, hands it in, and it lives as
long as the proxy does. The "per-host signing cadence" question the brief
raised answers itself once the one-capability-one-host invariant is taken
seriously — there is no cadence because there is no second host.

What this cannot do (recorded, not hidden)
-------------------------------------------
A target that pins a certificate — that ships a copy of the real cert or its
key and refuses anything else — cannot be intercepted, because our leaf is
signed by a CA it was never told to trust. §8.3 named this when it deferred the
proxy. For the disposable targets this platform tests it is not a problem; for
a real customer target that pins, it is a hard limit, and the honest position
is that the tool cannot see inside such a connection rather than that it
somehow can. The cert-pinning test exists to keep that true: it asserts the
connection is *refused at the TLS layer*, a failure that must stay legible as
"pinning, working as designed" and never blur into "the proxy is broken".
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

#: How long a per-host leaf is valid. Hours, not days: it is minted for one
#: run and thrown away with the proxy, so a long life buys nothing and a short
#: one bounds the blast radius of a leaked leaf key.
LEAF_TTL_HOURS = 12

#: How long a per-engagement CA is valid. It outlives many runs but not the
#: engagement; a year is generous and still finite.
CA_TTL_DAYS = 365

_BACKDATE = _dt.timedelta(minutes=5)  # tolerate small clock skew between hosts


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _san_for_host(host: str) -> x509.GeneralName:
    """A SAN entry of the right kind for ``host``.

    curl verifies the leaf's SAN against the host it dialled. An IP host needs
    an ``IPAddress`` SAN and a name needs a ``DNSName``; getting this wrong
    makes the handshake fail with a name-mismatch that reads like a proxy bug
    rather than what it is.
    """
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


@dataclass(frozen=True)
class CAMaterial:
    """A per-engagement CA: the public cert, and the private key to sign with.

    The key half never leaves the control plane. This object is assembled
    inside an engagement-scoped transaction and used immediately to sign a
    leaf; it is not handed to the proxy.
    """

    cert_pem: str
    key_pem: str


@dataclass(frozen=True)
class LeafMaterial:
    """What the proxy is given: a leaf for one host, and the CA's public cert.

    ``ca_cert_pem`` is the *public* certificate only — it goes into the tool's
    trust store so the tool will accept the leaf. No private key here is the
    CA's; ``leaf_key_pem`` is the leaf's own, short-lived and single-host.
    """

    host: str
    ca_cert_pem: str
    leaf_cert_pem: str
    leaf_key_pem: str


def generate_ca(engagement_id: str) -> CAMaterial:
    """Create a fresh CA for one engagement.

    EC P-256 rather than RSA: smaller, faster to generate, and every TLS
    stack this touches supports it. The name carries the engagement id so a
    stray certificate in a log is traceable to where it came from.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cyberorch egress proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"cyberorch-ca:{engagement_id}"),
    ])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + _dt.timedelta(days=CA_TTL_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return CAMaterial(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def sign_leaf(ca: CAMaterial, host: str, *, ttl_hours: int = LEAF_TTL_HOURS) -> LeafMaterial:
    """Sign a leaf certificate for one host with the engagement CA."""
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca.key_pem.encode(), password=None)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + _dt.timedelta(hours=ttl_hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([_san_for_host(host)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return LeafMaterial(
        host=host,
        ca_cert_pem=ca.cert_pem,
        leaf_cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        leaf_key_pem=leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def leaf_spki_pin(leaf_cert_pem: str) -> str:
    """The base64 SHA-256 of the leaf's SubjectPublicKeyInfo (D36).

    This is exactly the value Chromium's
    ``--ignore-certificate-errors-spki-list`` accepts: the browser trusts a
    server certificate iff its SPKI hashes to one on the list. The browser tool
    reaches the target only through the egress proxy, which presents this
    per-run leaf (D35); pinning its SPKI means the browser trusts that leaf and
    nothing else — not the engagement CA, not the public roots — the same "pin
    our own leaf" shape as D35's curl ``--cacert``, one step tighter because it
    names the exact key rather than the issuer. A pinning target's own leaf,
    signed by a CA the browser was never told to trust, still fails cleanly.
    """
    import base64
    import hashlib

    cert = x509.load_pem_x509_certificate(leaf_cert_pem.encode())
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki_der).digest()).decode()


# ---------------------------------------------------------------------------
# Persistence — control plane only, engagement-scoped, never reached by the proxy
# ---------------------------------------------------------------------------
#
# Imported lazily-ish at module bottom so the pure-crypto functions above have
# no database dependency and can be unit-tested without a connection.

from sqlalchemy import Connection, text  # noqa: E402

from control_plane.audit.logger import record_audit  # noqa: E402


def ensure_engagement_ca(conn: Connection, engagement_id: str) -> CAMaterial:
    """Return this engagement's CA, generating and storing it on first use.

    Runs inside an engagement-scoped transaction, so the RLS policy on
    ``engagement_ca`` means the row read or written can only be this
    engagement's. ``cyberorch_app`` is the sole role granted access; the read
    roles (ui_reader, registry_admin, global_auditor) were never granted it,
    so the CA private key is as unreachable to them as ``credentials`` is.
    """
    row = conn.execute(
        text("SELECT ca_cert_pem, ca_key_pem FROM engagement_ca "
             "WHERE engagement_id = :eid"),
        {"eid": engagement_id},
    ).mappings().one_or_none()
    if row is not None:
        return CAMaterial(cert_pem=row["ca_cert_pem"], key_pem=row["ca_key_pem"])

    ca = generate_ca(engagement_id)
    # ON CONFLICT DO NOTHING closes the race between two dispatches creating the
    # first capability for a new engagement at once: one insert wins, and both
    # then read the winner rather than one clobbering the other's CA (which
    # would invalidate a leaf already handed to a running proxy).
    conn.execute(
        text("""
            INSERT INTO engagement_ca (engagement_id, ca_cert_pem, ca_key_pem)
            VALUES (:eid, :cert, :key)
            ON CONFLICT (engagement_id) DO NOTHING
        """),
        {"eid": engagement_id, "cert": ca.cert_pem, "key": ca.key_pem},
    )
    row = conn.execute(
        text("SELECT ca_cert_pem, ca_key_pem FROM engagement_ca "
             "WHERE engagement_id = :eid"),
        {"eid": engagement_id},
    ).mappings().one()
    record_audit(
        engagement_id=engagement_id, actor="tool_gateway",
        event_type="egress_ca.provisioned", subject_type="engagement_ca",
        subject_id=engagement_id,
        # The fingerprint, never the key. An audit record that carried the
        # private key would be the leak it is meant to detect.
        payload={"ca_provisioned": True},
    )
    return CAMaterial(cert_pem=row["ca_cert_pem"], key_pem=row["ca_key_pem"])


def mint_leaf_for_host(conn: Connection, engagement_id: str, host: str) -> LeafMaterial:
    """The one call the dispatch path makes: a leaf for the capability's host.

    Ties the two halves together — get-or-create the CA, sign one short-lived
    leaf for the single host — so dispatch never touches raw key material or
    the crypto primitives directly.
    """
    ca = ensure_engagement_ca(conn, engagement_id)
    leaf = sign_leaf(ca, host)
    record_audit(
        engagement_id=engagement_id, actor="tool_gateway",
        event_type="egress_leaf.minted", subject_type="egress_proxy",
        subject_id=host,
        payload={"host": host, "leaf_ttl_hours": LEAF_TTL_HOURS},
    )
    return leaf
