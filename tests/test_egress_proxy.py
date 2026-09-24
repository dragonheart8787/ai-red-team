"""The policy-aware egress proxy, and the topology that makes it unavoidable (D34).

§8.3 gives HTTP its own enforcement path because a network namespace can only
answer "can a packet reach this address". It cannot read a method, a hostname
or a request count, which are exactly what a capability constrains. This file
tests the thing that can.

Two levels, and the split is deliberate:

* the checks themselves run in-process against real sockets, so they are fast
  and every test in them runs everywhere;
* the *topology* is tested against containers, because the claim "the tool
  cannot go around the proxy" is a claim about routes in a namespace and
  nothing short of a namespace can support it.

**What proves a refusal.** Never the proxy's own log. A proxy reporting that it
refused something is a proxy reporting on itself, which is the shape D31 ruled
out when it insisted the kernel, and not the scanner, decide what was
reachable. Every refusal here is proven by the *target* — a request that was
refused never arrived, so the target has no record of it. The target's record
is written by the target and is outside the proxy's control, which is the
entire reason it is worth asserting on.
"""

from __future__ import annotations

import http.client
import http.server
import json
import subprocess
import threading
import time
import uuid

import pytest

from tool_gateway.egress_proxy import (
    BUDGET_EXHAUSTED,
    HOST_NOT_AUTHORIZED,
    METHOD_NOT_AUTHORIZED,
    NOT_ABSOLUTE_FORM,
    PORT_NOT_AUTHORIZED,
    TLS_NO_MATERIAL,
    Grant,
    LocalBudget,
    PolicyProxy,
    grant_from_capability,
)
from tool_gateway.sandbox import (
    PROXY_IMAGE,
    DockerSandbox,
    SandboxUnavailable,
    validate_allowlist,
)

WEB_TARGET_IMAGE = "cyberorch/web-target:local"

#: Target-side network: where the targets live.
TARGET_CIDR = "10.78.0.0/24"
TARGET_IP = "10.78.0.10"
TARGET_PORT = 8080

#: Tool-side network: the tool container and the proxy, and nothing else.
TOOL_CIDR = "10.81.0.0/24"

#: TEST-NET-2. Off every allowlist, named by the GET lure, in no scope object.
OUTSIDE_IP = "198.51.100.23"


# ---------------------------------------------------------------------------
# A real target, in-process. Its record is the witness.
# ---------------------------------------------------------------------------

class RecordingTarget:
    """An HTTP server that writes down what actually reached it.

    ``served`` is appended to inside the request handler, so a line exists only
    if a request arrived and was answered. Nothing the proxy does can add to it
    and nothing the proxy does can remove from it.
    """

    def __init__(self) -> None:
        self.served: list[tuple[str, str]] = []
        target = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: object) -> None:
                pass

            def _record_and_reply(self, body: bytes) -> None:
                target.served.append((self.command, self.path))
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/redirect"):
                    target.served.append((self.command, self.path))
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://{OUTSIDE_IP}:{TARGET_PORT}/admin"
                    )
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._record_and_reply(b"<p>inventory 198.51.100.23</p>")

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                self._record_and_reply(b"<p>echo:" + body + b"</p>")

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> RecordingTarget:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def port(self) -> int:
        return self._server.server_address[1]


def via_proxy(proxy: PolicyProxy, method: str, url: str, body: str | None = None):
    """Send one absolute-form request straight at the proxy.

    Deliberately ``http.client`` with the absolute URL rather than urllib's
    ProxyHandler. urllib consults ``no_proxy``, which in several environments
    (this repository's own dev container among them) covers 127.0.0.1 — so a
    test written that way connects *directly to the target* and passes while
    proving nothing about the proxy. That is the same class of mistake as
    D31's build check running on the build host, and it is worth one comment
    to make sure nobody reintroduces it here.
    """
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    headers = {"Content-Length": str(len(body))} if body is not None else {}
    conn.request(method, url, body=body, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    refusal = response.getheader("X-Cyberorch-Refusal")
    conn.close()
    return response.status, refusal, payload


@pytest.fixture
def target():
    with RecordingTarget() as running:
        yield running


def make_proxy(target: RecordingTarget, *, methods=("GET",), max_requests=5):
    grant = Grant(
        capability_id="CAP-TEST", host="127.0.0.1", port=target.port,
        methods=frozenset(methods), max_requests=max_requests,
    )
    return PolicyProxy(grant, bind=("127.0.0.1", 0))


# ---------------------------------------------------------------------------
# 1. Per-request checks — each refusal proven by the target's silence
# ---------------------------------------------------------------------------

def test_an_authorized_request_reaches_the_target(target):
    """The positive control. Without it every refusal below proves nothing."""
    with make_proxy(target) as proxy:
        status, refusal, body = via_proxy(
            proxy, "GET", f"http://127.0.0.1:{target.port}/index.html"
        )
    assert status == 200
    assert refusal is None
    assert b"inventory" in body
    assert target.served == [("GET", "/index.html")]


def test_a_method_the_capability_does_not_grant_never_reaches_the_target(target):
    """A GET capability cannot POST, whatever the tool attempts.

    The assertion that matters is the second one: the target served nothing.
    The status code is the proxy's account of itself; the empty record is the
    target's.
    """
    with make_proxy(target, methods=("GET",)) as proxy:
        status, refusal, _ = via_proxy(
            proxy, "POST", f"http://127.0.0.1:{target.port}/submit", body="a=1"
        )
    assert status == 403
    assert refusal == METHOD_NOT_AUTHORIZED
    assert target.served == []


def test_a_host_the_capability_does_not_name_never_reaches_the_target(target):
    with make_proxy(target) as proxy:
        status, refusal, _ = via_proxy(
            proxy, "GET", f"http://{OUTSIDE_IP}:{target.port}/admin"
        )
    assert status == 403
    assert refusal == HOST_NOT_AUTHORIZED
    assert target.served == []


def test_a_port_the_capability_does_not_name_is_refused(target):
    with make_proxy(target) as proxy:
        status, refusal, _ = via_proxy(
            proxy, "GET", f"http://127.0.0.1:{target.port + 1}/"
        )
    assert status == 403
    assert refusal == PORT_NOT_AUTHORIZED
    assert target.served == []


def test_an_origin_form_request_is_refused_rather_than_guessed_at(target):
    """"GET /path" carries no host, so there is nothing to check.

    Refused rather than resolved from the Host header: a proxy that falls back
    to the header is checking a value the client chose independently of where
    the connection actually goes.
    """
    with make_proxy(target) as proxy:
        status, refusal, _ = via_proxy(proxy, "GET", "/index.html")
    assert status == 403
    assert refusal == NOT_ABSOLUTE_FORM
    assert target.served == []


def test_connect_is_refused_when_the_proxy_has_no_leaf(target):
    """An HTTP-only proxy cannot inspect a tunnel, so it refuses CONNECT.

    D34's honest answer, kept for the case where no TLS material was provided:
    a generic connection failure would read as "the target is down" and send a
    Worker into retries against a wall. The reason is named instead. When a
    leaf *is* provided the TLS section below shows CONNECT is terminated, not
    refused.
    """
    with make_proxy(target) as proxy:  # make_proxy builds an HTTP-only proxy
        status, refusal, body = via_proxy(
            proxy, "CONNECT", f"127.0.0.1:{target.port}"
        )
    assert status == 501
    assert refusal == TLS_NO_MATERIAL
    detail = json.loads(body)["detail"]
    assert "TLS" in detail
    assert target.served == []


def test_the_host_check_is_exact_and_not_a_suffix_match():
    """One capability authorizes one host.

    Suffix matching is how "api.example.com" quietly becomes authorization for
    "api.example.com.attacker.net". §4.1.5's patterns live in the scope
    registry and have already done their work by the time a capability exists.
    """
    grant = Grant(capability_id="C", host="example.com", port=80,
                  methods=frozenset({"GET"}), max_requests=1)
    assert grant.allows("example.com", 80)[0]
    assert grant.allows("EXAMPLE.COM.", 80)[0]  # case and trailing dot only
    for imposter in ("example.com.attacker.net", "notexample.com",
                     "sub.example.com", "example.co"):
        allowed, reason = grant.allows(imposter, 80)
        assert not allowed, imposter
        assert reason == HOST_NOT_AUTHORIZED


# ---------------------------------------------------------------------------
# 2. Redirects — enforced on the follow-up request, not on the response
# ---------------------------------------------------------------------------

def test_a_client_that_follows_a_redirect_is_stopped_by_the_proxy(target):
    """The redirect test D31 could not write, because D31 had no proxy.

    D31 told curl not to follow redirects and called that the boundary. It was
    not: it was a client flag, and a boundary a client can turn off is a
    setting. Here the client follows the redirect *deliberately* — the request
    it then makes is refused on arrival, because the address the target chose
    is not the address the capability names.

    That is the property: enforcement does not depend on how the tool was
    configured.
    """
    with make_proxy(target) as proxy:
        status, _, _ = via_proxy(
            proxy, "GET", f"http://127.0.0.1:{target.port}/redirect"
        )
        assert status == 302, "the redirect itself is passed through as evidence"

        # Now do what a redirect-following client does: request the Location.
        followed, refusal, _ = via_proxy(
            proxy, "GET", f"http://{OUTSIDE_IP}:{TARGET_PORT}/admin"
        )

    assert followed == 403
    assert refusal == HOST_NOT_AUTHORIZED
    # The target served the redirect and nothing else. The second hop never
    # became a request to anywhere.
    assert target.served == [("GET", "/redirect")]


def test_the_location_header_is_passed_through_unrewritten(target):
    """Evidence is not edited on the way past.

    D31 records Location in the derived view as untrusted content, and a proxy
    that stripped or rewrote it would make the stored evidence disagree with
    what the target actually sent. Enforcement happens to the next request, not
    to this response.
    """
    with make_proxy(target) as proxy:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
        conn.request("GET", f"http://127.0.0.1:{target.port}/redirect")
        response = conn.getresponse()
        response.read()
        location = response.getheader("Location")
        conn.close()
    assert location == f"http://{OUTSIDE_IP}:{TARGET_PORT}/admin"


# ---------------------------------------------------------------------------
# 3. The within-run request ceiling
# ---------------------------------------------------------------------------

def test_a_tool_that_loops_is_stopped_at_the_capability_ceiling(target):
    """A loop inside the tool is a loop outside the broker's count (I3).

    The control plane spends one request per run against the database; it never
    sees a second one made inside the same container. This ceiling is what
    bounds that, and it is why the proxy counts at all.
    """
    with make_proxy(target, max_requests=2) as proxy:
        first = via_proxy(proxy, "GET", f"http://127.0.0.1:{target.port}/1")
        second = via_proxy(proxy, "GET", f"http://127.0.0.1:{target.port}/2")
        third = via_proxy(proxy, "GET", f"http://127.0.0.1:{target.port}/3")

    assert first[0] == 200 and second[0] == 200
    assert third[0] == 429
    assert third[1] == BUDGET_EXHAUSTED
    # Two arrived, the third did not. Counted at the target, not at the proxy.
    assert target.served == [("GET", "/1"), ("GET", "/2")]


def test_a_refused_request_does_not_spend_a_request(target):
    """Static checks run before the budget is touched.

    A request that was never authorized must not consume budget that an
    authorized one could have used — otherwise a tool could exhaust its own
    capability by aiming at hosts it was never granted.
    """
    with make_proxy(target, methods=("GET",), max_requests=1) as proxy:
        via_proxy(proxy, "POST", f"http://127.0.0.1:{target.port}/x", body="a=1")
        via_proxy(proxy, "GET", f"http://{OUTSIDE_IP}:{target.port}/x")
        allowed = via_proxy(proxy, "GET", f"http://127.0.0.1:{target.port}/ok")

    assert allowed[0] == 200
    assert target.served == [("GET", "/ok")]


def test_the_default_budget_is_the_grants_ceiling_not_unlimited():
    """A default that disables a check is how a check stops existing.

    :class:`PolicyProxy` takes a ``consume`` callback so the control plane can
    plug in the broker's atomic counter. If the default were "always allow",
    every proxy constructed without that argument would silently enforce
    nothing.
    """
    grant = Grant(capability_id="C", host="h", port=80,
                  methods=frozenset({"GET"}), max_requests=2)
    proxy = PolicyProxy(grant, bind=("127.0.0.1", 0))
    assert isinstance(proxy.consume, LocalBudget)
    assert proxy.consume.max_requests == 2
    assert proxy.consume() and proxy.consume()
    assert not proxy.consume()


def test_the_grant_is_built_from_the_capability_and_never_from_a_request():
    """§8.3: the proxy knows what it was told before any traffic arrived."""

    class _Budget:
        @staticmethod
        def as_dict():
            return {"tool": {"http": {"max_requests": 3}}}

    class _Capability:
        capability_id = "CAP-9"
        constraints = {"host": "10.78.0.10", "port": 8080, "path": "/x"}
        budget = _Budget()

    grant = grant_from_capability(_Capability(), methods=["GET"])
    assert grant.host == "10.78.0.10"
    assert grant.port == 8080
    assert grant.max_requests == 3
    assert grant.methods == frozenset({"GET"})


def test_a_capability_with_no_host_cannot_produce_a_grant():
    """Fail closed. A grant with no host would authorize whatever was asked."""

    class _Budget:
        @staticmethod
        def as_dict():
            return {}

    class _Capability:
        capability_id = "CAP-9"
        constraints = {"port": 8080}
        budget = _Budget()

    with pytest.raises(ValueError, match="names no host"):
        grant_from_capability(_Capability(), methods=["GET"])


# ---------------------------------------------------------------------------
# 3b. TLS termination (D35) — decrypt, check the plaintext, re-originate
# ---------------------------------------------------------------------------
#
# In-process, hermetic. The client is a raw socket doing CONNECT + TLS + HTTP
# by hand, deliberately not curl and not http.client.set_tunnel: this dev
# container's no_proxy covers 127.0.0.1 (so curl bypasses the proxy), and
# http.client.set_tunnel has its own quirks. A raw socket is what gives the
# tests full control over exactly what the tool sends. The real tool (curl) is
# exercised against containers in the topology section and in CI.

import datetime as _dt  # noqa: E402
import ipaddress as _ip  # noqa: E402
import socket as _socket  # noqa: E402
import ssl as _ssl  # noqa: E402
import tempfile as _tempfile  # noqa: E402

from cryptography import x509 as _x509  # noqa: E402
from cryptography.hazmat.primitives import hashes as _hashes  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as _ec  # noqa: E402
from cryptography.x509.oid import NameOID as _NameOID  # noqa: E402

from control_plane.tls.engagement_ca import generate_ca, sign_leaf  # noqa: E402
from tool_gateway.egress_proxy import server_tls_context_from_pem  # noqa: E402

LOCAL = "127.0.0.1"


def _self_signed(host: str) -> tuple[str, str]:
    """A throwaway self-signed cert+key for the in-process HTTPS target."""
    key = _ec.generate_private_key(_ec.SECP256R1())
    now = _dt.datetime.now(_dt.UTC)
    name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "target")])
    cert = (
        _x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(_x509.SubjectAlternativeName(
            [_x509.IPAddress(_ip.ip_address(host))]), False)
        .sign(key, _hashes.SHA256())
    )
    cf = _tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    cf.write(cert.public_bytes(_ser.Encoding.PEM))
    cf.close()
    kf = _tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    kf.write(key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                               _ser.NoEncryption()))
    kf.close()
    return cf.name, kf.name


class RecordingTlsTarget:
    """A self-signed HTTPS server that records what actually reached it.

    Same role as RecordingTarget but over TLS, so the proxy has a real
    handshake to re-originate. ``served`` is the witness: a line exists only if
    a request arrived and was answered inside the terminated tunnel.
    """

    def __init__(self) -> None:
        self.served: list[tuple[str, str]] = []
        target = self
        cert, key = _self_signed(LOCAL)

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                target.served.append(("GET", self.path))
                b = b"<p>secret inventory</p>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self) -> None:  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                target.served.append(("POST", self.path))
                b = b"echo:" + body
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self._server = http.server.ThreadingHTTPServer((LOCAL, 0), Handler)
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> RecordingTlsTarget:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def port(self) -> int:
        return self._server.server_address[1]


def _ca_trust_ctx(ca_cert_pem: str) -> _ssl.SSLContext:
    f = _tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    f.write(ca_cert_pem.encode())
    f.close()
    return _ssl.create_default_context(cafile=f.name)


def _tunnel(proxy, host, port, requests, *, client_ctx):
    """CONNECT to the proxy, TLS-handshake, send requests, read responses.

    Returns (connect_status_line, [(status_line, body_bytes), ...]). Raises the
    ssl error if the handshake is rejected — which is what the pinning test
    asserts on, a failure at the TLS layer distinct from a 403 body.
    """
    raw = _socket.create_connection((proxy.bind[0], proxy.port), timeout=8)
    raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = raw.recv(65536)
        if not chunk:
            break
        buf += chunk
    connect_status = buf.split(b"\r\n", 1)[0].decode()
    if " 200 " not in connect_status:
        raw.close()
        return connect_status, []
    tls = client_ctx.wrap_socket(raw, server_hostname=host)
    out = []
    try:
        for method, path, body in requests:
            req = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            if body is not None:
                req += f"Content-Length: {len(body)}\r\n"
            req += "\r\n"
            data = req.encode() + (body or b"")
            tls.sendall(data)
            rb = b""
            while b"\r\n\r\n" not in rb:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                rb += chunk
            head, _, rest = rb.partition(b"\r\n\r\n")
            cl = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    cl = int(line.split(b":", 1)[1])
            while len(rest) < cl:
                rest += tls.recv(65536)
            out.append((head.split(b"\r\n")[0].decode(), rest[:cl]))
    finally:
        tls.close()
    return connect_status, out


def _tls_proxy(target, *, methods=("GET",), max_requests=5):
    grant = Grant(capability_id="CAP-TLS", host=LOCAL, port=target.port,
                  methods=frozenset(methods), max_requests=max_requests)
    ca = generate_ca("ENG-TLS")
    leaf = sign_leaf(ca, LOCAL)
    ctx = server_tls_context_from_pem(leaf.leaf_cert_pem, leaf.leaf_key_pem)
    proxy = PolicyProxy(grant, bind=(LOCAL, 0), server_ctx=ctx)
    return proxy, ca


@pytest.fixture
def tls_target():
    with RecordingTlsTarget() as running:
        yield running


def test_tls_an_authorized_request_is_decrypted_and_reaches_the_target(tls_target):
    """The positive control: the proxy terminates, checks, and re-originates.

    Without it every TLS refusal below proves nothing.
    """
    proxy, ca = _tls_proxy(tls_target, methods=("GET",))
    with proxy:
        cstatus, out = _tunnel(proxy, LOCAL, tls_target.port,
                               [("GET", "/x", None)],
                               client_ctx=_ca_trust_ctx(ca.cert_pem))
    assert "200" in cstatus
    assert out[0][0].endswith("200 OK")
    assert b"secret inventory" in out[0][1]
    assert tls_target.served == [("GET", "/x")]


def test_tls_a_method_the_capability_forbids_never_reaches_the_target(tls_target):
    """The method check runs on the decrypted request, not the CONNECT."""
    proxy, ca = _tls_proxy(tls_target, methods=("GET",))
    with proxy:
        _, out = _tunnel(proxy, LOCAL, tls_target.port,
                         [("POST", "/submit", b"a=1")],
                         client_ctx=_ca_trust_ctx(ca.cert_pem))
    assert "403" in out[0][0]
    assert tls_target.served == []


def test_tls_a_host_the_capability_forbids_is_refused_at_connect(tls_target):
    """The CONNECT target is checked before the tunnel is even established."""
    grant = Grant(capability_id="C", host="10.99.0.1", port=tls_target.port,
                  methods=frozenset({"GET"}), max_requests=5)
    ca = generate_ca("E")
    leaf = sign_leaf(ca, "10.99.0.1")
    ctx = server_tls_context_from_pem(leaf.leaf_cert_pem, leaf.leaf_key_pem)
    with PolicyProxy(grant, bind=(LOCAL, 0), server_ctx=ctx) as proxy:
        cstatus, out = _tunnel(proxy, LOCAL, tls_target.port, [],
                               client_ctx=_ca_trust_ctx(ca.cert_pem))
    assert "403" in cstatus
    assert out == []
    assert tls_target.served == []


def test_tls_keep_alive_requests_are_each_counted(tls_target):
    """5.12: the count is per HTTP request, and TLS keep-alive does not loosen it.

    Three GETs down one tunnel against a ceiling of two: the first two are
    served, the third is refused for budget, and the target's own log shows
    exactly two — the count survives socket reuse because each request in the
    tunnel is checked and counted, not each connection.
    """
    proxy, ca = _tls_proxy(tls_target, methods=("GET",), max_requests=2)
    with proxy:
        _, out = _tunnel(
            proxy, LOCAL, tls_target.port,
            [("GET", "/1", None), ("GET", "/2", None), ("GET", "/3", None)],
            client_ctx=_ca_trust_ctx(ca.cert_pem),
        )
    statuses = [line for line, _ in out]
    assert statuses[0].endswith("200 OK")
    assert statuses[1].endswith("200 OK")
    assert "429" in statuses[2]
    assert tls_target.served == [("GET", "/1"), ("GET", "/2")]


def test_tls_a_client_that_does_not_trust_our_ca_is_refused_at_the_tls_layer(
    tls_target,
):
    """Cert pinning, the documented §8.3 limit — and its distinct failure mode.

    A client that pins the real certificate (or simply does not trust our
    per-engagement CA) rejects the leaf during the handshake. The refusal is an
    ``ssl`` error, raised *before* any HTTP request is formed — categorically
    different from a 403 body a policy refusal returns — and the target logs
    nothing, because nothing got past the handshake. That distinctness is the
    property: "pinning, working as designed" must never look like "the proxy is
    broken".
    """
    proxy, _ca = _tls_proxy(tls_target, methods=("GET",))
    with proxy:
        with pytest.raises(_ssl.SSLError):
            _tunnel(proxy, LOCAL, tls_target.port, [("GET", "/x", None)],
                    client_ctx=_ssl.create_default_context())
    assert tls_target.served == []


def test_tls_a_redirect_off_the_allowlist_is_refused_on_the_follow_up(tls_target):
    """Enforcement is on the next request, not the response (D31, over TLS).

    The proxy passes a 3xx back untouched; a client that follows it opens a new
    CONNECT to the redirect's host, which is refused because the capability
    names one host. Here the "follow" is explicit: a second tunnel to an
    unauthorised host is refused at CONNECT.
    """
    proxy, ca = _tls_proxy(tls_target, methods=("GET",))
    with proxy:
        # First hop authorised.
        _, out = _tunnel(proxy, LOCAL, tls_target.port, [("GET", "/redirect", None)],
                         client_ctx=_ca_trust_ctx(ca.cert_pem))
        assert out and out[0][0].endswith("200 OK")
        # Following the redirect means a CONNECT to the lure host — refused.
        cstatus, _ = _tunnel(proxy, "198.51.100.23", tls_target.port, [],
                             client_ctx=_ca_trust_ctx(ca.cert_pem))
    assert "403" in cstatus



# ---------------------------------------------------------------------------
# 4. The two-network topology — kernel evidence, containers required
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox()
    try:
        box.ensure_image()
        box.client().images.get(PROXY_IMAGE)
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "D34's topology tests assert that the tool container has no route "
            "to the target, which is a fact about a network namespace and "
            "cannot be established without one. Build the images with "
            "tool_gateway/images/build_nmap_image.sh, "
            "build_web_target_image.sh and build_egress_proxy_image.sh.",
            pytrace=False,
        )
    except Exception as exc:  # pragma: no cover - missing proxy image
        pytest.fail(
            f"the egress proxy image is missing ({exc}). Build it with "
            "tool_gateway/images/build_egress_proxy_image.sh",
            pytrace=False,
        )
    return box


def _wait_until_serving(name: str, timeout_seconds: float = 20.0) -> None:
    """Block until the target's HTTP server has bound its socket.

    Same gate as D31's, and for the same reason: ``docker run -d`` returns when
    the container exists, not when the process inside it is listening.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        logs = subprocess.run(["docker", "logs", name],
                              capture_output=True, text=True)
        if "Serving HTTP" in logs.stdout + logs.stderr:
            return
        alive = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True,
        ).stdout.strip()
        if alive != "true":
            break
        time.sleep(0.2)
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    pytest.fail(
        "the web target never started serving.\n"
        f"--- container stdout ---\n{logs.stdout}\n"
        f"--- container stderr ---\n{logs.stderr}",
        pytrace=False,
    )


def target_access_log(name: str) -> str:
    """The target's own record of what reached it.

    ``BaseHTTPRequestHandler`` logs one line per served request to stderr, and
    it is written by the target. This is the independent witness: the proxy
    cannot add to it or remove from it, so "this request is absent" is evidence
    about the world rather than a claim by the component under test.
    """
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    return logs.stdout + logs.stderr


@pytest.fixture(scope="module")
def topology(sandbox):
    """Tool-side network, target-side network, a target, and a proxy bridging."""
    name = f"cyberorch-web-target-{uuid.uuid4().hex[:8]}"
    target_network = sandbox.ensure_network([TARGET_CIDR])
    sandbox.ensure_network([TOOL_CIDR])

    started = subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", target_network.name,
         "--ip", TARGET_IP, WEB_TARGET_IMAGE],
        capture_output=True, text=True,
    )
    if started.returncode != 0:
        pytest.fail(f"could not start the web target: {started.stderr}",
                    pytrace=False)
    _wait_until_serving(name)

    endpoint = sandbox.start_egress_proxy(
        grant={
            "capability_id": "CAP-TOPOLOGY",
            "host": TARGET_IP,
            "port": TARGET_PORT,
            "methods": ["GET", "POST"],
            "max_requests": 20,
        },
        tool_side=[TOOL_CIDR], target_side=[TARGET_CIDR],
    )
    try:
        yield {"target_name": name, "proxy": endpoint}
    finally:
        sandbox.stop_egress_proxy(endpoint)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        sandbox.remove_network([TARGET_CIDR])
        sandbox.remove_network([TOOL_CIDR])


def test_the_tool_container_has_no_route_to_the_target(sandbox, topology):
    """The kernel-level half of D34's evidence.

    The tool joins the tool-side network only, and the target is on the other
    one. ENETUNREACH is the kernel saying no packet was built — the same fact
    D31 established for the CIDR allowlist, reused here to establish something
    new: a tool that ignores its ``--proxy`` flag and addresses the target
    directly does not quietly succeed, it reaches nothing.

    This is what makes the proxy unavoidable rather than merely recommended.
    """
    verdict = sandbox.probe_egress(
        target=TARGET_IP, port=TARGET_PORT, network_allowlist=[TOOL_CIDR]
    )
    assert verdict == "network_unreachable", (
        f"the tool side could reach the target directly ({verdict!r}); the "
        "proxy would then be advisory"
    )


def test_the_proxy_itself_is_reachable_from_the_tool_side(sandbox, topology):
    """The positive control for the test above.

    Without it, ENETUNREACH proves only that the tool-side namespace cannot
    reach anything at all, which would be confinement by accident.
    """
    proxy_host = topology["proxy"].url.removeprefix("http://").split(":")[0]
    verdict = sandbox.probe_egress(
        target=proxy_host, port=3128, network_allowlist=[TOOL_CIDR]
    )
    assert verdict == "reachable"


def _curl_through_proxy(sandbox, proxy_url: str, url: str, *extra: str):
    return sandbox.run(
        command=["/usr/bin/curl", "--silent", "--show-error", "--include",
                 "--proto", "=http", "--proxy", proxy_url,
                 "--max-time", "15", *extra, url],
        network_allowlist=[TOOL_CIDR], max_duration_seconds=30,
    )


def test_an_authorized_request_reaches_the_target_through_the_proxy(
    sandbox, topology
):
    """Positive control for the topology: the allowed path actually works."""
    result = _curl_through_proxy(
        sandbox, topology["proxy"].url, f"http://{TARGET_IP}:{TARGET_PORT}/index.html"
    )
    assert result.succeeded, result.stderr
    assert "200 OK" in result.stdout
    assert "/index.html" in target_access_log(topology["target_name"])


def test_a_refused_request_is_absent_from_the_targets_own_log(sandbox, topology):
    """The independent witness, asserted as an absence (D34 requirement 3).

    A request for a host the capability does not name is refused. The proof is
    not that the proxy said 403 — the proxy saying so is the proxy's account of
    its own behaviour. The proof is that the target, which writes its own
    access log and has no idea a proxy exists, never logged the path.

    The path is a fresh UUID so the assertion cannot pass by coincidence:
    nothing else in this run could have produced that string.
    """
    marker = f"/never-arrives-{uuid.uuid4().hex[:12]}"
    result = _curl_through_proxy(
        sandbox, topology["proxy"].url, f"http://{OUTSIDE_IP}:{TARGET_PORT}{marker}"
    )
    assert "403" in result.stdout

    log = target_access_log(topology["target_name"])
    assert marker not in log, (
        "the target logged a request the proxy was supposed to refuse"
    )


def test_a_redirect_off_the_allowlist_is_refused_even_when_curl_follows_it(
    sandbox, topology
):
    """--location on purpose. The client's configuration is not the boundary.

    D31's redirect protection was a curl flag. Here curl is told to follow
    redirects, the target answers 302 pointing at TEST-NET-2, and the follow-up
    request is refused by the proxy because the capability names one host.
    """
    result = _curl_through_proxy(
        sandbox, topology["proxy"].url,
        f"http://{TARGET_IP}:{TARGET_PORT}/redirect", "--location",
    )
    assert "302" in result.stdout or "403" in result.stdout
    # The refusal of the second hop is what matters, and it is visible as the
    # proxy's 403 in the followed response.
    assert "403" in result.stdout, (
        "curl followed the redirect and the proxy did not refuse the next hop"
    )


def test_the_tool_side_and_target_side_networks_must_differ(sandbox):
    """Sharing one range would put the tool back on the target's network."""
    with pytest.raises(ValueError, match="must be different"):
        sandbox.start_egress_proxy(
            grant={"capability_id": "C", "host": TARGET_IP, "port": TARGET_PORT,
                   "methods": ["GET"], "max_requests": 1},
            tool_side=[TARGET_CIDR], target_side=[TARGET_CIDR],
        )


def test_the_allowlist_validation_still_refuses_a_hostname():
    """§8.3's original rule, unchanged by the second network."""
    with pytest.raises(ValueError, match="not a CIDR"):
        validate_allowlist(["app.example.com"])


# ---------------------------------------------------------------------------
# 4b. TLS termination against containers — real curl, kernel + witness (D35)
# ---------------------------------------------------------------------------

TARGET_HTTPS_PORT = 8443


@pytest.fixture
def tls_topology(sandbox):
    """Like ``topology`` but the proxy terminates TLS for the HTTPS target.

    The CA and leaf are generated directly (no database needed for the crypto),
    the proxy is handed the leaf, and the CA's public cert is delivered to the
    tool container so curl can verify the proxy's leaf.
    """
    from tool_gateway.egress_proxy import Grant, grant_from_capability  # noqa: F401

    ca = generate_ca("ENG-CI-TLS")
    leaf = sign_leaf(ca, TARGET_IP)

    name = f"cyberorch-web-target-{uuid.uuid4().hex[:8]}"
    target_network = sandbox.ensure_network([TARGET_CIDR])
    sandbox.ensure_network([TOOL_CIDR])
    started = subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", target_network.name,
         "--ip", TARGET_IP, WEB_TARGET_IMAGE],
        capture_output=True, text=True,
    )
    if started.returncode != 0:
        pytest.fail(f"could not start the web target: {started.stderr}", pytrace=False)
    _wait_until_serving(name)

    endpoint = sandbox.start_egress_proxy(
        grant={
            "capability_id": "CAP-TLS-CI", "host": TARGET_IP,
            "port": TARGET_HTTPS_PORT, "methods": ["GET", "POST"],
            "max_requests": 20,
        },
        tool_side=[TOOL_CIDR], target_side=[TARGET_CIDR],
        leaf_cert_pem=leaf.leaf_cert_pem, leaf_key_pem=leaf.leaf_key_pem,
    )
    try:
        yield {"target_name": name, "proxy": endpoint, "ca_cert_pem": ca.cert_pem}
    finally:
        sandbox.stop_egress_proxy(endpoint)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        sandbox.remove_network([TARGET_CIDR])
        sandbox.remove_network([TOOL_CIDR])


def _curl_https_through_proxy(sandbox, endpoint, ca_cert_pem, url, *extra):
    from tool_gateway.sandbox import TOOL_CA_PATH
    return sandbox.run(
        command=["/usr/bin/curl", "--silent", "--show-error", "--include",
                 "--proto", "=https", "--proxy", endpoint.url,
                 "--cacert", TOOL_CA_PATH, "--max-time", "15", *extra, url],
        network_allowlist=[TOOL_CIDR], max_duration_seconds=30,
        ca_cert_pem=ca_cert_pem,
    )


def test_tls_an_authorized_https_request_reaches_the_target_through_the_proxy(
    sandbox, tls_topology
):
    """The positive control for the container TLS path.

    The proxy is marked TLS-capable, and an https GET verified against the
    per-engagement CA reaches the target and is logged there.
    """
    assert tls_topology["proxy"].tls is True
    result = _curl_https_through_proxy(
        sandbox, tls_topology["proxy"], tls_topology["ca_cert_pem"],
        f"https://{TARGET_IP}:{TARGET_HTTPS_PORT}/index.html",
    )
    assert result.succeeded, result.stderr
    assert "200 OK" in result.stdout
    assert "/index.html" in target_access_log(tls_topology["target_name"])


def test_tls_a_pinning_client_is_refused_and_the_target_never_sees_it(
    sandbox, tls_topology
):
    """§8.3's documented limit, with the two failures kept distinct (D35).

    curl pins the *real* target key with --pinnedpubkey. Through the MITM it is
    handed the proxy's leaf key instead, so the pin mismatches and curl fails at
    the TLS layer (exit 60 or 90) — not with a 200 and not with a policy 403.
    The witness seals it: the target's access log has no line for this request,
    because it died in the handshake before any HTTP was sent.

    The marker path is a fresh UUID so its absence cannot be a coincidence.
    """
    marker = f"/pinned-{uuid.uuid4().hex[:12]}"
    # Pin a key that is not the leaf's: the real target's cert is self-signed
    # and unknown to us, so any wrong pin will do to model "client expected a
    # different certificate". A syntactically valid but non-matching sha256 pin.
    wrong_pin = "sha256//" + "A" * 43 + "="
    result = _curl_https_through_proxy(
        sandbox, tls_topology["proxy"], tls_topology["ca_cert_pem"],
        f"https://{TARGET_IP}:{TARGET_HTTPS_PORT}{marker}",
        "--pinnedpubkey", wrong_pin,
    )
    # A TLS-layer refusal: curl did not get a 200, and it is not a proxy 403.
    assert not result.succeeded
    assert "200 OK" not in result.stdout
    assert "X-Cyberorch-Refusal" not in result.stdout
    # The independent witness: nothing reached the target.
    assert marker not in target_access_log(tls_topology["target_name"])
