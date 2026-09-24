"""Policy-aware egress proxy (§8.3, D34; TLS termination D35).

§8.3 split egress enforcement by protocol and gave the reason: binding a
capability to an address does not survive contact with reality, because one
hostname maps to many addresses, they move when the TTL lapses, and DNS
rebinding makes the gap attacker-controlled.

    HTTP/S      → Tool Container → Policy-aware Egress Proxy → Internet
    Raw TCP/UDP → Tool Container → Network Namespace + CIDR allowlist

D6 built the second path. D34 built the first for plain HTTP. D35 adds the
missing half: TLS termination, so an https request is checked on its decrypted
plaintext rather than refused.

What is checked, per request
-----------------------------
Every request is checked against one :class:`Grant`, built from the issued
capability before the proxy starts and never from anything in a request:

* **host and port** — against the single host the capability names. Not a
  pattern, not a suffix match: one capability authorises one target. For a
  plain-HTTP request the host is read from the absolute-form request line; for
  an https request it is the host the ``CONNECT`` tunnel was opened to, which
  is the address the TLS connection actually goes to — not the ``Host`` header
  inside the tunnel, which the client sets independently.
* **method** — against the methods the capability's action implies.
* **request count** — a within-run ceiling (see 5.12 below). Each *HTTP
  request* is counted, including several sent down one keep-alive connection,
  so the count does not loosen when TLS lets a tool reuse a socket.

TLS termination (D35)
----------------------
An https request through a proxy arrives as ``CONNECT host:port``. D34 refused
it because, tunnelled, the proxy could see only the hostname the tool asked
for — a self-report, which D31 established is not a check. D35 terminates
instead: the ``CONNECT`` target is checked against the grant *before* the
tunnel is established, then the proxy presents a leaf certificate for that host
(signed by the per-engagement CA the tool trusts — see
:mod:`control_plane.tls.engagement_ca`), decrypts, and runs the identical
per-request checks on the plaintext. The proxy holds only the leaf, never the
CA key.

A target that pins a certificate cannot be intercepted — the leaf is signed by
a CA it was never told to trust — and that is a documented limit, not a defect
(§8.3). The cert-pinning test asserts such a connection is refused *at the TLS
layer*, a failure that must stay distinct from a policy refusal.

Library defaults, audited (the D34 urlopen lesson)
---------------------------------------------------
D34 was bitten by ``urllib`` following redirects by default, which made the
proxy act on the target's instruction. Every library default this file relies
on is therefore named and confirmed, not assumed:

* **Forwarding uses ``http.client``, not ``urllib``.** ``http.client`` has no
  redirect logic at all — a 3xx is returned verbatim — so the footgun is gone
  by construction rather than patched. ``Location`` reaches the tool as
  evidence; if the tool follows it, that is a new request (often a new
  ``CONNECT`` to a new host) and it is checked on arrival.
* **No connection reuse.** One upstream connection is opened per forwarded
  request and closed after, so no cookie, auth or TLS-session state is carried
  between requests. (The client↔proxy connection *may* be kept alive; that is
  the keep-alive the count is designed to survive.)
* **The upstream TLS context is explicitly unverified.** ``PROTOCOL_TLS_CLIENT``
  defaults to ``check_hostname=True`` and ``verify_mode=CERT_REQUIRED``; both
  are turned off deliberately. The proxy is auditing content, not
  authenticating the target — a pentest target legitimately has a broken or
  self-signed certificate, and refusing to talk to it would make the tool
  useless against the systems it exists to test. The target's identity is
  established by the grant's host binding, not by its certificate. This is the
  same posture Burp and mitmproxy take upstream, and it is stated here so no
  one mistakes it for an oversight.
* **The server TLS context requires no client certificate.** We present a leaf;
  we do not ask the tool for one.

Why the refusals are not the evidence
--------------------------------------
This module writes an access log, and that log is *not* what the tests assert a
refusal with. A proxy reporting that it refused something is a proxy reporting
on itself. The evidence is the target's own access log: a request refused here
never reaches the target, so the target's log has no line for it. That witness
is outside this file's control — the same reason ``probe_egress`` asks the
kernel instead of the scanner.
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

#: Status returned for a request the capability does not authorize.
#:
#: 403 rather than 502: the request was understood and refused, and a gateway
#: error would read as "the target is having trouble", sending a Worker into a
#: retry loop against a boundary rather than reporting a refusal.
REFUSED_STATUS = 403

#: Status for a request whose budget is spent (§4.6).
BUDGET_STATUS = 429

#: Status for a CONNECT the proxy has no certificate to terminate (D35).
#:
#: Distinct from a policy refusal: it means this proxy was started without TLS
#: material, so it *cannot* inspect the tunnel — the honest D34 answer, kept
#: for the case where no leaf was provided.
TLS_STATUS = 501

#: Reason strings. They appear in the proxy's own log and in the body it
#: returns, and they are stable because the tests match on them -- while never
#: relying on them *alone* to prove a refusal. See the module docstring.
HOST_NOT_AUTHORIZED = "host_not_authorized"
PORT_NOT_AUTHORIZED = "port_not_authorized"
METHOD_NOT_AUTHORIZED = "method_not_authorized"
BUDGET_EXHAUSTED = "budget_exhausted"
TLS_NO_MATERIAL = "tls_termination_unavailable"
NOT_ABSOLUTE_FORM = "not_absolute_form"

TLS_NO_MATERIAL_MESSAGE = (
    "This proxy was started without a leaf certificate, so it cannot terminate "
    "and inspect a TLS tunnel. A CONNECT is therefore refused rather than "
    "blindly tunnelled, which would reduce the host check to trusting the "
    "hostname the tool itself asked for."
)


@dataclass(frozen=True)
class Grant:
    """What one capability authorizes, in the terms this proxy checks.

    Built from the issued capability by :func:`grant_from_capability` and then
    fixed. The proxy never learns anything from a request that could widen it.
    """

    capability_id: str
    host: str
    port: int
    methods: frozenset[str]
    max_requests: int

    def allows_method(self, method: str) -> bool:
        return method.upper() in self.methods

    def allows(self, host: str, port: int) -> tuple[bool, str | None]:
        """Whether this grant covers ``host:port``, and if not, which check failed.

        Host comparison is exact after case folding and after stripping a
        trailing dot. Deliberately not a suffix or wildcard match: "*.example.com"
        style matching is how one capability becomes authorization for a host
        nobody approved, and §4.1.5's patterns live in the scope registry, which
        has already done its work by the time a capability exists.
        """
        if host.lower().rstrip(".") != self.host.lower().rstrip("."):
            return False, HOST_NOT_AUTHORIZED
        if port != self.port:
            return False, PORT_NOT_AUTHORIZED
        return True, None


@dataclass
class AccessRecord:
    """One line of the proxy's own log."""

    method: str
    url: str
    host: str
    port: int
    decision: str
    reason: str | None = None
    status: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method, "url": self.url, "host": self.host,
            "port": self.port, "decision": self.decision, "reason": self.reason,
            "status": self.status,
        }


def grant_from_capability(capability, *, methods: Sequence[str]) -> Grant:
    """Build the grant for one issued capability.

    The host and port come from the capability's constraints — the same object
    OPA judged and the broker issued — and the methods from the action, through
    the caller. Nothing here reads a request.
    """
    constraints = dict(capability.constraints or {})
    host = str(constraints.get("host") or "")
    if not host:
        raise ValueError(
            "the capability names no host; a proxy grant with no host would "
            "authorize whatever the tool asked for"
        )
    return Grant(
        capability_id=capability.capability_id,
        host=host,
        port=int(constraints.get("port") or 80),
        methods=frozenset(m.upper() for m in methods),
        max_requests=int(
            (capability.budget.as_dict().get("tool", {}).get("http", {}) or {})
            .get("max_requests", 1)
        ),
    )


class LocalBudget:
    """Counts the requests one run makes, up to the capability's ceiling.

    Bounds the within-run failure mode only — a tool looping inside its own
    container. It is not the capability's budget: that lives in the database,
    survives restarts and is shared across runs, and it is spent by the control
    plane through ``consume_request``. Naming this one differently is the
    point; two things called "the budget" would eventually be assumed to be one
    thing.
    """

    def __init__(self, max_requests: int) -> None:
        self.max_requests = max(0, int(max_requests))
        self.used = 0
        self._lock = threading.Lock()

    def __call__(self) -> bool:
        with self._lock:
            if self.used >= self.max_requests:
                return False
            self.used += 1
            return True


# ---------------------------------------------------------------------------
# TLS contexts — server side presents the leaf, client side talks to the target
# ---------------------------------------------------------------------------

def server_tls_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """A server context presenting the leaf, loaded from files.

    Files rather than PEM strings, because the stdlib ``ssl`` module loads a
    certificate chain only from a path. In the container the leaf is a
    read-only bind mount, so nothing is written inside the read-only rootfs;
    the paths are not secret, only the key file's contents are, and those never
    pass through argv.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # We present a certificate; we never ask the tool for one. Stated rather
    # than left to the default so a future reader knows it was a decision.
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def server_tls_context_from_pem(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Same context, from PEM strings — for in-process callers and tests.

    Writes the two PEMs to short-lived files (0600), loads them, and removes
    them: ``load_cert_chain`` reads at call time, so the files need not outlive
    it. The container path uses :func:`server_tls_context` with mounted files
    instead and writes nothing.
    """
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".pem")
    try:
        os.write(cert_fd, cert_pem.encode())
        os.write(key_fd, key_pem.encode())
        os.close(cert_fd)
        os.close(key_fd)
        return server_tls_context(cert_path, key_path)
    finally:
        for path in (cert_path, key_path):
            try:
                os.unlink(path)
            except OSError:  # pragma: no cover
                pass


def _upstream_context() -> ssl.SSLContext:
    """The client context the proxy uses to reach the real target.

    Verification is off, and the module docstring says why at length: the proxy
    audits content, it does not authenticate the target, whose identity is the
    grant's host binding. ``PROTOCOL_TLS_CLIENT`` would default both of these
    on, so both are turned off explicitly — the exact class of default the D34
    urlopen bug taught us to name rather than inherit.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class PolicyProxy:
    """A forward proxy that checks every request against one :class:`Grant`.

    ``consume`` is called once per request that passes the static checks, and
    returning False refuses it. The default is a local counter bounded by the
    grant's ``max_requests`` — deliberately not "always allow", because a
    default that disables a check is how a check stops existing without anyone
    deciding that it should. The control plane passes the broker's atomic
    check-and-increment instead when it is the one running the proxy.

    ``server_ctx`` enables TLS termination (D35). When it is ``None`` the proxy
    is HTTP-only and a CONNECT is refused with :data:`TLS_NO_MATERIAL` — the
    honest "cannot inspect this" answer rather than a blind tunnel.
    """

    def __init__(
        self,
        grant: Grant,
        *,
        consume: Callable[[], bool] | None = None,
        bind: tuple[str, int] = ("0.0.0.0", 3128),
        upstream_timeout: float = 20.0,
        server_ctx: ssl.SSLContext | None = None,
        verbose: bool = False,
    ) -> None:
        self.grant = grant
        self.consume = consume or LocalBudget(grant.max_requests)
        self.bind = bind
        self.upstream_timeout = upstream_timeout
        self.server_ctx = server_ctx
        self.upstream_ctx = _upstream_context()
        # Printed for an operator reading `docker logs`, never for a test to
        # assert a refusal with. See the module docstring: a proxy reporting
        # that it refused something is a proxy reporting on itself.
        self.verbose = verbose
        self.access_log: list[AccessRecord] = []
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------
    @property
    def port(self) -> int:
        if self._server is None:
            return self.bind[1]
        return self._server.server_address[1]

    def start(self) -> PolicyProxy:
        handler = _make_handler(self)
        self._server = http.server.ThreadingHTTPServer(self.bind, handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="egress-proxy"
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> PolicyProxy:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- decision ---------------------------------------------------------
    def record(self, entry: AccessRecord) -> None:
        with self._lock:
            self.access_log.append(entry)
        if self.verbose:
            print(json.dumps(entry.as_dict(), sort_keys=True), flush=True)

    def check(self, method: str, url: str) -> tuple[bool, str | None, int]:
        """Decide one request. Returns ``(allowed, reason, status)``.

        Order matters and is deliberate: the static checks run before the
        budget is touched, so a request that was never authorized does not
        spend a request the capability could have used for one that was.

        Accepts both http and https URLs — the https ones are reconstructed
        from the CONNECT target inside a terminated tunnel, so the host checked
        is the address the connection actually goes to.
        """
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False, NOT_ABSOLUTE_FORM, REFUSED_STATUS

        if not self.grant.allows_method(method):
            return False, METHOD_NOT_AUTHORIZED, REFUSED_STATUS

        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        allowed, reason = self.grant.allows(parsed.hostname, port)
        if not allowed:
            return False, reason, REFUSED_STATUS

        if not self.consume():
            return False, BUDGET_EXHAUSTED, BUDGET_STATUS
        return True, None, 200


# ---------------------------------------------------------------------------
# Forwarding — one implementation, shared by the plain-HTTP and tunnelled paths
# ---------------------------------------------------------------------------

_HOP_BY_HOP = frozenset({
    "proxy-connection", "connection", "keep-alive", "host",
    "content-length", "transfer-encoding", "te", "trailer", "upgrade",
})


def _origin_request(
    proxy: PolicyProxy, *, scheme: str, host: str, port: int, method: str,
    path: str, headers: list[tuple[str, str]], body: bytes | None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    """One request to the real target. Never follows a redirect (http.client).

    A new connection per call, closed after: no session, cookie or TLS state is
    carried between requests. HTTPS goes over the explicitly-unverified upstream
    context (see the module docstring).
    """
    if scheme == "https":
        conn = http.client.HTTPSConnection(
            host, port, timeout=proxy.upstream_timeout, context=proxy.upstream_ctx
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=proxy.upstream_timeout)
    try:
        conn.request(method, path, body=body, headers=dict(headers))
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp.getheaders(), data
    finally:
        conn.close()


def _forward(handler, proxy: PolicyProxy, method: str, url: str) -> None:
    """Forward one authorized request and write the response back to the tool."""
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    length = int(handler.headers.get("Content-Length") or 0)
    body = handler.rfile.read(length) if length else None

    fwd_headers = [
        (name, value) for name, value in handler.headers.items()
        if name.lower() not in _HOP_BY_HOP
    ]

    try:
        status, resp_headers, resp_body = _origin_request(
            proxy, scheme=scheme, host=host, port=port, method=method,
            path=path, headers=fwd_headers, body=body,
        )
    except (OSError, http.client.HTTPException) as exc:
        proxy.record(AccessRecord(
            method=method, url=url, host=host, port=port,
            decision="UPSTREAM_ERROR", reason=str(exc), status=502,
        ))
        message = json.dumps({"upstream_error": str(exc)}).encode()
        handler.send_response(502)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(message)))
        handler.end_headers()
        handler.wfile.write(message)
        return

    proxy.record(AccessRecord(
        method=method, url=url, host=host, port=port,
        decision="ALLOW", status=status,
    ))

    handler.send_response(status)
    for name, value in resp_headers:
        if name.lower() in _HOP_BY_HOP:
            continue
        # Location is passed through untouched. It is evidence, and the request
        # that would follow it is checked on arrival.
        handler.send_header(name, value)
    # Explicit length lets the client find the body boundary and, over a
    # keep-alive connection, send the next request — which is counted too.
    handler.send_header("Content-Length", str(len(resp_body)))
    handler.end_headers()
    if method != "HEAD":
        handler.wfile.write(resp_body)


def _refuse(handler, proxy: PolicyProxy, method: str, url: str,
            reason: str, status: int) -> None:
    parsed = urllib.parse.urlsplit(url)
    proxy.record(AccessRecord(
        method=method, url=url, host=parsed.hostname or "",
        port=parsed.port or 0, decision="DENY", reason=reason, status=status,
    ))
    body = json.dumps({
        "refused_by": "cyberorch-egress-proxy",
        "reason": reason,
        "capability_id": proxy.grant.capability_id,
        "detail": TLS_NO_MATERIAL_MESSAGE if reason == TLS_NO_MATERIAL else None,
    }).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Cyberorch-Refusal", reason)
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    # A refused request ends this connection; the tool got its answer.
    handler.close_connection = True


def _serve(handler, proxy: PolicyProxy, method: str, url: str) -> None:
    """Check one request and either forward it or refuse it."""
    allowed, reason, status = proxy.check(method, url)
    if not allowed:
        _refuse(handler, proxy, method, url, reason or "refused", status)
        return
    _forward(handler, proxy, method, url)


def _make_inner_handler(proxy: PolicyProxy, connect_host: str, connect_port: int):
    """Handler for requests read off a terminated TLS tunnel (origin-form).

    Inside a tunnel the tool sends ``GET /path`` with a ``Host`` header, not an
    absolute URL. The authoritative host is ``connect_host`` — the address the
    tunnel actually goes to — so the URL is rebuilt from it, never from the
    ``Host`` header the client controls independently.
    """
    scheme_host = f"https://{connect_host}:{connect_port}"

    class InnerHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "cyberorch-egress-proxy/1"

        def log_message(self, *args: Any) -> None:  # noqa: A003
            pass

        def _dispatch(self, method: str) -> None:
            _serve(self, proxy, method, f"{scheme_host}{self.path}")

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch("PUT")

        def do_DELETE(self) -> None:  # noqa: N802
            self._dispatch("DELETE")

        def do_PATCH(self) -> None:  # noqa: N802
            self._dispatch("PATCH")

        def do_HEAD(self) -> None:  # noqa: N802
            self._dispatch("HEAD")

    return InnerHandler


def _make_handler(proxy: PolicyProxy):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "cyberorch-egress-proxy/1"
        max_request_line = 8190

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            pass

        def _handle(self, method: str) -> None:
            url = self.path
            if not url.lower().startswith("http://"):
                # Origin-form ("GET /path") to the proxy directly means the
                # client treated it as an ordinary server. There is no host to
                # check, so it is refused rather than guessed from the Host
                # header. (Tunnelled requests are origin-form too, but they are
                # served by the inner handler with the CONNECT host, not here.)
                _refuse(self, proxy, method, url, NOT_ABSOLUTE_FORM, REFUSED_STATUS)
                return
            _serve(self, proxy, method, url)

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle("DELETE")

        def do_PATCH(self) -> None:  # noqa: N802
            self._handle("PATCH")

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle("HEAD")

        def do_CONNECT(self) -> None:  # noqa: N802
            # host:port the tunnel is being opened to. This is what gets checked
            # against the grant, before any tunnel exists — it is the address
            # the TLS connection will actually reach.
            target = self.path
            host, _, port_s = target.partition(":")
            try:
                port = int(port_s) if port_s else 443
            except ValueError:
                port = -1

            if proxy.server_ctx is None:
                # No leaf to present: this proxy cannot inspect a tunnel, so it
                # refuses rather than blindly relaying. The honest D34 answer.
                _refuse(self, proxy, "CONNECT", f"connect://{target}",
                        TLS_NO_MATERIAL, TLS_STATUS)
                return

            allowed, reason = proxy.grant.allows(host, port)
            if not allowed:
                proxy.record(AccessRecord(
                    method="CONNECT", url=f"connect://{target}", host=host,
                    port=port if port > 0 else 0, decision="DENY",
                    reason=reason, status=REFUSED_STATUS,
                ))
                # Refuse the tunnel outright. curl reports this as a failed
                # CONNECT (a 403 on the tunnel), which is distinct from both a
                # TLS handshake failure (pinning) and a per-request refusal
                # inside an established tunnel.
                body = json.dumps({
                    "refused_by": "cyberorch-egress-proxy", "reason": reason,
                    "capability_id": proxy.grant.capability_id,
                }).encode()
                self.send_response(REFUSED_STATUS)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Cyberorch-Refusal", reason or "refused")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
                return

            # The tunnel target is authorised. Establish it, then terminate TLS
            # and serve the decrypted requests through the inner handler.
            #
            # The CONNECT 200 is written raw and flushed to the socket *before*
            # the TLS wrap. send_response buffers into self.wfile, and wrapping
            # the underlying socket while that buffer is unflushed makes the
            # plaintext 200 and the TLS handshake collide on the wire — the
            # client sees a connection reset mid-CONNECT. Raw write + flush
            # keeps the two cleanly ordered.
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
            try:
                tls_sock = proxy.server_ctx.wrap_socket(
                    self.connection, server_side=True
                )
            except (ssl.SSLError, OSError) as exc:
                proxy.record(AccessRecord(
                    method="CONNECT", url=f"connect://{target}", host=host,
                    port=port if port > 0 else 0, decision="TLS_ERROR",
                    reason=str(exc), status=None,
                ))
                self.close_connection = True
                return

            inner = _make_inner_handler(proxy, host, port)
            try:
                # Drives the inner handler's request loop over the decrypted
                # socket. BaseHTTPRequestHandler.__init__ calls handle(), which
                # loops handle_one_request() for as long as the connection stays
                # open — so each request in a keep-alive tunnel is checked and
                # counted, which is the 5.12 answer.
                inner(tls_sock, self.client_address, self.server)
            finally:
                try:
                    tls_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                tls_sock.close()
            self.close_connection = True

    return Handler


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - container entry
    """Run the proxy from a container.

    The grant arrives as one JSON argument; the leaf certificate and key arrive
    as *file paths* (read-only bind mounts), never as argv, so the private key
    is not in the process table or ``docker inspect``. A proxy started without
    leaf paths is HTTP-only and refuses CONNECT — the same object, one
    capability's life, no reload.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Policy-aware egress proxy (§8.3).")
    parser.add_argument("--grant", required=True, help="JSON grant object.")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3128)
    parser.add_argument("--leaf-cert", help="Path to the leaf certificate PEM.")
    parser.add_argument("--leaf-key", help="Path to the leaf private key PEM.")
    args = parser.parse_args(argv)

    raw = json.loads(args.grant)
    grant = Grant(
        capability_id=str(raw["capability_id"]),
        host=str(raw["host"]),
        port=int(raw["port"]),
        methods=frozenset(m.upper() for m in raw["methods"]),
        max_requests=int(raw["max_requests"]),
    )

    server_ctx = None
    if args.leaf_cert and args.leaf_key:
        server_ctx = server_tls_context(args.leaf_cert, args.leaf_key)

    proxy = PolicyProxy(grant, bind=(args.bind, args.port),
                        server_ctx=server_ctx, verbose=True)
    tls = "on" if server_ctx is not None else "off"
    print(f"egress proxy listening on {args.bind}:{args.port} "
          f"for {grant.capability_id} -> {grant.host}:{grant.port} "
          f"{sorted(grant.methods)} tls={tls}", flush=True)
    server = http.server.ThreadingHTTPServer((args.bind, args.port),
                                             _make_handler(proxy))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
