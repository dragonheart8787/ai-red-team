"""Policy-aware egress proxy (§8.3, D34).

§8.3 split egress enforcement by protocol and gave the reason: binding a
capability to an address does not survive contact with reality, because one
hostname maps to many addresses, they move when the TTL lapses, and DNS
rebinding makes the gap attacker-controlled.

    HTTP/S      → Tool Container → Policy-aware Egress Proxy → Internet
    Raw TCP/UDP → Tool Container → Network Namespace + CIDR allowlist

D6 built the second path. This is the first, and it exists because the
namespace can only answer "can a packet reach this address" — it cannot read a
method, a hostname or a request count, which are exactly the things a
capability constrains.

What is checked, per request
-----------------------------
Every request is checked against one :class:`Grant`, which is built from the
issued capability before the proxy starts and never from anything in the
request:

* **host and port** — against the single host the capability names. Not a
  pattern, not a suffix match: one capability authorizes one target;
* **method** — against the methods the capability's action implies. A web.get
  capability cannot POST even if the tool tries;
* **request count** — at two levels, because one level cannot cover both
  failure modes. Across runs, the Capability Broker's atomic
  check-and-increment (§8.5) is the authority and the control plane spends one
  request before the run starts. Within a run, this proxy holds a counter
  bounded by the same ``max_requests``, because a tool that loops inside one
  container never returns to the control plane to be counted — a loop inside
  the tool is a loop outside the broker's count, which is how I3 stops meaning
  anything. The in-container proxy has no database connection and is not given
  one: keeping credentials off the sandbox network matters more than having a
  single counter, and the two bounds are each sound for what they bound.

What the tool says about itself is never an input. The request line carries the
host, so this is not a hostname the tool asserts out of band — it is the
address the request is actually made to, which is the same fact the target
would see.

Redirects
----------
A 3xx response is passed through unchanged, because ``Location`` is evidence
(D31) and rewriting evidence would make the record disagree with what the
target sent. Enforcement is not in the response at all: if the client follows
the redirect it issues a **second request**, that request arrives here, and it
is checked like any other. A redirect off the allowlist and a redirect to a
different in-allowlist host are both refused on arrival, with no dependence on
the client having been configured not to follow. The test proves this with a
client that follows redirects deliberately.

TLS
----
``CONNECT`` is refused with a message naming the reason. Everything above
depends on reading the request line and the headers; inside a TLS session this
proxy could see only the hostname the tool itself asked to connect to, which
turns a check into a self-report — the exact failure mode D31 established the
rule against when it insisted the kernel, not the scanner, decide what was
reachable. D35 adds termination so the check can stay real.

Why the refusals are not the evidence
--------------------------------------
This module writes an access log, and that log is *not* what the tests assert a
refusal with. A proxy reporting that it refused something is a proxy reporting
on itself. The evidence is the target's own access log: a request that was
refused here never reaches the target, so the target's log has no line for it.
That witness is outside this file's control, which is what makes it worth
having — the same reason ``probe_egress`` asks the kernel instead of the
scanner.
"""

from __future__ import annotations

import http.server
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
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

#: Status for CONNECT / TLS, which this proxy cannot inspect (D35).
TLS_STATUS = 501

#: Reason strings. They appear in the proxy's own log and in the body it
#: returns, and they are stable because the tests match on them -- while never
#: relying on them *alone* to prove a refusal. See the module docstring.
HOST_NOT_AUTHORIZED = "host_not_authorized"
PORT_NOT_AUTHORIZED = "port_not_authorized"
METHOD_NOT_AUTHORIZED = "method_not_authorized"
BUDGET_EXHAUSTED = "budget_exhausted"
TLS_NOT_SUPPORTED = "tls_not_supported"
NOT_ABSOLUTE_FORM = "not_absolute_form"

TLS_MESSAGE = (
    "This proxy terminates plain HTTP so it can check the method, path, host "
    "and request count of every request against the capability. It cannot read "
    "any of those inside a TLS session, and a CONNECT tunnel would reduce the "
    "host check to trusting the hostname the tool itself asked for. TLS "
    "termination is D35."
)


class _RefuseToFollowRedirects(urllib.request.HTTPRedirectHandler):
    """Make urllib hand a 3xx back instead of chasing it.

    ``urlopen`` follows redirects by default, which would make *the proxy* the
    thing that acts on the target's instruction — the precise inversion D31
    ruled out, and worse here than at the client, because a proxy that follows
    does so before any check has been applied to the new address.

    Returning ``None`` from ``redirect_request`` raises ``HTTPError`` for the
    3xx, which the forwarding path already handles by passing the status,
    headers and body through untouched. So the redirect reaches the tool as
    evidence, and the request that would follow it arrives here as a new
    request and is checked like any other.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


#: One opener for every forwarded request, built once.
#:
#: Also drops urllib's cookie and auth handling by simply not installing any:
#: this proxy carries no credential material, and a shared cookie jar would let
#: one target set state that another request carries.
_FORWARDER = urllib.request.build_opener(_RefuseToFollowRedirects)


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


class PolicyProxy:
    """A forward proxy that checks every request against one :class:`Grant`.

    ``consume`` is called once per request that passes the static checks, and
    returning False refuses it. The default is a local counter bounded by the
    grant's ``max_requests`` — deliberately not "always allow", because a
    default that disables a check is how a check stops existing without anyone
    deciding that it should. The control plane passes the broker's atomic
    check-and-increment instead when it is the one running the proxy.
    """

    def __init__(
        self,
        grant: Grant,
        *,
        consume: Callable[[], bool] | None = None,
        bind: tuple[str, int] = ("0.0.0.0", 3128),
        upstream_timeout: float = 20.0,
        verbose: bool = False,
    ) -> None:
        self.grant = grant
        self.consume = consume or LocalBudget(grant.max_requests)
        self.bind = bind
        self.upstream_timeout = upstream_timeout
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
        """
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http",) or not parsed.hostname:
            return False, NOT_ABSOLUTE_FORM, REFUSED_STATUS

        if not self.grant.allows_method(method):
            return False, METHOD_NOT_AUTHORIZED, REFUSED_STATUS

        port = parsed.port or 80
        allowed, reason = self.grant.allows(parsed.hostname, port)
        if not allowed:
            return False, reason, REFUSED_STATUS

        if not self.consume():
            return False, BUDGET_EXHAUSTED, BUDGET_STATUS
        return True, None, 200


def _make_handler(proxy: PolicyProxy):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "cyberorch-egress-proxy/1"
        # Absolute-form request lines are long; the default is plenty but
        # stating it keeps a target-supplied URL from being a memory question.
        max_request_line = 8190

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            # The proxy keeps a structured log of its own; the stdlib's
            # stderr chatter would interleave with the target's access log in
            # container output and make the independent witness harder to read.
            pass

        # -- helpers ------------------------------------------------------
        def _refuse(self, method: str, url: str, reason: str, status: int) -> None:
            parsed = urllib.parse.urlsplit(url)
            proxy.record(AccessRecord(
                method=method, url=url, host=parsed.hostname or "",
                port=parsed.port or 0, decision="DENY", reason=reason,
                status=status,
            ))
            body = json.dumps({
                "refused_by": "cyberorch-egress-proxy",
                "reason": reason,
                "capability_id": proxy.grant.capability_id,
                "detail": TLS_MESSAGE if reason == TLS_NOT_SUPPORTED else None,
            }).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Cyberorch-Refusal", reason)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _forward(self, method: str, url: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(length) if length else None

            forwarded = urllib.request.Request(url, data=payload, method=method)
            for name, value in self.headers.items():
                lowered = name.lower()
                # Hop-by-hop headers, and the ones urllib sets itself.
                if lowered in ("proxy-connection", "connection", "keep-alive",
                               "host", "content-length", "transfer-encoding"):
                    continue
                forwarded.add_header(name, value)

            parsed = urllib.parse.urlsplit(url)
            try:
                with _FORWARDER.open(
                    forwarded, timeout=proxy.upstream_timeout
                ) as upstream:
                    status = upstream.status
                    headers = list(upstream.headers.items())
                    body = upstream.read()
            except urllib.error.HTTPError as exc:
                # A 4xx/5xx from the target is the target's answer, not a
                # refusal by this proxy, and it has to reach the tool as the
                # status the target actually sent.
                status = exc.code
                headers = list(exc.headers.items()) if exc.headers else []
                body = exc.read()
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                proxy.record(AccessRecord(
                    method=method, url=url, host=parsed.hostname or "",
                    port=parsed.port or 80, decision="UPSTREAM_ERROR",
                    reason=str(exc), status=502,
                ))
                message = json.dumps({"upstream_error": str(exc)}).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(message)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(message)
                return

            proxy.record(AccessRecord(
                method=method, url=url, host=parsed.hostname or "",
                port=parsed.port or 80, decision="ALLOW", status=status,
            ))

            self.send_response(status)
            for name, value in headers:
                if name.lower() in ("transfer-encoding", "connection",
                                    "content-length"):
                    continue
                # Location is passed through untouched. It is evidence, and
                # the request that would follow it is checked on arrival.
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _handle(self, method: str) -> None:
            url = self.path
            if not url.lower().startswith("http://"):
                # Origin-form ("GET /path") means the client treated this as an
                # ordinary server. There is no host to check in that request,
                # so it is refused rather than guessed at from the Host header.
                self._refuse(method, url, NOT_ABSOLUTE_FORM, REFUSED_STATUS)
                return
            allowed, reason, status = proxy.check(method, url)
            if not allowed:
                self._refuse(method, url, reason or "refused", status)
                return
            self._forward(method, url)

        # -- methods ------------------------------------------------------
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
            self._refuse("CONNECT", f"connect://{self.path}",
                         TLS_NOT_SUPPORTED, TLS_STATUS)

    return Handler


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - container entry
    """Run the proxy from a container.

    The grant arrives as one JSON argument rather than as separate flags, so
    that a partially-specified grant is a parse error instead of a default.
    There is no flag that widens it and no way to reload it: the proxy's life
    is one capability's life.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Policy-aware egress proxy (§8.3).")
    parser.add_argument("--grant", required=True, help="JSON grant object.")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3128)
    args = parser.parse_args(argv)

    raw = json.loads(args.grant)
    grant = Grant(
        capability_id=str(raw["capability_id"]),
        host=str(raw["host"]),
        port=int(raw["port"]),
        methods=frozenset(m.upper() for m in raw["methods"]),
        max_requests=int(raw["max_requests"]),
    )

    # No database connection from inside the container, by design: the
    # in-container proxy enforces host, port, method and the within-run request
    # ceiling, while the capability's persistent budget is spent by the control
    # plane before the run starts. Keeping credentials off the sandbox network
    # is worth more than a single shared counter.
    proxy = PolicyProxy(grant, bind=(args.bind, args.port), verbose=True)
    print(f"egress proxy listening on {args.bind}:{args.port} "
          f"for {grant.capability_id} -> {grant.host}:{grant.port} "
          f"{sorted(grant.methods)}", flush=True)
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
