"""Static HTTP GET adapter — the first web content to enter the system (D31).

The Worker gains a tool, not a role. This is the same kind of extension D6 made
when it added Nmap: a capability whose ``action`` the Tool Gateway knows how to
turn into a command. No Web Agent, no new decision point, no new place where
policy is interpreted.

Scope, stated as much by what is refused as by what is built:

* **GET only.** Any other method is refused by :func:`build_plan` rather than
  handled. D31 rested the ``changes_state=False`` claim on that refusal; D34
  moved the claim somewhere sturdier — see below.
* **No redirect following at the client.** A 302 is a target-controlled
  instruction to fetch a different address, and following it would let the
  fetched host choose the next host — authorization by redirect, which is I8
  inverted. ``Location`` is recorded in the derived view as untrusted content,
  where it is a discovery signal for a human or a later proposal.

  Since D34 this flag is no longer the *enforcement*. A client that follows
  redirects issues a second request, and that request goes through the egress
  proxy and is checked against the capability like any other. The proxy is the
  boundary; ``--no-location`` is defence in depth, and a test follows
  redirects deliberately to prove which of the two is holding.
* **No TLS.** https is refused with a message naming the reason (D35 will add
  proxy-side TLS termination), rather than failing at the socket as though the
  target were unreachable.

Where the side-effect flags get their authority (D34)
------------------------------------------------------
D31 wrote: ``changes_state=False`` is trustworthy because ``build_plan``
*cannot* emit a POST — a property, not a claim. Adding :mod:`http_post` to the
same namespace ends that argument, because now something in ``web.*`` can.

The authority moved rather than weakened. The flags OPA sees are floored by
:func:`tool_gateway.registry.side_effects_for`, keyed on the **action**, which
was fixed when OPA decided and the broker issued and which dispatch reads back
off the issued capability. There is no parameter anywhere on that path that
could carry a different value — that is the structural property, checked by a
test that inspects the signatures rather than by a runtime guard.

Budget lives in §4.6's ``tool`` sub-object: ``http.max_requests`` and
``http.requests_per_second``. Since D34 the count is also enforced where the
requests actually leave, by the proxy, against the broker's atomic counter.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tool_gateway.adapters import _http
from tool_gateway.adapters._http import AdapterError  # re-exported: callers catch it

TOOL = "curl"

#: The action namespace this adapter serves (§4.1.5).
#:
#: ``web.*`` already existed as a scope-object pattern -- D13's report compared
#: proposals against it -- so a scope object written ``web.*`` covers this
#: without the registry learning a new shape. The adapter refuses anything
#: outside the namespace rather than assuming its caller checked.
ACTION = "web.get"
ACTION_NAMESPACE = _http.ACTION_NAMESPACE

#: The only method this tool will ever emit.
METHOD = "GET"

#: The tool's own side-effect profile, for §4.1's ``writes_data`` /
#: ``changes_state``.
#:
#: Read by :mod:`tool_gateway.registry`, which is what the policy path consults.
#: A GET writes nothing to the target and changes none of its state.
#:
#: Note what is deliberately *not* done with these: a Worker that claims
#: ``writes_data=True`` for a web.get is not corrected down to False. The floor
#: only raises (I6c) — a system that overrode an agent's caution with its own
#: optimism would be loosening, the one direction I6c forbids.
WRITES_DATA = False
CHANGES_STATE = False

#: Every web.* run goes through the policy-aware egress proxy (§8.3, D34).
#:
#: Dispatch refuses to run a proxy-requiring adapter with no proxy rather than
#: running it directly. An unproxied web request is not a degraded run, it is
#: an unchecked one.
REQUIRES_PROXY = True

#: Grace between the tool's own deadline and the sandbox kill.
#:
#: Deliberately its own constant rather than a shared one. D11 found the Worker
#: silently running on the Reviewer's 30-second deadline because the two had
#: been allowed to share a number; two tools with independent timeouts must not
#: acquire a common one by refactoring. _http.py shares the response parser
#: between the adapters and deliberately does not share this.
TOOL_STOP_GRACE_SECONDS = 5

DEFAULT_MAX_BYTES = _http.DEFAULT_MAX_BYTES


@dataclass(frozen=True)
class HttpGetPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    url: str
    host: str
    port: int
    path: str
    max_duration_seconds: int
    max_bytes: int
    max_requests: int
    requests_per_second: float | None
    proxy_url: str | None = None

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint.

        The method is included even though it is always GET. A fingerprint that
        omits a constant is a fingerprint that silently changes meaning if the
        constant ever stops being one — which is exactly what happened to the
        namespace when D34 added a second method to it.
        """
        return {
            "url": self.url,
            "method": METHOD,
            "max_bytes": self.max_bytes,
        }


def tool_version() -> str:
    """The installed curl version, for the §7 fingerprint."""
    return _http.curl_version()


def tool_deadline(max_duration_seconds: int) -> int:
    """When curl is asked to stop, given when the sandbox will kill it.

    Independent of every other adapter's deadline by construction -- it reads
    this module's own grace constant. See :data:`TOOL_STOP_GRACE_SECONDS`.
    """
    return max(1, max_duration_seconds - TOOL_STOP_GRACE_SECONDS)


def validate_action(action: str) -> str:
    """Refuse an action outside this adapter's namespace (§4.1.5)."""
    if action != ACTION:
        raise AdapterError(
            "http_get: " + _http.namespace_refusal(ACTION, action, method=METHOD)
        )
    return action


def validate_method(method: str | None) -> str:
    """GET, or nothing."""
    if method is None or method == "":
        return METHOD
    if method.upper() != METHOD:
        raise AdapterError(
            f"http_get performs {METHOD} only; refused method {method!r}. "
            "A method with side effects belongs to web.post, which is a "
            "different action with a different side-effect profile (D34)."
        )
    return METHOD


def build_plan(
    *,
    constraints: Mapping[str, Any],
    budget: Mapping[str, Any],
    target: str,
    action: str = ACTION,
    proxy_url: str | None = None,
    ca_cert_path: str | None = None,
) -> HttpGetPlan:
    """Turn a capability into one concrete HTTP GET.

    The target is an address or an in-scope name that the Authorization
    Resolver already matched to a scope object; this adapter does not resolve
    anything. Since D34 the connection is made to ``proxy_url`` and the target
    appears in the absolute-form request line, which is what lets the proxy
    check the host against the capability.
    """
    validate_action(action)
    validate_method(constraints.get("method"))

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    limits = _http.http_budget(budget)
    scheme, host, port, path, url = _http.request_target(
        constraints, target, default_port=80, ca_cert_path=ca_cert_path)

    command = _http.base_command(
        method=METHOD, url=url, scheme=scheme, max_bytes=limits["max_bytes"],
        deadline_seconds=tool_deadline(max_duration),
        requests_per_second=limits["requests_per_second"], proxy_url=proxy_url,
        ca_cert_path=ca_cert_path,
    )

    return HttpGetPlan(
        command=tuple(command), url=url, host=host, port=port, path=path,
        max_duration_seconds=max_duration, max_bytes=limits["max_bytes"],
        max_requests=limits["max_requests"],
        requests_per_second=limits["requests_per_second"], proxy_url=proxy_url,
    )


def extract_candidate_targets(body: str) -> list[str]:
    """Address-like strings in a response body, for discovery only (I8, D20)."""
    return _http.extract_candidate_targets(body)


def derive_view(stdout: str, stderr: str, *, truncated_at: int = 4000) -> dict[str, Any]:
    """Build the §4.4 derived view — the only thing an LLM is shown."""
    return _http.derive_view(
        stdout, stderr, method=METHOD, truncated_at=truncated_at
    )
