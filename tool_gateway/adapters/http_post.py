"""HTTP POST adapter — the first tool that changes a target's state (D34).

D31 built web.get deliberately unable to do this, and rested a claim on that
inability: ``changes_state=False`` was trustworthy because ``build_plan``
*could not* emit a POST. This module ends that argument, so D34 had to replace
it rather than weaken it. See :mod:`tool_gateway.registry` for where the flags
get their authority now — keyed on the action, which is fixed at the moment OPA
decides and read back off the issued capability at dispatch, with no parameter
anywhere on the path that could carry a different value.

What this adapter refuses, and why each refusal is load-bearing:

* **POST only — not PUT, not DELETE, not PATCH.** Evaluated at D34 and kept
  closed. DELETE is irreversible at the target and the system has no
  blast-radius accounting to put behind it; nothing in the pipeline has a
  caller for either. A destructive capability with no caller only widens what
  §8.3 calls "the most a compromised Worker can do", which is the union of its
  live capabilities.
* **No TLS.** https is refused by name (see :data:`_http.TLS_REFUSAL`), because
  the egress proxy reads method, path and host out of every request and can
  read none of them inside a TLS session. D35 adds termination.
* **A body the capability supplies, never the target.** The request body comes
  from ``constraints["body"]``, which travelled through OPA and the broker. A
  body assembled from a previous response would let the target dictate what is
  written to it next, which is I8 inverted with side effects attached.
* **``--data-binary``, never ``--data``.** curl's ``--data`` strips newlines
  and, given ``@``, reads a *file* off the tool container. A target-influenced
  string reaching it would be a file-read primitive. ``--data-binary`` with the
  body passed through ``@-`` on stdin keeps it inert.

Everything else — the response parser, the discovery extraction, the derived
view, the budget schema — is shared with web.get through
:mod:`tool_gateway.adapters._http` rather than copied, for the reason D30
recorded: two implementations of one fact drift, and the drift shows up as two
tools disagreeing about what the same target said.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tool_gateway.adapters import _http
from tool_gateway.adapters._http import AdapterError  # re-exported: callers catch it

TOOL = "curl"

#: The action namespace this adapter serves (§4.1.5).
ACTION = "web.post"
ACTION_NAMESPACE = _http.ACTION_NAMESPACE

#: The only method this tool will ever emit.
METHOD = "POST"

#: Methods inside the web.* namespace that exist as actions but have no adapter.
#:
#: Listed rather than left implicit so the refusal can say "deliberately not
#: implemented" instead of "unknown action". §5's
#: ``requires_known_classification`` already names them, which is what makes
#: the distinction visible: the policy is ready for them, the gateway is not.
DELIBERATELY_UNIMPLEMENTED = ("web.put", "web.delete")

#: The tool's own side-effect profile, for §4.1's ``writes_data`` /
#: ``changes_state``.
#:
#: Both True, and this is the first adapter for which that is so. A POST is a
#: request for the target to accept data and act on it; whether a particular
#: endpoint happens to be read-only is the target's business and not something
#: this side can know. Declaring the cautious value where the truth is
#: unknowable is the only direction I6c permits.
WRITES_DATA = True
CHANGES_STATE = True

#: Every web.* run goes through the policy-aware egress proxy (§8.3, D34).
REQUIRES_PROXY = True

#: Grace between the tool's own deadline and the sandbox kill.
#:
#: This adapter's own constant, equal to the others today by coincidence. D11's
#: lesson stands: two tools must not acquire a shared timeout by refactoring,
#: and a test breaks one adapter's grace to prove the others do not move.
TOOL_STOP_GRACE_SECONDS = 5

#: Ceiling on the request body the capability may carry.
#:
#: A limit on what this system can *send*, distinct from ``http.max_bytes``,
#: which limits what it will read back. They are different directions and a
#: shared number would quietly make one of them meaningless.
MAX_REQUEST_BODY_BYTES = 64_000

#: Content types a capability may ask for.
#:
#: An allowlist rather than a pass-through: the Content-Type selects how the
#: target parses the body, so a free-form value lets a proposal reach parsers
#: (XML external entities, multipart file handling) that nothing in this
#: deliverable has reasoned about.
ALLOWED_CONTENT_TYPES = (
    "application/x-www-form-urlencoded",
    "application/json",
    "text/plain",
)
DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded"


@dataclass(frozen=True)
class HttpPostPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    url: str
    host: str
    port: int
    path: str
    body: str
    content_type: str
    max_duration_seconds: int
    max_bytes: int
    max_requests: int
    requests_per_second: float | None
    proxy_url: str | None = None

    #: The body is fed on stdin rather than as an argv element. See
    #: :func:`build_plan`.
    stdin: str = ""

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint.

        The body is part of the identity of the action: two POSTs to one URL
        with different bodies are two different things happening to the target,
        and a fingerprint that ignored the body would dedup the second into the
        first and skip it.
        """
        return {
            "url": self.url,
            "method": METHOD,
            "content_type": self.content_type,
            "body": self.body,
            "max_bytes": self.max_bytes,
        }


def tool_version() -> str:
    """The installed curl version, for the §7 fingerprint."""
    return _http.curl_version()


def tool_deadline(max_duration_seconds: int) -> int:
    """When curl is asked to stop, given when the sandbox will kill it."""
    return max(1, max_duration_seconds - TOOL_STOP_GRACE_SECONDS)


def validate_action(action: str) -> str:
    """Refuse an action outside this adapter's namespace (§4.1.5)."""
    if action in DELIBERATELY_UNIMPLEMENTED:
        raise AdapterError(
            f"http_post: {action!r} is deliberately not implemented (D34). POST "
            "was opened because the system has a use for it; PUT and DELETE "
            "were evaluated and kept closed — DELETE is irreversible at the "
            "target and nothing here accounts for that blast radius."
        )
    if action != ACTION:
        raise AdapterError(
            "http_post: " + _http.namespace_refusal(ACTION, action, method=METHOD)
        )
    return action


def validate_method(method: str | None) -> str:
    """POST, or nothing."""
    if method is None or method == "":
        return METHOD
    if method.upper() != METHOD:
        raise AdapterError(
            f"http_post performs {METHOD} only; refused method {method!r}. "
            "Each method with a different side-effect profile is a different "
            "action, so that the profile can be looked up from the action (D34)."
        )
    return METHOD


def validate_body(constraints: Mapping[str, Any]) -> tuple[str, str]:
    """The request body and its content type, from the capability alone."""
    body = constraints.get("body")
    if body is None:
        raise AdapterError(
            "web.post requires an explicit body in the capability's constraints. "
            "An empty default would mean the proposal that was approved and the "
            "request that was sent described different things."
        )
    if not isinstance(body, str):
        raise AdapterError(f"body must be a string, not {type(body).__name__}")
    encoded = body.encode("utf-8", "surrogatepass")
    if len(encoded) > MAX_REQUEST_BODY_BYTES:
        raise AdapterError(
            f"body is {len(encoded)} bytes, over the {MAX_REQUEST_BODY_BYTES}-byte "
            "ceiling on what one request may send"
        )

    content_type = str(constraints.get("content_type") or DEFAULT_CONTENT_TYPE)
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise AdapterError(
            f"content_type {content_type!r} is not one of "
            f"{', '.join(ALLOWED_CONTENT_TYPES)}. The type selects the target's "
            "parser, so it is an allowlist rather than a pass-through."
        )
    return body, content_type


def build_plan(
    *,
    constraints: Mapping[str, Any],
    budget: Mapping[str, Any],
    target: str,
    action: str = ACTION,
    proxy_url: str | None = None,
    ca_cert_path: str | None = None,
) -> HttpPostPlan:
    """Turn a capability into one concrete HTTP POST.

    The body reaches curl on **stdin** (``--data-binary @-``) rather than as an
    argv element. Three reasons, in descending order of how badly each would
    bite: a body on the command line is visible in the process table and in the
    ``tool_run.started`` audit payload, which records ``plan.command``; argv has
    a length limit that a legitimate body can exceed; and ``--data-binary @``
    followed by anything other than ``-`` reads a file off the tool container,
    so keeping the sigil fixed at ``@-`` means no body value can ever select a
    path.
    """
    validate_action(action)
    validate_method(constraints.get("method"))

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    limits = _http.http_budget(budget)
    scheme, host, port, path, url = _http.request_target(
        constraints, target, default_port=80, ca_cert_path=ca_cert_path)
    body, content_type = validate_body(constraints)

    command = _http.base_command(
        method=METHOD, url=url, scheme=scheme, max_bytes=limits["max_bytes"],
        deadline_seconds=tool_deadline(max_duration),
        requests_per_second=limits["requests_per_second"], proxy_url=proxy_url,
        ca_cert_path=ca_cert_path,
    )
    # Inserted before the URL, which base_command leaves last.
    insert_at = len(command) - 1
    command[insert_at:insert_at] = [
        "--header", f"Content-Type: {content_type}",
        # Never bare --data: it strips newlines, and with a leading @ it reads
        # a file. The sigil is fixed here so no body value can select a path.
        "--data-binary", "@-",
    ]

    return HttpPostPlan(
        command=tuple(command), url=url, host=host, port=port, path=path,
        body=body, content_type=content_type,
        max_duration_seconds=max_duration, max_bytes=limits["max_bytes"],
        max_requests=limits["max_requests"],
        requests_per_second=limits["requests_per_second"], proxy_url=proxy_url,
        stdin=body,
    )


def extract_candidate_targets(body: str) -> list[str]:
    """Address-like strings in a response body, for discovery only (I8, D20)."""
    return _http.extract_candidate_targets(body)


def derive_view(stdout: str, stderr: str, *, truncated_at: int = 4000) -> dict[str, Any]:
    """Build the §4.4 derived view — the only thing an LLM is shown.

    Identical to web.get's, deliberately. The response to a POST is generated
    in reaction to input this system supplied, which makes it the most
    target-controlled evidence the pipeline has yet carried; it goes through
    the same ``untrusted_content`` boundary D10.5 built for scanner banners. If
    that boundary needed strengthening for this, it was never sufficient for
    the banners either.
    """
    return _http.derive_view(
        stdout, stderr, method=METHOD, truncated_at=truncated_at,
        extra={"request_body_was_supplied_by_capability": True},
    )
