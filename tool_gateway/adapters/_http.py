"""Shared machinery for the HTTP adapters (D31 web.get, D34 web.post).

Two adapters that parse the same responses must not do it twice. This stage's
record is largely a list of what happens when two things that should agree are
computed separately -- the approval record and the capability it authorized
(D30), the preview and the stored row (D29) -- and each was closed by making
one derivation serve both readers. A second copy of "where does the body start
in a curl --include capture" would drift the same way, and the drift would show
up as two tools disagreeing about what a target said.

What is deliberately **not** shared:

* ``TOOL_STOP_GRACE_SECONDS`` and ``tool_deadline``. D11 found the Worker
  running on the Reviewer's deadline because two components had been allowed to
  share a number. Each adapter computes its own deadline from its own constant,
  and a test breaks one to prove the other does not move. Sharing the response
  parser is safe because it has no authority; sharing a timeout is not.
* ``WRITES_DATA`` / ``CHANGES_STATE``. They differ per tool, and the whole
  point of D34's side-effect floor is that the value is looked up from the
  action rather than carried around.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping
from typing import Any

#: Default ceiling on the response body pulled into evidence.
DEFAULT_MAX_BYTES = 262_144

#: The action namespace the HTTP adapters serve (§4.1.5).
ACTION_NAMESPACE = "web."

_HEADER_LINE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.*?)\s*$")
_STATUS_LINE = re.compile(r"^HTTP/(\d(?:\.\d)?)\s+(\d{3})")

# Absolute and scheme-relative URLs, and bare host:port / bare IPv4, anywhere in
# a body. Deliberately generous: this feeds *discovery*, where over-reporting
# costs an escalation and under-reporting hides an injected lure (D20).
_URLISH = re.compile(
    r"""(?:(?:https?:)?//[^\s"'<>)\]]+)        # //host/... or http://host/...
      | (?:\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?) # 203.0.113.77 or with a port
    """,
    re.VERBOSE,
)


class AdapterError(ValueError):
    """The capability cannot be turned into a request."""


#: Message for an https request on a run that was given no CA to verify with.
#:
#: D34 refused TLS outright and said so; D35 terminates it *when* the control
#: plane has handed this run a per-engagement CA (see
#: control_plane.tls.engagement_ca). Absent that CA the tool has nothing to
#: verify the proxy's leaf against, so the honest answer is still an explicit
#: refusal naming the reason, never a generic socket failure that reads like an
#: unreachable target.
TLS_REFUSAL = (
    "an https request needs the per-engagement CA the egress proxy terminates "
    "TLS with, and this run was given none. Without it the tool cannot verify "
    "the proxy's leaf certificate, so the TLS session is refused rather than "
    "trusted blindly. Supply the engagement CA (D35) to make https checkable."
)


def wants_tls(constraints: Mapping[str, Any], port: int) -> bool:
    """Whether this request is for TLS, however it was spelled.

    A request for TLS can arrive three ways -- an explicit ``scheme``, port
    443, or an ``https://`` target -- and a check that caught only one would
    surprise someone. Kept in one place so the adapters and the refusal agree.
    """
    scheme = constraints.get("scheme")
    if scheme is not None and scheme.lower() == "https":
        return True
    if port == 443:
        return True
    target = str(constraints.get("_target") or "")
    return target.lower().startswith("https:")


def curl_version() -> str:
    """The installed curl version, for the §7 fingerprint."""
    binary = shutil.which("curl")
    if binary is None:
        return "unknown"
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return "unknown"
    match = re.search(r"curl (\S+)", out)
    return match.group(1) if match else "unknown"


def http_budget(budget: Mapping[str, Any]) -> dict[str, Any]:
    """§4.6's ``budget.tool.http`` sub-object, validated.

    The control plane owns duration, targets and concurrency; what a request
    rate means is the adapter's business, which is why this lives here and not
    in the broker.
    """
    tool_budget = dict(budget.get("tool") or {})
    values = dict(tool_budget.get("http") or {})

    max_requests = int(values.get("max_requests", 1))
    if max_requests < 1:
        raise AdapterError("http.max_requests must be at least 1")
    if max_requests != 1:
        # One plan is one request. A budget above one is honoured by the
        # control plane issuing further capabilities, not by an adapter
        # looping -- a loop inside the tool is a loop outside the broker's
        # count, which is how I3 stops meaning anything. Since D34 the proxy
        # counts the requests that actually leave, so a looping tool would
        # also be refused there; this stays because a refusal before the
        # request is better than one after it.
        raise AdapterError(
            f"http.max_requests={max_requests} but this adapter performs exactly "
            "one request per run; ask the broker for another capability"
        )

    rps = values.get("requests_per_second")
    requests_per_second = float(rps) if rps is not None else None
    if requests_per_second is not None and requests_per_second <= 0:
        raise AdapterError("http.requests_per_second must be positive")

    max_bytes = int(values.get("max_bytes", DEFAULT_MAX_BYTES))
    if max_bytes <= 0:
        raise AdapterError("http.max_bytes must be positive")

    return {
        "max_requests": max_requests,
        "requests_per_second": requests_per_second,
        "max_bytes": max_bytes,
    }


def request_target(
    constraints: Mapping[str, Any], target: str, *, default_port: int,
    ca_cert_path: str | None = None,
) -> tuple[str, str, int, str, str]:
    """Validate the target and return ``(scheme, host, port, path, url)``.

    The target is an address or an in-scope name the Authorization Resolver
    already matched to a scope object; no adapter resolves anything. The URL is
    absolute — that is what lets the proxy read the host out of the request
    line (plain HTTP) or the CONNECT target (https) and check it.

    An https request is allowed only when ``ca_cert_path`` is set: the tool
    verifies the proxy's leaf against that CA, and without it there is nothing
    to verify against, so it is refused with the reason named (D35).
    """
    if not target:
        raise AdapterError("no target")

    tls = wants_tls({**dict(constraints), "_target": target},
                    int(constraints.get("port") or 0))
    if tls and ca_cert_path is None:
        raise AdapterError(TLS_REFUSAL)

    scheme = "https" if tls else "http"
    port = int(constraints.get("port") or (443 if tls else default_port))
    if not 0 < port < 65536:
        raise AdapterError(f"invalid port {port!r}")

    path = str(constraints.get("path") or "/")
    if not path.startswith("/"):
        raise AdapterError(f"path must start with '/': {path!r}")

    return scheme, target, port, path, f"{scheme}://{target}:{port}{path}"


def base_command(
    *, method: str, url: str, scheme: str, max_bytes: int, deadline_seconds: int,
    requests_per_second: float | None, proxy_url: str | None,
    ca_cert_path: str | None = None,
) -> list[str]:
    """The curl invocation both adapters share, minus anything method-specific.

    Every flag here is a refusal. The ones that matter most:

    ``--proto =http``
        curl speaks a dozen protocols and a target-supplied string must not be
        able to select one. Since D34 it also states the TLS boundary at the
        client: an https URL fails here even if something upstream let it
        through.
    ``--no-location``
        Redirects are data, not instructions (D31). Note what this is *not*
        doing since D34: it is no longer the enforcement. A redirect is
        followed by issuing a second request, that request goes through the
        proxy, and the proxy checks it against the capability like any other.
        The client flag is defence in depth; the proxy is the boundary. A test
        proves it by following redirects deliberately.
    ``--proxy``
        All web.* traffic is addressed to the proxy. The tool container has no
        route to the target at all (§8.3's two-network topology), so a tool
        that dropped this flag would reach nothing rather than reaching the
        target unchecked.
    """
    command = [
        "/usr/bin/curl",
        "--request", method,
        # Headers on stdout ahead of the body, so one capture yields both and
        # the derived view does not have to guess where the body starts.
        "--include",
        # curl speaks a dozen protocols; pin it to exactly the one this request
        # is for so a target-supplied string cannot select another. https is
        # permitted only when we also hand curl a CA to verify against, below.
        "--proto", "=https" if scheme == "https" else "=http",
        "--no-location",
        # No credential material, no cookie jar, no netrc: these tools have
        # nothing to leak because they are never given anything.
        "--no-netrc",
        "--disable",
        "--max-filesize", str(max_bytes),
        "--max-time", str(deadline_seconds),
        "--connect-timeout", str(min(10, deadline_seconds)),
        "--silent", "--show-error",
    ]
    if scheme == "https" and ca_cert_path is not None:
        # Verify the proxy's leaf against the per-engagement CA, and nothing
        # else: --cacert replaces the default trust store, so a leaf signed by
        # any other CA -- including a real public one -- is rejected. That is
        # what makes a pinning target's refusal clean (D35).
        command += ["--cacert", ca_cert_path]
    if proxy_url is not None:
        command += ["--proxy", proxy_url]
    if requests_per_second is not None:
        # curl's own pacing, so a rate the capability granted is not left to
        # the caller to honour.
        command += ["--rate", f"{max(1, int(requests_per_second))}/s"]
    command.append(url)
    return command


def extract_candidate_targets(body: str) -> list[str]:
    """Address-like strings in a response body, for discovery only (I8, D20).

    Everything returned here is *attacker-controlled by construction*: it came
    out of a document the target served. It is computed by the harness rather
    than reported by the Worker, which is D20's whole point -- provenance has
    to be a fact the pipeline derives, not a channel the agent self-declares.

    Being listed here authorizes nothing. It is the input to
    ``introduced_by_untrusted``, which escalates; the Authorization Resolver
    still requires a scope object naming the target, and D13/D15/D31 showed
    that is the boundary that actually holds.
    """
    seen: list[str] = []
    for match in _URLISH.findall(body):
        candidate = match.rstrip(".,;:)\"'")
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


def derive_view(
    stdout: str, stderr: str, *, method: str, truncated_at: int = 4000,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the §4.4 derived view — the only thing an LLM is shown.

    Marked ``untrusted_content`` exactly as D10.5/D13 mark a scanner banner,
    and the boundary is reused unchanged rather than redesigned per tool. That
    mattered at D31, where the evidence became a whole document the target
    chose to serve rather than a fragment a scanner parsed; it matters again at
    D34, where the document is generated *in response to input the system
    supplied*. The mechanism does not change for either, which is the claim:
    if it needed changing for a POST response it was never sufficient for a
    banner.

    The raw response is kept by the caller under §4.4's raw/derived split; what
    is built here is only ever the derived side.
    """
    head, _, body = stdout.partition("\r\n\r\n")
    if not body and "\n\n" in stdout:
        head, _, body = stdout.partition("\n\n")

    status_code = None
    http_version = None
    status = _STATUS_LINE.search(head)
    if status:
        http_version, code = status.group(1), status.group(2)
        status_code = int(code)

    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:
        match = _HEADER_LINE.match(line)
        if match:
            headers[match.group(1).lower()] = match.group(2)

    view = {
        "untrusted_content": True,
        "method": method,
        "http_version": http_version,
        "status_code": status_code,
        "content_type": headers.get("content-type"),
        "content_length": headers.get("content-length"),
        # Recorded, never followed. A Location is the target proposing where to
        # go next, which is a discovery signal and not a routing decision.
        "location_header": headers.get("location"),
        "redirect_not_followed": status_code is not None and 300 <= status_code < 400,
        "headers": headers,
        "body_excerpt": body[:truncated_at],
        "body_truncated": len(body) > truncated_at,
        "body_bytes": len(body.encode("utf-8", "replace")),
        # Discovery input, not authorization. See extract_candidate_targets.
        "candidate_targets": extract_candidate_targets(body),
        "stderr_excerpt": stderr[:truncated_at],
    }
    if extra:
        view.update(extra)
    return view


def namespace_refusal(adapter_action: str, action: str, *, method: str) -> str:
    """The message for an action outside an adapter's namespace (§4.1.5)."""
    if action.startswith(ACTION_NAMESPACE):
        detail = (
            f"; the action is in the web.* namespace but this adapter only "
            f"implements {method}"
        )
    else:
        detail = f"; {action!r} is not even in the {ACTION_NAMESPACE}* namespace"
    return f"this adapter serves {adapter_action!r}, not {action!r}{detail}"
