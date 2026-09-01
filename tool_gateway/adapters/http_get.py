"""Static HTTP GET adapter — the first web content to enter the system (D31).

The Worker gains a tool, not a role. This is the same kind of extension D6 made
when it added Nmap: a capability whose ``action`` the Tool Gateway knows how to
turn into a command, confined by the same network namespace and the same CIDR
allowlist. No Web Agent, no new decision point, no new place where policy is
interpreted.

Scope, stated as much by what is refused as by what is built:

* **GET only.** Any other method is refused by :func:`build_plan` rather than
  handled, because a tool that *can* POST is a tool whose ``changes_state``
  claim depends on it choosing not to.
* **No redirect following.** This one is load-bearing rather than tidy. A
  302 is a target-controlled instruction to fetch a different address, and
  following it would let the fetched host choose the next host — authorization
  by redirect, which is I8 inverted. The namespace would still refuse anything
  off the allowlist, but a redirect to a *different in-allowlist host* would
  bypass the scope object that authorized this one. ``Location`` is recorded in
  the derived view as untrusted content, where it is a discovery signal for a
  human or a later proposal, and never an automatic fetch.
* **No JS, no browser, no egress proxy.** §8.3's policy-aware egress proxy is a
  larger piece of work; this deliverable establishes the data path under the
  isolation D6 already proved, so that the proxy has something to be added to.

Budget lives in §4.6's ``tool`` sub-object, and this is the first tool to use
it: ``http.max_requests`` and ``http.requests_per_second`` were designed there
and never exercised. The control plane still owns duration, targets and
concurrency; what a request rate means is the adapter's business.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

TOOL = "curl"

#: The action namespace this adapter serves (§4.1.5).
#:
#: ``web.*`` already existed as a scope-object pattern -- D13's report compared
#: proposals against it -- so a scope object written ``web.*`` covers this
#: without the registry learning a new shape. The adapter refuses anything
#: outside the namespace rather than assuming its caller checked.
ACTION = "web.get"
ACTION_NAMESPACE = "web."

#: The only method this tool will ever emit.
METHOD = "GET"

#: The tool's own side-effect profile, for §4.1's ``writes_data`` /
#: ``changes_state``.
#:
#: Declared by the tool rather than believed from the Worker. A GET writes
#: nothing to the target and changes none of its state, and that is true here
#: because :func:`build_plan` refuses every method that could — not because a
#: proposal said so. The distinction is the whole point: an agent's claim that
#: an action is side-effect-free is a claim, whereas an adapter that cannot
#: emit a POST is a property.
#:
#: Note what is deliberately *not* done with these: a Worker that claims
#: ``writes_data=True`` for a web.get is not corrected down to False. That
#: claim only tightens (it can trigger §5's prerequisite and escalate), and a
#: system that overrode an agent's caution with its own optimism would be
#: loosening — the one direction I6c forbids.
WRITES_DATA = False
CHANGES_STATE = False

#: Grace between the tool's own deadline and the sandbox kill.
#:
#: Deliberately its own constant rather than a shared one. D11 found the Worker
#: silently running on the Reviewer's 30-second deadline because the two had
#: been allowed to share a number; two tools with independent timeouts must not
#: acquire a common one by refactoring. The value happens to equal nmap's today
#: and that is a coincidence the tests pin as separate.
TOOL_STOP_GRACE_SECONDS = 5

#: Default ceiling on the response body pulled into evidence.
DEFAULT_MAX_BYTES = 262_144

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

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint.

        The method is included even though it is always GET. A fingerprint that
        omits a constant is a fingerprint that silently changes meaning if the
        constant ever stops being one.
        """
        return {
            "url": self.url,
            "method": METHOD,
            "max_bytes": self.max_bytes,
        }


def tool_version() -> str:
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
            f"http_get serves {ACTION!r}, not {action!r}"
            + (
                "; the action is in the web.* namespace but this adapter only "
                "implements GET"
                if action.startswith(ACTION_NAMESPACE)
                else f"; {action!r} is not even in the {ACTION_NAMESPACE}* namespace"
            )
        )
    return action


def validate_method(method: str | None) -> str:
    """GET, or nothing.

    A constraint naming any other method is refused rather than coerced to GET.
    Silently downgrading it would mean a proposal that asked to POST executed
    as something else and reported success, and the audit trail would record
    the request nobody made.
    """
    if method is None or method == "":
        return METHOD
    if method.upper() != METHOD:
        raise AdapterError(
            f"http_get performs {METHOD} only; refused method {method!r}. "
            "Methods with side effects are out of scope for this tool (D31)."
        )
    return METHOD


def build_plan(
    *,
    constraints: Mapping[str, Any],
    budget: Mapping[str, Any],
    target: str,
    action: str = ACTION,
) -> HttpGetPlan:
    """Turn a capability into one concrete HTTP GET.

    The target is an address or an in-scope name that the Authorization
    Resolver already matched to a scope object; this adapter does not resolve
    anything. ``--resolve`` is not used and no DNS is configured in the image,
    so a name that is not an address simply fails to connect rather than
    reaching whatever a resolver would have chosen (§8.3).
    """
    validate_action(action)
    validate_method(constraints.get("method"))

    if not target:
        raise AdapterError("no target")

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    tool_budget = dict(budget.get("tool") or {})
    http_budget = dict(tool_budget.get("http") or {})
    max_requests = int(http_budget.get("max_requests", 1))
    if max_requests < 1:
        raise AdapterError("http.max_requests must be at least 1")
    if max_requests != 1:
        # One plan is one request. A budget above one is honoured by the
        # control plane issuing further capabilities, not by this adapter
        # looping -- a loop inside the tool is a loop outside the broker's
        # count, which is how I3 stops meaning anything.
        raise AdapterError(
            f"http.max_requests={max_requests} but this adapter performs exactly "
            "one request per run; ask the broker for another capability"
        )
    rps = http_budget.get("requests_per_second")
    requests_per_second = float(rps) if rps is not None else None
    if requests_per_second is not None and requests_per_second <= 0:
        raise AdapterError("http.requests_per_second must be positive")

    port = int(constraints.get("port") or 80)
    if not 0 < port < 65536:
        raise AdapterError(f"invalid port {port!r}")
    path = str(constraints.get("path") or "/")
    if not path.startswith("/"):
        raise AdapterError(f"path must start with '/': {path!r}")
    max_bytes = int(http_budget.get("max_bytes", DEFAULT_MAX_BYTES))
    if max_bytes <= 0:
        raise AdapterError("http.max_bytes must be positive")

    host = target
    url = f"http://{host}:{port}{path}"

    command = [
        "/usr/bin/curl",
        # Only ever GET, stated to curl as well as enforced above.
        "--request", METHOD,
        # Headers on stdout ahead of the body, so one capture yields both and
        # the derived view does not have to guess where the body starts.
        "--include",
        # Refuse anything that is not HTTP. curl speaks a dozen protocols and
        # a target-supplied string must not be able to select one.
        "--proto", "=http",
        # Redirects are data, not instructions. See the module docstring.
        "--no-location",
        # No credential material, no cookie jar, no netrc: this tool has
        # nothing to leak because it is never given anything.
        "--no-netrc",
        "--disable",
        "--max-filesize", str(max_bytes),
        "--max-time", str(tool_deadline(max_duration)),
        "--connect-timeout", str(min(10, tool_deadline(max_duration))),
        "--silent", "--show-error",
        url,
    ]
    if requests_per_second is not None:
        # curl's own pacing, so a rate the capability granted is not left to
        # the caller to honour.
        command += ["--rate", f"{max(1, int(requests_per_second))}/s"]

    return HttpGetPlan(
        command=tuple(command), url=url, host=host, port=port, path=path,
        max_duration_seconds=max_duration, max_bytes=max_bytes,
        max_requests=max_requests, requests_per_second=requests_per_second,
    )


def extract_candidate_targets(body: str) -> list[str]:
    """Address-like strings in a response body, for discovery only (I8, D20).

    Everything returned here is *attacker-controlled by construction*: it came
    out of a document the target served. It is computed by the harness rather
    than reported by the Worker, which is D20's whole point -- provenance has
    to be a fact the pipeline derives, not a channel the agent self-declares.

    Being listed here authorizes nothing. It is the input to
    ``introduced_by_untrusted``, which escalates; the Authorization Resolver
    still requires a scope object naming the target, and D13/D15 showed that is
    the boundary that actually holds.
    """
    seen: list[str] = []
    for match in _URLISH.findall(body):
        candidate = match.rstrip(".,;:)\"'")
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


def derive_view(
    stdout: str, stderr: str, *, truncated_at: int = 4000
) -> dict[str, Any]:
    """Build the §4.4 derived view — the only thing an LLM is shown.

    Marked ``untrusted_content`` exactly as D10.5/D13 mark a scanner banner,
    and the boundary is reused unchanged rather than redesigned for a new tool.
    That matters more here than it did there: this is the first evidence that
    is a *whole document the target chose to serve* rather than a fragment a
    scanner parsed out of a service response, so the density of
    attacker-authored text is far higher and the mechanism protecting against
    it is the same one. If it needed changing for web content, it was never
    sufficient for banners either.

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

    return {
        "untrusted_content": True,
        "method": METHOD,
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
