"""Playwright navigation adapter — the Web Agent's third step (D36).

D31 brought static content in (web.get), D34 added a body the target reacts to
(web.post), D35 made https checkable. This adapter runs a real browser: it
navigates a page, lets its JavaScript execute, and returns what rendered. The
risk it introduces is different in kind from the first four injection rounds —
not "is this content trusted" but "is the environment that executes it isolated
enough" — so the adapter is thin and the isolation lives in the image, the
sandbox, and the in-container runner (:mod:`tool_gateway.browser_runner`).

Like the other web.* adapters this one only *builds* a plan; the process that
touches the network is the runner, confined to a container with no route to the
target but the egress proxy. The adapter's job is to turn a capability into the
runner's arguments and to refuse, before a container starts, anything the run
must not attempt.

The budget is a new sub-schema, not web.get's ``http.max_requests`` (§4.6, D36
§二). One ``page.goto`` fans out into sub-resources (CSS, scripts, XHR, fonts)
the agent never proposed individually; counting them against a request budget
would conflate "navigate once" with "this page happened to import forty
things", and make the budget a number the target controls. So a navigation is
the unit: ``max_navigations`` bounds top-level loads, and each navigation has
its own ``max_subresources_per_navigation`` ceiling and time window. See
:func:`browser_budget`.

Side effects: navigation itself writes nothing and changes nothing at the
target, so the profile matches web.get. A page's JavaScript can *try* to POST,
but that sub-request crosses the egress proxy and is checked against the
capability's method grant like any other (D34); it is not this action silently
gaining web.post's profile.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tool_gateway import browser_runner
from tool_gateway.adapters._http import AdapterError  # re-exported: callers catch it

TOOL = "chromium"

#: The action namespace this adapter serves (§4.1.5).
ACTION = "web.render"
ACTION_NAMESPACE = "web."

#: Navigation writes nothing at the target; any state change a page's script
#: attempts is a separate proxied sub-request, checked against the capability's
#: method grant (D34), not a profile this action quietly acquires.
WRITES_DATA = False
CHANGES_STATE = False

#: Every web.* run goes through the policy-aware egress proxy (§8.3).
REQUIRES_PROXY = True

#: Grace between the browser's own deadline and the sandbox kill. This adapter's
#: own constant (D11: two tools must not share a timeout by refactoring).
TOOL_STOP_GRACE_SECONDS = 10

#: Defaults for the browser budget sub-schema, used when a dimension is unset.
DEFAULT_MAX_NAVIGATIONS = 1
DEFAULT_MAX_SUBRESOURCES = 25
DEFAULT_NAV_TIMEOUT_SECONDS = 30

#: Ceilings on the ceilings. A capability may ask for less; it may not ask for a
#: budget so large the sandbox kill is the only real bound. These are the
#: adapter's, not the control plane's, because what a "navigation" or a
#: "sub-resource" is belongs to this tool.
MAX_ALLOWED_NAVIGATIONS = 10
MAX_ALLOWED_SUBRESOURCES = 200


@dataclass(frozen=True)
class BrowserRenderPlan:
    """What will actually be executed, before it is executed."""

    command: tuple[str, ...]
    url: str
    host: str
    port: int
    path: str
    max_duration_seconds: int
    max_navigations: int
    max_subresources_per_navigation: int
    nav_timeout_seconds: int
    proxy_url: str | None = None

    #: The flat request ceiling handed to the proxy as a backstop: the most
    #: sub-requests this whole run could legitimately make. The proxy still
    #: counts every request (D34); this keeps that count from refusing a page
    #: whose fan-out the browser budget already permits.
    proxy_max_requests: int = 0

    def as_params(self) -> dict[str, Any]:
        """Normalized parameters for the §7 execution fingerprint."""
        return {
            "url": self.url,
            "action": ACTION,
            "max_navigations": self.max_navigations,
            "max_subresources_per_navigation": self.max_subresources_per_navigation,
        }


def tool_version() -> str:
    """The pinned browser revision, for the §7 fingerprint.

    Read from the image's baked-in manifest at run time is the accurate answer;
    absent the image (unit tests on the host) the pinned constant is reported.
    """
    return "chromium-1194"


def tool_deadline(max_duration_seconds: int) -> int:
    """When the browser is asked to stop, given when the sandbox will kill it."""
    return max(1, max_duration_seconds - TOOL_STOP_GRACE_SECONDS)


def validate_action(action: str) -> str:
    """Refuse an action outside this adapter's namespace (§4.1.5)."""
    if action != ACTION:
        detail = (
            "; it is in the web.* namespace but this adapter only renders pages"
            if action.startswith(ACTION_NAMESPACE)
            else f"; {action!r} is not in the {ACTION_NAMESPACE}* namespace"
        )
        raise AdapterError(f"browser serves {ACTION!r}, not {action!r}{detail}")
    return action


def browser_budget(budget: Mapping[str, Any]) -> dict[str, Any]:
    """§4.6's ``budget.tool.browser`` sub-object, validated (D36 §二).

    Three dimensions, each fail-closed: an out-of-range value is refused, never
    clamped, because a clamp would run a different budget than the one that was
    approved. The defaults are the smallest useful navigation (one load), not
    the largest permitted.
    """
    tool_budget = dict(budget.get("tool") or {})
    values = dict(tool_budget.get("browser") or {})

    max_navigations = int(values.get("max_navigations", DEFAULT_MAX_NAVIGATIONS))
    if not 1 <= max_navigations <= MAX_ALLOWED_NAVIGATIONS:
        raise AdapterError(
            f"browser.max_navigations={max_navigations} is outside "
            f"1..{MAX_ALLOWED_NAVIGATIONS}"
        )

    max_subresources = int(
        values.get("max_subresources_per_navigation", DEFAULT_MAX_SUBRESOURCES))
    if not 1 <= max_subresources <= MAX_ALLOWED_SUBRESOURCES:
        raise AdapterError(
            f"browser.max_subresources_per_navigation={max_subresources} is "
            f"outside 1..{MAX_ALLOWED_SUBRESOURCES}"
        )

    nav_timeout = int(
        values.get("max_navigation_duration_seconds", DEFAULT_NAV_TIMEOUT_SECONDS))
    if nav_timeout <= 0:
        raise AdapterError("browser.max_navigation_duration_seconds must be positive")

    return {
        "max_navigations": max_navigations,
        "max_subresources_per_navigation": max_subresources,
        "nav_timeout_seconds": nav_timeout,
    }


def _parse_target(
    constraints: Mapping[str, Any], target: str
) -> tuple[str, str, int, str, str]:
    """Return ``(scheme, host, port, path, url)`` for an http/https target.

    The URL is absolute so the proxy can read the host, exactly as the http
    adapters build it. A bare ``host`` defaults to http; an explicit
    ``https://`` or port 443 makes it https.
    """
    if not target:
        raise AdapterError("no target")
    has_scheme = "://" in target
    scheme = "https" if str(target).lower().startswith("https:") else "http"
    bare = target.split("://", 1)[1] if has_scheme else target
    bare = bare.split("/", 1)[0].split(":", 1)[0]

    port = int(constraints.get("port") or (443 if scheme == "https" else 80))
    if port == 443 and not has_scheme:
        scheme = "https"
    if not 0 < port < 65536:
        raise AdapterError(f"invalid port {port!r}")

    path = str(constraints.get("path") or "/")
    if not path.startswith("/"):
        raise AdapterError(f"path must start with '/': {path!r}")

    return scheme, bare, port, path, f"{scheme}://{bare}:{port}{path}"


def build_plan(
    *,
    constraints: Mapping[str, Any],
    budget: Mapping[str, Any],
    target: str,
    action: str = ACTION,
    proxy_url: str | None = None,
    proxy_cert_spki: str | None = None,
    ca_cert_path: str | None = None,  # accepted for a uniform dispatch signature
) -> BrowserRenderPlan:
    """Turn a capability into one browser navigation.

    The target's URL is built and refused here for anything that is not
    http/https — a ``file:``, ``ws:`` or ``chrome:`` target never reaches a
    container. This is the same refusal the runner makes at run time, called
    through the runner's own :func:`~tool_gateway.browser_runner.classify_target`
    so there is one definition of "what will not navigate", not two that can
    drift (D30). It matters because a headless Chromium *will* read a ``file://``
    it is pointed at (D36 §四); the refusal is the boundary, so it is enforced
    twice on purpose — before the container, and inside it.
    """
    validate_action(action)

    max_duration = int(budget.get("max_duration_seconds", 600))
    if max_duration <= 0:
        raise AdapterError("max_duration_seconds must be positive")

    limits = browser_budget(budget)

    # Refuse anything that is not http/https before a container starts, through
    # the runner's own classifier so there is one definition of "will not
    # navigate". A target with a scheme is checked as written; a bare host is
    # checked as http.
    reason = browser_runner.classify_target(
        target if "://" in str(target) else f"http://{target}")
    if reason is not None:
        raise AdapterError(
            f"browser refuses target {target!r}: {reason}. Only http/https "
            "navigate; a file:, ws: or browser-internal scheme is refused before "
            "a container starts (D36)."
        )

    scheme, host, port, path, url = _parse_target(constraints, target)

    command = [
        url,
        "--max-navigations", str(limits["max_navigations"]),
        "--max-subresources", str(limits["max_subresources_per_navigation"]),
        "--nav-timeout-seconds", str(min(limits["nav_timeout_seconds"],
                                         tool_deadline(max_duration))),
    ]
    if proxy_url is not None:
        command += ["--proxy-url", proxy_url]
    if proxy_cert_spki is not None:
        command += ["--proxy-cert-spki", proxy_cert_spki]

    proxy_max_requests = (
        limits["max_navigations"] * limits["max_subresources_per_navigation"]
    )

    return BrowserRenderPlan(
        command=tuple(command), url=url, host=host, port=port, path=path,
        max_duration_seconds=max_duration,
        max_navigations=limits["max_navigations"],
        max_subresources_per_navigation=limits["max_subresources_per_navigation"],
        nav_timeout_seconds=limits["nav_timeout_seconds"],
        proxy_url=proxy_url, proxy_max_requests=proxy_max_requests,
    )


def derive_view(stdout: str, stderr: str, *, truncated_at: int = 4000) -> dict[str, Any]:
    """Build the §4.4 derived view from the runner's JSON output.

    The runner already emits a structured result; this marks it as untrusted
    content (the rendered DOM is entirely target-controlled) and reuses the same
    boundary every other tool's evidence passes through.
    """
    import json

    parsed: dict[str, Any]
    try:
        parsed = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        parsed = {"parse_error": True}

    return {
        "untrusted_content": True,
        "action": ACTION,
        "refused": bool(parsed.get("refused", False)),
        "reason": parsed.get("reason"),
        "status_code": parsed.get("status"),
        "final_url": parsed.get("final_url"),
        "subresource_count": parsed.get("subresource_count"),
        "body_excerpt": (parsed.get("content_excerpt") or "")[:truncated_at],
        "stderr_excerpt": stderr[:truncated_at],
    }
