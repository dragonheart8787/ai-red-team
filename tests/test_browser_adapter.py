"""The Playwright adapter and its budget sub-schema (D36 §二).

Two things are proved here without a browser:

1. the adapter turns a capability into the runner's arguments correctly, and
   refuses — before any container starts — a target that must not navigate;
2. the browser budget (a navigation is the unit, sub-resources have their own
   ceiling) is really enforced, pinned by a mutation test in the same shape as
   D34's ``consume_request`` proof: stub the one check out and the guarantee
   fails.
"""

from __future__ import annotations

import pytest

from tool_gateway import browser_runner, registry
from tool_gateway.adapters import browser
from tool_gateway.adapters._http import AdapterError


def _budget(**browser_dims):
    return {"max_duration_seconds": 600, "tool": {"browser": browser_dims}}


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------

def test_web_render_routes_to_the_browser_adapter():
    assert registry.adapter_for("web.render") is browser
    assert registry.requires_proxy("web.render") is True


def test_navigation_itself_writes_nothing_and_changes_nothing():
    """A render's profile matches web.get; a page's POST attempt is a separate
    proxied sub-request checked on its own (D34), not a profile this action
    silently acquires."""
    profile = registry.side_effects_for("web.render")
    assert profile is not None
    assert profile.writes_data is False
    assert profile.changes_state is False


# ---------------------------------------------------------------------------
# The budget sub-schema
# ---------------------------------------------------------------------------

def test_the_default_budget_is_the_smallest_useful_navigation():
    limits = browser.browser_budget({"max_duration_seconds": 600})
    assert limits["max_navigations"] == browser.DEFAULT_MAX_NAVIGATIONS
    assert limits["max_subresources_per_navigation"] == browser.DEFAULT_MAX_SUBRESOURCES


@pytest.mark.parametrize("dims", [
    {"max_navigations": 0},
    {"max_navigations": browser.MAX_ALLOWED_NAVIGATIONS + 1},
    {"max_subresources_per_navigation": 0},
    {"max_subresources_per_navigation": browser.MAX_ALLOWED_SUBRESOURCES + 1},
    {"max_navigation_duration_seconds": 0},
])
def test_an_out_of_range_budget_is_refused_not_clamped(dims):
    """A clamp would run a different budget than the one approved. Fail closed."""
    with pytest.raises(AdapterError):
        browser.browser_budget(_budget(**dims))


# ---------------------------------------------------------------------------
# Plan construction
# ---------------------------------------------------------------------------

def test_the_plan_passes_every_ceiling_to_the_runner():
    plan = browser.build_plan(
        constraints={}, budget=_budget(
            max_navigations=2, max_subresources_per_navigation=8,
            max_navigation_duration_seconds=15),
        target="10.78.0.10", proxy_url="http://10.82.0.2:3128",
        proxy_cert_spki="PIN==",
    )
    assert "--max-navigations" in plan.command
    assert plan.command[plan.command.index("--max-subresources") + 1] == "8"
    assert plan.command[plan.command.index("--proxy-url") + 1] == "http://10.82.0.2:3128"
    assert plan.command[plan.command.index("--proxy-cert-spki") + 1] == "PIN=="
    # The proxy's flat backstop is the most sub-requests the whole run permits.
    assert plan.proxy_max_requests == 2 * 8
    assert plan.url == "http://10.78.0.10:80/"


def test_a_bare_host_becomes_an_absolute_http_url_for_the_proxy():
    plan = browser.build_plan(
        constraints={"path": "/login"}, budget=_budget(), target="app.example.com")
    assert plan.url == "http://app.example.com:80/login"
    assert plan.host == "app.example.com"


def test_https_target_builds_an_https_url():
    plan = browser.build_plan(
        constraints={"port": 443}, budget=_budget(), target="https://app.example.com")
    assert plan.url.startswith("https://app.example.com:443/")


@pytest.mark.parametrize("target", [
    "file:///etc/cyberorch/leaf-key.pem",  # the D35 secret, the §四 target
    "ws://host/socket",
    "chrome://version",
])
def test_a_non_http_target_is_refused_before_a_container_starts(target):
    with pytest.raises(AdapterError, match="refuses target"):
        browser.build_plan(constraints={}, budget=_budget(), target=target)


def test_an_action_outside_the_namespace_is_refused():
    with pytest.raises(AdapterError):
        browser.build_plan(constraints={}, budget=_budget(),
                           target="10.0.0.1", action="network.scan")


# ---------------------------------------------------------------------------
# The sub-resource ceiling is load-bearing (mutation test, §二.3)
# ---------------------------------------------------------------------------

class _FakePage:
    """A page that fires N request events during goto, then aborts if closed.

    Enough of Playwright's surface for ``_navigate`` to run with no browser:
    ``on`` registers the request handler, ``goto`` fires it ``fetches`` times
    (stopping if the context was closed by the ceiling abort), ``content`` and
    ``url`` complete the happy path.
    """

    def __init__(self, fetches: int):
        self._fetches = fetches
        self._handler = None
        self.url = "http://10.78.0.10/"
        self.context = self

    def on(self, event, handler):
        if event == "request":
            self._handler = handler

    def close(self):  # context.close()
        self._closed = True

    _closed = False

    def goto(self, url, wait_until=None, timeout=None):
        for _ in range(self._fetches):
            if self._closed:
                raise RuntimeError("navigation aborted: context closed")
            if self._handler:
                self._handler(object())
        return type("R", (), {"status": 200})()

    def content(self):
        return "<html>ok</html>"


def test_a_navigation_over_its_subresource_ceiling_is_refused():
    """The guarantee: a page cannot fetch more sub-resources than granted."""
    result = browser_runner._navigate(
        _FakePage(fetches=30), "http://10.78.0.10/",
        max_subresources=10, nav_timeout_ms=5000)
    assert result["refused"] is True
    assert result["reason"] == browser_runner.BUDGET_SUBRESOURCES


def test_a_navigation_within_its_ceiling_renders():
    result = browser_runner._navigate(
        _FakePage(fetches=5), "http://10.78.0.10/",
        max_subresources=10, nav_timeout_ms=5000)
    assert result["refused"] is False
    assert result["subresource_count"] == 5


def test_removing_the_ceiling_check_breaks_the_guarantee(monkeypatch):
    """Mutation test (§二.3, D34's consume_request shape): stub the one check
    that enforces the ceiling and the over-budget navigation is no longer
    refused — proving that check, not something incidental, is the enforcement."""
    # Sanity: with the real check, over-ceiling is refused (asserted above too).
    monkeypatch.setattr(browser_runner, "_over_ceiling", lambda count, ceiling: False)
    result = browser_runner._navigate(
        _FakePage(fetches=30), "http://10.78.0.10/",
        max_subresources=10, nav_timeout_ms=5000)
    # The guarantee has failed: 30 > 10 sub-resources, yet the run is not refused.
    assert result["refused"] is False
    assert result["subresource_count"] == 30
