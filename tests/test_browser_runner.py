"""The browser tool's decisions that do not need a browser (D36).

The runner (:mod:`tool_gateway.browser_runner`) is the process that runs inside
the sandbox and drives Playwright. Most of it can only be exercised with a
browser and a container, which is CI's job; but the decisions that are the
*boundary* -- which schemes navigate, that a WebSocket is refused, that the
sandbox flags are never dropped -- are pure functions, and those are tested
here so a regression in them fails on every machine, not only where Docker runs.

The reason this split matters: D36 §四 established that a headless Chromium
pointed at ``file://`` will read a file its uid can read; the browser does not
refuse. So the scheme refusal below is not decoration -- it is the layer that
stops the browser being *asked* to read a local path in the first place, and it
has to hold independently of anything the browser does.
"""

from __future__ import annotations

import pytest

from tool_gateway.browser_runner import (
    REFUSED_SCHEME,
    REFUSED_WEBSOCKET,
    build_launch_kwargs,
    classify_target,
)


@pytest.mark.parametrize("url", [
    "http://10.78.0.10:8080/index.html",
    "https://app.staging.example.com/login",
    "HTTP://UPPER/case",
])
def test_http_and_https_targets_navigate(url):
    assert classify_target(url) is None


@pytest.mark.parametrize("url", [
    "file:///etc/cyberorch/leaf-key.pem",  # the D35 secret, the §四 target
    "file:///etc/passwd",
    "chrome://version",
    "devtools://devtools/bundled/inspector.html",
    "view-source:http://x/",
    "about:blank",
])
def test_local_and_internal_schemes_are_refused(url):
    """The browser will not refuse these itself (§四); the runner must."""
    assert classify_target(url) == REFUSED_SCHEME


@pytest.mark.parametrize("url", ["ws://host/socket", "wss://host/socket", "WSS://H/s"])
def test_websocket_is_refused_with_its_own_reason(url):
    """§三: WebSocket is a deliberate scope exclusion, named distinctly so the
    refusal reads as 'not offered' rather than 'unknown scheme'."""
    assert classify_target(url) == REFUSED_WEBSOCKET


def test_the_sandbox_flags_are_always_present_and_never_re_enabled():
    """--no-sandbox is required (Chromium's own sandbox cannot run cap-dropped),
    and nothing in the inputs can turn it back into a privileged launch."""
    kwargs = build_launch_kwargs(proxy_url=None, proxy_cert_spki=None)
    assert "--no-sandbox" in kwargs["args"]
    assert kwargs["headless"] is True
    assert "proxy" not in kwargs
    # No input path adds a --sandbox or an --enable-* that would widen it.
    assert not any("sandbox" in a and a != "--no-sandbox" for a in kwargs["args"])


def test_a_proxy_and_an_spki_pin_are_wired_when_given():
    kwargs = build_launch_kwargs(
        proxy_url="http://10.82.0.2:3128", proxy_cert_spki="Zm9vYmFy"
    )
    assert kwargs["proxy"] == {"server": "http://10.82.0.2:3128"}
    assert "--ignore-certificate-errors-spki-list=Zm9vYmFy" in kwargs["args"]


def test_the_spki_pin_trusts_exactly_one_key_not_a_ca_or_the_public_roots():
    """The pin lists our leaf's SPKI only. There is no flag that trusts a CA or
    disables verification wholesale, so a leaf with any other key is rejected --
    which is what keeps a pinning target's failure clean (D35)."""
    kwargs = build_launch_kwargs(proxy_url=None, proxy_cert_spki="ONEKEY")
    spki_flags = [a for a in kwargs["args"] if a.startswith("--ignore-certificate-errors")]
    assert spki_flags == ["--ignore-certificate-errors-spki-list=ONEKEY"]
    assert not any("ignore-certificate-errors" == a for a in kwargs["args"])
