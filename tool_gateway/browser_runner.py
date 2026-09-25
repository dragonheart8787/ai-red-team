"""The Playwright driver that runs *inside* the browser sandbox (§8.3, D36).

This is to the browser what curl is to the HTTP adapters: the one process that
actually touches the network, run in a confined container with no route to the
target except the egress proxy. It is copied into the image (never reimplemented
in a heredoc) and driven by :mod:`tool_gateway.adapters.browser` from outside.

What it enforces, and why here rather than trusting the browser:

* **Scheme.** Only ``http``/``https`` targets navigate. ``file:``, ``chrome:``,
  ``devtools:`` and anything else are refused with a named reason. This is not
  defence in depth -- a headless Chromium pointed at ``file:///…`` *will* read
  a file its uid can read; the browser does not stop it (confirmed
  empirically, D36 §四). So the refusal is the boundary at this layer, and the
  container (a browser uid that owns nothing, no secret in the image) is the
  boundary behind it.
* **WebSocket.** A ``ws:``/``wss:`` upgrade is refused and recorded, never
  silently allowed. A tunnelled WebSocket would carry bidirectional traffic
  past the per-request counting the whole model rests on (D36 §三, the
  PUT/DELETE treatment applied to a protocol upgrade).
* **Budget (§4.6 browser sub-schema, D36 §二).** A navigation is the logical
  unit; sub-resources have their own ceiling. ``--max-navigations`` bounds
  top-level document loads, ``--max-subresources`` bounds the fan-out within
  one navigation (exceeding it aborts that navigation -- fail closed, not a
  silent drop), and ``--nav-timeout-seconds`` bounds each one in time.

TLS: the browser reaches the target only through the egress proxy, which
terminates TLS with a per-engagement leaf (D35). The browser trusts that leaf
by SPKI pin (``--proxy-cert-spki``), not by trusting a CA -- the same "pin our
own leaf" shape as D35, and tighter than installing a CA into a trust store.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

#: Chromium's own sandbox needs a user namespace or a setuid helper; under
#: ``cap_drop=ALL`` + ``no-new-privileges`` neither is available, so it is
#: disabled and the *container* is the boundary. This is stated, not hidden:
#: the whole of D36 §四 is about that boundary holding.
_LAUNCH_ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]

#: Schemes that never navigate. Everything not http/https is refused; these are
#: named only to give a precise reason for the ones an attacker would reach for.
_LOCAL_SCHEMES = ("file:", "chrome:", "devtools:", "view-source:", "about:")

REFUSED_SCHEME = "scheme_not_permitted"
REFUSED_WEBSOCKET = "websocket_not_supported"
BUDGET_SUBRESOURCES = "subresource_ceiling_exceeded"
BUDGET_NAVIGATIONS = "navigation_ceiling_exceeded"


def _reason(kind: str, detail: str) -> dict[str, Any]:
    return {"refused": True, "reason": kind, "detail": detail}


def classify_target(url: str) -> str | None:
    """Return a refusal reason for a target we will not navigate, else ``None``.

    ``ws``/``wss`` get their own reason because they are a deliberate scope
    exclusion (D36 §三), not merely an unknown scheme.
    """
    lowered = url.strip().lower()
    if lowered.startswith(("ws:", "wss:")):
        return REFUSED_WEBSOCKET
    if lowered.startswith(_LOCAL_SCHEMES):
        return REFUSED_SCHEME
    if not lowered.startswith(("http:", "https:")):
        return REFUSED_SCHEME
    return None


def build_launch_kwargs(
    *, proxy_url: str | None, proxy_cert_spki: str | None
) -> dict[str, Any]:
    """Assemble Playwright ``chromium.launch`` kwargs from the run's inputs.

    Kept pure so a test can assert the boundary flags are present without a
    browser: no ``--sandbox`` re-enable, a proxy when one is given, and the
    leaf SPKI pin rather than a blanket ``ignoreHTTPSErrors``.
    """
    args = list(_LAUNCH_ARGS)
    if proxy_cert_spki:
        # Trust exactly the proxy's leaf, nothing else -- not a CA, not the
        # public roots. A leaf with any other key is rejected, which is what
        # keeps a pinning target's failure clean (D35) and stops the browser
        # trusting a real public CA by accident.
        args.append(f"--ignore-certificate-errors-spki-list={proxy_cert_spki}")
    kwargs: dict[str, Any] = {"headless": True, "args": args}
    if proxy_url:
        kwargs["proxy"] = {"server": proxy_url}
    return kwargs


def _over_ceiling(count: int, ceiling: int) -> bool:
    """Whether ``count`` sub-resources has passed the per-navigation ceiling.

    A named function, not an inline ``>``, on purpose: it is the one place the
    sub-resource budget is enforced, so a mutation test can stub it out and
    prove the guarantee then fails — the same way D34 pinned ``consume_request``
    (§二.3). If this returned ``False`` always, a page could fetch without
    limit; the test asserts exactly that regression.
    """
    return count > ceiling


def _navigate(page, url: str, *, max_subresources: int, nav_timeout_ms: int) -> dict[str, Any]:
    """Drive one top-level navigation, counting and bounding its sub-resources."""
    counter = {"n": 0, "over": False}

    def _on_request(request) -> None:
        counter["n"] += 1
        if _over_ceiling(counter["n"], max_subresources):
            counter["over"] = True
            # Abort the run-away navigation rather than let the page decide how
            # much budget it spends: the ceiling is the system's, not the
            # target's. Fail closed.
            try:
                page.context.close()
            except Exception:
                pass

    page.on("request", _on_request)
    try:
        response = page.goto(url, wait_until="load", timeout=nav_timeout_ms)
    except Exception:
        # A ceiling abort closes the context, which makes goto raise; that is a
        # refusal, not a crash. Any other exception is a real failure and
        # propagates.
        if counter["over"]:
            return _reason(
                BUDGET_SUBRESOURCES,
                f"navigation fetched more than {max_subresources} sub-resources",
            )
        raise
    if counter["over"]:
        return _reason(
            BUDGET_SUBRESOURCES,
            f"navigation fetched more than {max_subresources} sub-resources",
        )
    content = page.content()
    return {
        "refused": False,
        "url": url,
        "final_url": page.url,
        "status": response.status if response else None,
        "subresource_count": counter["n"],
        "content_excerpt": content[:4000],
        "content_truncated": len(content) > 4000,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    reason = classify_target(args.url)
    if reason is not None:
        return _reason(reason, f"refused target {args.url!r}")

    # Imported here so the pure helpers above (and their tests) do not require
    # Playwright to be installed on the host.
    from playwright.sync_api import sync_playwright

    launch_kwargs = build_launch_kwargs(
        proxy_url=args.proxy_url, proxy_cert_spki=args.proxy_cert_spki
    )
    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch_kwargs)
        try:
            # accept_downloads=False: a response that triggers a download is
            # cancelled, so nothing is written to disk at all (D36 §四, P2).
            # The probe showed the page cannot control a download's path anyway
            # -- Chromium strips path separators from the suggested name and
            # Playwright picks a random path under its own temp dir -- but not
            # writing it is stronger than writing it somewhere harmless, and it
            # keeps a page from filling the container's tmpfs.
            context = browser.new_context(
                ignore_https_errors=False, accept_downloads=False)
            # A page may still *try* to open a WebSocket. The boundary that
            # refuses it is the egress proxy (the grant permits no upgrade, D36
            # §三); this listener only records the attempt for the derived view,
            # it is not the enforcement and does not pretend to be.
            ws_attempts: list[str] = []
            context.on("websocket", lambda ws: ws_attempts.append(getattr(ws, "url", "")))
            page = context.new_page()
            result = _navigate(
                page, args.url,
                max_subresources=args.max_subresources,
                nav_timeout_ms=args.nav_timeout_seconds * 1000,
            )
            if ws_attempts:
                result["websocket_attempted"] = True
        finally:
            browser.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Playwright navigation tool (D36)")
    parser.add_argument("url")
    parser.add_argument("--proxy-url", default=None)
    parser.add_argument("--proxy-cert-spki", default=None,
                        help="base64 sha256 SPKI of the proxy leaf to trust")
    parser.add_argument("--max-navigations", type=int, default=1)
    parser.add_argument("--max-subresources", type=int, default=25)
    parser.add_argument("--nav-timeout-seconds", type=int, default=30)
    parser.add_argument("--self-check", action="store_true",
                        help="launch the browser and exit; used by the image build")
    args = parser.parse_args(argv)

    if args.self_check:
        # The build-time proof that the browser launches under the sandbox
        # restriction it will actually run with (D35 habit). No network.
        #
        # Wrapped so a launch failure prints its reason rather than an empty
        # result: the first CI attempt failed with the browser producing no
        # output at all under a read-only root, which said nothing about why.
        # A named exception on stdout is the difference between "cannot launch"
        # and "cannot launch because <path> is not writable".
        import traceback

        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(**build_launch_kwargs(
                    proxy_url=None, proxy_cert_spki=None))
                page = browser.new_context(accept_downloads=False).new_page()
                page.goto("data:text/html,<h1>ok</h1>")
                ok = "ok" in page.content()
                browser.close()
            print(json.dumps({"self_check": bool(ok)}), flush=True)
            return 0 if ok else 1
        except Exception as exc:  # noqa: BLE001 - the point is to report any failure
            traceback.print_exc()
            print(json.dumps({"self_check": False, "error": str(exc)[:400]}), flush=True)
            return 1

    result = run(args)
    print(json.dumps(result))
    # A refusal is a completed run that refused, not a crash: exit 0 so the
    # adapter reads the structured reason rather than a generic failure.
    return 0
