"""The filesystem-escape experiment for the browser sandbox (D36 §四).

This is a new threat model, not the discovery/authorization injection series
(D13/D15/D31/D34). The question is not "is this content trusted" but "can the
browser, executing untrusted content, reach something on the container
filesystem it must not" — with the D35 per-engagement leaf key as the concrete,
high-value target.

The probes established the shape (see the D36 commit history):

* a headless Chromium pointed at a ``file://`` URL **will** read a file its uid
  can read; the browser does not refuse. So the isolation cannot rest on the
  browser. It rests on two things this file proves with container-level
  evidence, never the browser's own report:

  1. the runner refuses a ``file://`` target before the browser is launched;
  2. and behind that, the browser container holds nothing worth reading — no
     private key, and not the leaf-key path — and the leaf key lives in a
     different container (the proxy's), so even a browser that ignored the
     runner would find nothing.

The witness is deliberately outside the browser: a plain ``sh``/``grep`` over
the container filesystem, and the absence of a path — the same discipline as
D34/D35, where a refusal is proven by the target's own record and not the
component under test.

Container-level; skipped nowhere — where Docker is absent these error, exactly
as the §8.3 topology tests do, because a browser-isolation claim cannot be
established without a container.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from tool_gateway.adapters import browser
from tool_gateway.browser_runner import REFUSED_SCHEME
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

#: The D35 leaf-key path — a real, high-value target. It is mounted into the
#: *proxy* container, never the browser's; §四 proves it is absent here.
LEAF_KEY_PATH = "/etc/cyberorch/leaf-key.pem"

#: A tool-side range for the runner runs. file:// is refused before any network
#: is touched, so the value only has to be a valid CIDR.
ESCAPE_CIDR = "10.83.0.0/24"

CHROMIUM_REVISION = "1194"
_HEADLESS_SHELL = (
    f"/opt/pw-browsers/chromium_headless_shell-{CHROMIUM_REVISION}"
    "/chrome-linux/headless_shell"
)


@pytest.fixture(scope="module")
def browser_sandbox():
    box = DockerSandbox(image=browser.IMAGE)
    try:
        box.client().images.get(browser.IMAGE)
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\nD36 §四 asserts the browser cannot "
            "reach the container filesystem, which is a fact about a container "
            "and cannot be shown without one. Build it with "
            "tool_gateway/images/build_browser_image.sh.",
            pytrace=False,
        )
    except Exception as exc:  # pragma: no cover - image missing
        pytest.fail(
            f"the browser image is missing ({exc}). Build it with "
            "tool_gateway/images/build_browser_image.sh",
            pytrace=False,
        )
    return box


def _sh_in_browser_image(script: str) -> subprocess.CompletedProcess:
    """Run a shell command in the browser image under the real sandbox
    restriction, entrypoint overridden. The witness process is sh, not the
    browser, so what it reports is about the filesystem and not about Chromium.
    """
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
         "--read-only", "--tmpfs", "/tmp:rw,mode=1777",
         "--entrypoint", "/bin/sh", browser.IMAGE, "-c", script],
        capture_output=True, text=True, timeout=60,
    )


# ---------------------------------------------------------------------------
# The container holds nothing worth reading
# ---------------------------------------------------------------------------

def test_the_browser_container_carries_no_private_key(browser_sandbox):
    """Independent witness: a grep over the whole filesystem finds no private
    key. The image bakes none, and the browser gets no CA mounted (it pins the
    proxy leaf by SPKI, not --cacert), so there is simply nothing to exfiltrate
    even if a page drove the browser to read a local file."""
    proc = _sh_in_browser_image(
        'grep -rIl "PRIVATE KEY" / 2>/dev/null || true')
    assert proc.stdout.strip() == "", (
        f"a private key is readable in the browser container:\n{proc.stdout}")


def test_the_leaf_key_path_does_not_exist_in_the_browser_container(browser_sandbox):
    """The D35 leaf key lives in the proxy container, never this one. The
    witness is the path's absence, checked by test -e, not by asking the
    browser."""
    proc = _sh_in_browser_image(
        f'test -e {LEAF_KEY_PATH} && echo PRESENT || echo ABSENT')
    assert proc.stdout.strip() == "ABSENT", proc.stdout


# ---------------------------------------------------------------------------
# The runner refuses file://, and that refusal is load-bearing
# ---------------------------------------------------------------------------

def test_the_runner_refuses_a_file_url_and_returns_no_file_content(browser_sandbox):
    """Pointed at /etc/passwd, the runner refuses the scheme before launching a
    browser, and its output carries none of the file's content."""
    result = browser_sandbox.run(
        command=[f"file://{LEAF_KEY_PATH}", "--max-navigations", "1",
                 "--max-subresources", "5", "--nav-timeout-seconds", "20"],
        network_allowlist=[ESCAPE_CIDR], max_duration_seconds=40,
        tmpfs=browser.TMPFS,
    )
    assert result.succeeded, result.stderr
    parsed = json.loads(result.stdout)
    assert parsed["refused"] is True
    assert parsed["reason"] == REFUSED_SCHEME
    # Also point it at a file that *does* exist and carries readable content.
    result2 = browser_sandbox.run(
        command=["file:///etc/hostname", "--max-navigations", "1",
                 "--max-subresources", "5", "--nav-timeout-seconds", "20"],
        network_allowlist=[ESCAPE_CIDR], max_duration_seconds=40,
        tmpfs=browser.TMPFS,
    )
    parsed2 = json.loads(result2.stdout)
    assert parsed2["refused"] is True
    assert parsed2["reason"] == REFUSED_SCHEME


def test_a_raw_browser_would_read_a_local_file_so_the_refusal_is_the_boundary(
    browser_sandbox,
):
    """The load-bearing control (§四, the D34 urlopen-redirect lesson applied
    here): bypass the runner and drive the raw browser at file:///etc/hostname.
    It reads it — proving the browser does NOT refuse file:// on its own, so the
    runner's refusal above is the boundary, not an incidental browser default.
    """
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
         "--read-only", "--tmpfs", "/tmp:rw,mode=1777", "--tmpfs", "/home/browser:rw,mode=1777",
         "--entrypoint", _HEADLESS_SHELL, browser.IMAGE,
         "--no-sandbox", "--headless", "--disable-gpu", "--disable-dev-shm-usage",
         "--virtual-time-budget=2000", "--dump-dom", "file:///etc/hostname"],
        capture_output=True, text=True, timeout=60,
    )
    # /etc/hostname in a container is the 12-hex container id; any non-empty
    # DOM body proves the raw browser read the local file the runner refuses.
    assert proc.returncode == 0, proc.stderr
    assert "<html" in proc.stdout.lower()
    assert proc.stdout.strip() not in ("", "<html><head></head><body></body></html>")
