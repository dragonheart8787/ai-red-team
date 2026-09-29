"""D49 regression: the ``dns_server`` constraint is opt-in, not a default
behavior change, for every tool other than ``ad.collect``.

D49 added ``dns_server`` in three places: ``ad_collector.build_plan`` (reads
and validates it), ``function_api.execution_constraints`` (carries it through
from a proposal's target block, unconditionally on action -- the same rule
D37 already established for ``port``/``path``/``scheme``), and
``dispatch_collection`` (authorizes it against ``network_allowlist``). The
user's own instruction for this deliverable was explicit that this must not
"accidentally touch existing tools' network behavior just because a new
parameter was added" -- this file is the regression test that instruction
asked for, not merely an absence of code changes in nmap.py/_http.py/
browser.py/semgrep.py/sandbox.py.

Two things are checked:

1. Each non-AD adapter's ``build_plan`` produces a byte-identical plan
   whether or not ``dns_server`` is present in ``constraints`` -- proving the
   key is inert wherever it is not ``ad_collector`` reading it, not merely
   that nobody happened to test the combination.
2. ``DockerSandbox.run``'s signature -- and the two ``containers.create``
   call sites inside it -- carry no new DNS-related parameter. The D49
   finding (module docstring, ``ad_collector.py``) is precisely that no
   sandbox-level change was needed at all; this is the check that a future
   edit does not quietly add one without this file going red.
"""

from __future__ import annotations

import inspect

from control_plane.api.function_api import execution_constraints
from tool_gateway.adapters import browser, http_get, nmap, semgrep
from tool_gateway.sandbox import DockerSandbox

TARGET_IP = "10.84.0.10"
DNS_SERVER = "10.84.0.1"


# ---------------------------------------------------------------------------
# execution_constraints carries dns_server the same way it carries
# port/path/scheme (D37) -- unconditionally on the action, only when present.
# ---------------------------------------------------------------------------

def test_execution_constraints_carries_dns_server_when_the_proposal_names_it():
    constraints = execution_constraints(
        {"logical_identity": {"type": "ad_domain", "value": "corp.example.com"},
         "dns_server": DNS_SERVER},
        "corp.example.com",
    )
    assert constraints["dns_server"] == DNS_SERVER


def test_execution_constraints_are_unchanged_for_an_nmap_proposal_naming_no_dns_server():
    """The D37 precedent (test_web_render_e2e.py), re-run for D49: a proposal
    that names no dns_server must not gain the key."""
    scan = execution_constraints({"ports": "22,80", "scan_type": "connect"}, TARGET_IP)
    assert set(scan) == {"host", "ports", "scan_type"}
    assert "dns_server" not in scan


# ---------------------------------------------------------------------------
# Each non-AD adapter ignores dns_server even when it is present --
# opt-in, not a default behavior change.
# ---------------------------------------------------------------------------

def test_nmap_build_plan_ignores_a_present_dns_server():
    budget = {"max_duration_seconds": 60}
    without = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "connect"},
        budget=budget, target=TARGET_IP,
    )
    with_dns = nmap.build_plan(
        constraints={"ports": "8080", "scan_type": "connect", "dns_server": DNS_SERVER},
        budget=budget, target=TARGET_IP,
    )
    assert with_dns.command == without.command


def test_http_get_build_plan_ignores_a_present_dns_server():
    budget = {"max_duration_seconds": 60, "tool": {"http": {"max_requests": 1}}}
    without = http_get.build_plan(
        constraints={"port": 8080, "path": "/index.html"},
        budget=budget, target=TARGET_IP,
    )
    with_dns = http_get.build_plan(
        constraints={"port": 8080, "path": "/index.html", "dns_server": DNS_SERVER},
        budget=budget, target=TARGET_IP,
    )
    assert with_dns.command == without.command
    assert with_dns.url == without.url


def test_browser_build_plan_ignores_a_present_dns_server():
    budget = {
        "max_duration_seconds": 60,
        "tool": {"browser": {
            "max_navigations": 2, "max_subresources_per_navigation": 8,
            "max_navigation_duration_seconds": 15,
        }},
    }
    without = browser.build_plan(
        constraints={"path": "/login"}, budget=budget, target="app.example.com",
    )
    with_dns = browser.build_plan(
        constraints={"path": "/login", "dns_server": DNS_SERVER},
        budget=budget, target="app.example.com",
    )
    assert with_dns.command == without.command
    assert with_dns.url == without.url


def test_semgrep_build_plan_ignores_a_present_dns_server():
    budget = {"max_duration_seconds": 60}
    target = "https://example.invalid/repo.git#main"
    without = semgrep.build_plan(constraints={}, budget=budget, target=target)
    with_dns = semgrep.build_plan(
        constraints={"dns_server": DNS_SERVER}, budget=budget, target=target,
    )
    assert with_dns.command == without.command


# ---------------------------------------------------------------------------
# DockerSandbox itself is untouched (the D49 finding: no sandbox-level
# change was needed at all -- see ad_collector.py's own module docstring).
# ---------------------------------------------------------------------------

def test_docker_sandbox_run_signature_has_no_dns_parameter():
    params = set(inspect.signature(DockerSandbox.run).parameters)
    assert not any("dns" in name.lower() for name in params), (
        f"DockerSandbox.run gained a DNS-related parameter: {params}; D49's own "
        f"finding was that no sandbox-level change is needed -- if this now "
        f"fails, that finding no longer holds and D49's report needs revisiting."
    )


def test_docker_sandbox_source_never_passes_a_dns_kwarg_to_containers_create():
    """A second, independent check of the same fact via the actual source
    text -- inspect.signature only proves run()'s own parameters; this
    proves neither of the two containers.create(...) call sites inside it
    (the normal path and the --network-mode host debug path) grew a dns=
    argument some other caller of the docker SDK could reach.
    """
    import tool_gateway.sandbox as sandbox_module

    source = inspect.getsource(sandbox_module)
    assert "containers.create" in source, "sanity check: the module shape changed"
    assert "dns=" not in source
