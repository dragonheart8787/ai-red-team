"""Scenario — web.render end to end with a real browser (§10, D37).

The companion to ``tests/test_web_render_e2e.py``: that file proves the whole
pipeline down to what dispatch would run, with a stub sandbox, on every
machine. This one runs the real thing — a browser container, the egress proxy
terminating TLS with a per-engagement leaf, and a target whose key content and
lure exist only after its JavaScript runs — so the SPKI pin, the tmpfs, and the
browser budget are exercised in a real dispatch and not only asserted on a
recorded call. Container-level, so it errors where Docker is absent, exactly as
the §8.3 topology tests do.

Three things it establishes that the hermetic file cannot:

* a page whose meaningful content is JS-generated is read by web.render and
  would be missed by a static GET — the operational basis for choosing
  web.render over web.get;
* the fifth injection carrier (a DOM node the page inserts only at runtime) is
  surfaced as a candidate target by the real render, while still authorizing
  nothing;
* the max_subresources_per_navigation ceiling aborts a real fan-out page in the
  real dispatch path, not only in the runner's unit test.
"""

from __future__ import annotations

import subprocess
import time
import uuid

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.capability.broker import Budget
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope
from control_plane.tls.engagement_ca import generate_ca, leaf_spki_pin, sign_leaf
from tool_gateway.adapters import browser
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

WEB_TARGET_IMAGE = "cyberorch/web-target:local"
TOOL_CIDR = "10.86.0.0/24"
TARGET_CIDR = "10.85.0.0/24"
TARGET_IP = "10.85.0.10"
TARGET_HTTPS_PORT = 8443
RENDER_LURE = "203.0.113.155"  # the JS-only lure (see build_web_target_image.sh)


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"}),
                    actions={"web.render": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _wait_until_serving(name: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        if "Serving HTTP" in logs.stdout + logs.stderr:
            return
        alive = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True).stdout.strip()
        if alive != "true":
            break
        time.sleep(0.2)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    pytest.fail(f"the web target {name} never started serving", pytrace=False)


@pytest.fixture(scope="module")
def browser_sandbox():
    box = DockerSandbox(image=browser.IMAGE)
    try:
        box.client().images.get(browser.IMAGE)
        box.client().images.get(WEB_TARGET_IMAGE)
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\nD37 runs web.render through a real "
            "browser against a real target. Build the images with "
            "tool_gateway/images/build_browser_image.sh and "
            "build_web_target_image.sh.",
            pytrace=False,
        )
    except Exception as exc:  # pragma: no cover - image missing
        pytest.fail(f"a required image is missing ({exc}).", pytrace=False)
    return box


@pytest.fixture(scope="module")
def render_topology(browser_sandbox):
    """A target serving JS pages, and a proxy terminating TLS for it with a
    per-engagement leaf the browser will pin."""
    ca = generate_ca("ENG-D37")
    leaf = sign_leaf(ca, TARGET_IP)
    spki = leaf_spki_pin(leaf.leaf_cert_pem)

    name = f"cyberorch-d37-target-{uuid.uuid4().hex[:8]}"
    target_network = browser_sandbox.ensure_network([TARGET_CIDR])
    browser_sandbox.ensure_network([TOOL_CIDR])
    endpoint = None
    try:
        started = subprocess.run(
            ["docker", "run", "-d", "--name", name, "--network", target_network.name,
             "--ip", TARGET_IP, WEB_TARGET_IMAGE],
            capture_output=True, text=True)
        if started.returncode != 0:
            pytest.fail(f"could not start the web target: {started.stderr}",
                        pytrace=False)
        _wait_until_serving(name)

        endpoint = browser_sandbox.start_egress_proxy(
            grant={"capability_id": "CAP-D37", "host": TARGET_IP,
                   "port": TARGET_HTTPS_PORT, "methods": ["GET"],
                   # Generous, so the runner's per-navigation ceiling is what
                   # aborts the fan-out test, cleanly attributed to the browser
                   # budget rather than the proxy backstop.
                   "max_requests": 100},
            tool_side=[TOOL_CIDR], target_side=[TARGET_CIDR],
            leaf_cert_pem=leaf.leaf_cert_pem, leaf_key_pem=leaf.leaf_key_pem,
        )
        yield {"proxy": endpoint, "ca_cert_pem": ca.cert_pem, "spki": spki}
    finally:
        if endpoint is not None:
            browser_sandbox.stop_egress_proxy(endpoint)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        browser_sandbox.remove_network([TARGET_CIDR])
        browser_sandbox.remove_network([TOOL_CIDR])


def _authorize(registry, engagement_id):
    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=TARGET_CIDR,
                   allowed_actions=["web.render"])
    registry.metadata(
        asset_id=f"ASSET-{engagement_id[-10:]}", identity_type="ip",
        identity_value=TARGET_IP, authority="AUTHORITATIVE",
        source="customer_declared", resource_class=["web_content"],
        data_class=["network_service"])
    return scope_id


def _render(conn, engagement_id, registry, topology, *, path, budget):
    scope_id = _authorize(registry, engagement_id)
    proposal = ProposedAction(
        action="web.render",
        target={"logical_identity": {"type": "ip", "value": TARGET_IP},
                "port": TARGET_HTTPS_PORT, "path": path, "scheme": "https"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        writes_data=False, changes_state=False,
    )
    return propose_action(
        conn, engagement_id=engagement_id, proposal=proposal,
        reviewer=HonestFakeReviewer(risk_hint="low"), policy=_policy(),
        agent_id="worker-1", sandbox=DockerSandbox(image=browser.IMAGE),
        network_allowlist=[TOOL_CIDR],
        proxy_url=topology["proxy"].url, ca_cert_pem=topology["ca_cert_pem"],
        proxy_cert_spki=topology["spki"], budget=budget,
    )


def test_web_render_reads_js_generated_content_end_to_end(
    engagement_id, registry, render_topology
):
    """The ALLOW path reaches a real browser, which renders the page and reads
    content that only exists after its JavaScript ran — content a static GET
    could not see. SPKI pin + tmpfs + budget all applied in a real dispatch."""
    with engagement_scope(engagement_id) as conn:
        outcome = _render(
            conn, engagement_id, registry, render_topology,
            path="/dynamic.html",
            budget=Budget(tool={"browser": {
                "max_navigations": 1, "max_subresources_per_navigation": 10}}))
        assert outcome.decision == "ALLOW", (outcome.deny_reasons, outcome.approval_reasons)
        assert outcome.run_id and outcome.evidence_id
        row = conn.execute(
            text("SELECT status, tool FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id}).mappings().one()
        assert row["status"] == "succeeded"
        assert row["tool"] == browser.TOOL
        view = conn.execute(
            text("SELECT derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id}).scalar_one()

    assert view["untrusted_content"] is True
    assert view["refused"] is False
    # Proof the browser actually ran the page: this text is JS-inserted.
    assert "RENDER-ONLY" in view["body_excerpt"]
    # Fifth injection carrier: the JS-only lure is surfaced for discovery.
    assert any(RENDER_LURE in c for c in view["candidate_targets"])


def test_the_subresource_ceiling_aborts_a_real_fanout(
    engagement_id, registry, render_topology
):
    """A real gallery page fetching 40 sub-resources against a ceiling of 5:
    the navigation is aborted, fail-closed, in the real dispatch path — not
    only in the runner's unit test."""
    with engagement_scope(engagement_id) as conn:
        outcome = _render(
            conn, engagement_id, registry, render_topology,
            path="/fanout.html",
            budget=Budget(tool={"browser": {
                "max_navigations": 1, "max_subresources_per_navigation": 5}}))
        assert outcome.run_id and outcome.evidence_id
        view = conn.execute(
            text("SELECT derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id}).scalar_one()

    assert view["refused"] is True
    assert view["reason"] == "subresource_ceiling_exceeded"
