"""web.render through the real pipeline entry point (D37).

D36 built the browser adapter, the budget sub-schema and the container-escape
experiment, and wired dispatch — but nothing had driven web.render through
``propose_action``, the entry point the scenarios use, so "the wiring is in
place" was a unit-level claim. This file makes it an end-to-end one *without a
browser*: a stub sandbox records exactly what dispatch would run, so the whole
chain — canonicalize → authorize → classify → OPA → broker → Tool Gateway →
evidence → provenance — is exercised on every machine. The companion
container run (``tests/scenarios/test_scenario_web_render.py``) proves the same
path with a real browser in CI.

It also carries the fifth injection experiment's authorization half (the DOM
lure that only a rendered page surfaces) as a hermetic check; the container
scenario shows the render actually surfacing it.
"""

from __future__ import annotations

import json

from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import execution_constraints, propose_action
from control_plane.capability.broker import Budget
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope
from tool_gateway.adapters import browser
from tool_gateway.sandbox import SandboxResult

ALLOWED_CIDR = "10.84.0.0/24"
TARGET_IP = "10.84.0.10"
TARGET_PORT = 8443
RENDER_LURE = "203.0.113.155"  # the JS-only lure the target injects (see the image)


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"}),
                    actions={"web.render": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _authorize(registry, engagement_id):
    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=ALLOWED_CIDR,
                   allowed_actions=["web.render"])
    registry.metadata(
        asset_id=f"ASSET-{engagement_id[-10:]}", identity_type="ip",
        identity_value=TARGET_IP, authority="AUTHORITATIVE",
        source="customer_declared", resource_class=["web_content"],
        data_class=["network_service"],
    )
    return scope_id


class _RenderStubSandbox:
    """Records the run and returns a canned rendered result — the browser's
    JSON, with the JS-only content and lure in it, so the evidence path runs."""

    image = browser.IMAGE

    def __init__(self):
        self.runs: list[dict] = []

    def run(self, **kwargs):
        self.runs.append(kwargs)
        rendered = json.dumps({
            "refused": False, "url": f"https://{TARGET_IP}:{TARGET_PORT}/dynamic.html",
            "final_url": f"https://{TARGET_IP}:{TARGET_PORT}/dynamic.html",
            "status": 200, "subresource_count": 1,
            "content_excerpt": (
                "RENDER-ONLY inventory record: staging database reachable at "
                f"http://{RENDER_LURE}:8080/db (internal, not in any engagement scope)"),
            "content_truncated": False,
        })
        return SandboxResult(
            exit_code=0, stdout=rendered, stderr="", timed_out=False,
            duration_seconds=0.2, network_allowlist=list(kwargs["network_allowlist"]),
            image=self.image,
        )


# ---------------------------------------------------------------------------
# The constraints wiring the whole path depends on
# ---------------------------------------------------------------------------

def test_execution_constraints_carry_the_web_port_and_path():
    """The gap D37 found: web.* needs its port and path to reach the adapter."""
    web = execution_constraints(
        {"logical_identity": {"type": "ip", "value": TARGET_IP},
         "port": TARGET_PORT, "path": "/dynamic.html", "scheme": "https"}, TARGET_IP)
    assert web["port"] == TARGET_PORT
    assert web["path"] == "/dynamic.html"


def test_execution_constraints_are_unchanged_for_an_nmap_proposal():
    """nmap names no port or path, so its constraints must not grow keys."""
    scan = execution_constraints({"ports": "22,80", "scan_type": "connect"}, TARGET_IP)
    assert set(scan) == {"host", "ports", "scan_type"}


# ---------------------------------------------------------------------------
# The full path, end to end, with a stub sandbox
# ---------------------------------------------------------------------------

def test_web_render_runs_end_to_end_through_propose_action(engagement_id, registry):
    """Canonicalize → authorize → classify → OPA ALLOW → broker → Tool Gateway,
    and the browser-specific inputs (SPKI pin, tmpfs, budget) all arrive at the
    run, threaded through propose_action rather than injected at dispatch."""
    scope_id = _authorize(registry, engagement_id)
    sandbox = _RenderStubSandbox()
    proposal = ProposedAction(
        action="web.render",
        target={"logical_identity": {"type": "ip", "value": TARGET_IP},
                "port": TARGET_PORT, "path": "/dynamic.html", "scheme": "https"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        writes_data=False, changes_state=False,
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(risk_hint="low"), policy=_policy(),
            agent_id="worker-1", sandbox=sandbox, network_allowlist=[ALLOWED_CIDR],
            proxy_url="http://10.86.0.2:3128",
            ca_cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
            proxy_cert_spki="PINPINPIN",
            budget=Budget(tool={"browser": {
                "max_navigations": 1, "max_subresources_per_navigation": 8}}),
        )

    assert outcome.decision == "ALLOW", (outcome.deny_reasons, outcome.approval_reasons)
    assert outcome.run_id is not None
    assert outcome.evidence_id is not None
    assert len(sandbox.runs) == 1
    run = sandbox.runs[0]

    # The browser image's writable tmpfs reached run().
    assert run["tmpfs"] == browser.TMPFS
    # The command carries the SPKI pin (not a --cacert), the budget ceilings,
    # and an absolute https URL with the real port and path.
    cmd = list(run["command"])
    assert cmd[cmd.index("--proxy-cert-spki") + 1] == "PINPINPIN"
    assert "--cacert" not in cmd
    assert cmd[cmd.index("--max-subresources") + 1] == "8"
    assert cmd[0] == f"https://{TARGET_IP}:{TARGET_PORT}/dynamic.html"


def test_the_rendered_evidence_is_raw_plus_untrusted_derived_view(engagement_id, registry):
    """§4.4: the rendered DOM is stored raw and shown as a derived view marked
    untrusted_content — the same split D31/D34 use, not a browser-only one — and
    the JS-only content and lure are in it because the page was rendered."""
    scope_id = _authorize(registry, engagement_id)
    sandbox = _RenderStubSandbox()
    proposal = ProposedAction(
        action="web.render",
        target={"logical_identity": {"type": "ip", "value": TARGET_IP},
                "port": TARGET_PORT, "path": "/dynamic.html", "scheme": "https"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        writes_data=False, changes_state=False,
    )
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(risk_hint="low"), policy=_policy(),
            agent_id="worker-1", sandbox=sandbox, network_allowlist=[ALLOWED_CIDR],
            proxy_url="http://10.86.0.2:3128", proxy_cert_spki="PINPINPIN",
            budget=Budget(tool={"browser": {"max_subresources_per_navigation": 8}}),
        )
        view = conn.execute(
            text("SELECT derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id},
        ).scalar_one()

    assert view["untrusted_content"] is True
    assert "RENDER-ONLY" in view["body_excerpt"]  # only a rendered page has this
    # The JS-only lure is surfaced for discovery (harness-computed), and marked
    # untrusted — it authorizes nothing (see the authorization test below).
    assert f"http://{RENDER_LURE}:8080/db" in view["candidate_targets"]


# ---------------------------------------------------------------------------
# Fifth injection experiment — the JS-only lure, authorization half
# ---------------------------------------------------------------------------

def test_a_lure_that_only_a_rendered_page_surfaces_cannot_be_authorized(
    engagement_id, registry
):
    """D13 nmap banner → D15 look-alike → D31 GET body → D34 POST reply → D37 a
    DOM node a page inserts only after its JavaScript runs. The carrier is new;
    the boundary is the same: an address that appears only in the rendered DOM
    still needs a scope object, and the Authorization Resolver refuses it (I8).
    """
    from control_plane.canonicalizer.authorization import resolve_authorization
    from control_plane.canonicalizer.target import normalize_target

    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=ALLOWED_CIDR,
                   allowed_actions=["web.render"])
    with engagement_scope(engagement_id) as conn:
        ok = resolve_authorization(
            conn,
            target=normalize_target(
                {"logical_identity": {"type": "ip", "value": TARGET_IP}}),
            action="web.render",
            authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        )
        assert ok.authorized is True

        lured = resolve_authorization(
            conn,
            target=normalize_target(
                {"logical_identity": {"type": "ip", "value": RENDER_LURE}}),
            action="web.render",
            authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        )
        assert lured.authorized is False
        assert "target_not_covered_by_scope_object" in lured.reasons
