"""D12.5 — replay the D11-4 and D11-5 findings against the live target.

The D12 fixes were mutation-tested and pinned by unit and Rego tests. This
runs them once more through the whole pipeline, in the environment where the
findings were made: the real target container on the real allowlist network,
the real reviewer backend, and the real Docker sandbox.

Four cases, and the distinctions between them are the point:

A. ``cidr 10.79.0.0/24`` with ``max_targets: 1`` — the D11-4 counterexample.
   Must DENY at OPA, with no capability minted. "Denied at OPA" and "capability
   issued then refused downstream" both end in no scan, so the Capability
   Broker is wrapped and its call count asserted at zero, and the sandbox is
   one that raises if it is touched at all.

B. ``cidr 10.79.0.2/24`` — the D11-5 counterexample. Must fail *earlier*, in
   the Canonicalizer, before a proposal row exists and before OPA is consulted.
   A DENY here would be the wrong answer for the right-looking reason: it would
   mean the address was silently widened to the /24 first and then stopped by
   case A's rule.

C. ``cidr 10.79.0.0/24`` with ``max_targets: 256`` — the control for A. Only
   the budget changes, and the scan must actually run against the live target.
   Without it, a DENY caused by anything else about a /24 would look identical.

D. ``ip 10.79.0.2`` with ``max_targets: 1`` — the control for B: one host, one
   address, and the ordinary path still works.

Nothing here is new behaviour. It exists so the record says the fixes hold
against a real target and not only against fixtures.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402

from agents.base_agent import ProposedAction  # noqa: E402
from agents.llm.selection import build_reviewer  # noqa: E402
from control_plane.api import function_api  # noqa: E402
from control_plane.canonicalizer.target import (  # noqa: E402
    CanonicalizationError,
    normalize_target,
)
from control_plane.capability.broker import Budget  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.policy.layers import load_effective_policy  # noqa: E402
from control_plane.registry.metadata_registry import register_metadata  # noqa: E402
from control_plane.registry.scope_registry import register_scope_object  # noqa: E402
from control_plane.state.db import engagement_scope, registry_admin_scope  # noqa: E402
from scripts.live_run.live_run import publish_baseline  # noqa: E402
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable  # noqa: E402

ACTOR = "d12-5-verification"
ALLOWLIST = "10.79.0.0/24"


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class CountingBroker:
    """Wraps issue_capability so "was it called" is directly observable.

    The technique §10's Scenario B uses, for the reason it uses it: the absence
    of a capability row cannot tell "never asked for" from "asked for and
    refused", and only the first is what enforcing at OPA means.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls: list[dict] = []

    def __call__(self, conn, **kwargs):
        self.calls.append(kwargs)
        return self._inner(conn, **kwargs)

    @property
    def call_count(self) -> int:
        return len(self.calls)


class ExplodingSandbox:
    """Reaching the Tool Gateway at all is the failure."""

    image = "must-not-run"

    def run(self, **kwargs):
        raise AssertionError(f"the sandbox was reached: {kwargs}")


def assert_policy_permits_scanning(engagement_id: str) -> dict[str, Any]:
    """Refuse to run if the stored policy does not allow ``network.scan``.

    A verification run that comes back DENY because some unrelated layer denies
    the action is not evidence about D12; it is evidence about the database it
    happened to run against, and reading it as the former is the whole risk of
    a live check. So the precondition is asserted, loudly, and the offending
    layers are named.

    What it deliberately does *not* do is fix the condition. Silently retiring a
    global emergency overlay so that a verification passes would be the exact
    move this project has refused since D6 — adjusting the check until the
    result is the one wanted. Retiring a layer is an operator action, and it
    belongs in the audit trail under an operator's name.
    """
    with engagement_scope(engagement_id) as conn:
        policy = load_effective_policy(conn, engagement_id)
        if policy.action_decision("network.scan") == "ALLOW":
            return policy.as_dict()
        offenders = conn.execute(
            text("SELECT id, layer, version, engagement_id, document "
                 "FROM policy_layers WHERE active IS TRUE "
                 "AND (engagement_id IS NULL OR engagement_id = :e) "
                 "AND document->'actions' ? 'network.scan' ORDER BY id"),
            {"e": engagement_id},
        ).mappings().all()

    lines = "\n".join(
        f"    id={r['id']} {r['layer']} v{r['version']} "
        f"{'GLOBAL' if r['engagement_id'] is None else 'engagement-scoped'} "
        f"{json.dumps(r['document'])}"
        for r in offenders
    )
    raise SystemExit(
        "the stored policy does not permit network.scan, so nothing this run "
        "reports would be about D12.\n"
        f"effective actions: {policy.as_dict()['actions']}\n"
        f"active layers mentioning network.scan:\n{lines or '    (none)'}\n\n"
        "Retire whatever should not be in force -- deactivate_policy_layer, "
        "under an operator's name so the cleanup is audited -- and run again. "
        "This script will not do it for you."
    )


def container_ip(name: str, network: str) -> str:
    out = subprocess.run(
        ["docker", "inspect", name, "--format",
         "{{ (index .NetworkSettings.Networks \"" + network + "\").IPAddress }}"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if not out:
        raise SystemExit(f"container {name!r} has no address on {network!r}")
    return out


def setup(engagement_id: str, target_ip: str) -> str:
    scope_object_id = uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="cidr", value=ALLOWLIST,
            allowed_actions=["network.recon", "network.scan"], actor=ACTOR,
        )
        # Both the range and the single host, so no case can be denied for a
        # missing classification instead of the thing it is testing.
        for identity_type, identity_value in (("cidr", ALLOWLIST), ("ip", target_ip)):
            register_metadata(
                conn, engagement_id=engagement_id, asset_id=uid("ASSET"),
                identity_type=identity_type, identity_value=identity_value,
                authority="AUTHORITATIVE", source="operator_declared",
                resource_class=["network_host"], data_class=["network_service"],
                actor=ACTOR,
            )
    return scope_object_id


def proposal_for(*, identity_type: str, value: str, scope_object_id: str,
                 ports: str) -> ProposedAction:
    return ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": identity_type, "value": value},
                "ports": ports, "scan_type": "connect"},
        authorization={"source": "engagement_scope",
                       "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
        resources=("network_host",), expected_data=("port_state",),
        reason=f"D12.5 verification against {value}",
    )


def run_case(*, engagement_id: str, proposal: ProposedAction, budget: Budget,
             reviewer, sandbox) -> dict[str, Any]:
    """One trip through propose_action, with the broker counted."""
    original = function_api.issue_capability
    broker = CountingBroker(original)
    function_api.issue_capability = broker
    try:
        with engagement_scope(engagement_id) as conn:
            policy = load_effective_policy(conn, engagement_id)
            outcome = function_api.propose_action(
                conn, engagement_id=engagement_id, proposal=proposal,
                reviewer=reviewer, policy=policy, agent_id="d12-5-worker",
                sandbox=sandbox, network_allowlist=[ALLOWLIST], budget=budget,
                execution_context={"auth_context_id": "AUTHCTX-D12-5"},
            )
    finally:
        function_api.issue_capability = original

    with engagement_scope(engagement_id) as conn:
        capability_rows = conn.execute(
            text("SELECT count(*) FROM capabilities WHERE proposal_id = :p"),
            {"p": outcome.proposal_id},
        ).scalar_one()
        proposal_rows = conn.execute(
            text("SELECT count(*) FROM action_proposals WHERE proposal_id = :p"),
            {"p": outcome.proposal_id},
        ).scalar_one()
        events = [
            r[0] for r in conn.execute(
                text("SELECT event_type FROM audit_log WHERE subject_id = :p "
                     "ORDER BY audit_id"),
                {"p": outcome.proposal_id},
            ).all()
        ]
        run_rows = conn.execute(
            text("SELECT count(*) FROM tool_runs WHERE proposal_id = :p"),
            {"p": outcome.proposal_id},
        ).scalar_one()

    return {
        "decision": outcome.decision,
        "deny_reasons": list(outcome.deny_reasons),
        "approval_reasons": list(outcome.approval_reasons),
        "proposal_id": outcome.proposal_id,
        "capability_id": outcome.capability_id,
        "run_id": outcome.run_id,
        "evidence_id": outcome.evidence_id,
        "failure": outcome.failure,
        "broker_call_count": broker.call_count,
        "capability_rows": capability_rows,
        "action_proposal_rows": proposal_rows,
        "tool_run_rows": run_rows,
        "audit_events": events,
        "reviewer_opinion": (
            outcome.reviewer_opinion.as_dict() if outcome.reviewer_opinion else None
        ),
    }


def check(label: str, condition: bool, detail: str = "") -> bool:
    print(f"    [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  ({detail})" if detail else ""))
    return condition


def main() -> int:
    load_dotenv()
    backend = "claude_code"
    sandbox = DockerSandbox()
    try:
        sandbox.ensure_image()
    except SandboxUnavailable as exc:
        raise SystemExit(f"sandbox unavailable: {exc}") from exc

    network = sandbox.network_name([ALLOWLIST])
    target_ip = container_ip("d11-target", network)
    engagement_id = uid("ENG-D125")
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:e, 'CUST-D12-LOCAL', 1)"),
            {"e": engagement_id},
        )
    scope_object_id = setup(engagement_id, target_ip)
    policy_layer_id, published_now = publish_baseline(engagement_id)
    effective = assert_policy_permits_scanning(engagement_id)
    reviewer = build_reviewer(backend)

    print(f"engagement    {engagement_id}")
    print(f"target        {target_ip}  (network {network})")
    print(f"scope object  {scope_object_id}  cidr {ALLOWLIST}")
    print(f"policy layer  id={policy_layer_id} "
          f"({'published now' if published_now else 'reused'})")
    print(f"effective     {effective['actions']}  data_deny={effective['data_deny']}")
    print(f"reviewer      {backend}\n")

    results: dict[str, Any] = {
        "engagement_id": engagement_id, "target_ip": target_ip,
        "scope_object_id": scope_object_id, "reviewer_backend": backend,
    }
    ok = True

    # --- A: D11-4 replay ----------------------------------------------------
    print("A. cidr 10.79.0.0/24, max_targets=1  (D11-4 counterexample)")
    a = run_case(
        engagement_id=engagement_id,
        proposal=proposal_for(identity_type="cidr", value=ALLOWLIST,
                              scope_object_id=scope_object_id, ports="8080"),
        budget=Budget(max_duration_seconds=120, max_targets=1),
        reviewer=reviewer, sandbox=ExplodingSandbox(),
    )
    results["A_budget_exceeded"] = a
    ok &= check("decision is DENY", a["decision"] == "DENY", a["decision"])
    ok &= check("deny reason is target_count_exceeds_budget",
                "target_count_exceeds_budget" in a["deny_reasons"],
                str(a["deny_reasons"]))
    ok &= check("not denied for some other reason as well",
                a["deny_reasons"] == ["target_count_exceeds_budget"],
                str(a["deny_reasons"]))
    ok &= check("broker call count is 0", a["broker_call_count"] == 0,
                str(a["broker_call_count"]))
    ok &= check("no capabilities row", a["capability_rows"] == 0)
    ok &= check("no capability.issued in audit_log",
                "capability.issued" not in a["audit_events"])
    ok &= check("reached OPA (policy.decided recorded)",
                "policy.decided" in a["audit_events"], str(a["audit_events"]))
    ok &= check("proposal row was persisted", a["action_proposal_rows"] == 1)
    ok &= check("no tool run", a["tool_run_rows"] == 0)

    # --- B: D11-5 replay ----------------------------------------------------
    print("\nB. cidr 10.79.0.2/24  (D11-5 counterexample: host bits set)")
    print("    direct canonicalizer call:")
    try:
        normalize_target({"logical_identity": {"type": "cidr",
                                               "value": "10.79.0.2/24"}})
        canonicalizer_raised, canonicalizer_error = False, None
    except CanonicalizationError as exc:
        canonicalizer_raised, canonicalizer_error = True, str(exc)
    ok &= check("normalize_target raises CanonicalizationError",
                canonicalizer_raised, canonicalizer_error or "returned a value")
    ok &= check("the error names host bits, not a parse failure",
                bool(canonicalizer_error) and "host bits" in canonicalizer_error)
    print(f"      {canonicalizer_error}")

    print("    through the pipeline:")
    b = run_case(
        engagement_id=engagement_id,
        proposal=proposal_for(identity_type="cidr", value="10.79.0.2/24",
                              scope_object_id=scope_object_id, ports="8080"),
        budget=Budget(max_duration_seconds=120, max_targets=1),
        reviewer=reviewer, sandbox=ExplodingSandbox(),
    )
    results["B_host_bits"] = b
    results["B_canonicalizer_error"] = canonicalizer_error
    ok &= check("decision is DENY", b["decision"] == "DENY", b["decision"])
    ok &= check("deny reason is target_not_canonicalizable",
                b["deny_reasons"] == ["target_not_canonicalizable"],
                str(b["deny_reasons"]))
    # The distinction that matters: this must fail *before* OPA, not be widened
    # to the /24 and then stopped by case A's rule.
    ok &= check("stopped BEFORE OPA (no policy.decided)",
                "policy.decided" not in b["audit_events"],
                str(b["audit_events"]))
    ok &= check("not denied by the budget rule",
                "target_count_exceeds_budget" not in b["deny_reasons"])
    ok &= check("no proposal row persisted", b["action_proposal_rows"] == 0)
    ok &= check("audit shows proposal.rejected",
                b["audit_events"] == ["proposal.rejected"],
                str(b["audit_events"]))
    ok &= check("broker call count is 0", b["broker_call_count"] == 0)
    ok &= check("no reviewer was consulted", b["reviewer_opinion"] is None)

    # --- C: control for A ---------------------------------------------------
    print("\nC. cidr 10.79.0.0/24, max_targets=256  (control for A)")
    c = run_case(
        engagement_id=engagement_id,
        proposal=proposal_for(identity_type="cidr", value=ALLOWLIST,
                              scope_object_id=scope_object_id, ports="8080"),
        budget=Budget(max_duration_seconds=120, max_targets=256),
        reviewer=reviewer, sandbox=sandbox,
    )
    results["C_budget_covers_range"] = c
    ok &= check("not denied by the budget rule",
                "target_count_exceeds_budget" not in c["deny_reasons"],
                str(c["deny_reasons"]))
    ok &= check("no deny reasons at all", c["deny_reasons"] == [],
                str(c["deny_reasons"]))
    if c["decision"] == "ALLOW":
        ok &= check("the scan actually ran", c["run_id"] is not None)
        ok &= check("evidence was written", c["evidence_id"] is not None)
        ok &= check("broker was called once", c["broker_call_count"] == 1)
    else:
        # The reviewer escalated. Not a failure of D12 — record it and say so.
        check("HUMAN_APPROVAL came from the reviewer, not the budget",
              c["decision"] == "HUMAN_APPROVAL" and c["approval_reasons"] != [],
              f"{c['decision']} {c['approval_reasons']}")

    # --- D: control for B ---------------------------------------------------
    print("\nD. ip 10.79.0.2, max_targets=1  (control for B)")
    d = run_case(
        engagement_id=engagement_id,
        proposal=proposal_for(identity_type="ip", value=target_ip,
                              scope_object_id=scope_object_id,
                              ports="25,80,8080"),
        budget=Budget(max_duration_seconds=120, max_targets=1),
        reviewer=reviewer, sandbox=sandbox,
    )
    results["D_single_host"] = d
    ok &= check("target canonicalized", "policy.decided" in d["audit_events"],
                str(d["audit_events"]))
    ok &= check("no deny reasons", d["deny_reasons"] == [], str(d["deny_reasons"]))
    if d["decision"] == "ALLOW":
        ok &= check("the scan actually ran", d["run_id"] is not None)
    else:
        check("HUMAN_APPROVAL came from the reviewer, not the kernel",
              d["decision"] == "HUMAN_APPROVAL" and d["approval_reasons"] != [],
              f"{d['decision']} {d['approval_reasons']}")

    results["all_checks_passed"] = bool(ok)
    print(f"\n{'ALL CHECKS PASSED' if ok else 'SOME CHECKS FAILED'}")

    out = REPO_ROOT / "d12_5_verification.json"
    if len(sys.argv) > 1:
        out = Path(sys.argv[1])
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"wrote {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
