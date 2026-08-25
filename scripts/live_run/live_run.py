"""Drive one full pipeline run against a real container target (D11).

Not a test. This is the harness for the live run recorded in
``docs/LIVE_RUN_REPORT.md``: it stands up an engagement through the same
functions production uses, hands the scripted planner and worker the target's
*actual* address, and dumps everything the run touched so the report can quote
it rather than describe it.

Three things it deliberately does not do:

* **No raw SQL for anything that has an operation.** The scope object and the
  asset classification go in through ``register_scope_object`` /
  ``register_metadata`` over a ``registry_admin`` connection, and the policy
  through ``publish_policy_layer`` / ``load_effective_policy``. The point of a
  live run is to exercise the real path; seeding it by hand would verify the
  seeding.
* **No hardcoded target.** The address is read back from Docker, so the run is
  against whatever the container actually got.
* **No fallbacks.** If the sandbox is unavailable, the reviewer is
  unconfigured, or the target is outside the allowlist, this stops and says so.
  A live run that quietly degrades into a simulated one is worse than no live
  run.

The one gap it cannot close: there is no production function that creates an
engagement row. Every caller in the tree writes it with an ``INSERT``, this
one included, and that is written up as a finding rather than papered over.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402

from agents.fake.fake_planner import FakePlanner, scan_task  # noqa: E402
from agents.fake.fake_worker import FakeWorker  # noqa: E402
from agents.llm.selection import BACKEND_ENV, build_reviewer  # noqa: E402
from control_plane.api.function_api import (  # noqa: E402
    claim_task,
    complete_task,
    create_task,
    propose_action,
    query_evidence,
)
from control_plane.audit.query import engagement_timeline, reconstruct_decision  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.evidence.store import read_raw_artifact, verify_artifact  # noqa: E402
from control_plane.policy.layers import load_effective_policy, publish_policy_layer  # noqa: E402
from control_plane.provenance import graph  # noqa: E402
from control_plane.registry.metadata_registry import register_metadata  # noqa: E402
from control_plane.registry.scope_registry import register_scope_object  # noqa: E402
from control_plane.state.db import engagement_scope, registry_admin_scope  # noqa: E402
from tool_gateway.sandbox import (  # noqa: E402
    DockerSandbox,
    SandboxUnavailable,
    target_within_allowlist,
)

ACTOR = "d11-live-run"


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def container_ip(name: str, network: str) -> str:
    """Read the target's real address out of Docker."""
    out = subprocess.run(
        ["docker", "inspect", name, "--format",
         "{{ (index .NetworkSettings.Networks \"" + network + "\").IPAddress }}"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if not out:
        raise SystemExit(
            f"container {name!r} has no address on network {network!r}. "
            "Start it with scripts/live_run/start_target.sh first."
        )
    return out


def create_engagement(engagement_id: str, customer_id: str) -> None:
    """Insert the engagement row.

    FINDING (D11-3): this is the one step with no production operation behind
    it. ``pause``/``resume``/``kill``/``complete`` all exist in
    control_plane.orchestrator.engagement; creation does not, so every caller
    — the test fixtures, the stateful machine, and this script — writes the row
    directly. Left as raw SQL rather than hidden behind a helper here, so the
    gap is visible in the live run instead of being smoothed over by it.
    """
    with engagement_scope(engagement_id) as conn:
        conn.execute(
            text("INSERT INTO engagements (engagement_id, customer_id, "
                 "policy_snapshot_version) VALUES (:eid, :cid, 1)"),
            {"eid": engagement_id, "cid": customer_id},
        )


def seed_registries(engagement_id: str, *, allowlist_cidr: str, target_ip: str,
                    actions: list[str]) -> tuple[str, str]:
    """Register scope and classification through the Engagement Manager path."""
    scope_object_id = uid("SCOPE")
    asset_id = uid("ASSET")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="cidr", value=allowlist_cidr, allowed_actions=actions, actor=ACTOR,
        )
        register_metadata(
            conn, engagement_id=engagement_id, asset_id=asset_id,
            identity_type="ip", identity_value=target_ip,
            authority="AUTHORITATIVE", source="operator_declared",
            resource_class=["network_host"], data_class=["network_service"],
            actor=ACTOR,
        )
    return scope_object_id, asset_id


BASELINE_DOCUMENT = {
    "data_deny": ["PII", "customer_database"],
    "actions": {"network.scan": "ALLOW", "network.recon": "ALLOW"},
}


def publish_baseline(engagement_id: str) -> tuple[int, bool]:
    """Publish the global baseline layer, or reuse the one already there.

    Reuse rather than republish under a fresh version, and the reason is the
    first thing this live run turned up (D11-1): a global layer applies to
    every engagement forever and nothing expires it, so a harness that bumped
    the version on each run would leave a new permanent global row behind
    every time — which is exactly how nineteen stale emergency overlays
    accumulated in this database.

    Returns (policy layer id, whether it was published now).
    """
    with engagement_scope(engagement_id) as conn:
        existing = conn.execute(
            text("SELECT id FROM policy_layers WHERE active IS TRUE "
                 "AND engagement_id IS NULL AND layer = 'baseline_global' "
                 "ORDER BY id DESC LIMIT 1")
        ).scalar_one_or_none()
        if existing is not None:
            return int(existing), False
        return publish_policy_layer(
            conn, engagement_id=engagement_id, layer="baseline_global", version=1,
            document=BASELINE_DOCUMENT, actor=ACTOR,
        ), True


def run_pipeline(*, engagement_id: str, scope_object_id: str, target_ip: str,
                 allowlist: list[str], ports: str, scan_type: str, sandbox,
                 reviewer, policy) -> dict[str, Any]:
    planner = FakePlanner([scan_task(target_ip=target_ip,
                                     scope_object_id=scope_object_id)])
    worker = FakeWorker(ports=ports, scan_type=scan_type)

    with engagement_scope(engagement_id) as conn:
        task = planner.plan(engagement_id=engagement_id)[0]
        task_id = create_task(conn, engagement_id=engagement_id, task=task,
                              created_by=planner.agent_id)
        claimed = claim_task(conn, engagement_id=engagement_id,
                             agent_id=worker.agent_id)
        proposal = worker.propose(task=task, task_id=task_id)

        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=reviewer, policy=policy, agent_id=worker.agent_id,
            sandbox=sandbox, network_allowlist=allowlist,
            execution_context={"auth_context_id": "AUTHCTX-D11"},
        )
        complete_task(conn, engagement_id=engagement_id, task_id=task_id,
                      result_summary=f"live scan {outcome.decision}",
                      actor=worker.agent_id)

    return {
        "task_id": task_id,
        "claimed_task_id": claimed,
        "proposal": {
            "action": proposal.action,
            "target": proposal.target,
            "authorization": proposal.authorization,
            "discovery": proposal.discovery,
        },
        "outcome": {
            "decision": outcome.decision,
            "deny_reasons": list(outcome.deny_reasons),
            "approval_reasons": list(outcome.approval_reasons),
            "proposal_id": outcome.proposal_id,
            "capability_id": outcome.capability_id,
            "run_id": outcome.run_id,
            "evidence_id": outcome.evidence_id,
            "metadata_authority": outcome.metadata_authority,
            "canonical_data_class": list(outcome.canonical_data_class),
            "failure": outcome.failure,
            "reviewer_opinion": (
                outcome.reviewer_opinion.as_dict() if outcome.reviewer_opinion else None
            ),
        },
    }


def collect(engagement_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Read back everything the run wrote."""
    outcome = result["outcome"]
    collected: dict[str, Any] = {}

    with engagement_scope(engagement_id) as conn:
        if outcome["run_id"]:
            collected["tool_run"] = dict(conn.execute(
                text("SELECT run_id, proposal_id, capability_id, tool, tool_version, "
                     "normalized_target, normalized_params, execution_context, "
                     "execution_fingerprint, status, network_allowlist, exit_code, "
                     "fresh_until FROM tool_runs WHERE run_id = :r"),
                {"r": outcome["run_id"]},
            ).mappings().one())
            collected["tool_run"]["fresh_until"] = str(
                collected["tool_run"]["fresh_until"]
            )

        if outcome["capability_id"]:
            collected["capability"] = dict(conn.execute(
                text("SELECT capability_id, agent_id, proposal_id, scope_object_id, "
                     "action, constraints, budget, requests_used, policy_version, "
                     "revoked, revoked_reason FROM capabilities "
                     "WHERE capability_id = :c"),
                {"c": outcome["capability_id"]},
            ).mappings().one())

        if outcome["evidence_id"]:
            row = conn.execute(
                text("SELECT evidence_id, run_id, type, raw_artifact_path, raw_sha256, "
                     "raw_logically_immutable, derived_view, tool, tool_version "
                     "FROM evidence WHERE evidence_id = :e"),
                {"e": outcome["evidence_id"]},
            ).mappings().one()
            collected["evidence"] = dict(row)
            collected["evidence_verified"] = verify_artifact(
                conn, outcome["evidence_id"]
            )
            collected["raw_artifact"] = read_raw_artifact(
                row["raw_artifact_path"]
            ).decode(errors="replace")
            collected["agent_visible_evidence"] = query_evidence(
                conn, evidence_id=outcome["evidence_id"]
            )

            chain = graph.why(conn, node_type="evidence",
                              node_id=outcome["evidence_id"])
            collected["provenance"] = [
                {"from": f"{e.from_type}:{e.from_id}",
                 "to": f"{e.to_type}:{e.to_id}", "relation": e.relation}
                for e in chain
            ]

        decision_chain = reconstruct_decision(conn, proposal_id=outcome["proposal_id"])
        collected["decision_chain"] = {
            "decision": decision_chain.decision,
            "why": list(decision_chain.why()),
            "executed": decision_chain.executed,
            "capability_ids": list(decision_chain.capability_ids),
            "run_ids": list(decision_chain.run_ids),
            "reviewer_claim": decision_chain.reviewer_claim(),
            "stages": {
                stage: [e.event_type for e in events]
                for stage, events in decision_chain.by_stage().items()
            },
            "events": [
                {"audit_id": e.audit_id, "event_type": e.event_type, "actor": e.actor,
                 "decision": e.decision, "reasons": list(e.reasons),
                 "payload": e.payload}
                for e in decision_chain.events
            ],
        }
        collected["timeline"] = [
            {"audit_id": e.audit_id, "event_type": e.event_type, "actor": e.actor,
             "decision": e.decision, "reasons": list(e.reasons)}
            for e in engagement_timeline(conn)
        ]
    return collected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-container", default="d11-target")
    parser.add_argument("--allowlist", default="10.79.0.0/24")
    parser.add_argument("--ports", default="1-1024,3306,5432,6379,8080,8443")
    parser.add_argument("--scan-type", default="connect",
                        help="connect | ping | version")
    parser.add_argument("--out", default=None, help="write the full dump as JSON")
    parser.add_argument(
        "--backend", default=None,
        help="reviewer backend; defaults to $CYBERORCH_REVIEWER_BACKEND",
    )
    args = parser.parse_args()

    load_dotenv()
    backend = args.backend or os.environ.get(BACKEND_ENV)
    if not backend:
        raise SystemExit(
            f"{BACKEND_ENV} is not set. D11 runs against a real reviewer; "
            "refusing to fall back to the fake one silently."
        )

    sandbox = DockerSandbox()
    try:
        sandbox.ensure_image()
    except SandboxUnavailable as exc:
        raise SystemExit(f"sandbox unavailable: {exc}") from exc

    network = sandbox.network_name([args.allowlist])
    target_ip = container_ip(args.target_container, network)
    if not target_within_allowlist(target_ip, [args.allowlist]):
        raise SystemExit(
            f"target {target_ip} is outside the allowlist {args.allowlist}"
        )

    engagement_id = uid("ENG-D11")
    customer_id = "CUST-D11-LOCAL"
    create_engagement(engagement_id, customer_id)
    scope_object_id, asset_id = seed_registries(
        engagement_id, allowlist_cidr=args.allowlist, target_ip=target_ip,
        actions=["network.recon", "network.scan"],
    )
    policy_version, published_now = publish_baseline(engagement_id)
    with engagement_scope(engagement_id) as conn:
        policy = load_effective_policy(conn, engagement_id)

    reviewer = build_reviewer(backend)

    print(f"engagement    {engagement_id}")
    print(f"target        {target_ip}  (container {args.target_container})")
    print(f"allowlist     {args.allowlist}  (network {network})")
    print(f"scope object  {scope_object_id}")
    print(f"asset         {asset_id}")
    print(f"policy layer  id={policy_version} "
          f"({'published now' if published_now else 'reused'})  {policy.as_dict()}")
    print(f"scan type     {args.scan_type}")
    print(f"reviewer      {backend}")
    print()

    result = run_pipeline(
        engagement_id=engagement_id, scope_object_id=scope_object_id,
        target_ip=target_ip, allowlist=[args.allowlist], ports=args.ports,
        scan_type=args.scan_type, sandbox=sandbox, reviewer=reviewer,
        policy=policy,
    )
    result["collected"] = collect(engagement_id, result)
    result["engagement_id"] = engagement_id
    result["target_ip"] = target_ip
    result["scope_object_id"] = scope_object_id
    result["asset_id"] = asset_id
    result["allowlist"] = [args.allowlist]
    result["reviewer_backend"] = backend
    result["policy"] = policy.as_dict()

    outcome = result["outcome"]
    print(f"decision      {outcome['decision']}")
    print(f"deny          {outcome['deny_reasons']}")
    print(f"approval      {outcome['approval_reasons']}")
    print(f"capability    {outcome['capability_id']}")
    print(f"run           {outcome['run_id']}")
    print(f"evidence      {outcome['evidence_id']}")
    if outcome["reviewer_opinion"]:
        print(f"reviewer      {json.dumps(outcome['reviewer_opinion'], indent=2)}")

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, default=str))
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
