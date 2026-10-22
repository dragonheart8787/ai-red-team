#!/usr/bin/env python
"""The first-step checks ACCEPTANCE 5.50 and 5.54 ask for, made against a finished D40 run (D68).

5.54 (the harness was edited for D59/D60 and not run since): confirm that behaviour under the new
``propose_action`` matches the pre-D60 report (``docs/D40_THREE_ROLE_INTEGRATION_REPORT.md``) --
the same decision for the same proposal in each round, the web leg reaching the proxy rather than
``network_in_use_by_another_engagement``, the injection engagement unaffected, and every proposal
ending at ``recorded`` or ``closed`` with ``provenance_complete`` true.

5.50 (``web.render`` requires a known classification and the harness was never run against that):
after ``setup_engagement`` the web host resolves as known and ``AUTHORITATIVE`` for the ``ip``
identity, and a ``web.render`` proposal for it is not escalated with
``unknown_classification_for_action_class``.

    PYTHONPATH=. python scripts/live_run/verify_d40_rerun.py \\
        --run docs/D68_S7_BASELINE/d40_comparison/d40_rerun.json \\
        --baseline docs/d40_runs/d40_three_role.json

It reads the run's record and the database, and **adds two proposals** to the main engagement (a
``web.render`` for the web host, once in the URL form the Worker proposes and once as the ``ip``
the scope object names), decided by the real pipeline with no sandbox behind it, so the decision is
observed and nothing runs. Both are labelled in the output. Nothing is repaired.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from sqlalchemy import text  # noqa: E402

from agents.base_agent import ProposedAction  # noqa: E402
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer  # noqa: E402
from control_plane.api import function_api  # noqa: E402
from control_plane.canonicalizer.metadata import resolve_metadata  # noqa: E402
from control_plane.canonicalizer.target import normalize_target  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.policy.layers import load_effective_policy  # noqa: E402
from control_plane.state.db import engagement_scope  # noqa: E402
from tests.task_support import task_for  # noqa: E402
from tool_gateway.sandbox import SandboxUnavailable  # noqa: E402


class AbsentSandbox:
    """Where a dispatch would run: nowhere. The decision is made before it is reached."""

    def run(self, **kwargs):
        raise SandboxUnavailable("verification sandbox: the decision is what is observed")


def decisions(record: dict) -> list[list]:
    """(round, offered action, proposed action, target, decision, deny, approval) per task run."""
    out = []
    for rnd in record["main_run"]["rounds"]:
        for run in rnd["task_runs"]:
            proposal, outcome = run.get("proposal") or {}, run.get("outcome") or {}
            out.append([rnd["round"], run["action_offered"], proposal.get("action"),
                        proposal.get("target_value"), outcome.get("decision"),
                        sorted(outcome.get("deny_reasons") or []),
                        sorted(outcome.get("approval_reasons") or [])])
    return out


def stages(engagement_id: str) -> list[dict]:
    with engagement_scope(engagement_id) as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT pipeline_stage, stage_detail, provenance_complete, decision, count(*) AS n "
            "FROM action_proposals GROUP BY 1, 2, 3, 4 ORDER BY 1, 2")).mappings()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=REPO / "docs/d40_runs/d40_three_role.json")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    load_dotenv()

    run, base = json.loads(args.run.read_text()), json.loads(args.baseline.read_text())
    main_id, inject_id = run["main_run"]["engagement_id"], run["injection_experiment"][
        "engagement_id"]
    report: dict = {"main_engagement": main_id, "injection_engagement": inject_id}

    # 5.54 (1): the same decision for the same proposal, round by round
    new, old = decisions(run), decisions(base)
    report["decisions_now"], report["decisions_before"] = new, old

    def key(row):          # the web host's address differs between runs; the shape does not
        return [row[0], row[1], row[2], (row[3] or "").split("//")[-1][:7] if row[2] == "web.get"
                else row[3], row[4], row[5]]

    report["same_decision_per_proposal"] = [key(r) for r in new] == [key(r) for r in old]
    report["approval_reasons_differ"] = [
        [r[0], r[2], r[3], a, b] for r, o in zip(new, old, strict=False)
        for a, b in [(r[6], o[6])] if a != b]

    # 5.54 (2): the web leg and the proxy
    web = [r for r in new if r[2] == "web.get"]
    report["web_leg"] = {
        "web_proposals": web,
        "proxy_started_for_the_engagement": bool(run.get("proxy_url")),
        "any_network_in_use_by_another_engagement": any(
            "network_in_use_by_another_engagement" in json.dumps(rr)
            for rnd in run["main_run"]["rounds"] for rr in rnd["task_runs"]),
        "reached_the_proxy": [r for r in web if r[4] != "DENY"],
    }
    # 5.54 (3): the injection engagement
    report["injection_engagement_decisions"] = [
        [r["round"], (t.get("proposal") or {}).get("action"),
         (t.get("outcome") or {}).get("decision")]
        for r in run["injection_experiment"]["rounds"] for t in r.get("task_runs", [])]
    # 5.54 (4): the pipeline stage of every proposal
    report["pipeline_stages"] = {"main": stages(main_id), "injection": stages(inject_id)}

    # 5.50: classification of the web host, and a web.render proposal for it
    web_ip = run["web_ip"]
    with engagement_scope(main_id) as conn:
        by_ip = resolve_metadata(conn, target=normalize_target(
            {"logical_identity": {"type": "ip", "value": web_ip}}))
        by_url = resolve_metadata(conn, target=normalize_target(
            {"logical_identity": {"type": "url", "value": f"http://{web_ip}/"}}))
        policy = load_effective_policy(conn, main_id)
        scope_id = conn.execute(text(
            "SELECT scope_object_id FROM scope_registry WHERE type = 'ip' AND value = :v"),
            {"v": web_ip}).scalar_one()
    report["web_host_classification"] = {
        "ip_identity": {"known": by_ip.known, "authority": by_ip.authority},
        "url_identity_the_worker_proposes": {"known": by_url.known, "authority": by_url.authority}}
    rendered = {}
    for label, target in (("url (the form the Worker proposes)",
                           {"type": "url", "value": f"http://{web_ip}/"}),
                          ("ip", {"type": "ip", "value": web_ip})):
        proposal = ProposedAction(
            action="web.render", target={"logical_identity": target},
            authorization={"source": "engagement_scope", "scope_object_id": scope_id},
            discovery={"source": "explicit_scope"})
        # a proposal names the task it serves (D68): one made from this proposal, as a harness would
        proposal = dataclasses.replace(proposal, task_id=task_for(main_id, proposal))
        outcome = function_api.propose_action(
            engagement_id=main_id, proposal=proposal, reviewer=HonestFakeReviewer(),
            policy=policy, agent_id="verify-d40-rerun", sandbox=AbsentSandbox(),
            network_allowlist=[f"{web_ip}/32"])
        rendered[label] = {"decision": outcome.decision,
                           "deny_reasons": list(outcome.deny_reasons),
                           "approval_reasons": list(outcome.approval_reasons),
                           "failure": outcome.failure}
    report["web_render_proposals_added_by_this_check"] = rendered
    report["web_render_escalated_unknown_classification"] = {
        k: "unknown_classification_for_action_class" in v["approval_reasons"]
        for k, v in rendered.items()}

    text_out = json.dumps(report, indent=2, default=str)
    print(text_out)
    if args.out:
        args.out.write_text(text_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
