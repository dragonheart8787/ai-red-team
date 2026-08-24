"""See and clear the human-approval queue (§4.7, D24).

The operator surface the DEFERRED item recorded before D10.5 asked for. A
proposal is here only because OPA decided ``HUMAN_APPROVAL``; this tool never
adds a judgement of its own about what to show or what to allow.

    python scripts/approvals.py --engagement ENG-... list
    python scripts/approvals.py --engagement ENG-... approve PROP-... --scope this_proposal_only
    python scripts/approvals.py --engagement ENG-... deny PROP-... --reason "out of window"
    python scripts/approvals.py --engagement ENG-... watch --interval 30

Same shape as ``scripts/policy_layers.py`` / ``scripts/global_audit.py``:
argparse, a readable default, ``--json`` where it helps. ``list`` and ``watch``
are read-only and write nothing; ``approve`` and ``deny`` record the decision
through the ordinary audit path. It connects as ``cyberorch_app`` — no new
grant. Fail-closed: any error leaves the proposal pending and issues nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.api.approvals import (  # noqa: E402
    APPROVED_SCOPES,
    ApprovalError,
    deny_approval,
    grant_approval,
    list_pending_approvals,
)
from control_plane.audit.query import reconstruct_decision  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.state.db import engagement_scope  # noqa: E402


def _why(conn, proposal_id: str) -> list[str]:
    """The escalation's context, reusing D8's reconstruct_decision (constraint 1).

    Nothing is recomputed here — the reasons are OPA's, read back from the
    audit trail — so the reader sees why this proposal was flagged without
    running a second SQL query of their own.
    """
    out: list[str] = []
    chain = reconstruct_decision(conn, proposal_id=proposal_id)
    if chain.decision:
        out.append(f"      OPA decision: {chain.decision}")
    if chain.why():
        out.append(f"      approval reasons: {', '.join(chain.why())}")
    claim = chain.reviewer_claim()
    if claim:
        out.append(f"      reviewer said: risk={claim.get('risk_hint')} "
                   f"sensitive_hint={claim.get('possible_sensitive_data_hint')}")
    return out


def render(conn, pending: list[dict]) -> str:
    out: list[str] = [f"{len(pending)} proposal(s) awaiting human approval:", ""]
    for p in pending:
        ident = (p["target"] or {}).get("logical_identity", {})
        out.append(f"  {p['proposal_id']}  {p['action']} on "
                   f"{ident.get('type')}:{ident.get('value')}")
        out.append(f"      task={p['task_id']}  agent={p['agent_id']}  "
                   f"since {p['created_at']}")
        out.extend(_why(conn, p["proposal_id"]))
        out.append("")
    if not pending:
        out.append("  (none — nothing is waiting on you)")
        out.append("")
    return "\n".join(out)


def cmd_list(args) -> int:
    with engagement_scope(args.engagement) as conn:
        pending = list_pending_approvals(conn, engagement_id=args.engagement)
        if args.json:
            print(json.dumps(
                [{k: (str(v) if k == "created_at" else v) for k, v in p.items()}
                 for p in pending], indent=2, sort_keys=True, default=str))
        else:
            print(render(conn, pending))
    return 0


def cmd_approve(args) -> int:
    try:
        with engagement_scope(args.engagement) as conn:
            outcome = grant_approval(
                conn, engagement_id=args.engagement, proposal_id=args.proposal_id,
                approver=args.by, approved_scope=args.scope,
                valid_for_seconds=args.valid_hours * 3600,
            )
    except ApprovalError as exc:
        # Fail-closed: the transaction rolled back, nothing was written.
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if outcome.issued:
        print(f"approved {outcome.proposal_id} (scope={outcome.approved_scope}); "
              f"capability {outcome.capability_id} issued via the broker.")
        return 0
    # The approval object exists and is valid; the broker declined to issue for
    # its own reasons. Reported, not hidden — and not retried as an approval.
    print(f"approval {outcome.approval_id} recorded, but the broker did not "
          f"issue a capability: {', '.join(outcome.reasons)}", file=sys.stderr)
    return 3


def cmd_deny(args) -> int:
    try:
        with engagement_scope(args.engagement) as conn:
            deny_approval(conn, engagement_id=args.engagement,
                          proposal_id=args.proposal_id, denier=args.by,
                          reason=args.reason or "")
    except ApprovalError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"denied {args.proposal_id}; no capability issued.")
    return 0


def cmd_watch(args) -> int:
    """Poll for new pending approvals. Not a daemon, not a push system — the
    minimum that means you do not have to keep re-running ``list`` by hand."""
    seen: set[str] = set()
    print(f"watching {args.engagement} every {args.interval}s "
          f"(ctrl-c to stop)...", file=sys.stderr)
    while True:
        try:
            with engagement_scope(args.engagement) as conn:
                pending = list_pending_approvals(conn, engagement_id=args.engagement)
                fresh = [p for p in pending if p["proposal_id"] not in seen]
                if fresh:
                    print(render(conn, fresh))
                seen = {p["proposal_id"] for p in pending}
        except Exception as exc:  # noqa: BLE001
            # Fail-closed: a failed poll changes nothing and never decides. Print
            # and keep watching rather than exiting on a transient error.
            print(f"poll failed (nothing changed): {exc}", file=sys.stderr)
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            print("stopped.", file=sys.stderr)
            return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Human approval queue (§4.7, D24).")
    parser.add_argument("--engagement", required=True, help="Engagement id.")
    parser.add_argument("--json", action="store_true", help="Machine-readable list.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List proposals awaiting approval.")

    ap = sub.add_parser("approve", help="Approve one proposal.")
    ap.add_argument("proposal_id")
    ap.add_argument("--scope", required=True, choices=APPROVED_SCOPES,
                    help="§4.7 approval scope (required — there is no approve-all).")
    ap.add_argument("--by", required=True, help="Who is approving (recorded).")
    ap.add_argument("--valid-hours", type=int, default=1,
                    help="How long the approval is valid (default 1h).")

    dn = sub.add_parser("deny", help="Deny one proposal.")
    dn.add_argument("proposal_id")
    dn.add_argument("--by", required=True, help="Who is denying (recorded).")
    dn.add_argument("--reason", default="", help="Why (recorded).")

    wa = sub.add_parser("watch", help="Poll for new pending approvals.")
    wa.add_argument("--interval", type=int, default=30)

    args = parser.parse_args(argv)
    load_dotenv()
    return {
        "list": cmd_list, "approve": cmd_approve,
        "deny": cmd_deny, "watch": cmd_watch,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
