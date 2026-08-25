"""Reconstruct one task's full decision history (§4.4, §5.3).

The task-level companion to the per-proposal reconstruction the scenario tests
and the D8 audit report already use. ``reconstruct_decision`` answers "what
happened to this *proposal*"; a task can produce more than one proposal and has
a lifecycle of its own (``task.created`` / ``claimed`` / ``completed``) that the
per-proposal view deliberately excludes. This command answers "what did this
*task* do, from the moment it was created to the moment it finished", by putting
the task's own events beside one reconstructed chain per proposal.

    python scripts/task_history.py --engagement ENG-123 TASK-abc123
    python scripts/task_history.py --engagement ENG-123 TASK-abc123 --json

Same shape as scripts/global_audit.py and scripts/approvals.py: argparse, a
readable default, ``--json`` for anything that parses it.

Read-only. It connects as the ordinary application role and adds no write path;
the reconstruction is two existing read functions plus one SELECT for the
proposal ids, all scoped to the engagement by RLS.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.audit.query import TaskHistory, reconstruct_task_history  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.state.db import engagement_scope  # noqa: E402


def render(history: TaskHistory) -> str:
    out: list[str] = []
    status = "completed" if history.completed else "in progress"
    out.append(f"Task {history.task_id} — {status}")
    out.append("")

    out.append(f"  lifecycle ({len(history.lifecycle_events)} event(s)):")
    if history.lifecycle_events:
        for e in history.lifecycle_events:
            out.append(f"    {e.event_type}  by {e.actor} at {e.ts}  (audit_id={e.audit_id})")
    else:
        out.append("    (none recorded)")
    out.append("")

    counts = ", ".join(f"{k}={v}" for k, v in sorted(history.decision_counts.items()))
    out.append(f"  proposals ({len(history.decisions)}){f': {counts}' if counts else ''}")
    if not history.decisions:
        out.append("    (this task produced no proposals)")
    for chain in history.decisions:
        out.append(f"    {chain.proposal_id}  ->  {chain.decision or 'PENDING'}")
        if chain.why():
            out.append(f"        reasons: {', '.join(chain.why())}")
        out.append(f"        reached: {', '.join(chain.reached_stages) or '(none)'}"
                   f"{'  [executed]' if chain.executed else ''}")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct one task's full decision history (§5.3)."
    )
    parser.add_argument("--engagement", required=True, help="Engagement id.")
    parser.add_argument("task_id", help="The task to reconstruct.")
    parser.add_argument("--json", action="store_true", help="Machine-readable output.")
    args = parser.parse_args(argv)

    load_dotenv()
    with engagement_scope(args.engagement) as conn:
        history = reconstruct_task_history(conn, task_id=args.task_id)

    if args.json:
        print(json.dumps(history.as_dict(), indent=2, sort_keys=True))
    else:
        print(render(history))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
