"""Read the globally-scoped audit trail (D11-7).

The command DEFERRED_MVP0.md 11.2 asks for. A policy layer published globally
constrains every engagement, but until D11-7 the record of who published it was
scoped to the publisher's own engagement — so from anywhere else it read back as
``published by: unknown``, and the D11 live run had to fall back to raw SQL
against a table no operation exposed.

    python scripts/global_audit.py
    python scripts/global_audit.py --event policy_layer.published
    python scripts/global_audit.py --json

Same shape as scripts/policy_layers.py: argparse, a readable default, ``--json``
for anything that parses it.

Read-only, and it connects as ``global_auditor`` — a role whose entire power is
SELECT on the global audit rows (an RLS policy enforces it). It can read nothing
else and write nothing, including no record of its own access.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from control_plane.audit.query import list_global_audit  # noqa: E402
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.state.db import global_auditor_scope  # noqa: E402


def render(events) -> str:
    out: list[str] = []
    out.append(f"{len(events)} global-scope audit event(s), newest first:")
    out.append("")
    for e in events:
        out.append(f"  {e.event_type}  (audit_id={e.audit_id})")
        out.append(f"      published by {e.actor} at {e.ts}")
        if e.subject_type or e.subject_id:
            out.append(f"      subject {e.subject_type}:{e.subject_id}")
        if e.decision:
            out.append(f"      decision {e.decision}")
        # For a policy overlay the document is the point — what was in force, not
        # a summary of it — so it is printed literally.
        if e.payload:
            out.append(f"      {json.dumps(e.payload, sort_keys=True)}")
        out.append("")
    if not events:
        out.append("  (none — no globally-scoped operation has been recorded)")
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List global-scope audit events (D11-7).")
    parser.add_argument(
        "--event", action="append", dest="events",
        help="Filter to an event type (repeatable), e.g. policy_layer.published.",
    )
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--json", action="store_true", help="Machine-readable output.")
    args = parser.parse_args(argv)

    load_dotenv()
    with global_auditor_scope() as conn:
        events = list_global_audit(conn, event_types=args.events, limit=args.limit)

    if args.json:
        print(json.dumps(
            [{"audit_id": e.audit_id, "ts": str(e.ts), "actor": e.actor,
              "event_type": e.event_type, "subject_type": e.subject_type,
              "subject_id": e.subject_id, "decision": e.decision,
              "payload": e.payload} for e in events],
            indent=2, sort_keys=True,
        ))
    else:
        print(render(events))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
