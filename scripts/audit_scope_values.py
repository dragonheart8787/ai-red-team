"""Report scope objects whose stored value the canonicalizer would now refuse.

D16 added canonicalization to ``register_scope_object``. Rows written before
that — and any row written since with a raw INSERT as ``registry_admin``, which
the write path cannot prevent — were never checked, so this asks the question
the write path now asks, of everything already in the table.

    python scripts/audit_scope_values.py --engagement ENG-1 --engagement ENG-2
    python scripts/audit_scope_values.py --engagement ENG-1 --json
    python scripts/audit_scope_values.py --engagement ENG-1 --include-inactive

**It reports and changes nothing.** What to do about a non-conforming row is a
decision about somebody's engagement — re-register it with the value that was
meant, retire it, or flag it for human review — and none of those is a choice a
script should make on an operator's behalf. The read path already refuses to
let such a row authorize anything (``scope_covers_target``), so nothing is
unsafe while the decision is pending; it is simply not doing the job it was
registered to do.

Read-only, over the ordinary ``cyberorch_app`` connection.

**The engagements have to be named; this cannot sweep the database.** Every
table it would need is under ``ENABLE`` *and* ``FORCE ROW LEVEL SECURITY``
(§8.6), so no application role sees another engagement's rows — including
``engagements`` itself, and including ``migration_owner``, which owns the
tables and is still bound by FORCE. That is I4 working exactly as intended, and
it is worth stating rather than routing around: the isolation that makes a
per-engagement answer trustworthy is the same isolation that makes a
database-wide sweep impossible through these roles. An operator who wants every
engagement checked supplies the list, because knowing which engagements exist is
their standing, not this script's.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402

from control_plane.canonicalizer.target import (  # noqa: E402
    CanonicalizationError,
    canonicalize_scope_value,
)
from control_plane.config import load_dotenv  # noqa: E402
from control_plane.state.db import engagement_scope  # noqa: E402


def scan(engagement_id: str, *, include_inactive: bool) -> list[dict]:
    clause = "" if include_inactive else " WHERE active IS TRUE"
    with engagement_scope(engagement_id) as conn:
        rows = conn.execute(text(
            "SELECT scope_object_id, engagement_id, type, value, active, "
            "registered_by, created_at, updated_at FROM scope_registry"
            + clause + " ORDER BY scope_object_id"
        )).mappings().all()

    findings = []
    for row in rows:
        try:
            canonical = canonicalize_scope_value(row["type"], row["value"])
        except CanonicalizationError as exc:
            findings.append({
                "scope_object_id": row["scope_object_id"],
                "engagement_id": row["engagement_id"],
                "type": row["type"], "value": row["value"],
                "active": row["active"], "registered_by": row["registered_by"],
                "created_at": str(row["created_at"]),
                "problem": "unusable", "detail": str(exc),
            })
            continue
        if canonical != row["value"]:
            # Parses, but is not stored in the form the resolver compares
            # against. Not refused by the read path — it simply matches less
            # than whoever registered it expected, which is the quieter half of
            # the same problem.
            findings.append({
                "scope_object_id": row["scope_object_id"],
                "engagement_id": row["engagement_id"],
                "type": row["type"], "value": row["value"],
                "active": row["active"], "registered_by": row["registered_by"],
                "created_at": str(row["created_at"]),
                "problem": "non_canonical", "canonical_form": canonical,
            })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engagement", action="append", dest="engagements", required=True,
        metavar="ENG-...",
        help="engagement to check; repeat for more. Required: RLS means this "
             "cannot enumerate them (see the module docstring).",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--include-inactive", action="store_true")
    args = parser.parse_args()

    load_dotenv()
    ids = args.engagements
    findings: list[dict] = []
    total = 0
    for engagement_id in ids:
        with engagement_scope(engagement_id) as conn:
            clause = "" if args.include_inactive else " WHERE active IS TRUE"
            total += conn.execute(text(
                "SELECT count(*) FROM scope_registry" + clause)).scalar_one()
        findings.extend(scan(engagement_id, include_inactive=args.include_inactive))

    if args.as_json:
        print(json.dumps({
            "engagements_scanned": len(ids),
            "scope_objects_scanned": total,
            "findings": findings,
        }, indent=2, default=str))
        return 1 if findings else 0

    scope = "all" if args.include_inactive else "active"
    print(f"scanned {total} {scope} scope object(s) across {len(ids)} engagement(s)")
    if not findings:
        print("no scope object holds a value the canonicalizer would refuse "
              "or rewrite.")
        return 0

    print(f"\n{len(findings)} finding(s) — reported only, nothing changed:\n")
    for f in findings:
        print(f"  [{f['problem']}] {f['scope_object_id']}  {f['type']} "
              f"{f['value']!r}")
        print(f"      engagement={f['engagement_id']} active={f['active']} "
              f"registered_by={f['registered_by']} at {f['created_at']}")
        if f["problem"] == "unusable":
            print(f"      {f['detail']}")
            print("      the read path already refuses to let this authorize "
                  "anything (scope_covers_target)")
        else:
            print(f"      would canonicalize to {f['canonical_form']!r}; as "
                  "stored it matches less than it appears to")
        print()
    print("What to do about each of these is an operator decision — re-register "
          "with the value that was meant, retire it, or flag for review. This "
          "script does not choose.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
