"""Enroll or withdraw an engagement from the scheduler -- an operator's action (D62, D58-1/A).

    python scripts/manage_scheduler_enrollment.py list
    python scripts/manage_scheduler_enrollment.py enroll   ENG-... --by alice
    python scripts/manage_scheduler_enrollment.py withdraw ENG-... --by alice

The scheduler touches only engagements listed here: an engagement nobody enrolled is never read,
never dispatched. This is the only code that writes the list, over the ``scheduler_admin``
connection, which nothing else may open (a test scans for that); neither ``cyberorch_app`` nor the
scheduler's own roles can write it. It asks for a person: without ``--yes`` it prints what will
happen and waits for the word on a terminal, and refuses when there is none. ``--yes`` exists for
scripted provisioning and is the caller's statement that a person already decided.

Every change writes a ``scope='global'`` audit record (``scheduler.enrolled`` / ``.withdrawn``).
Exit status: 0 done, 1 refused, 2 not confirmed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.scheduler import emit, vocab  # noqa: E402
from control_plane.state.db import assert_scheduler_admin, scheduler_admin_scope  # noqa: E402


def _confirm(summary: str, word: str, assume_yes: bool) -> bool:
    print(summary)
    if assume_yes:
        print("--yes given: proceeding without asking.")
        return True
    if not sys.stdin.isatty():
        print("refusing: no terminal to confirm on (use --yes only if a person has "
              "already decided).", file=sys.stderr)
        return False
    try:
        answer = input(f"type {word} to continue: ").strip()
    except EOFError:
        return False
    return answer == word


def _list() -> int:
    with scheduler_admin_scope() as conn:
        rows = conn.execute(text(
            "SELECT enrollment_id, engagement_id, enrolled_by, enrolled_at, withdrawn_by, "
            "withdrawn_at FROM scheduler_enrollment ORDER BY enrollment_id")).mappings().all()
    if not rows:
        print("no enrollments")
    for r in rows:
        state = ("live" if r["withdrawn_at"] is None
                 else f"withdrawn by {r['withdrawn_by']} at {r['withdrawn_at']}")
        print(f"#{r['enrollment_id']} {r['engagement_id']}  enrolled by {r['enrolled_by']} "
              f"at {r['enrolled_at']}  [{state}]")
    return 0


def _enroll(args: argparse.Namespace) -> int:
    summary = (f"ENROLL {args.engagement} in the scheduler as {args.by}\n"
               "  The scheduler will read this engagement and dispatch its approved proposals.")
    if not _confirm(summary, "ENROLL", args.yes):
        return 2
    try:
        with scheduler_admin_scope() as conn:
            assert_scheduler_admin(conn)
            conn.execute(text("INSERT INTO scheduler_enrollment (engagement_id, enrolled_by) "
                              "VALUES (:e, :b)"), {"e": args.engagement, "b": args.by})
            # Written before the transaction commits: if the audit record cannot be written, the
            # enrollment is not.
            emit.emit(vocab.ENROLLED, {"engagement_id": args.engagement, "by": args.by},
                      actor=args.by, subject_type="engagement", subject_id=args.engagement)
    except IntegrityError as exc:
        reason = ("no such engagement" if "foreign key" in str(exc).lower()
                  else "already enrolled")
        print(f"refused: {reason}", file=sys.stderr)
        return 1
    except emit.PayloadRejected:
        print("refused: the engagement id or --by is not a plain identifier", file=sys.stderr)
        return 1
    print(f"enrolled {args.engagement}")
    return 0


def _withdraw(args: argparse.Namespace) -> int:
    summary = (f"WITHDRAW {args.engagement} from the scheduler as {args.by}\n"
               "  Approved proposals in it stay approved; nothing will dispatch them.")
    if not _confirm(summary, "WITHDRAW", args.yes):
        return 2
    try:
        with scheduler_admin_scope() as conn:
            assert_scheduler_admin(conn)
            done = conn.execute(text(
                "UPDATE scheduler_enrollment SET withdrawn_by = :b, withdrawn_at = now() "
                "WHERE engagement_id = :e AND withdrawn_at IS NULL RETURNING enrollment_id"),
                {"e": args.engagement, "b": args.by}).first()
            if done is None:
                print("refused: not currently enrolled", file=sys.stderr)
                return 1
            emit.emit(vocab.WITHDRAWN, {"engagement_id": args.engagement, "by": args.by},
                      actor=args.by, subject_type="engagement", subject_id=args.engagement)
    except emit.PayloadRejected:
        print("refused: the engagement id or --by is not a plain identifier", file=sys.stderr)
        return 1
    print(f"withdrawn {args.engagement}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show every enrollment, live and withdrawn")
    for name, helptext in (("enroll", "enroll an engagement"), ("withdraw", "withdraw one")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("engagement")
        p.add_argument("--by", required=True, help="who is doing this (audited)")
        p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = parser.parse_args(argv)
    load_dotenv()
    if args.command == "list":
        return _list()
    return _enroll(args) if args.command == "enroll" else _withdraw(args)


if __name__ == "__main__":
    raise SystemExit(main())
