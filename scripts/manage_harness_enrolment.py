"""Register or withdraw an engagement for the production harness -- an operator's action (D69 H5b).

    python scripts/manage_harness_enrolment.py list
    python scripts/manage_harness_enrolment.py register --engagement ENG-... \\
        --purpose harness_lab --actor alice
    python scripts/manage_harness_enrolment.py withdraw --engagement ENG-... --actor alice

The harness's loop works only on the engagements listed here, and only on the rows whose purpose is
``harness_lab`` (``harness/enrolment_db.py``). This is the only code that writes the list: the loop
and its modules do not import it and hold no ``INSERT`` or ``UPDATE`` (a test scans for both). It
connects as ``cyberorch_app`` with no engagement bound, which is the role migration 0031 gives the
table to and no other.

**The purpose is the operator's statement, not a control.** ``--purpose`` is required and has no
default: a registration that does not say what it is for is refused, and the only value the
database accepts is ``harness_lab``. Nothing in ``engagements`` tells a laboratory engagement from a
real one, so the label can be wrong; it stops a mistaken registration and a later purpose being
picked up by a reader that does not ask for it, and it does not stop a person who means to lie.

It asks for a person: without ``--yes`` it prints what will happen and waits for the word on a
terminal, and refuses when there is none. ``--yes`` is the caller's statement that a person already
decided. The engagement id and ``--actor`` are written to the table and printed back to the next
operator, so they must be plain identifiers, and that is asked before the confirmation and before
the database (the rule is the one of ``manage_scheduler_enrollment.py``, ``emit.is_plain_id``,
written out here because the harness may not import the scheduler's package). ``list`` only reads,
in a read-only transaction.

Exit status: 0 done, 1 refused, 2 not confirmed (and, from the argument parser, a missing or unknown
argument). The table records who and when; this CLI writes no audit record.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.engine import Connection  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

from control_plane.config import load_dotenv  # noqa: E402
from control_plane.state.db import get_engine  # noqa: E402

#: What a registration may be for. The database holds the same list in a CHECK.
PURPOSES = ("harness_lab",)

#: ``control_plane.scheduler.emit.is_plain_id``'s rule, written out (see the module docstring).
_PLAIN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

#: A way to get a transaction: ``connect(read_only)`` is a context manager that yields a connection.
Connect = Callable[[bool], AbstractContextManager[Connection]]


@contextmanager
def _connect(read_only: bool) -> Iterator[Connection]:
    """A transaction as ``cyberorch_app`` with no engagement bound (the table is global)."""
    with get_engine().begin() as conn:
        if read_only:
            conn.execute(text("SET TRANSACTION READ ONLY"))
        yield conn


def is_plain_id(value: object) -> bool:
    return isinstance(value, str) and bool(_PLAIN_ID.fullmatch(value))


def _shown(value: str) -> str:
    """A stored name as it is printed: one that is not a plain identifier is shown quoted, so that
    it cannot move the cursor or pose as another line."""
    return value if is_plain_id(value) else repr(value)


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


# -- the writes: the only ones there are ----------------------------------------------------------


def register(conn: Connection, engagement_id: str, purpose: str, actor: str) -> str | None:
    """Write one registration. ``None`` when done, else why the database refused it."""
    try:
        with conn.begin_nested():
            conn.execute(text(
                "INSERT INTO harness_enrolment (engagement_id, purpose, enrolled_by) "
                "VALUES (:e, :p, :a)"), {"e": engagement_id, "p": purpose, "a": actor})
    except IntegrityError as exc:
        return {
            "23503": "no such engagement",
            "23505": "already registered",
            "23514": "purpose refused",
        }.get(getattr(exc.orig, "sqlstate", None), "refused by the database")
    return None


def withdraw(conn: Connection, engagement_id: str, actor: str) -> str | None:
    """End the live registration of an engagement. ``None`` when done, else why not."""
    done = conn.execute(text(
        "UPDATE harness_enrolment SET withdrawn_by = :a, withdrawn_at = now() "
        "WHERE engagement_id = :e AND withdrawn_at IS NULL RETURNING enrolment_id"),
        {"e": engagement_id, "a": actor}).first()
    return None if done is not None else "not currently registered"


# -- the read -------------------------------------------------------------------------------------


def listing(conn: Connection) -> list[str]:
    """One line per registration, live and withdrawn, oldest first."""
    rows = conn.execute(text(
        "SELECT enrolment_id, engagement_id, purpose, enrolled_by, enrolled_at, withdrawn_by, "
        "withdrawn_at FROM harness_enrolment ORDER BY enrolment_id")).mappings().all()
    lines = []
    for r in rows:
        state = ("live" if r["withdrawn_at"] is None
                 else f"withdrawn by {_shown(r['withdrawn_by'])} at {r['withdrawn_at']}")
        lines.append(f"#{r['enrolment_id']} {_shown(r['engagement_id'])} purpose={r['purpose']}  "
                     f"registered by {_shown(r['enrolled_by'])} at {r['enrolled_at']}  [{state}]")
    return lines


# -- the commands ---------------------------------------------------------------------------------


def _refuse_unless_valid(args: argparse.Namespace) -> int | None:
    """Asked first: before the confirmation, before the database."""
    for what, value in (("the engagement id", args.engagement), ("--actor", args.actor)):
        if not is_plain_id(value):
            print(f"refused: {what} is not a plain identifier (letters, digits, . _ : -; "
                  "at most 128)", file=sys.stderr)
            return 1
    if args.command == "register" and args.purpose not in PURPOSES:
        print(f"refused: --purpose is one of {', '.join(PURPOSES)}", file=sys.stderr)
        return 1
    return None


def _register(args: argparse.Namespace, connect: Connect) -> int:
    summary = (f"REGISTER {args.engagement} for the harness, purpose {args.purpose}, as "
               f"{args.actor}\n  The harness's loop will plan for this engagement and propose "
               "actions in it.")
    if not _confirm(summary, "REGISTER", args.yes):
        return 2
    with connect(False) as conn:
        refusal = register(conn, args.engagement, args.purpose, args.actor)
    if refusal is not None:
        print(f"refused: {refusal}", file=sys.stderr)
        return 1
    print(f"registered {args.engagement} ({args.purpose})")
    return 0


def _withdraw(args: argparse.Namespace, connect: Connect) -> int:
    summary = (f"WITHDRAW {args.engagement} from the harness as {args.actor}\n"
               "  The loop will not visit it again; tasks it already created stay as they are.")
    if not _confirm(summary, "WITHDRAW", args.yes):
        return 2
    with connect(False) as conn:
        refusal = withdraw(conn, args.engagement, args.actor)
    if refusal is not None:
        print(f"refused: {refusal}", file=sys.stderr)
        return 1
    print(f"withdrawn {args.engagement}")
    return 0


def _list(connect: Connect) -> int:
    with connect(True) as conn:
        lines = listing(conn)
    if not lines:
        print("no registrations")
    for line in lines:
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="show every registration, live and withdrawn (read only)")
    reg = sub.add_parser("register", help="register an engagement for the harness")
    reg.add_argument("--engagement", required=True)
    reg.add_argument("--purpose", required=True,
                     help="what the registration is for: harness_lab. There is no default.")
    reg.add_argument("--actor", required=True, help="who is doing this")
    reg.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    wd = sub.add_parser("withdraw", help="withdraw an engagement from the harness")
    wd.add_argument("--engagement", required=True)
    wd.add_argument("--actor", required=True, help="who is doing this")
    wd.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    return parser


def main(argv: list[str] | None = None, *, connect: Connect | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_dotenv()
    connect = connect if connect is not None else _connect
    if args.command == "list":
        return _list(connect)
    refused = _refuse_unless_valid(args)
    if refused is not None:
        return refused
    return _register(args, connect) if args.command == "register" else _withdraw(args, connect)


if __name__ == "__main__":
    raise SystemExit(main())
