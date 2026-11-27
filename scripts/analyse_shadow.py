"""The analysis of the shadow's records, and the ledger of looks (D69 shadow runner plan 2g, g3; S6,
plan item 156).

    python scripts/analyse_shadow.py look [--reason TEXT]

One look reads every record of the registration in the registered records directory and hands
them to the registered reading, ``REGISTERED_READING`` (``"module:function"``, the owner's: this
script provides the mechanism only and refuses while it is empty). In this order it refuses:

a. **the registration and the integrity guard** of ``scripts/run_shadow.py`` (its constants, read
   from that file, and ``run_shadow.integrity``: a clean tree, untracked files included, a HEAD
   that contains the registered commit, the registered files as committed), and an empty or
   malformed ``REGISTERED_READING`` (``reading_unregistered``);
b. **the records directory and its history**, the runner's step 2a (``records_dir_ignored``,
   ``record_removed``, ``record_modified``);
c. **the records**: every ``*.jsonl`` of the directory but the ledger, by file name, whose header
   names the registered commit; one whose header cannot be read or names no commit is
   ``record_unreadable`` (the runner treats it as this registration's too); none is ``no_records``;
d. **the ledger**, ``looks.jsonl`` in the records directory (absent: no look yet): every line an
   object, its ``look`` numbered from 1 without a gap, its ``records`` a list of file and sha256
   (``ledger_corrupt``); and only ever appended to (``ledger_rewritten``): the committed ledger of
   HEAD is the start of the ledger on disk, and every commit since the registered one that changed
   it kept the ledger of each of its parents as its start. (With the clean tree of a, HEAD's
   ledger is the one on disk unless git is told to look away -- ``--assume-unchanged`` -- so the
   commits are what the check is about.)
e. **the reason**: a look after the first needs ``--reason`` (``reason_required``); the refusal
   says how many looks there were and when the first was;
f. **the reading**, called with the records as read-only values (``ShadowRecord``); an exception,
   or a result that is not one short line, is ``reading_failed`` and nothing is written.

Then the look is **appended to the ledger, before its result is printed** (the plan's goal: each
look written down before its result is known; a look whose line cannot be written shows nothing):
``{"look", "at", "records": [{"file", "sha256"}...], "verdict", "reason"}``. The result is printed,
and when the set of records or a sha256 differs from the previous look's, a ``NOTE`` lists each
record added, changed or missing. The tree is then not clean, as expected: the next look waits
until that line is committed (a).

Every refusal prints ``refused: <code>: <explanation>`` to standard error and ends with exit 10.
This script writes no database, reads no model text (a record holds none) and calls no network;
git is the only process it runs.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from harness.exit_codes import EXIT_OK  # noqa: E402
from scripts import run_shadow  # noqa: E402
from scripts.run_shadow import LEDGER_NAME, Problem, Registration  # noqa: E402

# -- the registration ------------------------------------------------------------------------------
# The reading, ``"module:function"``: written only by the commit that registers the shadow (plan
# section 10; item 156 (d)). Until then empty, and every look is refused.
REGISTERED_READING: str | None = None

#: The longest result a reading may return: a verdict, not a report.
VERDICT_MAX_CHARS = 200

# -- the closed list of this script's own refusal codes (the runner's are used as they are) --------
READING_UNREGISTERED = "reading_unregistered"
NO_RECORDS = "no_records"
RECORD_UNREADABLE = "record_unreadable"
LEDGER_CORRUPT = "ledger_corrupt"
LEDGER_REWRITTEN = "ledger_rewritten"
REASON_REQUIRED = "reason_required"
READING_FAILED = "reading_failed"
LEDGER_UNWRITABLE = "ledger_unwritable"
REASONS = (READING_UNREGISTERED, NO_RECORDS, RECORD_UNREADABLE, LEDGER_CORRUPT, LEDGER_REWRITTEN,
           REASON_REQUIRED, READING_FAILED, LEDGER_UNWRITABLE)


class Refused(Exception):
    def __init__(self, problems: list[Problem]) -> None:
        super().__init__(problems)
        self.problems = problems


@dataclass(frozen=True)
class ShadowRecord:
    """One record as the reading sees it: its file name, the sha256 of its bytes, and its lines,
    each a read-only mapping (lists are tuples)."""

    file: str
    sha256: str
    header: Mapping[str, object]
    lines: tuple[Mapping[str, object], ...]


def _frozen(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _frozen(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_frozen(item) for item in value)
    return value


# -- a. the registration and the reading -----------------------------------------------------------

def reading_problems(spec: str | None) -> list[Problem]:
    module, _, function = (spec or "").partition(":")
    if not spec:
        return [(READING_UNREGISTERED, "REGISTERED_READING empty: there is no reading to look "
                                       "with")]
    if not module or not function:
        return [(READING_UNREGISTERED, "REGISTERED_READING is not 'module:function'")]
    return []


def _reading(spec: str) -> Callable:
    module, _, function = spec.partition(":")
    return getattr(importlib.import_module(module), function)


# -- c. the records --------------------------------------------------------------------------------

def read_records(directory: Path, registered_commit: str) -> list[ShadowRecord]:
    records, problems = [], []
    for path in sorted(directory.glob("*.jsonl")):
        if path.name == LEDGER_NAME:
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append((RECORD_UNREADABLE, f"{path.name} cannot be read "
                                                f"({type(exc).__name__})"))
            continue
        lines = [run_shadow._line(raw) for raw in data.splitlines()]
        header = lines[0] if lines else None
        commit = header.get("registered_commit") if header is not None \
            and header.get("line") == "header" else None
        if not isinstance(commit, str):
            problems.append((RECORD_UNREADABLE, f"{path.name}: its header cannot be read or names "
                                                "no commit"))
            continue
        if commit != registered_commit:
            continue                                    # another registration's
        records.append(ShadowRecord(
            file=path.name, sha256=hashlib.sha256(data).hexdigest(), header=_frozen(header),
            lines=tuple(_frozen(line) if line is not None else None for line in lines)))
    if problems:
        raise Refused(problems)
    if not records:
        raise Refused([(NO_RECORDS, f"no record of the registered commit {registered_commit[:7]} "
                                    f"in {directory.name}")])
    return records


# -- d. the ledger ---------------------------------------------------------------------------------

def parse_ledger(data: bytes) -> list[dict]:
    """The ledger's entries; ``ledger_corrupt`` unless every line is an entry, numbered from 1."""
    if data and not data.endswith(b"\n"):
        raise Refused([(LEDGER_CORRUPT, f"{LEDGER_NAME}: its last line is not ended")])
    entries = []
    for number, raw in enumerate(data.splitlines(), start=1):
        entry = run_shadow._line(raw)
        records = entry.get("records") if entry is not None else None
        if entry is None or not isinstance(records, list) or not all(
                isinstance(r, dict) and isinstance(r.get("file"), str)
                and isinstance(r.get("sha256"), str) for r in records):
            raise Refused([(LEDGER_CORRUPT, f"{LEDGER_NAME}: line {number} is not a look")])
        if type(entry.get("look")) is not int or entry["look"] != number:
            raise Refused([(LEDGER_CORRUPT, f"{LEDGER_NAME}: line {number} is look "
                                            f"{entry.get('look')!r}, not {number}")])
        entries.append(entry)
    return entries


def _committed(git: Callable, repo: Path, revision: str, name: str) -> bytes | None:
    """The file ``name`` at ``revision``; None if it is not there."""
    done = git(repo, "show", f"{revision}:{name}")
    return done.stdout if done.returncode == 0 else None


def ledger_history_problems(*, repo: Path, ledger: str, registered_commit: str, current: bytes,
                            git: Callable) -> list[Problem]:
    """``ledger_rewritten`` unless the ledger was only ever appended to: HEAD's is the start of
    ``current``, and each commit since ``registered_commit`` that changed it kept the ledger of
    every one of its parents as its start."""
    try:
        head = _committed(git, repo, "HEAD", ledger)
        if head is not None and not current.startswith(head):
            return [(LEDGER_REWRITTEN, f"{LEDGER_NAME} on disk does not begin with the ledger "
                                       "committed in HEAD")]
        if head is None and current:
            return [(LEDGER_REWRITTEN, f"{LEDGER_NAME} is on disk and not in HEAD")]
        done = git(repo, "log", "--full-history", "--format=%H %P",
                   f"{registered_commit}..HEAD", "--", ledger)
        if done.returncode != 0:
            return [(run_shadow.GIT_UNAVAILABLE, f"git cannot read the history of {LEDGER_NAME}")]
        for line in done.stdout.decode().splitlines():
            commit, *parents = line.split()
            after = _committed(git, repo, commit, ledger) or b""
            for parent in parents:
                before = _committed(git, repo, parent, ledger) or b""
                if not after.startswith(before):
                    return [(LEDGER_REWRITTEN, f"{LEDGER_NAME} was rewritten, not appended to, in "
                                               f"commit {commit[:7]}")]
    except Exception as exc:  # noqa: BLE001 - not being able to ask is a refusal
        return [(run_shadow.GIT_UNAVAILABLE, f"git could not be run ({type(exc).__name__}): "
                                             f"the history of {LEDGER_NAME}")]
    return []


# -- g. what changed since the previous look -------------------------------------------------------

def changes(previous: dict | None, records: list[ShadowRecord]) -> list[str]:
    if previous is None:
        return []
    before = {r["file"]: r["sha256"] for r in previous["records"]}
    now = {r.file: r.sha256 for r in records}
    lines = [f"  added: {name} (sha256 {sha})" for name, sha in now.items() if name not in before]
    lines += [f"  changed: {name} (sha256 {before[name]} -> {sha})" for name, sha in now.items()
              if name in before and before[name] != sha]
    lines += [f"  missing: {name} (sha256 {sha})" for name, sha in before.items()
              if name not in now]
    if lines:
        lines.insert(0, f"NOTE: the records differ from look {previous['look']}'s:")
    return lines


# -- the look --------------------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def look(*, reason: str | None, registration: Registration, reading: str | None, repo: Path,
         records_root: Path, git: Callable, out: Callable[[str], None], now: Callable[[], str]
         ) -> int:
    reg = registration
    problems = run_shadow.registration_problems(reg, repo=repo, records_root=records_root) \
        + reading_problems(reading)                                                       # a
    if problems:
        raise Refused(problems)
    checked = run_shadow.integrity(repo=repo, registered_commit=reg.commit, files=reg.files,
                                   git=git)
    if checked.problems:
        raise Refused(checked.problems)
    rel = Path(reg.records_dir).as_posix()
    directory = records_root / rel
    names = tuple(p.name for p in sorted(directory.glob("*.jsonl")) if p.name != LEDGER_NAME)
    problems = run_shadow.records_dir_problems(repo=repo, records_dir=rel, names=names, git=git)
    problems += run_shadow.record_history_problems(repo, rel, reg.commit, git)            # b
    problems += run_shadow.records_dir_entry_problems(directory)        # plan item 159
    if problems:
        raise Refused(problems)
    records = read_records(directory, reg.commit)                                         # c
    ledger_path = directory / LEDGER_NAME                                                 # d
    current = ledger_path.read_bytes() if ledger_path.exists() else b""
    earlier = parse_ledger(current)
    problems = ledger_history_problems(repo=repo, ledger=f"{rel}/{LEDGER_NAME}",
                                       registered_commit=reg.commit, current=current, git=git)
    if problems:
        raise Refused(problems)
    reason = (reason or "").strip() or None
    if earlier and reason is None:                                                        # e
        raise Refused([(REASON_REQUIRED, f"these records were already looked at {len(earlier)} "
                                         f"time(s), first on {earlier[0].get('at')}; another "
                                         "look needs --reason \"...\", written down in the "
                                         "ledger with the others")])
    try:                                                                                  # f
        verdict = _reading(reading)(tuple(records))
    except Exception as exc:  # noqa: BLE001 - what a reading raised is not printed
        raise Refused([(READING_FAILED, f"the reading failed ({type(exc).__name__})")]) from None
    if not isinstance(verdict, str) or not verdict.strip() or len(verdict) > VERDICT_MAX_CHARS \
            or any(ch in verdict for ch in "\r\n"):
        raise Refused([(READING_FAILED, f"the reading's result is not one line of at most "
                                        f"{VERDICT_MAX_CHARS} characters")])
    number = len(earlier) + 1
    entry = {"look": number, "at": now(),
             "records": [{"file": r.file, "sha256": r.sha256} for r in records],
             "verdict": verdict, "reason": reason}
    try:                                                                                  # h
        with ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise Refused([(LEDGER_UNWRITABLE, f"{LEDGER_NAME} cannot be written "
                                           f"({type(exc).__name__}): nothing is shown")]) from None
    out(f"look {number} of {len(records)} record(s) of {reg.commit[:7]}"                 # g
        + (f" (reason: {reason})" if reason else ""))
    for line in changes(earlier[-1] if earlier else None, records):
        out(line)
    for record in records:
        out(f"  {record.file} sha256 {record.sha256}")
    out(f"verdict: {verdict}")
    out(f"written to {rel}/{LEDGER_NAME} as look {number}; commit it before the next look")
    return EXIT_OK


def main(argv: list[str] | None = None, *, registration: Registration | None = None,
         reading: str | None = None, repo: Path = REPO_ROOT, records_root: Path | None = None,
         git: Callable = run_shadow._git, out: Callable[[str], None] = print,
         now: Callable[[], str] = _now) -> int:
    """``registration`` and ``reading`` default to the registered constants; ``records_root``, what
    ``REGISTERED_RECORDS_DIR`` is relative to, to the repository."""
    parser = argparse.ArgumentParser(prog="analyse_shadow.py", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("look", help="one look at the registration's records")
    one.add_argument("--reason", default=None, help="why another look (required after the first)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return look(reason=args.reason,
                    registration=registration if registration is not None
                    else run_shadow.registered(),
                    reading=REGISTERED_READING if reading is None else reading, repo=repo,
                    records_root=repo if records_root is None else records_root, git=git,
                    out=out, now=now)
    except Refused as refused:
        return run_shadow.refuse(refused.problems)


if __name__ == "__main__":
    raise SystemExit(main())
