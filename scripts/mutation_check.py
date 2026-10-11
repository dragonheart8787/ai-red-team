"""Mutation checks, run so that a mutation can only count if it was a real one (D63).

A mutation test answers "what would have to break for this to go red?". It is worth something only
if the thing it breaks is the thing under test. D62's first M2 mutation was ``SELECT DISTINCT ...
ORDER BY enrollment_id`` -- which Postgres rejects -- so 29 tests went red *because the query did
not run*, and the report said the withdrawal check had been shown to matter. It had not.

So this tool does not report "N red". For each mutation it:

1. runs the chosen tests **unmutated** and refuses to go on unless they are green;
2. applies the change, and requires that it **compiles and imports** (a Python edit) or **runs**
   (a SQL statement) before any test is run;
3. runs the tests and reads the result file: for every failure, its test name and the exception it
   died of;
4. sorts each failure into **target** (an assertion failed, or something that should have raised did
   not), **broken** (``SyntaxError``, ``ImportError``, ``NameError``, a SQL syntax or
   undefined-column/table/function error ... -- the mutation, not the code under test, is what
   failed), or **other** (listed for a person to read);
5. calls the mutation **valid** only if there are no *broken* failures, at least one *target*
   failure, and every test named in ``targets`` is among the target failures; and
6. restores the files byte for byte (and runs the SQL that undoes any database change), and checks.

``python scripts/mutation_check.py --list`` names them; ``python scripts/mutation_check.py M2 M13``
runs some; with no names, all. The result is printed and written to ``--out`` as JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv" / "bin" / "python")

# A failure that is the mutation's own fault, not the tested code's.
BROKEN = re.compile(
    r"SyntaxError|IndentationError|ImportError|ModuleNotFoundError|NameError|UnboundLocalError"
    r"|ProgrammingError|psycopg\.errors\.(Syntax|Undefined|Ambiguous|InvalidColumn|InvalidName"
    r"|DatatypeMismatch|GroupingError|InvalidTextRepresentation)")
# What a failed expectation looks like in a pytest result file.
TARGET = re.compile(r"^(assert\b|AssertionError|Failed: DID NOT RAISE|Failed:)")


def classify(message: str, *, allowed_errors: tuple[str, ...] = ()) -> str:
    """``target``, ``broken`` or ``other`` for one failure message."""
    head = message.strip()
    if TARGET.match(head):
        return "target"
    if BROKEN.search(head):
        return "broken"
    if any(name in head for name in allowed_errors):
        return "target"
    return "other"


@dataclass
class Edit:
    path: str
    old: str
    new: str


@dataclass
class Mutation:
    id: str
    summary: str
    tests: tuple[str, ...]
    edits: tuple[Edit, ...] = ()
    sql_up: tuple[str, ...] = ()
    sql_down: tuple[str, ...] = ()
    #: Tests that must be among the target failures. Empty: any target failure will do.
    targets: tuple[str, ...] = ()
    #: Exception names that are the expected way the *tested* code refuses (e.g. a CHECK firing).
    allowed_errors: tuple[str, ...] = ()
    #: Superuser statements run after the tests, before ``sql_down`` (rows the mutation let in).
    cleanup_sql: tuple[str, ...] = ()
    #: A callable returning (sql_up, sql_down) for mutations built from the live definition.
    build_sql: Callable[[], tuple[tuple[str, ...], tuple[str, ...]]] | None = None


@dataclass
class Result:
    id: str
    summary: str
    verdict: str = "not run"
    seconds: float = 0.0
    tests: tuple[str, ...] = ()
    passed: int = 0
    failures: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {"target": 0, "broken": 0, "other": 0}
        for f in self.failures:
            out[f["kind"]] += 1
        return out


# ---------------------------------------------------------------------------------------------
# the database
# ---------------------------------------------------------------------------------------------

def _load_env() -> None:
    sys.path.insert(0, str(ROOT))
    from control_plane.config import load_dotenv
    load_dotenv()


def _owner_sql(*statements: str) -> None:
    from sqlalchemy import create_engine, text
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _owner_scalar(statement: str) -> str:
    from sqlalchemy import create_engine, text
    engine = create_engine(os.environ["MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.begin() as conn:
            return conn.execute(text(statement)).scalar_one()
    finally:
        engine.dispose()


def _superuser_sql(statement: str) -> None:
    done = subprocess.run(["su", "postgres", "-c", f"psql -d cyberorch -v ON_ERROR_STOP=1 -c "
                           f"\"{statement}\""], capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"cleanup failed: {done.stderr[-300:]}")


# ---------------------------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------------------------

def _pytest(tests: tuple[str, ...]) -> tuple[ET.Element, int]:
    with tempfile.TemporaryDirectory() as tmp:
        xml = Path(tmp) / "result.xml"
        done = subprocess.run(
            [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={xml}", *tests],
            cwd=ROOT, capture_output=True, text=True)
        if not xml.exists():
            raise RuntimeError(f"pytest produced no result file:\n{done.stdout[-800:]}"
                               f"\n{done.stderr[-800:]}")
        return ET.parse(xml).getroot(), done.returncode


def _failures(root: ET.Element, allowed: tuple[str, ...]) -> tuple[int, list[dict]]:
    passed, out = 0, []
    for case in root.iter("testcase"):
        bad = case.find("failure")
        if bad is None:
            bad = case.find("error")
        if bad is None:
            if case.find("skipped") is None:
                passed += 1
            continue
        message = (bad.get("message") or "").splitlines()[0] if bad.get("message") else ""
        out.append({"test": f"{case.get('classname')}::{case.get('name')}".replace("tests.", ""),
                    "kind": classify(message, allowed_errors=allowed),
                    "message": message[:220]})
    return passed, out


def _compiles(path: Path) -> str | None:
    """None if the edited Python file compiles and its module imports; else why not."""
    if path.suffix != ".py":
        return None
    done = subprocess.run([PY, "-m", "py_compile", str(path)], capture_output=True, text=True)
    if done.returncode != 0:
        return f"does not compile: {done.stderr.strip()[-200:]}"
    rel = path.relative_to(ROOT).with_suffix("")
    if rel.parts[0] in ("tests", "db", "scripts"):
        return None                        # imported by pytest / alembic, which would report it
    done = subprocess.run([PY, "-c", f"import {'.'.join(rel.parts)}"], cwd=ROOT,
                          capture_output=True, text=True)
    return None if done.returncode == 0 else f"does not import: {done.stderr.strip()[-200:]}"


def run(mutation: Mutation, baselines: dict[tuple[str, ...], str]) -> Result:
    result = Result(mutation.id, mutation.summary, tests=mutation.tests)
    started = time.time()

    if mutation.tests not in baselines:
        root, _ = _pytest(mutation.tests)
        _passed, bad = _failures(root, ())
        baselines[mutation.tests] = "green" if not bad else "red: " + ", ".join(
            b["test"] for b in bad[:5])
    if baselines[mutation.tests] != "green":
        result.verdict = "INVALID"
        result.problems.append(f"the tests are not green before the mutation: "
                               f"{baselines[mutation.tests]}")
        return result

    originals: dict[Path, bytes] = {}
    sql_down: tuple[str, ...] = mutation.sql_down
    applied_sql = False
    try:
        for edit in mutation.edits:
            path = ROOT / edit.path
            originals.setdefault(path, path.read_bytes())
            source = path.read_text()
            if source.count(edit.old) != 1:
                result.verdict = "INVALID"
                result.problems.append(f"{edit.path}: the text to change appears "
                                       f"{source.count(edit.old)} times, not once")
                return result
            path.write_text(source.replace(edit.old, edit.new))
        for path in originals:
            why = _compiles(path)
            if why:
                result.verdict = "INVALID"
                result.problems.append(f"{path.relative_to(ROOT)} {why}")
                return result

        sql_up = mutation.sql_up
        if mutation.build_sql is not None:
            sql_up, sql_down = mutation.build_sql()
        if sql_up:
            try:
                _owner_sql(*sql_up)
                applied_sql = True
            except Exception as exc:
                result.verdict = "INVALID"
                result.problems.append(f"the SQL of the mutation does not run: {exc}"[:300])
                return result

        root, _code = _pytest(mutation.tests)
        result.passed, result.failures = _failures(root, mutation.allowed_errors)
    finally:
        for path, data in originals.items():
            path.write_bytes(data)
        try:
            for statement in mutation.cleanup_sql:
                _superuser_sql(statement)
            if applied_sql:
                _owner_sql(*sql_down)
        except Exception as exc:
            result.problems.append(f"RESTORE FAILED: {exc}"[:300])
        for path, data in originals.items():
            if path.read_bytes() != data:
                result.problems.append(f"{path.relative_to(ROOT)} was not restored")

    counts = result.counts()
    red_targets = {f["test"].split("::")[-1] for f in result.failures if f["kind"] == "target"}
    missing = [t for t in mutation.targets if t not in red_targets]
    if counts["broken"]:
        result.problems.append(f"{counts['broken']} failure(s) are the mutation's own error")
    if not counts["target"]:
        result.problems.append("no test failed on an assertion")
    if missing:
        result.problems.append(f"expected to be red on an assertion, and was not: {missing}")
    result.verdict = "valid" if not result.problems else "INVALID"
    result.seconds = round(time.time() - started, 1)
    return result


def _print(result: Result) -> None:
    c = result.counts()
    print(f"\n## {result.id}: {result.verdict}  (target {c['target']}, broken {c['broken']}, "
          f"other {c['other']}; {result.passed} passed; {result.seconds}s)")
    print(f"   {result.summary}")
    for f in result.failures:
        print(f"   [{f['kind']}] {f['test']}\n        {f['message']}")
    for p in result.problems:
        print(f"   PROBLEM: {p}")


def main(catalogue: dict[str, Mutation]) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ids", nargs="*")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.list:
        for m in catalogue.values():
            print(f"{m.id:8s} {m.summary}")
        return
    _load_env()
    chosen = [catalogue[i] for i in (args.ids or catalogue)]
    baselines: dict[tuple[str, ...], str] = {}
    results = []
    for mutation in chosen:
        result = run(mutation, baselines)
        _print(result)
        results.append(result)
        if args.out:
            args.out.write_text(json.dumps([r.__dict__ for r in results], indent=1, default=str))
    bad = [r.id for r in results if r.verdict != "valid"]
    print(f"\n{len(results) - len(bad)} valid, {len(bad)} not: {bad}")
    sys.exit(1 if bad else 0)
