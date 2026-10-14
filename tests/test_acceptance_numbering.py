"""The ACCEPTANCE document's numbers and statuses are one list that says one thing (pre-merge
audit).

The document is the record the code and the other documents point at ("ACCEPTANCE 5.92", "revised by
5.97"). Three ways it can stop being true without any test noticing, each checked here:

* **numbering** -- the rows of the numbered table (5.20 to the latest) are consecutive, each number
  once, in order (a row inserted in the wrong place, two rows with one number, a gap where a
  row was dropped);
* **status** -- every row from 5.58 on starts its status with one of the four words the document
  uses (Closed, Open, Designed, Stated);
* **references** -- every `ACCEPTANCE 5.N` in the repository's own files (code, tests, documents),
  and every `5.N` another row names with "Revised by", points at a row that exists.

(A row can still be wrong in what it says; this is only the part a program can know.)
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "ACCEPTANCE_MVP1_AGENTS.md"
STATUS_WORDS = ("Closed", "Open", "Designed", "Stated")
#: the numbered, status-bearing table that runs from D39's 5.20 to the latest completion
FIRST_NUMBER_OF_THE_TABLE = 20
ROW = re.compile(r"^\| \*\*(5\.(\d+))\*\* \| (.+?) \| (\*\*.*|.*)$")
#: every way the document lists an item: a table row, a bullet row of the old lists, a bold name
ANY_ITEM = re.compile(r"^\|\s*\*{0,2}(5\.\d+)\*{0,2}\s*\|", re.M)


def _rows() -> list[tuple[int, int, str]]:
    """``(line, number, status)`` of every row of the numbered table, in file order."""
    out = []
    for line_number, line in enumerate(DOC.read_text().splitlines(), 1):
        m = ROW.match(line)
        if m:
            status = re.sub(r"^\*\*", "", m.group(4))
            out.append((line_number, int(m.group(2)), status))
    return out


def _table() -> list[tuple[int, int, str]]:
    """The rows of the table the later stages append to: from 5.52 on, up to the first row that is
    out of order (the old "still open" list after it repeats and renumbers old items)."""
    rows = _rows()
    start = next(i for i, r in enumerate(rows) if r[1] == FIRST_NUMBER_OF_THE_TABLE)
    table = [rows[start]]
    for row in rows[start + 1:]:
        if row[1] < table[-1][1]:
            break
        table.append(row)
    return table


def test_the_rows_of_the_table_are_consecutive_each_number_once_and_in_order():
    numbers = [n for _, n, _ in _table()]
    assert numbers[0] == FIRST_NUMBER_OF_THE_TABLE
    assert numbers == list(range(numbers[0], numbers[0] + len(numbers))), (
        f"numbers are not consecutive: {numbers}")
    lines = [line for line, _, _ in _table()]
    assert lines == sorted(lines)


def test_the_table_reaches_the_latest_number_the_repository_points_at():
    highest_pointed_at = max(_pointers_in_files().keys(), default=0)
    assert _table()[-1][1] >= highest_pointed_at, (
        f"a file points at 5.{highest_pointed_at}, the table ends at 5.{_table()[-1][1]}")


#: the rows before this one say "Decided", "Recorded decision" and the like; later ones use four
STATUS_WORDS_FROM = 58


@pytest.mark.parametrize("line, number, status", [r for r in _table() if r[1] >= STATUS_WORDS_FROM],
                         ids=lambda v: f"5.{v}" if isinstance(v, int) and v > 5 else "")
def test_every_row_from_5_58_on_starts_its_status_with_one_of_the_documents_words(
        line, number, status):
    assert status.startswith(STATUS_WORDS), (
        f"5.{number} (line {line}) starts its status with {status[:40]!r}")


def _items() -> set[int]:
    return {int(n.split(".")[1]) for n in ANY_ITEM.findall(DOC.read_text())}


def _tracked(*patterns: str) -> list[str]:
    out = subprocess.run(["git", "ls-files", *patterns], cwd=REPO, capture_output=True, text=True,
                         check=True).stdout.split()
    # (the mutation catalogues quote the text they break, wrong pointers included)
    return [f for f in out if not f.startswith("tool_gateway/deadline/vendor/")
            and not f.startswith("scripts/mutations_") and f != "docs/ACCEPTANCE_MVP1_AGENTS.md"]


def _pointers_in_files() -> dict[int, set[str]]:
    found: dict[int, set[str]] = {}
    pattern = re.compile(r"ACCEPTANCE\s+§?\s*(5\.\d+(?:\s*(?:,|and|/)\s*5\.\d+)*)")
    for name in _tracked("*.py", "*.md", "*.yml", "*.sql", "*.rego"):
        path = REPO / name
        if not path.is_file():
            continue
        for m in pattern.finditer(path.read_text(errors="replace")):
            for n in re.findall(r"5\.(\d+)", m.group(1)):
                found.setdefault(int(n), set()).add(name)
    return found


#: pointers that name an item of an older list the document keeps in prose, not as a row
OLD_LIST_POINTERS = {1, 2, 4, 9}


def test_every_acceptance_pointer_in_the_repository_names_an_item_that_exists():
    items = _items() | {n for _, n, _ in _rows()} | OLD_LIST_POINTERS
    missing = {f"5.{n}": sorted(files)[:3] for n, files in _pointers_in_files().items()
               if n not in items}
    assert not missing, f"pointers to items the document does not have: {missing}"


def test_every_revised_by_names_a_row_that_exists_and_comes_after_the_row_it_revises():
    text = DOC.read_text()
    existing = {n for _, n, _ in _rows()}
    for line in text.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        own = int(m.group(2))
        for named in re.findall(r"[Rr]evised (?:by|at[^`(]*\() ?(?:`)?5\.(\d+)", line):
            assert int(named) in existing, f"5.{own} says revised by 5.{named}, which is not a row"
            assert int(named) > own, (
                f"5.{own} says revised by 5.{named}, which does not come after it")
