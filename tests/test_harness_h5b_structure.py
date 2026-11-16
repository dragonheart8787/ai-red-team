"""D69 H5b: the loop cannot write the enrolment list -- read with :mod:`ast`, nothing is run (T7).

The list is written by a person, with ``scripts/manage_harness_enrolment.py``, and read by the loop
through ``harness/enrolment_db.py``. Three things keep those two apart, and each is pinned here
because a test of behaviour cannot see it:

* the loop and the other five modules of H5a2, and the reader, do not import ``scripts`` or the
  CLI, and hold no ``INSERT``, ``UPDATE`` or ``DELETE`` in any string they build (a docstring is
  prose and is not read as one);
* the only code in the product that writes ``harness_enrolment`` is the CLI;
* neither the CLI nor the reader reaches into the scheduler (its package, or its enrolment writer,
  which a test of the scheduler's own already restricts to its own CLI).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOOP_MODULES = ("loop", "ports", "enrolment", "startup_check", "worker_step", "signals")
READER = "harness/enrolment_db.py"
CLI = "scripts/manage_harness_enrolment.py"
SQL_VERB = re.compile(r"\b(INSERT|UPDATE|DELETE)\b")
WRITES_THE_TABLE = re.compile(r"\b(INSERT\s+INTO|UPDATE)\s+harness_enrolment\b")


def _tree(relative: str) -> ast.Module:
    return ast.parse((ROOT / relative).read_text())


def _imports(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(("." * node.level) + (node.module or ""))
    return found


def _docstring_nodes(tree: ast.Module) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                ids.add(id(body[0].value))
    return ids


def _strings(tree: ast.Module, *, docstrings: bool) -> list[str]:
    skip = set() if docstrings else _docstring_nodes(tree)
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip]


def _names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    return names


NO_WRITE = [f"harness/{name}.py" for name in LOOP_MODULES] + [READER]


@pytest.mark.parametrize("module", NO_WRITE)
def test_the_loop_modules_and_the_reader_do_not_import_the_scripts_or_the_cli(module):
    for name in _imports(_tree(module)):
        assert name.split(".")[0] != "scripts", f"{module} imports {name}"
    assert "manage_harness_enrolment" not in _names(_tree(module))


@pytest.mark.parametrize("module", NO_WRITE)
def test_the_loop_modules_and_the_reader_hold_no_insert_update_or_delete_in_a_string(module):
    offending = [s for s in _strings(_tree(module), docstrings=False) if SQL_VERB.search(s)]
    assert offending == [], f"{module}: {offending}"


def test_the_only_code_that_writes_the_table_is_the_cli():
    writers = []
    for top in ("harness", "control_plane", "agents", "tool_gateway", "scripts"):
        for path in sorted((ROOT / top).rglob("*.py")):
            tree = ast.parse(path.read_text())
            if any(WRITES_THE_TABLE.search(s) for s in _strings(tree, docstrings=True)):
                writers.append(path.relative_to(ROOT).as_posix())
    assert writers == [CLI]


def test_the_cli_has_the_two_writes_and_the_reader_has_none():
    cli_strings = " ".join(_strings(_tree(CLI), docstrings=False))
    assert "INSERT INTO harness_enrolment" in cli_strings
    assert "UPDATE harness_enrolment" in cli_strings
    assert not SQL_VERB.search(" ".join(_strings(_tree(READER), docstrings=False)))


@pytest.mark.parametrize("module", [CLI, READER])
def test_neither_the_cli_nor_the_reader_reaches_into_the_scheduler(module):
    tree = _tree(module)
    for name in _imports(tree):
        assert not name.startswith("control_plane.scheduler"), f"{module} imports {name}"
    assert "scheduler_admin_scope" not in _names(tree)
    assert "assert_scheduler_admin" not in _names(tree)


def test_the_reader_imports_only_what_a_read_needs():
    roots = {name for name in _imports(_tree(READER))}
    assert roots == {
        "__future__", "collections.abc", "contextlib", "sqlalchemy", "sqlalchemy.engine",
        "control_plane.state.db",
    }


def test_the_reader_satisfies_the_enrolment_reader_interface_of_the_loop():
    methods = {n.name for n in ast.walk(_tree(READER)) if isinstance(n, ast.FunctionDef)}
    assert "enrolled" in methods
