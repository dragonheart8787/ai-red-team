"""D69 H5a2: the shape of the new modules, read with :mod:`ast` (nothing is imported or run).

Four things are pinned here because a test of behaviour cannot see them:

* the new modules import only the standard library and ``harness`` -- never ``control_plane``,
  ``sqlalchemy`` or ``signal`` -- and name none of the control plane's functions the harness must
  not name (the existing m2 test of ``tests/test_harness_task_source.py`` holds the same line for
  the whole package; this one holds it for these modules on its own, and adds ``executed_state``);
* the policy reaches ``propose`` by one path only: read in ``_load_policy``, bound to the name
  ``policy`` in ``run_task``, and handed on in the fourth position of the one ``propose`` call;
* a task is completed only by ``_complete``, which asks ``is_valid_summary`` first;
* the loop never judges whether an action ran: the summary comes from ``build_summary``.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from harness import loop

ROOT = Path(__file__).resolve().parents[1]
NEW_MODULES = ("ports", "enrolment", "startup_check", "signals", "worker_step", "loop")
ALLOWED_ROOTS = {
    "__future__", "collections", "dataclasses", "threading", "typing", "harness", "agents",
}
FORBIDDEN_NAMES = (
    "claim_task", "complete_task", "propose_action", "create_task", "get_engagement",
    "executed_state",
)


def _tree(name: str) -> ast.Module:
    return ast.parse((ROOT / "harness" / f"{name}.py").read_text())


def _imports(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(("." * node.level) + (node.module or ""))
    return found


def _names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
    return names


class _Calls(ast.NodeVisitor):
    """Every call, with the name of the function it is in (``<module>`` outside any)."""

    def __init__(self) -> None:
        self.calls: list[tuple[ast.Call, str]] = []
        self._stack: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((node, self._stack[-1] if self._stack else "<module>"))
        self.generic_visit(node)


def _calls(tree: ast.Module) -> list[tuple[ast.Call, str]]:
    visitor = _Calls()
    visitor.visit(tree)
    return visitor.calls


def _method_calls(tree: ast.Module, method: str) -> list[tuple[ast.Call, str]]:
    return [(call, where) for call, where in _calls(tree)
            if isinstance(call.func, ast.Attribute) and call.func.attr == method]


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(found) == 1, name
    return found[0]


# -- the imports and the names ----------------------------------------------------------------


@pytest.mark.parametrize("module", NEW_MODULES)
def test_a_new_module_imports_only_the_standard_library_and_the_harness(module):
    roots = {name.split(".")[0] for name in _imports(_tree(module))}
    assert roots <= ALLOWED_ROOTS, sorted(roots - ALLOWED_ROOTS)
    for name in _imports(_tree(module)):
        assert not name.startswith(("control_plane", "sqlalchemy", "signal")), name


@pytest.mark.parametrize("module", NEW_MODULES)
def test_a_new_module_names_none_of_the_control_plane_functions_nor_the_judging_function(module):
    names = _names(_tree(module))
    for forbidden in FORBIDDEN_NAMES:
        assert forbidden not in names, f"harness/{module}.py names {forbidden}"


def test_the_test_stand_in_imports_nothing_of_the_control_plane_either():
    tree = ast.parse((ROOT / "tests" / "harness_fakes.py").read_text())
    for name in _imports(tree):
        assert not name.startswith(("control_plane", "sqlalchemy")), name


# -- the policy: one way in ---------------------------------------------------------------------


def test_policy_is_read_only_in_load_policy_and_the_proposal_gets_that_value():
    tree = _tree("loop")

    reads = _method_calls(tree, "load_policy")
    assert [where for _, where in reads] == ["_load_policy"]

    local = [(call, where) for call, where in _calls(tree)
             if isinstance(call.func, ast.Name) and call.func.id == "_load_policy"]
    assert [where for _, where in local] == ["run_task"]

    proposals = _method_calls(tree, "propose")
    assert [where for _, where in proposals] == ["run_task"]
    call = proposals[0][0]
    assert isinstance(call.args[3], ast.Name) and call.args[3].id == "policy"

    run_task = _function(tree, "run_task")
    bindings = [n for n in ast.walk(run_task)
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "policy" for t in n.targets)]
    assert len(bindings) == 1
    assert bindings[0].value is local[0][0]


# -- the summary: one guarded way out ---------------------------------------------------------


def test_a_task_is_completed_only_in_complete_which_asks_is_valid_summary_first():
    tree = _tree("loop")

    writes = _method_calls(tree, "complete")
    assert [where for _, where in writes] == ["_complete"]

    guards = [call for call, where in _calls(tree)
              if where == "_complete" and isinstance(call.func, ast.Name)
              and call.func.id == "is_valid_summary"]
    assert len(guards) == 1
    assert guards[0].lineno < writes[0][0].lineno


def test_the_summary_comes_from_build_summary_and_is_what_complete_is_given():
    tree = _tree("loop")

    builds = [(call, where) for call, where in _calls(tree)
              if isinstance(call.func, ast.Name) and call.func.id == "build_summary"]
    assert [where for _, where in builds] == ["run_task"]
    run_task = _function(tree, "run_task")
    assigned = [n for n in ast.walk(run_task) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "summary" for t in n.targets)]
    assert [a.value for a in assigned] == [builds[0][0]]
    completes = [call for call, where in _calls(tree)
                 if where == "run_task" and isinstance(call.func, ast.Name)
                 and call.func.id == "_complete"]
    assert len(completes) == 1
    assert isinstance(completes[0].args[3], ast.Name) and completes[0].args[3].id == "summary"


def test_the_loop_has_no_other_literal_summary_than_not_run_and_that_one_is_a_named_constant():
    tree = _tree("loop")
    strings = {n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for word in ("executed", "unknown_outcome", "not_executed", "dedup_hit", "not_run"):
        assert word not in strings, word


# -- the signature --------------------------------------------------------------------------------


def test_run_loop_takes_every_argument_and_only_once_has_a_default():
    parameters = inspect.signature(loop.run_loop).parameters
    assert list(parameters) == [
        "ports", "bounds", "counters", "refusals", "window_limit", "stop_event", "once",
        "stop_events"]                                          # plan item 151: the event check
    defaults = {name: p.default for name, p in parameters.items()
                if p.default is not inspect.Parameter.empty}
    assert defaults == {"once": False, "stop_events": None}     # None: no event is asked
    assert parameters["window_limit"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["stop_event"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["stop_events"].kind is inspect.Parameter.KEYWORD_ONLY


def test_the_loop_does_not_exit_the_process_and_does_not_log():
    names = _names(_tree("loop"))
    for forbidden in ("exit", "_exit", "print", "logging", "logger", "getLogger", "warn"):
        assert forbidden not in names, forbidden
