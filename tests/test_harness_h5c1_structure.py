"""D69 H5c1: what the real adapter may name and where it stands (read with :mod:`ast`).

``harness/loop_adapter.py`` is the one module of the harness that names ``claim_task``,
``complete_task`` and ``propose_action`` (``tests/test_harness_task_source.py`` m2 lets exactly this
file do it, and is shown below to let no other). Pinned here because a test of behaviour cannot see
it:

* only the adapter names the three functions, and it names all three; ``create_task`` stays in the
  task source;
* the adapter holds no SQL of its own, does not import the scheduler, ``scripts`` or ``sqlalchemy``;
* its policy comes from the one loader function (``load_effective_policy``) and from nothing it
  builds itself;
* ``candidates_from_registry`` has one caller in the product, ``LoopAdapter.take_snapshot``;
* every connection the adapter opens is the subject of a ``with``, so it is closed on every path.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = "harness/loop_adapter.py"
THE_THREE = ("claim_task", "complete_task", "propose_action")
SQL_VERB = re.compile(r"\b(INSERT|UPDATE|DELETE|SELECT)\b", re.IGNORECASE)


def _tree(relative: str) -> ast.Module:
    return ast.parse((ROOT / relative).read_text())


def _names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    return names


def _imports(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(("." * node.level) + (node.module or ""))
    return found


def _harness_modules() -> list[str]:
    return [p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "harness").rglob("*.py"))]


def test_only_the_adapter_names_claim_complete_and_propose_and_it_names_all_three():
    for name in THE_THREE:
        named_in = [m for m in _harness_modules() if name in _names(_tree(m))]
        assert named_in == [ADAPTER], (name, named_in)


def test_create_task_is_still_named_only_in_the_task_source():
    named = [m for m in _harness_modules() if "create_task" in _names(_tree(m))]
    assert named == ["harness/task_source.py"]


def test_the_adapter_holds_no_sql_and_imports_no_scheduler_scripts_or_sqlalchemy():
    tree = _tree(ADAPTER)
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef))
                  and n.body and isinstance(n.body[0], ast.Expr)
                  and isinstance(n.body[0].value, ast.Constant)}
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and id(n) not in docstrings]
    assert [s for s in strings if SQL_VERB.search(s)] == []
    for name in _imports(tree):
        root = name.split(".")[0]
        assert root not in ("sqlalchemy", "scripts"), name
        assert not name.startswith("control_plane.scheduler"), name
    assert "get_engine" not in _names(tree)


def test_the_policy_is_the_one_the_loader_function_returns_and_nothing_the_adapter_builds():
    names = _names(_tree(ADAPTER))
    assert "load_effective_policy" in names
    for built in ("merge_policy", "PolicyLayer", "load_effective_policy_with", "EffectivePolicy"):
        assert built not in names, built


def _callers_of(function: str) -> list[tuple[str, str]]:
    """(file, enclosing function) of every call of ``function`` in the product's code."""
    found = []
    for top in ("harness", "control_plane", "agents", "tool_gateway", "scripts"):
        for path in sorted((ROOT / top).rglob("*.py")):
            tree = ast.parse(path.read_text())
            for outer in ast.walk(tree):
                if not isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(outer):
                    if isinstance(node, ast.Call) and _called_name(node) == function:
                        found.append((path.relative_to(ROOT).as_posix(), outer.name))
    return sorted(set(found))


def _called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def test_candidates_from_registry_has_one_caller_and_it_is_take_snapshot():
    assert _callers_of("candidates_from_registry") == [(ADAPTER, "take_snapshot")]


def test_every_connection_the_adapter_opens_is_the_subject_of_a_with():
    tree = _tree(ADAPTER)
    subjects = {id(item.context_expr) for node in ast.walk(tree) if isinstance(node, ast.With)
                for item in node.items}
    opened = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call) and _called_name(n) == "engagement_scope"]
    assert len(opened) == 6                      # accepts_work, live_tasks, take_snapshot, claim,
    for call in opened:                          # load_policy, complete -- and none shared
        assert id(call) in subjects, f"line {call.lineno}: a connection that no `with` closes"


def test_the_one_scope_per_port_rule_each_port_opens_its_own():
    tree = _tree(ADAPTER)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "LoopAdapter")
    opened_in = {}
    for method in (n for n in cls.body if isinstance(n, ast.FunctionDef)):
        calls = [n for n in ast.walk(method)
                 if isinstance(n, ast.Call) and _called_name(n) == "engagement_scope"]
        opened_in[method.name] = len(calls)
    assert {k: v for k, v in opened_in.items() if v} == {
        "accepts_work": 1, "live_tasks": 1, "take_snapshot": 1, "claim": 1, "load_policy": 1,
        "complete": 1}
