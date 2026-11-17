"""D69 H5c2: where the new modules stand -- read with :mod:`ast`, nothing is run.

``harness/lock.py``, ``harness/banner_facts.py``, ``harness/residue_listing.py`` and
``scripts/run_harness.py`` read the control plane and the database and write nothing of their own,
do not reach into the scheduler, and the script installs its handlers only through
``harness.signals.install`` (no call of ``signal.signal`` of its own).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NEW = ("harness/lock.py", "harness/banner_facts.py", "harness/residue_listing.py",
       "scripts/run_harness.py")
SQL_WRITE = re.compile(r"\b(INSERT|UPDATE|DELETE|TRUNCATE|CREATE|DROP|ALTER)\b", re.IGNORECASE)


def _tree(relative: str) -> ast.Module:
    return ast.parse((ROOT / relative).read_text())


def _strings(tree: ast.Module) -> list[str]:
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef))
                  and n.body and isinstance(n.body[0], ast.Expr)
                  and isinstance(n.body[0].value, ast.Constant)}
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docstrings]


@pytest.mark.parametrize("module", NEW)
def test_the_new_modules_hold_no_sql_write_and_do_not_reach_into_the_scheduler(module):
    tree = _tree(module)
    assert [s for s in _strings(tree) if SQL_WRITE.search(s)] == []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("control_plane.scheduler"), module
        elif isinstance(node, ast.Import):
            assert not any(a.name.startswith("control_plane.scheduler") for a in node.names)


def test_the_lock_text_is_only_advisory_lock_statements():
    sql = [" ".join(s.split()) for s in _strings(_tree("harness/lock.py"))
           if re.search(r"\bSELECT\b", s)]
    assert len(sql) == 2
    assert all("advisory" in statement for statement in sql), sql
    assert "SELECT pg_try_advisory_lock(:k)" in sql


def test_the_script_installs_its_handlers_through_install_and_calls_signal_signal_never():
    tree = _tree("scripts/run_harness.py")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    direct = [c for c in calls if isinstance(c.func, ast.Attribute) and c.func.attr == "signal"
              and isinstance(c.func.value, ast.Name) and c.func.value.id == "signal"]
    installs = [c for c in calls if isinstance(c.func, ast.Name) and c.func.id == "install"]
    assert direct == []
    assert len(installs) == 1


def test_the_loop_modules_of_h5a2_do_not_import_the_new_modules():
    for name in ("loop", "ports", "enrolment", "startup_check", "worker_step", "signals"):
        tree = _tree(f"harness/{name}.py")
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not imported & {"harness.lock", "harness.banner_facts", "harness.residue_listing",
                               "harness.loop_adapter", "scripts.run_harness"}, name
