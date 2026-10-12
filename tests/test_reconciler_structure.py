"""The plan half's structure, checked on the source (D64 §2.2a, step 6b).

The plan is worth having apart from the act half only while it stays a pure function of what was
read and what was configured. That holds only while the imports and the calls stay as they are, so
they are pinned here by reading the syntax tree -- not by grep, which a re-export or an alias walks
around:

* the pure modules (``model``, ``vocab``, ``plan``) import nothing that does I/O, tells the time,
  or reaches the database, Docker, the orchestrator, the audit trail, the vault or the policy
  engine;
* ``plan.py`` contains **no number of its own** -- every threshold arrives as an argument;
* ``observe.py`` calls no verb that changes a container, a network or a file, and its only SQL is
  the two reads;
* nothing in the package opens the engagement-scoped connection or the runtime engine: the reader
  role's scope is the only database door, and it is handed in, not imported;
* every configured threshold is used by the plan (or is named as used by something else).
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path

from control_plane.reconciler import config

REPO = Path(__file__).resolve().parents[1]
PKG = REPO / "control_plane" / "reconciler"

PURE = ("model", "vocab", "plan")
ALL = ("config", "model", "observe", "plan", "vocab")

FORBIDDEN_EVERYWHERE = (
    "control_plane.state", "control_plane.orchestrator", "control_plane.api", "control_plane.audit",
    "control_plane.capability", "control_plane.vault", "control_plane.tls",
    "control_plane.scheduler",
    "tool_gateway", "agents", "subprocess", "socket", "requests", "urllib", "http",
)
FORBIDDEN_IN_PURE = (
    "os", "sys", "io", "pathlib", "shutil", "tempfile", "time", "datetime", "random", "secrets",
    "uuid", "logging", "sqlalchemy", "docker", "psycopg", "control_plane.policy",
)
ALLOWED_PURE_IMPORTS = {
    "model": {"__future__", "dataclasses"},
    "vocab": {"__future__"},
    "plan": {"__future__", "re", "control_plane.reconciler.vocab",
             "control_plane.reconciler.config", "control_plane.reconciler.model"},
}
ALLOWED_CONFIG_IMPORTS = {"__future__", "collections.abc", "dataclasses", "docker.constants",
                          "control_plane.policy.ceiling"}
ALLOWED_OBSERVE_IMPORTS = {"__future__", "os", "stat", "collections.abc", "dataclasses",
                           "datetime", "typing", "sqlalchemy", "control_plane.reconciler.vocab",
                           "control_plane.reconciler.model"}


def _tree(name: str) -> ast.Module:
    return ast.parse((PKG / f"{name}.py").read_text())


def _modules(name: str) -> set[str]:
    """Every module a file imports from (``import a.b`` -> ``a.b``; ``from a import b`` -> ``a``)"""
    out: set[str] = set()
    for node in ast.walk(_tree(name)):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "control_plane.reconciler":       # `from <package> import <module>`
                out.update(f"{node.module}.{alias.name}" for alias in node.names)
            else:
                out.add(node.module or "")
    return out


def _starts(module: str, prefixes) -> bool:
    return any(module == p or module.startswith(p + ".") for p in prefixes)


def test_the_package_is_exactly_the_files_this_step_made():
    assert sorted(p.stem for p in PKG.glob("*.py")) == sorted(["__init__", *ALL])


def test_nothing_in_the_package_reaches_the_database_the_orchestrator_docker_or_the_audit_trail():
    for name in ALL:
        bad = [m for m in _modules(name) if _starts(m, FORBIDDEN_EVERYWHERE)]
        assert bad == [], (name, bad)


def test_the_pure_modules_import_nothing_that_does_io_or_tells_the_time():
    for name in PURE:
        modules = _modules(name)
        assert not [m for m in modules if _starts(m, FORBIDDEN_IN_PURE)], (name, modules)
        assert modules <= ALLOWED_PURE_IMPORTS[name], (name, modules - ALLOWED_PURE_IMPORTS[name])


def test_config_and_observe_import_only_what_they_are_listed_as_needing():
    assert _modules("config") <= ALLOWED_CONFIG_IMPORTS, _modules("config") - ALLOWED_CONFIG_IMPORTS
    assert _modules("observe") <= ALLOWED_OBSERVE_IMPORTS, \
        _modules("observe") - ALLOWED_OBSERVE_IMPORTS


def test_the_only_door_to_the_database_is_the_connection_that_is_handed_in():
    # no module names the reader scope or any engine: the caller opens it and passes it down
    for name in ALL:
        names = {a.attr if isinstance(a, ast.Attribute) else a.id
                 for a in ast.walk(_tree(name)) if isinstance(a, ast.Attribute | ast.Name)}
        assert not names & {"engagement_scope", "reconciler_reader_scope", "get_engine",
                            "get_reconciler_reader_engine", "create_engine", "audit_scope",
                            "record_audit", "propose_action", "dispatch_approved"}, name


# --- plan.py contains no number of its own ---------------------------------------------------

def test_plan_py_has_no_numeric_literal_but_zero_and_one():
    for name in ("plan", "vocab"):
        numbers = [n.value for n in ast.walk(_tree(name)) if isinstance(n, ast.Constant)
                   and isinstance(n.value, int | float) and not isinstance(n.value, bool)]
        assert set(numbers) <= {0, 1}, (name, sorted(set(numbers)))
    # the one conversion factor lives in model.py, named
    assert re.search(r"^US = 1_000_000$", (PKG / "model.py").read_text(), re.MULTILINE)


def test_plan_py_reads_no_clock_and_has_no_module_state():
    tree = _tree("plan")
    calls = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
             for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"open", "print", "input", "exec", "eval", "now", "time", "time_ns",
                        "monotonic", "utcnow", "today", "random", "getenv"}, calls
    for node in tree.body:                      # module level: only constants (UPPER_CASE) and defs
        if isinstance(node, ast.Assign):
            assert all(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets)
        assert not isinstance(node, ast.Global | ast.Nonlocal)
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Global | ast.Nonlocal)]


def test_the_plan_function_takes_what_was_read_and_what_was_configured_and_nothing_else():
    functions = {n.name: n for n in _tree("plan").body if isinstance(n, ast.FunctionDef)}
    assert [a.arg for a in functions["plan"].args.args] == ["obs", "th"]
    assert functions["plan"].args.kwonlyargs == [] and functions["plan"].args.defaults == []
    for fn in functions.values():
        assert fn.args.defaults == [] and fn.args.kw_defaults == [], fn.name   # no default value


# --- observe.py is read-only -----------------------------------------------------------------

CHANGING_VERBS = {
    "kill", "stop", "remove", "prune", "create", "run", "exec_run", "put_archive", "start",
    "restart", "pause", "unpause", "update", "rename", "connect", "disconnect", "commit",
    "unlink", "rmdir", "rmtree", "removedirs", "replace", "write", "write_text", "write_bytes",
    "chmod", "chown", "truncate", "mkdir", "symlink", "link", "utime", "commit_all", "begin",
}


def test_observe_calls_no_verb_that_changes_anything():
    for name in ("observe", "plan"):
        called = {n.func.attr for n in ast.walk(_tree(name))
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        assert not called & CHANGING_VERBS, (name, called & CHANGING_VERBS)


def test_observe_opens_nothing_for_writing_and_its_only_sql_is_the_two_reads():
    tree = _tree("observe")
    flags = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
             and n.attr.startswith("O_")]
    assert set(flags) == {"O_RDONLY", "O_DIRECTORY"}, flags
    statements = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                  and isinstance(n.value, str)
                  and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER)\b",
                                n.value)]
    reads = [s for s in statements if s.startswith("SELECT")]
    assert len(reads) == len(statements) == 2, statements
    for statement in reads:
        assert re.fullmatch(
            r"SELECT (\*|run_id, status) FROM reconciler_(stuck_proposals\(\)|run_states\("
            r"CAST\(:ids AS text\[\]\)\))", statement), statement
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(
        n.func, "id", "") in {"open", "exec", "eval"}]


# --- every configured number matters ---------------------------------------------------------

#: configured here, used by a later step: the sweep's period belongs to the service (6d)
USED_ELSEWHERE = {"network_sweep_period_s"}


def test_every_threshold_is_used_by_the_plan_or_named_as_used_elsewhere():
    plan_tree = _tree("plan")
    th_attrs = {n.attr for n in ast.walk(plan_tree) if isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name) and n.value.id == "th"}
    methods = {n.name: n for n in ast.walk(_tree("config")) if isinstance(n, ast.FunctionDef)}
    reached = set(th_attrs)
    for name in list(th_attrs):
        if name in methods:                       # a derived bound: what it reads from the config
            reached |= {a.attr for a in ast.walk(methods[name]) if isinstance(a, ast.Attribute)
                        and isinstance(a.value, ast.Name) and a.value.id == "self"}
            reached |= {m for m in methods if any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                and c.func.attr == m for c in ast.walk(methods[name]))}
    for _ in range(3):                            # a derived bound may call another
        for name in list(reached):
            if name in methods:
                reached |= {a.attr for a in ast.walk(methods[name]) if isinstance(a, ast.Attribute)
                            and isinstance(a.value, ast.Name) and a.value.id == "self"}
    fields = {f.name for f in dataclasses.fields(config.Thresholds)}
    unused = fields - reached - USED_ELSEWHERE
    assert unused == set(), f"configured and never used by the plan: {sorted(unused)}"
    assert USED_ELSEWHERE <= fields
