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

And the act half (step 6c), the other side of the same wall:

* the act modules import from ``control_plane.state.db`` exactly ``engagement_scope``, from the
  orchestrator exactly ``stages``, and nothing of the plan, the observation, the API, the audit
  trail, the vault, the tool gateway or the agents -- and never name ``propose_action``,
  ``dispatch_*`` or ``dispatch_approved`` (I7: it re-runs nothing);
* its SQL is exactly four statements of known shape (a conditional ``UPDATE`` of a proposal, the
  ``UPDATE`` of its in-flight runs, and one ``SELECT``): none deletes, inserts or names a table
  the reconciler has no business with;
* ``kill`` and ``remove`` are called only in ``act_docker``, ``unlink`` only in ``act_files``, and
  nothing in the package creates, runs, starts, stops or prunes anything;
* the deletion flag is ``False`` by default and no source file outside the tests sets it.
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
ALL = ("config", "model", "observe", "plan", "vocab")          # the plan half
ACT = ("act", "act_docker", "act_files", "outcome")            # the act half (step 6c)

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


def test_the_package_is_exactly_the_files_the_steps_made():
    assert sorted(p.stem for p in PKG.glob("*.py")) == sorted(["__init__", *ALL, *ACT])


def test_the_plan_half_reaches_neither_the_database_nor_the_orchestrator_nor_docker_nor_the_audit():
    for name in ALL:
        bad = [m for m in _modules(name) if _starts(m, FORBIDDEN_EVERYWHERE)]
        assert bad == [], (name, bad)
        assert not [m for m in _modules(name) if m.split(".")[-1] in ACT
                    and m.startswith("control_plane.reconciler")], name      # and not the act half


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

#: configured here, used by a later step: the sweep's period belongs to the service (6d), the
#: verification wait to the act half (6c)
USED_ELSEWHERE = {"network_sweep_period_s", "verify_wait_s"}


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


# =============================================================================================
# the act half
# =============================================================================================

FORBIDDEN_IN_ACT = (
    "control_plane.api", "control_plane.audit", "control_plane.capability", "control_plane.vault",
    "control_plane.tls", "control_plane.scheduler", "control_plane.policy",
    "control_plane.orchestrator.dispatch", "control_plane.orchestrator.engagement",
    "tool_gateway", "agents", "subprocess", "socket", "requests",
    "control_plane.reconciler.plan", "control_plane.reconciler.observe",
)
FORBIDDEN_NAMES_IN_ACT = {"propose_action", "dispatch_approved", "reconcile_stale_dispatches",
                          "record_audit", "audit_scope", "get_engine", "create_engine",
                          "reconciler_reader_scope", "scheduler_reader_scope"}


def _imported(name: str) -> dict[str, set[str]]:
    """``from <module> import <names>`` -> {module: names}."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(_tree(name)):
        if isinstance(node, ast.ImportFrom) and node.module:
            out.setdefault(node.module, set()).update(a.name for a in node.names)
    return out


def test_the_act_half_imports_the_one_scope_and_the_stage_helpers_and_nothing_of_the_plan():
    for name in ACT:
        modules = _modules(name)
        bad = [m for m in modules if _starts(m, FORBIDDEN_IN_ACT)]
        assert bad == [], (name, bad)
    assert _imported("act")["control_plane.state.db"] == {"engagement_scope"}
    assert _imported("act")["control_plane.orchestrator"] == {"stages"}
    for name in ("act_docker", "act_files", "outcome"):
        assert not [m for m in _modules(name) if m.startswith("control_plane.state")], name
        assert not [m for m in _modules(name) if m.startswith("control_plane.orchestrator")], name


def test_the_act_half_never_names_what_would_run_something_again_or_open_another_door():
    for name in ACT:
        tree = _tree(name)
        names = {a.attr if isinstance(a, ast.Attribute) else a.id
                 for a in ast.walk(tree) if isinstance(a, ast.Attribute | ast.Name)}
        names |= {alias.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                  for alias in n.names}                       # `from x import dispatch_something`
        assert not names & FORBIDDEN_NAMES_IN_ACT, (name, names & FORBIDDEN_NAMES_IN_ACT)
        assert not [n for n in names if n.startswith("dispatch_")], (name, names)


STATEMENTS = {
    "CLOSE_SQL": re.compile(
        r"UPDATE action_proposals SET pipeline_stage = :new, stage_detail = :detail, "
        r"stage_updated_at = now\(\), updated_at = now\(\) WHERE proposal_id = :pid "
        r"AND pipeline_stage = :expected AND stage_updated_at = :planned "
        r"RETURNING proposal_id"),
    "MARK_UNKNOWN_SQL": re.compile(
        r"UPDATE action_proposals SET pipeline_stage = :new, stage_detail = :detail, "
        r"dispatch_state = 'unknown_outcome', stage_updated_at = now\(\), updated_at = now\(\) "
        r"WHERE proposal_id = :pid AND pipeline_stage = :expected "
        r"AND stage_updated_at = :planned RETURNING proposal_id"),
    "RUNS_SQL": re.compile(
        r"UPDATE tool_runs SET status = 'unknown_outcome' WHERE proposal_id = :pid "
        r"AND status IN \('dispatching', 'running'\)"),
    "RUNS_LEFT_SQL": re.compile(
        r"SELECT count\(\*\) FROM tool_runs WHERE proposal_id = :pid "
        r"AND status IN \('dispatching', 'running'\)"),
}
SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|GRANT)\b")
NOT_FOR_THE_RECONCILER = re.compile(
    r"\b(DELETE|INSERT|DROP|TRUNCATE|CREATE|ALTER|GRANT|capabilities|approvals|credential_material"
    r"|audit_log|scope_registry|engagements)\b")


def _sql_constants() -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for name in ACT:
        for node in ast.walk(_tree(name)):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str) and SQL_WORD.search(node.value.value)):
                found[node.targets[0].id] = (name, " ".join(node.value.value.split()))
    return found


def test_the_act_half_has_exactly_four_sql_statements_each_of_a_known_shape():
    found = _sql_constants()
    assert set(found) == set(STATEMENTS), set(found) ^ set(STATEMENTS)
    for constant, (_module, statement) in found.items():
        assert STATEMENTS[constant].fullmatch(statement), (constant, statement)
        assert not NOT_FOR_THE_RECONCILER.search(statement), (constant, statement)
    # and no other string in the act modules is SQL: nothing is built or hidden elsewhere
    for name in ACT:
        tree = _tree(name)
        docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                      if isinstance(n, ast.Module | ast.FunctionDef | ast.ClassDef) and n.body
                      and isinstance(n.body[0], ast.Expr)
                      and isinstance(n.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and id(node) not in docstrings \
                    and SQL_WORD.search(node.value) and len(node.value.split()) > 6:
                assert " ".join(node.value.split()) in {s for _, s in found.values()}, node.value


def _attribute_calls(name: str) -> set[str]:
    return {n.func.attr for n in ast.walk(_tree(name))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}


def test_kill_and_remove_are_called_in_act_docker_only_and_unlink_in_act_files_only():
    for verb in ("kill", "remove"):
        assert {n for n in ALL + ACT if verb in _attribute_calls(n)} == {"act_docker"}, verb
    assert {n for n in ALL + ACT if "unlink" in _attribute_calls(n)} == {"act_files"}


def test_nothing_in_the_package_creates_runs_starts_stops_or_prunes():
    forbidden = {"create", "run", "exec_run", "prune", "put_archive", "start", "restart", "stop",
                 "pause", "unpause", "commit", "build", "pull", "push", "load", "update", "rename",
                 "connect", "disconnect", "exec_create", "exec_start", "rmtree", "removedirs",
                 "rmdir", "mkdir", "symlink", "link", "chmod", "chown", "truncate", "write",
                 "write_text", "write_bytes", "replace", "executemany"}
    for name in ALL + ACT:
        assert not _attribute_calls(name) & forbidden, (name, _attribute_calls(name) & forbidden)


def test_stages_abandon_is_called_in_act_py_alone():
    assert {n for n in ALL + ACT if "abandon" in _attribute_calls(n)} == {"act"}


# --- the deletion flag ---------------------------------------------------------------------------

def test_the_deletion_flag_is_off_by_default_and_nothing_in_the_product_turns_it_on():
    from control_plane.reconciler import act
    fields = {f.name: f for f in dataclasses.fields(act.Settings)}
    assert fields["allow_deletions"].default is False
    assert set(act.MODE_NAMES) == {"dry-run", "state-only"}
    assert not [k for k in config.KEYS if "DELET" in k or "ALLOW" in k]      # not configurable
    offenders = []
    for top in ("control_plane", "scripts", "agents", "tool_gateway"):
        for path in (REPO / top).rglob("*.py"):
            if path.name.startswith("mutations_"):
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.keyword) and node.arg == "allow_deletions" \
                        and not (isinstance(node.value, ast.Constant)
                                 and node.value.value is False):
                    offenders.append(f"{path.relative_to(REPO)}:{node.value.lineno}")
                if isinstance(node, ast.Assign | ast.AnnAssign) and any(
                        isinstance(t, ast.Name | ast.Attribute)
                        and getattr(t, "id", getattr(t, "attr", "")) == "allow_deletions"
                        for t in (node.targets if isinstance(node, ast.Assign) else [node.target])):
                    if isinstance(node, ast.Assign) or node.value is not None:
                        value = node.value
                        if not (isinstance(value, ast.Constant) and value.value is False):
                            offenders.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert offenders == [], f"something other than False reaches allow_deletions: {offenders}"
