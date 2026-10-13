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
SERVICE = ("service", "emit", "lock")                          # the process around them (step 6d)
EVERY = ALL + ACT + SERVICE

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
    assert sorted(p.stem for p in PKG.glob("*.py")) == sorted(["__init__", *EVERY])


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


def test_observe_opens_nothing_for_writing_and_its_only_sql_is_the_four_reads():
    tree = _tree("observe")
    flags = [n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
             and n.attr.startswith("O_")]
    assert set(flags) == {"O_RDONLY", "O_DIRECTORY"}, flags
    statements = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                  and isinstance(n.value, str)
                  and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER)\b",
                                n.value)]
    reads = [s for s in statements if s.startswith("SELECT")]
    assert len(reads) == len(statements) == 4, statements
    for statement in reads:
        assert re.fullmatch(
            r"SELECT (\*|run_id, status) FROM reconciler_(stuck_proposals\(\)"
            r"|stuck_proposals_after\(:after_us, :after_id\)"
            r"|network_conflicts\(:window_s\)"
            r"|run_states\(CAST\(:ids AS text\[\]\)\))", statement), statement
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(
        n.func, "id", "") in {"open", "exec", "eval"}]


# --- every configured number matters ---------------------------------------------------------

#: configured here, used by a later step: the sweep's period belongs to the service (6d), the
#: verification wait to the act half (6c), the failure summary's period and the retry-after-failure
#: wait to the service (6d, item 4)
USED_ELSEWHERE = {"network_sweep_period_s", "verify_wait_s", "summary_period_s",
                  "retry_after_failure_s", "max_pages", "max_actions_per_pass", "backoff_max_s",
                  "network_conflict_window_s"}


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
        assert {n for n in EVERY if verb in _attribute_calls(n)} == {"act_docker"}, verb
    assert {n for n in EVERY if "unlink" in _attribute_calls(n)} == {"act_files"}


def test_nothing_in_the_package_creates_runs_starts_stops_or_prunes():
    forbidden = {"create", "run", "exec_run", "prune", "put_archive", "start", "restart", "stop",
                 "pause", "unpause", "commit", "build", "pull", "push", "load", "update", "rename",
                 "connect", "disconnect", "exec_create", "exec_start", "rmtree", "removedirs",
                 "rmdir", "mkdir", "symlink", "link", "chmod", "chown", "truncate", "write",
                 "write_text", "write_bytes", "executemany"}
    for name in EVERY:
        if name == "lock":        # starts its own watchdog *thread*: nothing in Docker or on disk
            continue
        assert not _attribute_calls(name) & forbidden, (name, _attribute_calls(name) & forbidden)
    for name in EVERY:        # and nothing in `os` that changes the filesystem, but act_files
        os_calls = {n.func.attr for n in ast.walk(_tree(name)) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                    and n.func.value.id == "os"}
        assert not os_calls & {"replace", "rename", "remove", "rmdir", "removedirs", "mkdir",
                               "makedirs", "chmod", "chown", "symlink", "link", "truncate",
                               "utime"} - ({"unlink"} if name == "act_files" else set()), name


def test_stages_abandon_is_called_in_act_py_alone():
    assert {n for n in EVERY if "abandon" in _attribute_calls(n)} == {"act"}


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


# =============================================================================================
# the process around them
# =============================================================================================

def test_the_service_is_the_one_module_that_joins_the_halves():
    def importers(module: str, name: str | None = None) -> set[str]:
        out = set()
        for n in EVERY:
            for node in ast.walk(_tree(n)):
                if isinstance(node, ast.ImportFrom) and node.module == module and (
                        name is None or name in {a.name for a in node.names}):
                    out.add(n)
        return out

    assert importers("control_plane.reconciler", "act") == {"service"}
    assert importers("control_plane.reconciler", "observe") == {"service"}
    assert importers("control_plane.reconciler.plan") == {"service"}
    assert importers("control_plane.state.db", "reconciler_reader_scope") == {"service"}
    assert importers("control_plane.state.db", "engagement_scope") == {"act"}
    assert importers("control_plane.state.db", "open_reconciler_lock_connection") == {"lock"}
    assert importers("control_plane.audit.logger", "record_audit") == {"emit"}
    assert importers("control_plane.reconciler", "emit") == {"service"}
    assert importers("control_plane.reconciler.emit") <= {"service"}


def test_only_emit_writes_the_audit_trail_and_only_through_its_whitelist():
    for name in EVERY:
        calls = {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
                 for n in ast.walk(_tree(name)) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name | ast.Attribute)}
        if name != "emit":
            assert "record_audit" not in calls, name
    emit_calls = [n for n in ast.walk(_tree("emit")) if isinstance(n, ast.Call)
                  and getattr(n.func, "id", "") == "record_audit"]
    assert len(emit_calls) == 2                 # the global and the engagement-scoped write
    # and validation happens before either: `emit()` calls `validate` first
    emit_fn = next(n for n in _tree("emit").body if isinstance(n, ast.FunctionDef)
                   and n.name == "emit")
    first_call = next(c for c in ast.walk(emit_fn) if isinstance(c, ast.Call))
    assert getattr(first_call.func, "id", "") == "validate"


# =============================================================================================
# the order of change and record (D64 pre-deletion item 4, ACCEPTANCE 5.86)
# =============================================================================================

def _product_files():
    yield from (REPO / "control_plane").rglob("*.py")
    for top in ("tool_gateway", "agents", "scripts"):
        if (REPO / top).exists():
            yield from (REPO / top).rglob("*.py")


def _names_used(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    return names


def test_the_in_transaction_audit_writer_is_used_by_the_reconcilers_emit_alone():
    """It writes on the caller's connection, so it commits and rolls back with the caller. That is
    right for a record that says "this change committed" and wrong for a refusal that must survive
    a rollback; the other writer exists for that, and takes no connection."""
    users = {str(p.relative_to(REPO)) for p in _product_files()
             if "record_audit_in_transaction" in _names_used(p)}
    assert users == {"control_plane/reconciler/emit.py"}, users       # (logger.py only defines it)


def test_record_audit_still_takes_no_connection():
    import inspect

    from control_plane.audit.logger import record_audit, record_audit_in_transaction
    assert "conn" not in inspect.signature(record_audit).parameters
    assert list(inspect.signature(record_audit_in_transaction).parameters)[:1] == ["conn"]


def test_the_in_transaction_event_writer_is_called_by_the_service_alone():
    users = {n for n in EVERY if "emit_in_transaction" in _names_used(PKG / f"{n}.py")}
    assert users == {"service"}, users                    # (emit.py only defines it)


def _function(name: str, function: str) -> ast.FunctionDef:
    return next(n for n in ast.walk(_tree(name)) if isinstance(n, ast.FunctionDef)
                and n.name == function)


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if (isinstance(f, ast.Name) and f.id == name) or (
                    isinstance(f, ast.Attribute) and f.attr == name):
                out.append(n)
    return out


IRREVERSIBLE_CALLS = [
    ("act_docker", "_kill", "kill"), ("act_docker", "_remove_container", "remove"),
    ("act_docker", "_remove_network", "remove"), ("act_files", "_unlink", "unlink")]


def test_every_irreversible_call_comes_after_the_intent_in_the_same_function():
    for module, function, verb in IRREVERSIBLE_CALLS:
        node = _function(module, function)
        destructive = [c for c in _calls(node, verb)]
        intents = _calls(node, "declared")
        assert destructive and intents, (module, function)
        assert min(c.lineno for c in destructive) > max(c.lineno for c in intents), (
            f"{module}.{function}: the irreversible `{verb}` is not after `declared`")
        # and every way of declining before the call comes before the intent: an intent always
        # means "the call was about to be made"
        first_call = min(c.lineno for c in destructive)
        declines = [
            r for r in ast.walk(node) if isinstance(r, ast.Return)
            and isinstance(r.value, ast.Call) and getattr(r.value.func, "id", "") == "Result"
            and len(r.value.args) > 1
            and getattr(r.value.args[1], "id", "") in ("CHANGED", "GONE")
            and r.lineno < first_call]
        assert declines, (module, function)
        assert all(r.lineno < min(c.lineno for c in intents) for r in declines), (
            f"{module}.{function}: a decline comes after the intent was written")


def test_the_transitions_record_is_written_inside_its_transaction_block():
    """The record hook is called once, inside the very ``with engagement_scope`` block that makes
    the change -- not in a second block after it, which would be a second transaction."""
    node = _function("act", "_transition")
    blocks = [w for w in ast.walk(node) if isinstance(w, ast.With)
              and any(getattr(i.context_expr.func, "id", "") == "engagement_scope"
                      for i in w.items if isinstance(i.context_expr, ast.Call))
              and _calls(w, "_move")]
    assert len(blocks) == 1, "the change is made in one engagement_scope block"
    inside = _calls(blocks[0], "record")
    assert len(inside) == 1, "the record hook is called once, in the block that makes the change"
    assert min(c.lineno for c in _calls(blocks[0], "_move")) < inside[0].lineno
    assert len(_calls(node, "record")) == 1, "and nowhere else"


def test_the_service_hands_the_act_half_both_hooks():
    calls = [c for c in _calls(_tree("service"), "carry_out")]
    assert len(calls) == 1
    assert {k.arg for k in calls[0].keywords} >= {"record", "intend", "on_verified"}



def test_the_service_hands_observe_the_configured_page_count_and_the_act_half_the_configured_cap():
    observe_calls = _calls(_function("service", "_observe"), "observe")
    assert observe_calls
    given = {k.arg: ast.unparse(k.value) for k in observe_calls[0].keywords}
    assert given.get("max_pages") == "self.th.max_pages", given
    pass_once = _function("service", "pass_once")
    sliced = [n for n in ast.walk(pass_once) if isinstance(n, ast.Subscript)
              and "max_actions_per_pass" in ast.unparse(n)]
    assert sliced, "pass_once does not bound the actions it carries out by max_actions_per_pass"


# =============================================================================================
# the Docker verbs: an allow-list, not only a deny-list (D64-1; pre-deletion item 7)
# =============================================================================================
#
# The deny-list tests above name verbs that must not appear. That cannot notice a verb nobody
# thought of (``exec_run`` was on the list; ``export``, ``top`` or ``update`` might not be), and it
# is fooled by an alias. This one starts from the other end: every method called on anything that
# came from the Docker client -- directly or through any variable assigned from it -- must be on
# the list for its module. The list is what the reconciler may ask of Docker, in full.

DOCKER_ROOTS = {"client", "container", "network"}      # the names the Docker handles arrive by
OBSERVE_VERBS = {"containers.list", "networks.list", "reload", "attrs.get", "name.startswith"}
ACT_DOCKER_VERBS = {"containers.get", "containers.list", "networks.get", "reload", "kill", "remove",
                    "attrs.get", "name.startswith"}
ALLOWED_DOCKER_VERBS = {"observe": OBSERVE_VERBS, "act_docker": ACT_DOCKER_VERBS}


def _root_and_path(node: ast.AST) -> tuple[str | None, str]:
    path = []
    while isinstance(node, ast.Attribute):
        path.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):                   # f(x).y -- the root is whatever f(x) is
        inner_root, inner_path = _root_and_path(node.func)
        # the result of a producer (``client.containers.get(x)``) is a handle: ``.kill()`` on it is
        # a verb on the same root. The result of any other call (``attrs.get(...)``) is data.
        return (inner_root if inner_path in HANDLE_PRODUCERS else None), ".".join(reversed(path))
    return (node.id if isinstance(node, ast.Name) else None), ".".join(reversed(path))


#: the calls whose result is again a Docker handle (or a list of them); anything else a handle
#: gives back -- ``.attrs``, ``.labels``, ``.name``, ``.id`` -- is plain data
HANDLE_PRODUCERS = {"containers.get", "containers.list", "networks.get", "networks.list"}


def _is_handle_source(source: ast.AST, tainted: set[str]) -> bool:
    root, path = _root_and_path(source.func if isinstance(source, ast.Call) else source)
    if root not in tainted:
        return False
    if isinstance(source, ast.Call):
        return path in HANDLE_PRODUCERS            # a method that hands back a handle
    return not path                                 # an alias (``c = container``), not ``c.labels``


def docker_verbs_used(tree: ast.Module) -> set[str]:
    """Every ``root.path()`` call whose root is (or was assigned from) a Docker handle."""
    verbs: set[str] = set()
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.Lambda)):
        tainted = set(DOCKER_ROOTS) & ({a.arg for a in function.args.args} | DOCKER_ROOTS)
        body = ast.walk(function)
        changed = True
        while changed:                                # assignments and loops, to a fixed point
            changed = False
            for node in ast.walk(function):
                targets, source = [], None
                if isinstance(node, ast.Assign):
                    targets, source = node.targets, node.value
                elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
                    targets, source = [node.target], node.value
                elif isinstance(node, ast.For):
                    targets, source = [node.target], node.iter
                elif isinstance(node, ast.comprehension):
                    targets, source = [node.target], node.iter
                if source is None or not _is_handle_source(source, tainted):
                    continue
                for target in targets:
                    # a name, or a tuple of names; not ``seen[container.id] = container``, which
                    # makes a dict of handles and not a handle
                    plain = ([target] if isinstance(target, ast.Name) else
                             [e for e in getattr(target, "elts", []) if isinstance(e, ast.Name)])
                    for name in plain:
                        if name.id not in tainted:
                            tainted.add(name.id)
                            changed = True
        for node in body:
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                root, path = _root_and_path(node.func)
                if root in tainted and path:
                    verbs.add(path)
    return verbs


def test_every_method_called_on_a_docker_handle_is_on_the_modules_allow_list():
    for name in EVERY:
        used = docker_verbs_used(_tree(name))
        allowed = ALLOWED_DOCKER_VERBS.get(name, set())
        assert used <= allowed, (name, sorted(used - allowed))
    # the lists are not padded: each module uses all it is allowed
    assert docker_verbs_used(_tree("observe")) == OBSERVE_VERBS
    assert docker_verbs_used(_tree("act_docker")) == ACT_DOCKER_VERBS


def test_the_allow_list_walker_sees_an_aliased_and_an_unlisted_verb():
    """A positive control: the walker must flag what it exists to flag."""
    sample = ast.parse(
        "def f(client):\n"
        "    c = client.containers.get('x')\n"
        "    c.exec_run('rm -rf /')\n"
        "    for n in client.networks.list():\n"
        "        n.prune()\n"
        "    return [k.stop() for k in client.containers.list()]\n")
    assert docker_verbs_used(sample) == {"containers.get", "exec_run", "networks.list", "prune",
                                         "containers.list", "stop"}
