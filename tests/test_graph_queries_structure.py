"""Structural guarantees for the Security Graph's recursive queries (D42-6).

D42-2 measured two formulations of the same query and found a ~280x gap
between them at a small scale, growing to "times out on 7/10 samples" at a
larger one (docs/D42_2_CTE_BENCHMARK.md) — the difference between a
recursive CTE that dedups on ``(node, depth)`` via ``UNION`` and one that
tracks a per-path visited array and dedups nothing via ``UNION ALL``. Three
tests here turn "remember to write it the fast way" into something checked
rather than trusted, in the style of ``tests/test_capability_broker.py``'s
``_broker_code()`` (AST-strip real docstrings, then read the actual code)
and D41's mutation-tested rejection checks:

(a) no module besides ``control_plane/graph/queries.py`` may reference both
    ``WITH RECURSIVE`` and a ``security_graph_*`` table;
(b) every recursive block inside that module uses ``UNION``, never
    ``UNION ALL``;
(c) a behavioral guard against an adversarial hub-shaped fixture, which
    must complete inside a small time budget — and was manually confirmed,
    during this deliverable, to fail that budget when the module's SQL is
    temporarily reverted to the naive formulation (see the module-level
    note at the bottom of this file for the exact result).

``control_plane/provenance/graph.py``'s own ``why()`` also contains a
``WITH RECURSIVE`` — it predates this rule, walks a different, near-tree-
shaped graph (a bounded backward walk from one known node, §8.10), and
never mentions a ``security_graph_*`` table, so test (a) does not need to
special-case it: the combined filter (both substrings) already excludes it
on its own, rather than by a hand-maintained exception list.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path

from sqlalchemy import text

from control_plane.graph.queries import NodeRef, paths_within_hops, shortest_path
from control_plane.graph.store import GraphEdge, GraphNode, record_batch
from control_plane.state.db import engagement_scope
from scripts.bench.d42_bloodhound_cte_bench import ScaleConfig, generate_graph
from tests.helpers import make_tool_run

_REPO_ROOT = Path(__file__).resolve().parents[1]
_EXCLUDED_DIR_PARTS = {".venv", "__pycache__", ".git", "node_modules"}
_SECURITY_GRAPH_TABLES = ("security_graph_nodes", "security_graph_edges")
#: This file necessarily contains the literal strings it searches for (the
#: table names, "WITH RECURSIVE") in order to search for them -- excluded
#: from the scan it defines, the same way a checker never has to check
#: itself, only what it checks.
_THIS_FILE = Path(__file__).resolve()


def _repo_python_files() -> list[Path]:
    return [
        path for path in _REPO_ROOT.rglob("*.py")
        if not any(part in _EXCLUDED_DIR_PARTS for part in path.parts)
        and path.resolve() != _THIS_FILE
    ]


def _stripped_source(path: Path) -> str:
    """A file's source with real docstrings removed, comments already gone.

    Same technique as test_capability_broker.py's _broker_code(): only a
    bare string expression in the first position of a Module/Class/Function
    body is a docstring by Python's own definition, so this cannot mistake
    an assigned SQL string constant (control_plane/graph/queries.py's own
    _SHORTEST_PATH_QUERY = \"\"\"...\"\"\") for prose -- an assignment is
    never in docstring position.
    """
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return ast.unparse(tree)


def test_only_queries_module_defines_recursive_security_graph_queries():
    sanctioned = _REPO_ROOT / "control_plane" / "graph" / "queries.py"
    offenders = []
    for path in _repo_python_files():
        try:
            code = _stripped_source(path)
        except SyntaxError:  # pragma: no cover -- not a parseable Python file
            continue
        if "WITH RECURSIVE" in code and any(t in code for t in _SECURITY_GRAPH_TABLES):
            offenders.append(path)

    assert offenders == [sanctioned], (
        f"expected only {sanctioned} to define a recursive query over the "
        f"Security Graph tables; found: {offenders}"
    )


def _sql_string_constants(path: Path) -> list[str]:
    """Every string literal assigned to a module-level name -- never a
    docstring, whatever it happens to say in English. Distinguishing these
    two is exactly why this reads the AST instead of splitting on
    triple-quotes: a naive split cannot tell a module's own docstring
    (which may need to *describe*, in prose, the UNION ALL formulation it
    rejects) from the actual SQL text assigned to a query constant.
    """
    tree = ast.parse(path.read_text())
    constants = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                constants.append(node.value.value)
    return constants


def test_graph_queries_module_uses_union_not_union_all():
    path = _REPO_ROOT / "control_plane" / "graph" / "queries.py"
    recursive_blocks = [c for c in _sql_string_constants(path) if "WITH RECURSIVE" in c]
    assert recursive_blocks, "expected at least one WITH RECURSIVE SQL constant to check"
    for block in recursive_blocks:
        assert "UNION ALL" not in block, (
            "found UNION ALL in a Security Graph recursive query -- must be "
            "UNION (D42-2: the ALL/visited-array formulation is up to ~280x "
            "slower and times out at larger scale)"
        )


def _hub_fixture(engagement_id: str) -> tuple[str, NodeRef, NodeRef, NodeRef]:
    """A small but genuinely hub-shaped graph, loaded into the real tables.

    Reuses d42_bloodhound_cte_bench's own generator (not a second
    implementation of it) at a scale small enough to load quickly in a test
    suite, while keeping the same skewed IT-admin-group fanout that makes
    the naive formulation expensive. Returns (run_id, low_priv_user_ref,
    wide_fanout_ref, domain_admins_ref).
    """
    # Same size as D42-2's own "mid" scale (docs/D42_2_CTE_BENCHMARK.md) --
    # empirically confirmed during this test's own development that a
    # smaller fixture (600/120/60) did not reproduce the naive formulation's
    # blowup at all: the smaller graph lacked enough diamond/converging
    # structure for the per-path visited-array to multiply across, so the
    # mutation-verification pass below silently passed under the broken
    # formulation the first time this was tried. Recorded so a future
    # attempt to shrink this fixture "for speed" does not reintroduce that
    # same false confidence.
    cfg = ScaleConfig(
        name="structural-test-fixture", n_users=5000, n_computers=800,
        n_groups=400, n_da_members=8, n_dcs=3, n_it_groups=5,
    )
    g, da_idx, users, guaranteed_reachable = generate_graph(cfg, seed=7)

    def identity(idx: int) -> str:
        return f"{g.node_kind[idx]}-{idx}-{g.node_name[idx]}"

    nodes_by_idx = {
        i: GraphNode(identity_type="fqdn", identity_value=identity(i), kind=kind)
        for i, kind in enumerate(g.node_kind)
    }
    edges = [
        GraphEdge(src=nodes_by_idx[s], dst=nodes_by_idx[d], edge_type=et)
        for s, d, et in g.edges
    ]

    fanout: dict[int, int] = {}
    for s, _d, et in g.edges:
        if et == "AdminTo":
            fanout[s] = fanout.get(s, 0) + 1
    wide_fanout_idx = max(fanout, key=fanout.get)

    low_priv_idx = next(u for u in users if u not in guaranteed_reachable)

    with engagement_scope(engagement_id) as conn:
        run_id = make_tool_run(conn, engagement_id=engagement_id)
        record_batch(
            conn, engagement_id=engagement_id, run_id=run_id,
            nodes=list(nodes_by_idx.values()), edges=edges,
        )

    ref = lambda idx: NodeRef(  # noqa: E731
        identity_type="fqdn", identity_value=identity(idx),
    )
    return run_id, ref(low_priv_idx), ref(wide_fanout_idx), ref(da_idx)


def test_graph_queries_stay_fast_on_a_hub_shaped_fixture(engagement_id):
    """Regression guard for the exact cost D42-2 measured and rejected.

    Manually confirmed during D42-6's implementation that reverting
    control_plane/graph/queries.py's two recursive queries to the naive,
    per-path visited-array / UNION ALL formulation makes this test fail —
    see the note at the bottom of this file for the exact numbers observed.
    """
    _run_id, low_priv, wide_fanout, domain_admins = _hub_fixture(engagement_id)

    with engagement_scope(engagement_id) as conn:
        conn.execute(text("SET LOCAL statement_timeout = 5000"))

        start = time.perf_counter()
        shortest_path(conn, start=low_priv, target=domain_admins, max_depth=10)
        elapsed_shortest = time.perf_counter() - start

        start = time.perf_counter()
        reachable = paths_within_hops(conn, start=wide_fanout, max_depth=10)
        elapsed_paths = time.perf_counter() - start

    assert elapsed_shortest < 2.0, f"shortest_path took {elapsed_shortest:.2f}s on the hub fixture"
    assert elapsed_paths < 2.0, f"paths_within_hops took {elapsed_paths:.2f}s on the hub fixture"
    # The fixture is only useful as a regression guard if it is actually
    # hub-shaped -- a wide-fanout node reaching almost nothing would let a
    # broken (slow) formulation pass by accident.
    assert len(reachable) > 50, (
        f"hub fixture's wide-fanout node only reached {len(reachable)} nodes -- "
        "not hub-shaped enough to be a meaningful regression guard"
    )


# ---------------------------------------------------------------------------
# Mutation verification (manual, recorded here rather than automated)
# ---------------------------------------------------------------------------
#
# During D42-6's implementation, control_plane/graph/queries.py's two
# WITH RECURSIVE queries were temporarily rewritten to the naive formulation
# D42-2 rejected (UNION ALL, a per-path `visited` array, no dedup on
# (node_id, depth)) and this file's test suite was re-run against that
# mutation before being reverted. Both
# test_graph_queries_module_uses_union_not_union_all and
# test_graph_queries_stay_fast_on_a_hub_shaped_fixture failed under the
# mutation -- the first on the UNION ALL substring check directly, the
# second because the hub fixture's wide-fanout paths_within_hops query
# exceeded the 2s budget (2.03s observed, against the 5s statement_timeout
# ceiling this test also sets). The exact captured output is quoted in this
# deliverable's completion report rather than duplicated here, so this
# comment does not go stale independently of that record.
#
# This verification was re-run after a real, unrelated schema fix was found
# during the same implementation pass: security_graph_edges needed a second,
# single-column index on src_node_id (migration 0011) for the *correct*
# formulation itself to be fast -- see that migration's module docstring
# and the addenda in docs/D42_2_CTE_BENCHMARK.md and
# docs/D42_6_PATHS_WITHIN_HOPS_BENCHMARK.md for the full finding.
