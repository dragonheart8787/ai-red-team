"""Every ``ProposedAction`` built without a task is listed, with a class and a reason (D68 S1).

``propose_action`` is about to compare a proposal with the task it names (D68 P1), and to
escalate one that names none. Which of today's task-less callers must carry a task before that
switch is on, and which are expected to be escalated, is a classification (design note
``docs/D68_REVIEWER_SEMANTIC_VALIDATION_DESIGN.md`` section 12). This test keeps it true: a
``ProposedAction(...)`` that passes no ``task_id`` must be in :data:`TASK_LESS`, by file and
function, and an entry whose site now carries a task is stale.

The classes, and only these may be listed:

``K1``       asserts DENY. DENY outranks any approval reason, so nothing observable changes.
``K2``       uses HUMAN_APPROVAL as a fixture (to obtain an approvable proposal) or measures
             something that is reached either way. Stays HUMAN_APPROVAL, with one more reason --
             expected.
``NA``       builds a proposal only to hand it to a Reviewer; never reaches ``propose_action``.
             (None is listed today: the three reviewer-test helpers build theirs with
             ``ProposedAction(**fields)``, which the scan cannot read and takes as carrying one.)
``REBUILD``  rebuilds a proposal from its stored row for the approval re-derivation. D68 S3
             replaces the missing ``task_id`` with the stored signal.

A site that needs ALLOW, or asserts one named approval reason, is **not** a class: it carries a
task (``tests/task_support.py``). That is the point of the list -- the way to make a red result
here green is to give the proposal its task, and adding to the list needs a reviewer to accept
the class and the reason.

A construction counts as carrying a task when it passes ``task_id=`` itself, or when the
function around it calls ``attach_task`` / ``task_for`` or ``replace(..., task_id=...)``.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".venv", ".git", "node_modules", "cyber_orch.egg-info", "__pycache__", ".mypy_cache"}
CLASSES = {"K1", "K2", "NA", "REBUILD"}

#: (path, enclosing function) -> (class, how many task-less constructions, why)
TASK_LESS: dict[tuple[str, str], tuple[str, int, str]] = {
    # --- tests that assert DENY -------------------------------------------------------------
    ("tests/test_approvals.py", "test_only_a_human_approval_proposal_can_be_approved"):
        ("K1", 1, "a DENY proposal cannot be approved"),
    ("tests/test_audit_coverage.py", "test_reconstruct_decision_returns_an_ordered_grouped_chain"):
        ("K1", 1, "a DENY chain for an out-of-scope target"),
    ("tests/test_audit_coverage.py",
     "test_reconstruct_decision_exposes_the_reviewers_claim_beside_the_truth"):
        ("K1", 1, "a DENY beside a lying reviewer"),
    ("tests/test_policy_engine.py", "test_the_budget_deny_happens_before_a_capability_exists"):
        ("K1", 1, "a budget DENY; the broker must not be reached"),
    ("tests/test_web_console.py", "test_the_console_cannot_approve_what_opa_never_escalated"):
        ("K1", 1, "a DENY proposal cannot be approved through the console"),
    ("scripts/live_run/d13_worker.py", "kernel_control"):
        ("K1", 1, "recorded in D13: DENY target_out_of_scope for both labels"),
    ("scripts/live_run/d15_lookalike.py", "kernel_control"):
        ("K1", 1, "recorded in D15: the lure address is out of scope"),
    ("scripts/live_run/d17_supervisor.py", "close_everything"):
        ("K1", 1, "a real DENY into the decision ledger"),
    # --- HUMAN_APPROVAL used as a fixture, or something reached either way -----------------
    ("tests/test_approvals.py", "_escalated_proposal"):
        ("K2", 1, "an escalated proposal to approve"),
    ("tests/test_approvals.py", "_escalated_with_params"):
        ("K2", 1, "an escalated proposal to approve"),
    ("tests/test_approvals.py",
     "test_a_proposal_naming_no_parameters_still_records_what_was_granted"):
        ("K2", 1, "an escalated proposal to approve"),
    ("tests/test_approved_dispatch.py", "_proposal"):
        ("K2", 1, "an escalated proposal, approved, then dispatched (34 tests)"),
    ("tests/test_http_get.py", "test_opa_receives_false_for_both_side_effect_flags"):
        ("K2", 1, "measures the policy input, which is built whatever the decision"),
    ("tests/test_web_console.py", "_escalate"):
        ("K2", 1, "an escalated proposal to approve"),
    # --- the approval re-derivation ---------------------------------------------------------
    ("control_plane/api/approved_dispatch.py", "_rederive"):
        ("REBUILD", 1, "rebuilt from the stored row; D68 S3 replays the stored signal here"),
}


def _is_proposed_action(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "ProposedAction") or (
        isinstance(func, ast.Attribute) and func.attr == "ProposedAction")


def _carries_task(call: ast.Call) -> bool:
    # ``**kwargs`` cannot be read statically; it is taken as carrying one rather than guessed at.
    return any(k.arg == "task_id" or k.arg is None for k in call.keywords)


def _function_attaches_a_task(func: ast.AST) -> bool:
    """The function gives its proposal a task: by a helper (``attach_task`` / ``task_for``) or by
    ``replace(proposal, task_id=...)``. Any other call with a ``task_id=`` keyword
    (``complete_task(task_id=...)``) is about a task, not about this proposal."""
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", getattr(node.func, "attr", None))
        if name in ("attach_task", "task_for"):
            return True
        if name == "replace" and any(k.arg == "task_id" for k in node.keywords):
            return True
    return False


def _functions_by_size(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    found = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return sorted(found, key=lambda f: f.end_lineno - f.lineno)


def task_less_sites() -> dict[tuple[str, str], list[int]]:
    """(path, innermost enclosing function) -> line numbers of the constructions with no task."""
    found: dict[tuple[str, str], list[int]] = {}
    for path in sorted(REPO.rglob("*.py")):
        relative = path.relative_to(REPO)
        if SKIP_DIRS & set(relative.parts):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        functions = _functions_by_size(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _is_proposed_action(node)):
                continue
            if _carries_task(node):
                continue
            inside = next((f for f in functions if f.lineno <= node.lineno <= f.end_lineno), None)
            if inside is not None and _function_attaches_a_task(inside):
                continue
            enclosing = inside.name if inside is not None else "<module>"
            found.setdefault((relative.as_posix(), enclosing), []).append(node.lineno)
    return found


def test_every_proposal_built_without_a_task_is_listed_with_a_class():
    unlisted = {k: v for k, v in task_less_sites().items() if k not in TASK_LESS}
    assert not unlisted, (
        "a ProposedAction is built with no task_id and is not in TASK_LESS. Give it its task "
        "(tests/task_support.attach_task) -- that is the default; list it only if it is K1, K2, "
        "NA or REBUILD, with the reason. Sites: "
        + "; ".join(f"{p}::{fn} line {','.join(map(str, ls))}" for (p, fn), ls in unlisted.items()))


def test_no_listed_site_has_been_given_a_task_or_removed():
    sites = task_less_sites()
    stale = sorted(k for k in TASK_LESS if k not in sites)
    assert not stale, (
        "listed in TASK_LESS but no longer built without a task (or gone): remove the entry. "
        + "; ".join(f"{p}::{fn}" for p, fn in stale))


def test_the_count_of_each_listed_site_is_what_the_list_says():
    sites = task_less_sites()
    wrong = {k: (len(sites[k]), TASK_LESS[k][1]) for k in TASK_LESS
             if k in sites and len(sites[k]) != TASK_LESS[k][1]}
    assert not wrong, f"site -> (found, listed): {wrong}"


def test_only_the_four_classes_are_listed_and_each_has_a_reason():
    bad = {k: v for k, v in TASK_LESS.items() if v[0] not in CLASSES or not v[2].strip()}
    assert not bad, bad


def test_the_ratchet_sees_a_task_less_construction_and_a_helper_that_attaches():
    """The scan itself, on two snippets: it must flag the one and pass the other."""
    def sites(source: str) -> int:
        tree = ast.parse(source)
        count = 0
        functions = _functions_by_size(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_proposed_action(node) \
                    and not _carries_task(node):
                inside = next(f for f in functions if f.lineno <= node.lineno <= f.end_lineno)
                count += not _function_attaches_a_task(inside)
        return count

    bare = "def f():\n    p = ProposedAction(action='x')\n    return p\n"
    attached = "def f(e):\n    p = ProposedAction(action='x')\n    return attach_task(e, p)\n"
    keyword = "def f():\n    return ProposedAction(action='x', task_id='T')\n"
    unrelated = "def f():\n    p = ProposedAction(action='x')\n    complete_task(task_id='T')\n"
    assert (sites(bare), sites(attached), sites(keyword), sites(unrelated)) == (1, 0, 0, 1)


def test_the_helper_makes_the_task_the_product_would_have_made():
    """The helper creates a task whose identity equals the proposal's, so P1 will match it."""
    import uuid

    from sqlalchemy import text

    from agents.base_agent import ProposedAction
    from control_plane.api.function_api import _task_identity
    from control_plane.state.db import engagement_scope
    from tests import task_support
    from tests.helpers import make_engagement

    engagement_id = f"ENG-TASKSUP-{uuid.uuid4().hex[:8]}"
    make_engagement(engagement_id)
    proposal = ProposedAction(
        action="network.scan",
        target={"logical_identity": {"type": "ip", "value": "10.77.0.5"}, "ports": "80"},
        authorization={"source": "engagement_scope", "scope_object_id": "SCOPE-x"},
        discovery={"source": "explicit_scope"},
    )
    attached = task_support.attach_task(engagement_id, proposal)
    assert attached.task_id and attached.action == proposal.action
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT goal, action, identity_key, status FROM tasks WHERE task_id = :t"),
            {"t": attached.task_id}).mappings().one()
    assert row["identity_key"] == _task_identity(proposal.action, proposal.target)[1]
    assert row["status"] == "queued" and "10.77.0.5" in row["goal"]
