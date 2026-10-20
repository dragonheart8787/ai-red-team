"""Structure of the plan-fit wiring (D68 S3), checked on the source, not on a run.

The replay is only a replay if there is one way to build the policy input. These tests fail when a
new caller of ``evaluate_policy`` or ``build_policy_input`` is added that does not take part in it,
and when the test-only enforcement seam is read by anything that ships.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests.conftest import ENFORCE_ENV

REPO = Path(__file__).resolve().parent.parent
SHIPPED = ("control_plane", "agents", "tool_gateway", "scripts")


def _calls(name: str):
    """(path, enclosing function, call node) for every call of ``name`` in the shipped code."""
    out = []
    for top in SHIPPED:
        for path in sorted((REPO / top).rglob("*.py")):
            tree = ast.parse(path.read_text())
            functions = sorted(
                (n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
                key=lambda f: f.end_lineno - f.lineno)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called = getattr(node.func, "id", getattr(node.func, "attr", None))
                if called != name:
                    continue
                inside = next((f.name for f in functions
                               if f.lineno <= node.lineno <= f.end_lineno), "<module>")
                out.append((path.relative_to(REPO).as_posix(), inside, node))
    return out


def test_the_policy_input_is_built_in_exactly_one_place():
    callers = {(p, fn) for p, fn, _ in _calls("build_policy_input")}
    assert callers == {("control_plane/api/function_api.py", "evaluate_policy")}, (
        "a second place builds the policy input: it must take the stored plan_fit through the "
        "same path, or the re-derivation and the decision can disagree")


def test_both_callers_of_evaluate_policy_say_what_they_pass_and_take_it_from_one_function():
    callers = _calls("evaluate_policy")
    assert {(p, fn) for p, fn, _ in callers} == {
        ("control_plane/api/function_api.py", "_decide"),
        ("control_plane/api/approved_dispatch.py", "_rederive"),
    }, "a new caller of evaluate_policy: it must pass plan_fit as the other two do"
    for path, fn, node in callers:
        keywords = {k.arg: k.value for k in node.keywords}
        assert "plan_fit" in keywords, f"{path}::{fn} does not pass plan_fit"
        assert "policy_signal(" in ast.unparse(keywords["plan_fit"]), (
            f"{path}::{fn} builds its plan_fit some other way than relation.policy_signal")


def test_build_policy_input_forwards_what_it_is_given():
    (_, _, node), = _calls("build_policy_input")
    keywords = {k.arg: ast.unparse(k.value) for k in node.keywords}
    assert keywords.get("plan_fit") == "plan_fit"


def test_the_rederivation_never_reads_the_task_or_the_proposal_for_the_signal():
    """It replays what the decision stored. A read of ``tasks`` there, or a signal taken from the
    rebuilt proposal, is the defect this test exists to keep out."""
    source = (REPO / "control_plane/api/approved_dispatch.py").read_text()
    assert "assess_task_relation" not in source
    assert "FROM tasks" not in source and "from tasks" not in source
    assert ('plan_fit=plan_relation.policy_signal(hints["plan_fit"]) if "plan_fit" in hints'
            in source)


def test_nothing_that_ships_reads_the_test_enforcement_variable():
    for top in SHIPPED:
        for path in (REPO / top).rglob("*.py"):
            assert ENFORCE_ENV not in path.read_text(), path


def test_the_enforcement_seam_is_engaged_exactly_when_asked():
    """With the variable set the suite runs enforced; without it, it does not. Asserted both ways
    so that the CI step that sets it cannot silently run a suite that is not enforced."""
    import os

    from control_plane.api import function_api
    from control_plane.canonicalizer.authorization import AuthorizationResolution
    from control_plane.canonicalizer.metadata import MetadataResolution
    from control_plane.canonicalizer.target import normalize_target
    from control_plane.policy.merge import PolicyLayer, merge_policy

    names = ("baseline_global", "emergency_overlay", "customer", "engagement")
    policy_input = function_api.build_policy_input(
        target=normalize_target({"logical_identity": {"type": "ip", "value": "10.20.0.7"}}),
        action="network.scan",
        authorization=AuthorizationResolution(authorized=True, scope_object_id="S"),
        metadata=MetadataResolution(known=True, data_class=(), resource_class=(), authority="x"),
        policy=merge_policy(*(PolicyLayer(name=n) for n in names)), scope_objects=[],
        plan_fit=None)
    assert policy_input["policy"]["task_relation_enforce"] is (os.environ.get(ENFORCE_ENV) == "1")
