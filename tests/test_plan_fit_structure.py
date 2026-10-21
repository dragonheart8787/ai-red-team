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


def test_only_the_tests_about_the_switch_itself_opt_out_of_the_enforced_run():
    """``switch_as_published`` lets a test see the switch as its own policy sets it. These are the
    modules that may use it: the ones that test the switch. Any other module that wants out of the
    enforced run adds itself here, in a diff a reviewer reads."""
    users = {p.relative_to(REPO).as_posix() for p in (REPO / "tests").rglob("*.py")
             if "switch_as_published" in p.read_text()}
    assert users == {
        "tests/conftest.py",                    # the definition
        "tests/test_plan_fit_structure.py",     # this test
        "tests/test_plan_fit_relation.py",      # the shadow: with the switch off, nothing changes
        "tests/test_plan_fit_replay.py",        # approved with it off, dispatched with it on
        "tests/test_plan_fit_goal_fit.py",      # the validator's wiring: switch off / on
        "tests/test_plan_fit_shadow.py",        # counts decisions made with the switches off
    }, users


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


def test_the_validator_is_called_from_one_place_and_inside_except_exception():
    """D68 S5, a hard requirement: the control plane calls a plan-fit validator in exactly one
    place (``_ask``), ``_ask`` is called in exactly one place (``assess_goal_fit``), and that call
    sits inside a ``try`` whose handler catches ``Exception`` -- so an unexpected exception from a
    validator can never leave ``propose_action`` as an exception."""
    calls = [(p, fn) for p, fn, node in _calls("assess")
             if p.startswith("control_plane/") and "query" in {k.arg for k in node.keywords}]
    assert calls == [("control_plane/plan_fit/goal_fit.py", "_ask")], calls

    tree = ast.parse((REPO / "control_plane/plan_fit/goal_fit.py").read_text())
    asks = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and getattr(n.func, "id", None) == "_ask"]
    assert len(asks) == 1, "``_ask`` is called from more than one place"
    (call,) = asks
    enclosing = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                 and any(call is inner for inner in ast.walk(f))]
    assert "assess_goal_fit" in {f.name for f in enclosing}
    guarded = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
                call is inner for stmt in node.body for inner in ast.walk(stmt)):
            names = {getattr(h.type, "id", None) for h in node.handlers}
            guarded |= "Exception" in names
            # and not by a handler that would also swallow a stop request
            assert None not in names and "BaseException" not in names
    assert guarded, "the validator is called outside a try/except Exception"
    # nothing else in the control plane reaches the validator's methods
    for attr in ("provenance", "calls"):
        users = [(p, fn) for p, fn, _ in _calls(attr) if p.startswith("control_plane/")]
        assert all(p == "control_plane/plan_fit/goal_fit.py" for p, _ in users), (attr, users)


def test_the_rederivation_never_calls_a_validator():
    """A replayed ``goal_fit`` must not cost a model call, and cannot change: the stored value is
    the decision's. The re-derivation does not import the goal-fit module, the validators, or
    the types a validator is called with."""
    source = (REPO / "control_plane/api/approved_dispatch.py").read_text()
    for name in ("goal_fit", "assess_goal_fit", "PlanFitQuery", "plan_fit_validator", ".assess("):
        # ``plan_fit=`` (the signal) is allowed; the module, the query and the validator are not
        assert name not in source.replace("plan_fit=", "").replace('"plan_fit"', ""), name
