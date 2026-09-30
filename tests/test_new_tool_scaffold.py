"""The new-tool scaffold does not decide anything for anyone (D53).

The scaffold (``scripts/new_tool_scaffold.py``) exists to save typing the parts
that were identical across six integrations. Its one dangerous failure mode is
the opposite of a bug: looking finished. A generated adapter that defaulted
``WRITES_DATA = False`` would state, on the author's behalf, that a tool does
nothing to its target; a generated test that skipped would let CI go green over
an unwritten injection test. So this file checks the negative space: what an
**untouched** scaffold refuses to do.

Nothing here judges whether a *particular tool's* decisions are right. That is
what ``docs/ADR_*.md`` is for and no test can stand in for it.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import adapter_kit

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "new_tool_scaffold", REPO / "scripts" / "new_tool_scaffold.py"
)
scaffold = importlib.util.module_from_spec(_spec)
sys.modules["new_tool_scaffold"] = scaffold
_spec.loader.exec_module(scaffold)

NAME, ACTION = "sampletool", "secrets.scan"


@pytest.fixture()
def generated(tmp_path):
    out = tmp_path / "out"
    scaffold.generate(NAME, ACTION, out)
    return out


def _load(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# What it writes, and what it refuses to write
# ---------------------------------------------------------------------------

def test_it_writes_the_expected_files_and_nothing_into_the_repository(generated):
    expected = {
        "tool_gateway/adapters/sampletool.py",
        "tests/test_sampletool_adapter.py",
        "tool_gateway/images/sampletool.Dockerfile",
        "tool_gateway/images/build_sampletool_image.sh",
        "REGISTRATION_sampletool.md",
        "docs/ADR_SAMPLETOOL.md",
    }
    written = {str(p.relative_to(generated)) for p in generated.rglob("*") if p.is_file()}
    assert written == expected
    assert not (REPO / "tool_gateway" / "adapters" / "sampletool.py").exists()
    assert os.access(generated / "tool_gateway/images/build_sampletool_image.sh", os.X_OK)


def test_it_never_overwrites(generated):
    with pytest.raises(scaffold.ScaffoldError, match="never overwrites"):
        scaffold.generate(NAME, ACTION, generated)


@pytest.mark.parametrize("name,action,message", [
    ("semgrep", "secrets.scan", "already exists"),        # an existing adapter file
    ("sampletool", "code.scan", "already served"),           # an existing action
    ("Bad-Name", "secrets.scan", "invalid --name"),
    ("sampletool", "noverb", "invalid --action"),
])
def test_it_refuses_collisions_and_malformed_requests(tmp_path, name, action, message):
    with pytest.raises(scaffold.ScaffoldError, match=message):
        scaffold.generate(name, action, tmp_path / "o")
    assert not (tmp_path / "o").exists(), "a refused request must write nothing"


def test_it_refuses_to_write_into_the_repository_root():
    with pytest.raises(scaffold.ScaffoldError, match="repository root"):
        scaffold.generate(NAME, ACTION, REPO)


# ---------------------------------------------------------------------------
# It decides nothing
# ---------------------------------------------------------------------------

DECISIONS = (
    "WRITES_DATA", "CHANGES_STATE", "REQUIRES_PROXY", "NEEDS_DISPATCH", "SAMPLETOOL_VERSION",
)


def _assigned(tree: ast.Module, name: str):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return node.value
    raise AssertionError(f"{name} is not assigned in the generated adapter")


@pytest.mark.parametrize("decision", DECISIONS)
def test_every_judgement_is_emitted_undecided(generated, decision):
    tree = ast.parse((generated / "tool_gateway/adapters/sampletool.py").read_text())
    value = _assigned(tree, decision)
    assert isinstance(value, ast.Name) and value.id == "NotImplemented", (
        f"{decision} must be emitted as NotImplemented; a default would be the scaffold "
        "answering a question about the tool"
    )


def test_the_generated_view_shows_a_model_none_of_the_tools_output(generated):
    module = _load(generated / "tool_gateway/adapters/sampletool.py", "sampletool_view_probe")
    view = module.derive_view("secret=hunter2", "boom")
    assert view["untrusted_content"] is True
    assert "hunter2" not in repr(view) and "boom" not in repr(view)
    assert view["stdout_bytes"] == len("secret=hunter2")


def test_the_generated_command_and_version_are_not_invented(generated):
    module = _load(generated / "tool_gateway/adapters/sampletool.py", "sampletool_cmd_probe")
    with pytest.raises(NotImplementedError, match="DECIDE\\(command\\)"):
        module.build_plan(constraints={}, budget={}, target="x")
    with pytest.raises(NotImplementedError, match="DECIDE\\(version\\)"):
        module.tool_version()


def test_the_untouched_adapter_fails_the_contract_on_every_decision(generated):
    module = _load(generated / "tool_gateway/adapters/sampletool.py", "sampletool_untouched")
    problems = "\n".join(adapter_kit.adapter_violations(module, action=ACTION))
    for decision in ("WRITES_DATA", "CHANGES_STATE", "REQUIRES_PROXY", "NEEDS_DISPATCH"):
        assert decision in problems, f"{decision} passed the contract while undecided"
    assert "tool_version() raised NotImplementedError" in problems


def test_the_dockerfile_and_build_script_refuse_to_build_until_chosen(generated):
    dockerfile = (generated / "tool_gateway/images/sampletool.Dockerfile").read_text()
    assert "exit 1" in dockerfile and "ENTRYPOINT [\"/DECIDE/path/to/sampletool\"]" in dockerfile
    assert not re.search(r"^ARG SAMPLETOOL_VERSION=\S", dockerfile, re.M), (
        "the pin must have no default"
    )
    script = (generated / "tool_gateway/images/build_sampletool_image.sh").read_text()
    assert 'SAMPLETOOL_VERSION="${SAMPLETOOL_VERSION:-}"' in script
    assert "DECIDE(version)" in script and "DECIDE(selfcheck)" in script
    # The self-check must run exactly as the sandbox does, or it proves nothing (D31, D36).
    for flag in ("--network none", "--cap-drop ALL", "no-new-privileges:true", "--read-only"):
        assert flag in script


def test_the_generated_build_script_is_valid_shell_and_refuses_to_run_undecided(generated):
    script = generated / "tool_gateway/images/build_sampletool_image.sh"
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0

    # No docker needed: the refusal comes before the first docker call.
    ran = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True,
        env={"PATH": os.environ["PATH"]},
    )
    assert ran.returncode == 1
    assert "DECIDE(version)" in ran.stderr

    versioned = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True,
        env={"PATH": os.environ["PATH"], "SAMPLETOOL_VERSION": "8.18.4"},
    )
    assert versioned.returncode == 1
    assert "DECIDE(selfcheck)" in versioned.stderr, (
        "the self-check must also be chosen, not defaulted"
    )


# ---------------------------------------------------------------------------
# It goes red, never skipped, and green only through decisions
# ---------------------------------------------------------------------------

def _run_generated_tests(out: Path, extra: str = "") -> subprocess.CompletedProcess:
    """Run the generated tests as if the files had been copied into the repository."""
    (out / "tests" / "conftest.py").write_text(textwrap.dedent(f'''
        import importlib.util, sys
        import tool_gateway.adapters as pkg

        spec = importlib.util.spec_from_file_location(
            "tool_gateway.adapters.sampletool", r"{out}/tool_gateway/adapters/sampletool.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["tool_gateway.adapters.sampletool"] = module
        spec.loader.exec_module(module)
        pkg.sampletool = module
        {extra}
    '''))
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(out / "tests" / "test_sampletool_adapter.py"),
         "-q", "-p", "no:cacheprovider", "-rA", "--no-header",
         "-k", "not authorized", "--rootdir", str(out)],
        cwd=REPO, capture_output=True, text=True,
    )


def test_an_untouched_scaffold_is_red_and_never_skipped(generated):
    result = _run_generated_tests(generated)
    outcomes = re.findall(
        r"^(PASSED|FAILED|SKIPPED|XFAIL|XPASS|ERROR) \S+::(\w+)", result.stdout, re.M
    )
    assert outcomes, result.stdout[-2000:]
    by = {}
    for status, name in outcomes:
        by.setdefault(status, set()).add(name)

    assert result.returncode != 0
    assert not (by.keys() & {"SKIPPED", "XFAIL", "XPASS"}), (
        f"a scaffolded test skipped or xfailed -- CI rejects any skip: {by}"
    )
    # The single green test is the mechanical safe default (an untrusted, JSON view).
    # Everything else is a decision or a wiring step nobody has done yet.
    only_green = {"test_derive_view_marks_the_output_untrusted_and_is_json"}
    assert by.get("PASSED", set()) <= only_green, by
    assert {
        "test_the_adapter_meets_the_local_contract",
        "test_the_adapter_is_wired_in_everywhere_a_new_tool_must_be",
        "test_every_input_is_accounted_for_in_the_fingerprint",
        "test_derive_view_shows_a_model_only_what_was_decided",
        "test_a_lure_in_the_tools_output_is_marked_introduced",
        "test_the_action_runs_end_to_end_through_propose_action",
        "test_the_dimensions_that_are_not_adapter_inputs_are_pinned",
    } <= by["FAILED"]


def test_filling_in_the_decisions_turns_the_local_contract_green_and_only_that(generated):
    """The path to green exists, and it goes through the person, not around them."""
    path = generated / "tool_gateway/adapters/sampletool.py"
    text = path.read_text()
    for decision, value in {
        "WRITES_DATA": "False", "CHANGES_STATE": "False", "REQUIRES_PROXY": "False",
        "NEEDS_DISPATCH": '"dispatch_scan"', "SAMPLETOOL_VERSION": '"8.18.4"',
    }.items():
        text, n = re.subn(
            rf"^{decision} = NotImplemented", f"{decision} = {value}", text, flags=re.M
        )
        assert n == 1, decision
    path.write_text(text)
    module = _load(path, "sampletool_decided")

    assert adapter_kit.adapter_violations(module, action=ACTION) == []
    assert module.tool_version() == "sampletool-8.18.4"

    # ...but it is not registered, and the wiring checks say so, one by one.
    wiring = "\n".join(adapter_kit.registration_violations(module, action=ACTION))
    assert "registry.ADAPTERS['secrets.scan'] is not this adapter" in wiring
    assert "EVIDENCE_PREFIX has no entry for TOOL 'sampletool'" in wiring
    assert "build_sampletool_image.sh" in wiring
    # ...and the analysis a person owes before registering: no document, no registration.
    assert "no docs/ADR_SAMPLETOOL.md" in wiring


# ---------------------------------------------------------------------------
# --check on a tool that is already in the repository
# ---------------------------------------------------------------------------

def test_check_is_clean_for_a_fully_wired_tool_and_names_a_missing_one():
    assert scaffold.check("semgrep") == []
    with pytest.raises(scaffold.ScaffoldError, match="not in the repository"):
        scaffold.check("nosuchtool")
