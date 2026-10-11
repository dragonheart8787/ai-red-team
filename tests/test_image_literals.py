"""Every Docker image a test names is one CI builds or pulls (D63 closeout 4).

It has happened twice: a test named an image that a workstation had and the CI runner did not
(``busybox:latest`` in the residue-check tests, CI run 150; the first time it was a web-target
image nobody had added to the workflow). Each time the suite was green locally and red in CI, and
the cause was found by reading the log. This reads the same thing before the push.

*The set CI has.* Read from ``.github/workflows/test.yml``, not written down a second time: every
``tool_gateway/images/build_*.sh`` step it runs, the tag that script builds
(``IMAGE="${IMAGE:-…}"``) and the base image it pulls (``BASE="${BASE:-…}"``), the job's service
images, and any ``docker pull`` in a step.

*What a test names.* Read from the syntax trees of everything under ``tests/``: the first argument
of ``containers.run`` / ``containers.create`` / ``images.get`` / ``images.pull``, any ``image=``
keyword, and any name that has ``image`` in it assigned a string -- when the string looks like an
image reference (it has a tag or a registry path). Prose and comments are not looked at.

Every such literal must be in the set CI has, or be listed below with the reason it is not (a stub
that never reaches Docker; an image a test needs to be *absent*). A listed literal must still be in
the tests (a stale entry fails), and an "absent" one must really not be in CI's set.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
IMAGES = ROOT / "tool_gateway" / "images"
TESTS = ROOT / "tests"

IMAGE_REFERENCE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*(:[A-Za-z0-9][A-Za-z0-9._-]*)$"
    r"|^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)+$")
BUILD_SCRIPT = re.compile(r"^\s*(?:\./)?tool_gateway/images/(build_[a-z0-9_]+\.sh)\b", re.M)
DEFAULTED = r'^{name}="\$\{{{name}:-([^}}]+)\}}"'

#: Literals that are not an image CI builds, and why. Both are checked for staleness.
NOT_BUILT = {
    "cyberorch-tool:test": "a stub sandbox's label (tests/test_web_post_body.py); it never "
                           "reaches Docker",
    "cyberorch/broken:local": "the IMAGE of a deliberately broken adapter class "
                              "(tests/test_adapter_contract.py); never run",
}
#: Images a test needs to be missing. These must not be in the set CI has.
MUST_BE_ABSENT = {
    "cyberorch/does-not-exist:none": "tests/test_dispatch.py: the missing-image path",
}


def _script_default(script: Path, name: str) -> str | None:
    found = re.search(DEFAULTED.format(name=name), script.read_text(), re.M)
    return found.group(1) if found else None


def images_ci_has() -> set[str]:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    job = workflow["jobs"]["test"]
    have: set[str] = set()
    for service in (job.get("services") or {}).values():
        have.add(service["image"])
    for step in job["steps"]:
        run = step.get("run") or ""
        for script_name in BUILD_SCRIPT.findall(run):
            script = IMAGES / script_name
            for variable in ("IMAGE", "BASE"):
                value = _script_default(script, variable)
                if value:
                    have.add(value)
        have.update(re.findall(r"docker pull\s+(\S+)", run))
    return have


def image_literals_in_tests() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}

    def note(node: ast.AST, path: Path) -> None:
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and IMAGE_REFERENCE.match(node.value)):
            found.setdefault(node.value, []).append(f"{path.relative_to(ROOT)}:{node.lineno}")

    for path in sorted(TESTS.rglob("*.py")):
        if path == Path(__file__).resolve():
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = ast.unparse(node.func.value)
                first_argument = (
                    (node.func.attr in ("run", "create") and owner.endswith("containers"))
                    or (node.func.attr in ("get", "pull", "remove") and owner.endswith("images")))
                if first_argument and node.args:
                    note(node.args[0], path)
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg and "image" in keyword.arg.lower():
                        note(keyword.value, path)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = (target.id if isinstance(target, ast.Name)
                            else target.attr if isinstance(target, ast.Attribute) else "")
                    if "image" in name.lower():
                        note(node.value, path)
    return found


def test_the_set_ci_has_is_read_from_the_workflow_and_is_not_empty():
    have = images_ci_has()
    assert {"cyberorch/nmap:local", "cyberorch/web-target:local", "cyberorch/semgrep:local",
            "python:3.12-slim", "postgres:16"} <= have, sorted(have)


def test_every_image_a_test_names_is_one_ci_builds_or_pulls():
    have = images_ci_has()
    unknown = {literal: where for literal, where in image_literals_in_tests().items()
               if literal not in have and literal not in NOT_BUILT
               and literal not in MUST_BE_ABSENT}
    assert not unknown, (
        "tests name Docker images that CI neither builds nor pulls (so they pass on a "
        f"workstation that has them and fail in CI): {unknown}. Add the build to "
        ".github/workflows/test.yml, use an image it has, or list the literal in this module "
        "with the reason.")


def test_the_exemptions_are_still_needed_and_the_absent_images_are_really_absent():
    literals = image_literals_in_tests()
    stale = [name for name in (*NOT_BUILT, *MUST_BE_ABSENT) if name not in literals]
    assert not stale, f"listed here but no longer named by any test: {stale}"
    have = images_ci_has()
    assert not [name for name in MUST_BE_ABSENT if name in have], (
        "an image a test needs to be missing is built or pulled by CI")
    assert not [name for name in NOT_BUILT if name in have], (
        "listed as not built, but CI builds it: remove it from NOT_BUILT")


def test_every_adapter_and_sandbox_image_is_one_ci_builds():
    """What the tests dispatch to: the registered adapters' images and the sandbox defaults."""
    from tool_gateway import sandbox
    from tool_gateway.registry import ADAPTERS

    wanted = {getattr(adapter, "IMAGE", None) for adapter in ADAPTERS.values()}
    wanted |= {sandbox.DEFAULT_IMAGE, sandbox.PROXY_IMAGE}
    wanted.discard(None)
    missing = sorted(wanted - images_ci_has())
    assert not missing, f"adapter or sandbox images CI does not build: {missing}"
