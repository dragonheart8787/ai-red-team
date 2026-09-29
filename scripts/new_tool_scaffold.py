#!/usr/bin/env python3
"""Generate the mechanical parts of a new tool adapter (D53).

    python scripts/new_tool_scaffold.py --name gitleaks --action secrets.scan --out /tmp/gl
    python scripts/new_tool_scaffold.py --check gitleaks

The first form writes an adapter, its tests, a Dockerfile and build script, an
ADR worksheet and a registration checklist into ``--out``. It touches nothing in
the repository: you review the output and copy it in.

What it is not
--------------
It does not decide how a tool is authorized or constrained, and it is built so
that it cannot look as though it did. Every judgement -- side effects, egress,
dispatch shape, evidence handling, the version pin, the command itself -- is
emitted as ``NotImplemented`` or a ``raise``, so the generated adapter fails
``tests/adapter_kit.adapter_violations`` and every generated placeholder test
*fails* (CI treats a skip as a failure, and a scaffold that could go green by
omission would be batch onboarding). What it saves is the typing of the parts
that were identical across six integrations, and the six mistakes each of them
made finding out which parts those were. See ``docs/NEW_TOOL_ONBOARDING.md``.

``--check`` runs the same contract checks against a tool already copied into the
repository and lists what is still undecided or unwired.
"""

from __future__ import annotations

import argparse
import importlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = Path(__file__).resolve().parent / "new_tool_templates"
ADR_TEMPLATE = REPO / "docs" / "templates" / "ADR_NEW_TOOL_TEMPLATE.md"

# Lower-case letters and digits only: the name becomes the image slug
# (cyberorch/<name>:local) and the build script name, and adapter_kit derives the
# script from the slug. An underscore would make the two disagree.
_NAME = re.compile(r"^[a-z][a-z0-9]{1,30}$")
_ACTION = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$")

#: (template, path relative to the output directory)
FILES = (
    ("adapter.py.tmpl", "tool_gateway/adapters/{name}.py"),
    ("test_adapter.py.tmpl", "tests/test_{name}_adapter.py"),
    ("Dockerfile.tmpl", "tool_gateway/images/{name}.Dockerfile"),
    ("build_image.sh.tmpl", "tool_gateway/images/build_{name}_image.sh"),
    ("REGISTRATION.md.tmpl", "REGISTRATION_{name}.md"),
)


class ScaffoldError(Exception):
    """The request cannot be honoured; nothing was written."""


def _render(text: str, name: str, action: str) -> str:
    return (
        text.replace("{{Name}}", name.capitalize())
        .replace("{{NAME}}", name.upper())
        .replace("{{name}}", name)
        .replace("{{action}}", action)
    )


def _refuse_collisions(name: str, action: str) -> None:
    sys.path.insert(0, str(REPO))
    from tool_gateway import registry

    if (REPO / "tool_gateway" / "adapters" / f"{name}.py").exists():
        raise ScaffoldError(f"tool_gateway/adapters/{name}.py already exists")
    if action in registry.ADAPTERS:
        raise ScaffoldError(f"action {action!r} is already served by an adapter")
    tools = {getattr(m, "TOOL", None) for m in registry.ADAPTERS.values()}
    if name in tools:
        raise ScaffoldError(f"TOOL name {name!r} is already used by a registered adapter")
    if (REPO / "tool_gateway" / "images" / f"{name}.Dockerfile").exists():
        raise ScaffoldError(f"tool_gateway/images/{name}.Dockerfile already exists")


def generate(name: str, action: str, out: Path) -> list[Path]:
    """Write the scaffold into ``out`` (which must be empty or absent)."""
    if not _NAME.match(name):
        raise ScaffoldError(
            f"invalid --name {name!r}: lower-case letters and digits, starting with a letter"
        )
    if not _ACTION.match(action):
        raise ScaffoldError(f"invalid --action {action!r}: expected <namespace>.<verb>")
    _refuse_collisions(name, action)

    out = out.resolve()
    if out == REPO:
        raise ScaffoldError("--out is the repository root; generate elsewhere and copy in")
    if out.exists() and any(out.iterdir()):
        raise ScaffoldError(f"{out} is not empty; the scaffold never overwrites")

    written: list[Path] = []
    for template, relative in FILES:
        target = out / relative.format(name=name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            _render((TEMPLATES / template).read_text(encoding="utf-8"), name, action),
            encoding="utf-8",
        )
        written.append(target)
    build = out / f"tool_gateway/images/build_{name}_image.sh"
    build.chmod(0o755)

    adr = out / f"docs/ADR_{name.upper()}.md"
    adr.parent.mkdir(parents=True, exist_ok=True)
    adr.write_text(
        ADR_TEMPLATE.read_text(encoding="utf-8").replace("{{NAME}}", name.upper()),
        encoding="utf-8",
    )
    written.append(adr)
    return written


def check(name: str) -> list[str]:
    """Contract violations for a tool that has been copied into the repository."""
    sys.path.insert(0, str(REPO))
    from tests import adapter_kit

    try:
        adapter = importlib.import_module(f"tool_gateway.adapters.{name}")
    except ModuleNotFoundError as exc:
        raise ScaffoldError(
            f"tool_gateway/adapters/{name}.py is not in the repository: {exc}"
        ) from exc
    action = getattr(adapter, "ACTION", None)
    problems = adapter_kit.adapter_violations(adapter, action=action)
    problems += adapter_kit.registration_violations(adapter, action=str(action))
    return problems


def _count_markers(paths: list[Path]) -> int:
    return sum(p.read_text(encoding="utf-8").count("DECIDE(") for p in paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--name", help="tool name: lower-case letters and digits")
    parser.add_argument("--action", help="action string, e.g. secrets.scan")
    parser.add_argument("--out", type=Path, help="empty directory to write into (required)")
    parser.add_argument("--check", metavar="NAME", help="check a tool already in the repository")
    args = parser.parse_args(argv)

    try:
        if args.check:
            problems = check(args.check)
            for problem in problems:
                print(f"UNRESOLVED: {problem}")
            print(
                f"\n{len(problems)} unresolved. A clean result says the wiring is consistent; "
                "it says nothing about whether the decisions in docs/ADR_* were right."
            )
            return 1 if problems else 0
        if not (args.name and args.action and args.out):
            parser.error("--name, --action and --out are all required")
        written = generate(args.name, args.action, args.out)
    except ScaffoldError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for path in written:
        print(f"wrote {path}")
    print(
        f"\n{_count_markers(written)} DECIDE markers. Nothing is registered and nothing is "
        "decided; the generated adapter fails its contract check on purpose.\n"
        f"Next: docs/NEW_TOOL_ONBOARDING.md §1 -- write docs/ADR_{args.name.upper()}.md first, "
        f"then follow REGISTRATION_{args.name}.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
