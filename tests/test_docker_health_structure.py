"""The services do not classify Docker's exceptions themselves (ACCEPTANCE 5.109).

Twice the scheduler and the reconciler disagreed with the daemon about whether it was lost (5.107,
5.109) because each had its own idea. The idea is in ``control_plane/docker_health.py`` and this
file keeps it there:

* each service's ``_translate`` calls ``docker_health.is_lost`` and its module imports neither
  ``docker`` nor ``requests`` and names no Docker or connection exception class;
* the only modules that name the stop reason ``docker_lost`` (``STOP_DOCKER_LOST``) are those two
  services and the vocabularies that define it -- and each service that does so imports the shared
  module.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SERVICES = {
    "scheduler": REPO / "control_plane" / "scheduler" / "service.py",
    "reconciler": REPO / "control_plane" / "reconciler" / "service.py",
}
DEFINERS = {"control_plane/scheduler/vocab.py", "control_plane/reconciler/emit.py"}
CLASSES = {"DockerException", "APIError", "NotFound", "ConnectionError", "TimeoutError", "OSError",
           "RequestException", "ReadTimeout", "ConnectTimeout", "BrokenPipeError",
           "ConnectionResetError", "ConnectionRefusedError"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text())


def _imports(tree: ast.Module) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out |= {f"{node.module}.{a.name}" for a in node.names}
    return out


def test_each_service_imports_the_shared_classification_and_calls_it_in_translate():
    for name, path in SERVICES.items():
        tree = _tree(path)
        assert "control_plane.docker_health" in _imports(tree), name
        translate = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                         and n.name == "_translate")
        calls = {ast.unparse(n.func) for n in ast.walk(translate) if isinstance(n, ast.Call)}
        assert "docker_health.is_lost" in calls, (name, calls)


def test_no_service_imports_docker_or_requests_or_names_a_docker_exception():
    for name, path in SERVICES.items():
        tree = _tree(path)
        banned = {m for m in _imports(tree) if m.split(".")[0] in ("docker", "requests")}
        assert not banned, (name, banned)
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
            n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert not names & CLASSES, (name, names & CLASSES)


def test_the_walker_sees_a_classification_written_by_hand():
    bad = ast.parse("from docker.errors import APIError\n"
                    "def _translate(e):\n    return isinstance(e, ConnectionError)\n")
    assert {m.split('.')[0] for m in _imports(bad)} & {"docker"}
    assert {n.id for n in ast.walk(bad) if isinstance(n, ast.Name)} & CLASSES


def test_only_the_two_services_and_their_vocabularies_name_the_stop_reason():
    found = set()
    for path in (REPO / "control_plane").rglob("*.py"):
        text = path.read_text()
        if "STOP_DOCKER_LOST" in text or "EXIT_DOCKER_LOST" in text:
            found.add(str(path.relative_to(REPO)))
    allowed = DEFINERS | {str(p.relative_to(REPO)) for p in SERVICES.values()}
    assert found <= allowed, sorted(found - allowed)
    for rel in found - DEFINERS:
        assert "docker_health" in (REPO / rel).read_text(), rel
