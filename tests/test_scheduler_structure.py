"""The scheduler's structure, checked on the source (D62).

The point of splitting the scheduler into a decision side and an execution side is that the side
that *decides* cannot reach what it must not decide on, and the side that *acts* is not asked why.
That holds only while the imports stay as they are, so they are pinned here by reading the syntax
tree -- not by grep, which a re-export or an alias walks around.

Also here: the audit-payload whitelist (no event can carry a goal, a target or evidence text), and
the rule that the operator's enrollment connection is used by the operator's script only.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from control_plane.scheduler import emit, vocab
from tests import scheduler_support as sup
from tests.test_scheduler_skips import RecordingSandbox

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "control_plane" / "scheduler"


def _imports(path: Path) -> set[str]:
    """Every name a module imports, as ``module.name`` (``import x`` as ``x``)."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def _db_names(path: Path) -> set[str]:
    return {i.rsplit(".", 1)[1] for i in _imports(path) if i.startswith("control_plane.state.db.")}


def _modules():
    return {p.stem: p for p in PKG.glob("*.py")}


READER_SCOPES = {"scheduler_reader_scope", "scheduler_reader_enrollment_scope"}
EXECUTION_SCOPES = {"engagement_scope", "get_engine", "registry_admin_scope",
                    "global_policy_admin_scope", "global_audit_scope", "global_auditor_scope",
                    "credential_admin_scope"}


def test_the_decision_side_can_reach_only_the_reader_connection():
    names = _db_names(PKG / "decide.py")
    assert names == READER_SCOPES
    imports = _imports(PKG / "decide.py")
    for forbidden in ("control_plane.api", "control_plane.audit", "control_plane.vault",
                      "control_plane.orchestrator", "control_plane.capability",
                      "control_plane.policy", "tool_gateway", "docker", "agents"):
        assert not [i for i in imports if i == forbidden or i.startswith(forbidden + ".")], (
            f"decide.py imports {forbidden}")
    assert "control_plane.scheduler.emit" not in {i.rsplit(".", 1)[0] for i in imports
                                                  if i.startswith("control_plane.scheduler")}


def test_the_execution_side_has_no_reader_connection_and_no_decision_logic():
    names = _db_names(PKG / "execute.py")
    assert names == {"engagement_scope"}
    imports = _imports(PKG / "execute.py")
    assert "control_plane.api.approved_dispatch.dispatch_approved" in imports
    assert not [i for i in imports if i.startswith("control_plane.scheduler.decide")]
    assert not READER_SCOPES & names


def test_the_state_writer_module_uses_the_state_writer_connection_only():
    assert _db_names(PKG / "state.py") == {"scheduler_state_writer_scope"}


def test_the_audit_emitter_reaches_no_scheduler_connection():
    assert not _db_names(PKG / "emit.py") & (READER_SCOPES | EXECUTION_SCOPES)


def test_only_the_service_joins_the_two_sides():
    """No module but ``service`` imports both ``decide`` and ``execute``; nothing else imports
    either one alongside the other, so ids and closed codes are all that cross."""
    def sees(imports: set[str], module: str) -> bool:
        return any(i.startswith(f"control_plane.scheduler.{module}") or i == f".{module}"
                   for i in imports)

    both = [name for name, path in _modules().items()
            if sees(_imports(path), "decide") and sees(_imports(path), "execute")]
    assert both == ["service"]


def test_the_service_reads_no_policy_and_keeps_none():
    """No policy cache: the policy is loaded at the moment of dispatch, in ``execute``, only."""
    holders = [n for n, p in _modules().items()
               if any(i.endswith("load_effective_policy") or i.startswith("control_plane.policy")
                      for i in _imports(p))]
    assert holders == ["execute"]
    for name, path in _modules().items():
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                    node.value, (ast.Dict, ast.List, ast.Set)):
                assert _is_constant_name(node), (
                    f"{name}: module-level mutable state at line {node.lineno}")


def _is_constant_name(node) -> bool:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return all(isinstance(t, ast.Name) and t.id.isupper() for t in targets)


def test_the_enrollment_writer_is_used_by_the_operators_script_only():
    users = []
    for path in list((ROOT / "control_plane").rglob("*.py")) + list(
            (ROOT / "scripts").glob("*.py")) + list((ROOT / "agents").rglob("*.py")) + list(
            (ROOT / "tool_gateway").rglob("*.py")):
        tree = ast.parse(path.read_text())
        used = any(
            (isinstance(n, ast.Name) and n.id == "scheduler_admin_scope")
            or (isinstance(n, ast.Attribute) and n.attr == "scheduler_admin_scope")
            for n in ast.walk(tree))
        if used:
            users.append(path.relative_to(ROOT).as_posix())
    assert users == ["scripts/manage_scheduler_enrollment.py"]


def test_nothing_the_agents_or_tools_run_can_import_the_scheduler():
    offenders = []
    for top in ("agents", "tool_gateway"):
        for path in (ROOT / top).rglob("*.py"):
            if any(i.startswith("control_plane.scheduler") for i in _imports(path)):
                offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


# ---------------------------------------------------------------------------------------------
# the audit payload whitelist
# ---------------------------------------------------------------------------------------------

def test_every_scheduler_event_has_a_schema_and_no_other_kind_can_be_written():
    assert set(emit.SCHEMAS) == set(vocab.EVENTS)
    with pytest.raises(emit.PayloadRejected):
        emit.validate("scheduler.something_else", {})
    with pytest.raises(emit.PayloadRejected):
        emit.validate("policy.decided", {"proposal_id": "PROP-1"})


@pytest.mark.parametrize("extra", [
    {"goal": "scan the payroll subnet"}, {"target": "10.0.0.5"}, {"evidence": "open ports: 22"},
    {"stdout": "x"}, {"reason": "free text"}, {"note": ""},
])
def test_an_extra_key_is_refused_on_every_event(extra):
    good = {
        vocab.DISPATCHED: {"proposal_id": "PROP-1", "reason_code": vocab.APPROVED_AND_IDLE},
        vocab.SKIPPED: {"proposal_id": "PROP-1", "reason_code": vocab.SCOPE_TOO_NARROW},
        vocab.DEFERRED: {"reason_code": "engagement_paused", "waiting_count": 1},
        vocab.RESUMED: {"deferred_seconds": 3, "waiting_count": 1},
        vocab.STOPPED: {"instance_id": "SCHED-1", "reason_code": vocab.STOP_SIGNAL},
        vocab.START_REFUSED: {"instance_id": "SCHED-1", "reason_code": vocab.LOCK_HELD},
    }
    for event, payload in good.items():
        assert emit.validate(event, payload) == payload             # the control
        with pytest.raises(emit.PayloadRejected):
            emit.validate(event, {**payload, **extra})


@pytest.mark.parametrize("value", [
    "scan the payroll subnet and report", "10.96.62.9; DROP TABLE x", "line one\nline two",
    "", " ", "x" * 500, None, 7, ["PROP-1"], {"a": 1},
])
def test_a_value_that_is_not_an_id_or_a_closed_code_is_refused(value):
    with pytest.raises(emit.PayloadRejected):
        emit.validate(vocab.SKIPPED, {"proposal_id": value, "reason_code": vocab.SCOPE_TOO_NARROW})
    with pytest.raises(emit.PayloadRejected):
        emit.validate(vocab.SKIPPED, {"proposal_id": "PROP-1", "reason_code": value})


def test_a_reason_code_that_is_valid_for_another_event_is_refused_here():
    with pytest.raises(emit.PayloadRejected):
        emit.validate(vocab.SKIPPED, {"proposal_id": "PROP-1", "reason_code": "engagement_paused"})
    with pytest.raises(emit.PayloadRejected):
        emit.validate(vocab.DEFERRED, {"reason_code": vocab.SCOPE_TOO_NARROW, "waiting_count": 1})
    with pytest.raises(emit.PayloadRejected):
        emit.validate(vocab.STOPPED, {"instance_id": "SCHED-1", "reason_code": "lock_held"})


def test_a_counter_is_a_non_negative_integer():
    for bad in (-1, 1.5, True, "3", None):
        with pytest.raises(emit.PayloadRejected):
            emit.validate(vocab.RESUMED, {"deferred_seconds": bad, "waiting_count": 0})


def test_an_engagement_event_without_an_engagement_is_refused():
    with pytest.raises(emit.PayloadRejected):
        emit.emit(vocab.SKIPPED, {"proposal_id": "PROP-1", "reason_code": vocab.SCOPE_TOO_NARROW})


def test_what_the_scheduler_really_wrote_carries_no_goal_target_or_scope_text(
    engagement_id, registry,
):
    """Not just the schema: run the scheduler through dispatch, skip, defer and resume, then read
    back every record it wrote and look for the text of the things it must never copy."""
    cidr, host, narrow = "10.96.72.0/24", "10.96.72.9", "10.96.72.64/30"
    sup.publish_engagement_policy(engagement_id)
    scope = sup.register_scope(registry, type="cidr", value=cidr)
    small = sup.register_scope(registry, type="cidr", value=narrow)
    sup.enroll(engagement_id)
    try:
        sup.approved_proposal(engagement_id, scope, host=host)
        sup.approved_proposal(engagement_id, small, host="10.96.72.66")
        sup.pause(engagement_id)
        with sup.running(RecordingSandbox()) as sched:
            sched.tick()
            sup.resume(engagement_id)
            sched.tick()
            sched.tick()
        events = sup.audit(engagement_id, *vocab.EVENTS)
    finally:
        sup.withdraw(engagement_id)

    assert {e["event_type"] for e in events} >= {
        vocab.DEFERRED, vocab.RESUMED, vocab.DISPATCHED, vocab.SKIPPED}
    blob = json.dumps([e["payload"] for e in events]).lower()
    for text_it_must_not_copy in (host, cidr, narrow, "10.96.72", "network.scan", "nmap",
                                  "8080", "connect", "payroll", "scan", "goal", "evidence"):
        assert text_it_must_not_copy not in blob, text_it_must_not_copy
    for event in events:
        _, schema = emit.SCHEMAS[event["event_type"]]
        assert set(event["payload"]) == set(schema)
