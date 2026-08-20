"""Dispatch state machine, evidence and tool_runs (§4.1, §4.4, §7, §8.8, I7).

The scan itself is real: a container, a target, and nmap. What is under test
here is everything around it — that a proposal walks QUEUED → DISPATCHING →
RUNNING → SUCCEEDED exactly once, that the run and its evidence land with a
fingerprint that captures what would make the scan different, and that a
dispatch interrupted before its result becomes UNKNOWN_OUTCOME rather than
FAILED.

That last one is the one worth being careful about. §8.8 downgraded I7 from
exactly-once because the window is unclosable: the target may have executed the
action while the control plane was dying. Recording it as failed invites a
retry, and a retry of something with side effects is the harm the invariant
exists to prevent.
"""

from __future__ import annotations

import subprocess
import uuid

import pytest
from sqlalchemy import text

from control_plane.capability.broker import Budget, issue_capability
from control_plane.dedup.fingerprint import execution_context, execution_fingerprint
from control_plane.evidence.store import read_raw_artifact, verify_artifact
from control_plane.orchestrator.dispatch import (
    QUEUED,
    RUNNING,
    SUCCEEDED,
    UNKNOWN_OUTCOME,
    claim_for_dispatch,
    dispatch_scan,
    reconcile_stale_dispatches,
)
from control_plane.state.db import engagement_scope
from tool_gateway.sandbox import DockerSandbox, SandboxUnavailable

ALLOWED_CIDR = "10.78.0.0/24"
TARGET_IP = "10.78.0.10"


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@pytest.fixture(scope="module")
def sandbox():
    box = DockerSandbox()
    try:
        box.ensure_image()
    except SandboxUnavailable as exc:
        pytest.fail(
            f"sandbox unavailable: {exc}\n"
            "Dispatch is tested against a real scan on purpose; a mocked tool "
            "would verify the mock. Build the image with "
            "tool_gateway/images/build_nmap_image.sh.",
            pytrace=False,
        )
    return box


@pytest.fixture(scope="module")
def scan_target(sandbox):
    name = f"cyberorch-dispatch-target-{uuid.uuid4().hex[:8]}"
    network = sandbox.ensure_network([ALLOWED_CIDR])
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--network", network.name,
         "--ip", TARGET_IP, sandbox.image, "/usr/bin/ncat", "-l", "8080", "-k"],
        check=True, capture_output=True,
    )
    yield TARGET_IP
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    sandbox.remove_network([ALLOWED_CIDR])


def _proposal(conn, engagement_id, *, target=TARGET_IP, state=QUEUED) -> str:
    proposal_id = _uid("PROP")
    conn.execute(
        text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, dispatch_state, action, target,
                "authorization", discovery)
            VALUES (:pid, :eid, 'fake-worker', :key, :state, 'network.scan',
                    CAST(:target AS jsonb), CAST(:auth AS jsonb),
                    CAST(:disc AS jsonb))
        """),
        {
            "pid": proposal_id, "eid": engagement_id, "key": f"key-{proposal_id}",
            "state": state,
            "target": f'{{"logical_identity": {{"type": "ip", "value": "{target}"}}}}',
            "auth": '{"source": "engagement_scope", "scope_object_id": "SCOPE-1"}',
            "disc": '{"source": "explicit_scope"}',
        },
    )
    return proposal_id


def _capability(conn, engagement_id, *, duration=60, ports="8080"):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action="network.scan", actor="orchestrator",
        constraints={"ports": ports, "scan_type": "connect"},
        budget=Budget(max_duration_seconds=duration), ttl_seconds=duration,
    )
    assert result.issued is True, result.reasons
    return result.capability


def _state(conn, proposal_id: str) -> str:
    return conn.execute(
        text("SELECT dispatch_state FROM action_proposals WHERE proposal_id = :p"),
        {"p": proposal_id},
    ).scalar_one()


# ---------------------------------------------------------------------------
# Idempotent dispatch (I7)
# ---------------------------------------------------------------------------

def test_a_proposal_is_claimed_for_dispatch_only_once(engagement_id):
    """I7: one idempotency key, one dispatch by the control plane."""
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        assert claim_for_dispatch(conn, proposal_id) is True
        assert claim_for_dispatch(conn, proposal_id) is False
        assert _state(conn, proposal_id) == "dispatching"


def test_duplicate_idempotency_keys_are_rejected_by_the_database(engagement_id):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with engagement_scope(engagement_id) as conn:
            for _ in range(2):
                conn.execute(
                    text("""
                        INSERT INTO action_proposals (proposal_id, engagement_id,
                            agent_id, request_idempotency_key, action, target,
                            "authorization", discovery)
                        VALUES (:pid, :eid, 'a', 'same-key', 'network.scan',
                                '{}'::jsonb, '{}'::jsonb, '{}'::jsonb)
                    """),
                    {"pid": _uid("PROP"), "eid": engagement_id},
                )


# ---------------------------------------------------------------------------
# A real scan, end to end
# ---------------------------------------------------------------------------

def test_successful_scan_writes_evidence_run_and_state(engagement_id, sandbox,
                                                       scan_target):
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        capability = _capability(conn, engagement_id)
        outcome = dispatch_scan(
            conn, engagement_id=engagement_id, proposal_id=proposal_id,
            capability=capability, target=scan_target, actor="orchestrator",
            sandbox=sandbox, network_allowlist=[ALLOWED_CIDR],
            execution_context=execution_context(auth_context_id="AUTHCTX-1"),
        )

        assert outcome.dispatched is True
        assert outcome.state == SUCCEEDED, outcome.reason
        assert _state(conn, proposal_id) == SUCCEEDED

        run = conn.execute(
            text("SELECT tool, tool_version, status, exit_code, network_allowlist, "
                 "execution_fingerprint, normalized_target, fresh_until "
                 "FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).mappings().one()
        assert run["tool"] == "nmap"
        assert run["status"] == SUCCEEDED
        assert run["exit_code"] == 0
        assert run["network_allowlist"] == [ALLOWED_CIDR]
        assert run["fresh_until"] is not None

        evidence = conn.execute(
            text("SELECT raw_sha256, raw_artifact_path, derived_view, "
                 "raw_logically_immutable FROM evidence WHERE evidence_id = :e"),
            {"e": outcome.evidence_id},
        ).mappings().one()

        # §4.4: the derived view is the only thing an LLM sees, and it always
        # says where it came from.
        assert evidence["derived_view"]["untrusted_content"] is True
        assert any(
            p["port"] == 8080 and p["state"] == "open"
            for p in evidence["derived_view"]["open_ports"]
        ), evidence["derived_view"]
        assert evidence["raw_logically_immutable"] is True
        assert verify_artifact(conn, outcome.evidence_id) is True

        # The raw artifact keeps what the derived view summarizes away.
        raw = read_raw_artifact(evidence["raw_artifact_path"])
        assert b"nmap" in raw and scan_target.encode() in raw


def test_scan_is_audited_from_start_to_finish(engagement_id, sandbox, scan_target):
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        capability = _capability(conn, engagement_id)
        outcome = dispatch_scan(
            conn, engagement_id=engagement_id, proposal_id=proposal_id,
            capability=capability, target=scan_target, actor="orchestrator",
            sandbox=sandbox, network_allowlist=[ALLOWED_CIDR],
        )
    with engagement_scope(engagement_id) as conn:
        events = conn.execute(
            text("SELECT event_type FROM audit_log WHERE subject_id = :s "
                 "ORDER BY audit_id"),
            {"s": outcome.run_id},
        ).scalars().all()
    assert events == ["tool_run.started", "tool_run.succeeded"]


def test_a_revoked_capability_cannot_dispatch(engagement_id, sandbox, scan_target):
    """The capability is checked at the point of use, not only at issue."""
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        capability = _capability(conn, engagement_id)
        conn.execute(
            text("UPDATE capabilities SET revoked = TRUE WHERE capability_id = :c"),
            {"c": capability.capability_id},
        )
        from control_plane.capability.broker import get_capability

        outcome = dispatch_scan(
            conn, engagement_id=engagement_id, proposal_id=proposal_id,
            capability=get_capability(conn, capability.capability_id),
            target=scan_target, actor="orchestrator", sandbox=sandbox,
            network_allowlist=[ALLOWED_CIDR],
        )
        assert outcome.dispatched is False
        assert outcome.reason == "capability_not_live"
        assert _state(conn, proposal_id) == QUEUED


# ---------------------------------------------------------------------------
# Fingerprint (§7)
# ---------------------------------------------------------------------------

def test_fingerprint_changes_with_tool_version_and_context():
    """§7: leaving either out causes a false negative — the scan that would
    have found something is skipped as already done."""
    base = dict(
        engagement_id="ENG-1", tool="nmap", tool_version="7.94",
        normalized_target="10.20.0.7",
        normalized_params={"ports": "8080", "scan_type": "connect"},
        execution_context={"auth_context_id": "AUTHCTX-1"},
    )
    original = execution_fingerprint(**base)

    assert execution_fingerprint(**{**base, "tool_version": "7.95"}) != original
    assert execution_fingerprint(**{**base, "ruleset_version": "abc"}) != original
    assert execution_fingerprint(
        **{**base, "execution_context": {"auth_context_id": "AUTHCTX-2"}}
    ) != original
    assert execution_fingerprint(
        **{**base, "normalized_params": {"ports": "1-1024", "scan_type": "connect"}}
    ) != original
    assert execution_fingerprint(**base) == original


def test_fingerprint_is_order_independent():
    a = execution_fingerprint(
        engagement_id="E", tool="nmap", tool_version="7.94", normalized_target="t",
        normalized_params={"a": 1, "b": 2},
    )
    b = execution_fingerprint(
        engagement_id="E", tool="nmap", tool_version="7.94", normalized_target="t",
        normalized_params={"b": 2, "a": 1},
    )
    assert a == b


def test_execution_context_carries_identifiers_not_secrets():
    context = execution_context(auth_context_id="AUTHCTX-19", source_revision=None)
    assert context == {"auth_context_id": "AUTHCTX-19"}


def test_a_second_identical_scan_is_deduplicated(engagement_id, sandbox, scan_target):
    """§7: same fingerprint, still fresh, so the tool does not run again."""
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        first = dispatch_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id), capability=capability,
            target=scan_target, actor="orchestrator", sandbox=sandbox,
            network_allowlist=[ALLOWED_CIDR],
        )
        assert first.state == SUCCEEDED

        second_proposal = _proposal(conn, engagement_id)
        second = dispatch_scan(
            conn, engagement_id=engagement_id, proposal_id=second_proposal,
            capability=capability, target=scan_target, actor="orchestrator",
            sandbox=sandbox, network_allowlist=[ALLOWED_CIDR],
        )

    assert second.dispatched is False
    assert second.reason == "dedup_hit"
    assert second.run_id == first.run_id


# ---------------------------------------------------------------------------
# UNKNOWN_OUTCOME (§8.8, I7)
# ---------------------------------------------------------------------------

def test_an_interrupted_dispatch_becomes_unknown_not_failed(engagement_id):
    """§8.8's unclosable window.

    The control plane died between handing the action over and recording the
    result. The action may well have executed. Marking it FAILED would invite a
    retry, and retrying something with side effects is the harm I7 exists to
    prevent — so it becomes UNKNOWN_OUTCOME and waits for a human.
    """
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        claim_for_dispatch(conn, proposal_id)
        conn.execute(
            text("UPDATE action_proposals SET dispatch_state = :r, "
                 "updated_at = now() - interval '10 minutes' WHERE proposal_id = :p"),
            {"p": proposal_id, "r": RUNNING},
        )

        stale = reconcile_stale_dispatches(
            conn, engagement_id=engagement_id, older_than_seconds=60,
            actor="reconciler",
        )
        assert proposal_id in stale
        assert _state(conn, proposal_id) == UNKNOWN_OUTCOME


def test_reconciliation_does_not_touch_live_dispatches(engagement_id):
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        claim_for_dispatch(conn, proposal_id)
        stale = reconcile_stale_dispatches(
            conn, engagement_id=engagement_id, older_than_seconds=3600,
            actor="reconciler",
        )
        assert proposal_id not in stale
        assert _state(conn, proposal_id) == "dispatching"


def test_unknown_outcome_is_audited_as_needing_a_human(engagement_id):
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        claim_for_dispatch(conn, proposal_id)
        conn.execute(
            text("UPDATE action_proposals SET updated_at = now() - interval '1 hour' "
                 "WHERE proposal_id = :p"),
            {"p": proposal_id},
        )
        reconcile_stale_dispatches(
            conn, engagement_id=engagement_id, older_than_seconds=60,
            actor="reconciler",
        )
    with engagement_scope(engagement_id) as conn:
        row = conn.execute(
            text("SELECT event_type, reasons, payload FROM audit_log "
                 "WHERE subject_id = :s"),
            {"s": proposal_id},
        ).mappings().one()
    assert row["event_type"] == "dispatch.unknown_outcome"
    assert "interrupted_before_result" in row["reasons"]
    assert row["payload"]["requires_human_review"] is True


def test_an_unavailable_sandbox_yields_unknown_outcome(engagement_id, scan_target):
    """The tool may have started before the sandbox call failed.

    Nothing distinguishes "never launched" from "launched and then lost" at
    this layer, so the honest state is unknown.
    """
    broken = DockerSandbox(image="cyberorch/does-not-exist:none")
    with engagement_scope(engagement_id) as conn:
        proposal_id = _proposal(conn, engagement_id)
        capability = _capability(conn, engagement_id)
        outcome = dispatch_scan(
            conn, engagement_id=engagement_id, proposal_id=proposal_id,
            capability=capability, target=scan_target, actor="orchestrator",
            sandbox=broken, network_allowlist=[ALLOWED_CIDR],
        )
        assert outcome.state == UNKNOWN_OUTCOME
        assert _state(conn, proposal_id) == UNKNOWN_OUTCOME
        assert conn.execute(
            text("SELECT status FROM tool_runs WHERE run_id = :r"),
            {"r": outcome.run_id},
        ).scalar_one() == UNKNOWN_OUTCOME
