"""§4.6's request budget, now actually spent (D34).

**This file tests the repair of an existing defect, not a mechanism D34
invented.** ``consume_request`` and its atomic check-and-increment have been in
the Capability Broker since the capability work, written exactly as §8.5
specifies — ``UPDATE ... WHERE requests_used < :maximum RETURNING`` — and until
D34 nothing on any production path called it. A grep for the name found it in
two test files and nowhere else: ``max_requests`` was a number in a database.

D31 did not surface it because its adapter refuses any ``max_requests`` above
one, so a run was always exactly one request and the count never mattered. D34
adds a second HTTP adapter and a proxy that counts what leaves, which is the
point at which an uncounted budget becomes a hole rather than a formality.

The mutation test at the end is the one that matters. "I added the call" is not
evidence; the evidence is that removing the call breaks a guarantee, asserted
by removing it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from control_plane.capability.broker import Budget, issue_capability
from control_plane.orchestrator import dispatch
from control_plane.orchestrator.dispatch import (
    BUDGET_EXHAUSTED,
    FAILED,
    PROXY_REQUIRED,
    QUEUED,
    SUCCEEDED,
    dispatch_scan,
)
from control_plane.state.db import engagement_scope
from tool_gateway.sandbox import SandboxResult

TARGET_IP = "10.78.0.10"
ALLOWED_CIDR = "10.78.0.0/24"
PROXY_URL = "http://10.81.0.2:3128"


class StubSandbox:
    """A sandbox that records what it was asked to run and answers 200.

    No Docker: what is under test here is the control plane's accounting, and
    a container would only make the test slower and less able to run anywhere.
    The isolation properties are tested against real containers in
    test_egress_proxy.py, where they belong.
    """

    def __init__(self) -> None:
        self.runs: list[dict] = []

    def run(self, *, command, network_allowlist, max_duration_seconds,
            run_id=None, stdin=None, ca_cert_pem=None):
        self.runs.append({
            "command": list(command), "allowlist": list(network_allowlist),
            "stdin": stdin, "ca_cert_pem": ca_cert_pem,
        })
        return SandboxResult(
            exit_code=0,
            stdout="HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<p>ok</p>",
            stderr="", timed_out=False, duration_seconds=0.1,
            network_allowlist=tuple(network_allowlist), image="stub",
        )


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _proposal(conn, engagement_id, *, action="web.get") -> str:
    proposal_id = _uid("PROP")
    conn.execute(
        text("""
            INSERT INTO action_proposals (proposal_id, engagement_id, agent_id,
                request_idempotency_key, dispatch_state, action, target,
                "authorization", discovery)
            VALUES (:pid, :eid, 'fake-worker', :key, :state, :action,
                    CAST(:target AS jsonb), CAST(:auth AS jsonb),
                    CAST(:disc AS jsonb))
        """),
        {
            "pid": proposal_id, "eid": engagement_id, "key": f"key-{proposal_id}",
            "state": QUEUED, "action": action,
            "target": f'{{"logical_identity": {{"type": "ip", "value": "{TARGET_IP}"}}}}',
            "auth": '{"source": "engagement_scope", "scope_object_id": "SCOPE-1"}',
            "disc": '{"source": "explicit_scope"}',
        },
    )
    return proposal_id


def _capability(conn, engagement_id, *, action="web.get", max_requests=1,
                constraints=None):
    result = issue_capability(
        conn, engagement_id=engagement_id, capability_id=_uid("CAP"),
        agent_id="fake-worker", action=action, actor="orchestrator",
        constraints=constraints or {"host": TARGET_IP, "port": 8080,
                                    "path": "/index.html"},
        budget=Budget(
            max_duration_seconds=60,
            tool={"http": {"max_requests": max_requests}},
        ),
        ttl_seconds=60,
    )
    assert result.issued is True, result.reasons
    return result.capability


def _requests_used(conn, capability_id: str) -> int:
    return conn.execute(
        text("SELECT requests_used FROM capabilities WHERE capability_id = :c"),
        {"c": capability_id},
    ).scalar_one()


def _dispatch(conn, engagement_id, capability, *, sandbox, proxy_url=PROXY_URL):
    return dispatch_scan(
        conn, engagement_id=engagement_id,
        proposal_id=_proposal(conn, engagement_id, action=capability.action),
        capability=capability, target=TARGET_IP, actor="orchestrator",
        sandbox=sandbox, network_allowlist=["10.81.0.0/24"],
        proxy_url=proxy_url,
        # A fresh context per call: the dedup cache would otherwise return the
        # first run for the second and no budget would be spent, which would
        # make this file pass for the wrong reason.
        execution_context={"nonce": uuid.uuid4().hex},
    )


# ---------------------------------------------------------------------------
# The budget is now spent on the production path
# ---------------------------------------------------------------------------

def test_a_dispatched_run_spends_a_request(engagement_id):
    """The counter moves. Before D34 it never did outside a test.

    ``max_requests=1`` because that is the only value the HTTP adapters accept:
    one plan is one request, and a budget above one is honoured by the control
    plane issuing another capability rather than by a tool looping. So the
    interesting number here is 0 → 1, and the refusal of the second run is the
    next test.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, max_requests=1)
        assert _requests_used(conn, capability.capability_id) == 0

        outcome = _dispatch(conn, engagement_id, capability, sandbox=StubSandbox())

        assert outcome.state == SUCCEEDED, outcome.reason
        assert _requests_used(conn, capability.capability_id) == 1


def test_a_capability_whose_budget_is_spent_cannot_dispatch_again(engagement_id):
    """I3: execution ⊆ the issued capability, budget included."""
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, max_requests=1)
        sandbox = StubSandbox()

        first = _dispatch(conn, engagement_id, capability, sandbox=sandbox)
        second = _dispatch(conn, engagement_id, capability, sandbox=sandbox)

        assert first.state == SUCCEEDED
        assert second.state == FAILED
        assert second.reason == BUDGET_EXHAUSTED
        assert len(sandbox.runs) == 1, "the refused dispatch still ran the tool"
        assert _requests_used(conn, capability.capability_id) == 1


def test_the_refusal_is_audited_as_a_decision(engagement_id):
    """A budget stopping something is a decision, and §4.4 records decisions."""
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, max_requests=1)
        _dispatch(conn, engagement_id, capability, sandbox=StubSandbox())
        _dispatch(conn, engagement_id, capability, sandbox=StubSandbox())

        rows = conn.execute(
            text("""
                SELECT decision, reasons FROM audit_log
                WHERE subject_id = :c AND event_type = 'capability.budget_exhausted'
            """),
            {"c": capability.capability_id},
        ).mappings().all()

    assert len(rows) == 1
    assert rows[0]["decision"] == "DENY"
    assert BUDGET_EXHAUSTED in rows[0]["reasons"]


def test_an_nmap_run_does_not_spend_an_http_request(engagement_id):
    """§4.6's own reasoning: "one request" has no meaning for a port scan.

    That is why the budget object separates tool-specific dimensions from the
    universal ones. The adapters that count declare ``max_requests`` on their
    plan; nmap's plan has no such field and nothing is counted for it.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id, action="network.scan",
            constraints={"ports": "8080", "scan_type": "connect"},
        )
        outcome = dispatch_scan(
            conn, engagement_id=engagement_id,
            proposal_id=_proposal(conn, engagement_id, action="network.scan"),
            capability=capability, target=TARGET_IP, actor="orchestrator",
            sandbox=StubSandbox(), network_allowlist=[ALLOWED_CIDR],
            execution_context={"nonce": uuid.uuid4().hex},
        )
        assert outcome.state == SUCCEEDED, outcome.reason
        assert _requests_used(conn, capability.capability_id) == 0


# ---------------------------------------------------------------------------
# The mutation: is the call load-bearing?
# ---------------------------------------------------------------------------

def test_removing_the_consume_call_breaks_the_budget_guarantee(
    engagement_id, monkeypatch
):
    """D34 requirement 2, and the only test here that proves anything.

    "I added the call" is not evidence. This removes it -- replaces
    ``consume_request`` on the dispatch module with one that always says yes,
    which is precisely the state the code was in before D34 -- and asserts that
    the guarantee above then fails: a capability with ``max_requests=1``
    dispatches twice, the tool runs twice, and ``requests_used`` never moves.

    If someone deletes the call in dispatch_scan, this test goes red by
    *passing its precondition and failing its conclusion*, and
    test_a_capability_whose_budget_is_spent_cannot_dispatch_again goes red too.
    Two failures, one cause, and neither of them silent.
    """
    monkeypatch.setattr(dispatch, "consume_request", lambda *a, **k: True)

    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, max_requests=1)
        sandbox = StubSandbox()

        first = _dispatch(conn, engagement_id, capability, sandbox=sandbox)
        second = _dispatch(conn, engagement_id, capability, sandbox=sandbox)

        # Without the real call, the budget stops holding: both dispatches run.
        assert first.state == SUCCEEDED
        assert second.state == SUCCEEDED, (
            "the second dispatch was refused even with consume_request stubbed "
            "out, so something other than the budget refused it and the test "
            "above is not measuring what it claims"
        )
        assert len(sandbox.runs) == 2
        assert _requests_used(conn, capability.capability_id) == 0


# ---------------------------------------------------------------------------
# A web action with no proxy is refused, not run unproxied
# ---------------------------------------------------------------------------

def test_a_web_action_without_a_proxy_is_refused(engagement_id):
    """An unproxied web request is not a degraded run, it is an unchecked one.

    The tool container has no route to the target anyway (§8.3's two-network
    topology), so this would fail at the socket a moment later and read as an
    unreachable target. Refusing here keeps the reason attached to the cause.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        sandbox = StubSandbox()
        outcome = _dispatch(conn, engagement_id, capability,
                            sandbox=sandbox, proxy_url=None)

    assert outcome.state == FAILED
    assert outcome.reason == PROXY_REQUIRED
    assert sandbox.runs == []


def test_the_proxy_url_reaches_the_command(engagement_id):
    """curl is told to use it, so the request is addressed to the proxy."""
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id)
        sandbox = StubSandbox()
        _dispatch(conn, engagement_id, capability, sandbox=sandbox)

    command = sandbox.runs[0]["command"]
    assert command[command.index("--proxy") + 1] == PROXY_URL


def test_a_post_body_reaches_the_sandbox_as_stdin_and_not_as_an_argument(
    engagement_id
):
    """The body stays out of argv all the way down to the container.

    Checked at the sandbox boundary rather than at the adapter, because the
    adapter's plan is only half the claim -- what matters is what dispatch
    actually hands the sandbox.
    """
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id, action="web.post",
            constraints={"host": TARGET_IP, "port": 8080, "path": "/submit",
                         "body": "q=inventory"},
        )
        sandbox = StubSandbox()
        outcome = _dispatch(conn, engagement_id, capability, sandbox=sandbox)

    assert outcome.state == SUCCEEDED, outcome.reason
    assert sandbox.runs[0]["stdin"] == "q=inventory"
    assert "q=inventory" not in " ".join(sandbox.runs[0]["command"])


def test_the_audit_payload_does_not_carry_the_request_body(engagement_id):
    """``tool_run.started`` records plan.command, which is why the body is not in it."""
    with engagement_scope(engagement_id) as conn:
        capability = _capability(
            conn, engagement_id, action="web.post",
            constraints={"host": TARGET_IP, "port": 8080, "path": "/submit",
                         "body": "password=hunter2"},
        )
        _dispatch(conn, engagement_id, capability, sandbox=StubSandbox())

        payloads = conn.execute(
            text("SELECT payload::text FROM audit_log "
                 "WHERE event_type = 'tool_run.started'"),
        ).scalars().all()

    assert payloads
    assert not any("hunter2" in p for p in payloads)


@pytest.mark.parametrize("action", ["web.get", "web.post"])
def test_every_proxied_action_is_refused_without_one(engagement_id, action):
    """Both web adapters, not just the one that happened to be tested."""
    constraints = {"host": TARGET_IP, "port": 8080, "path": "/x"}
    if action == "web.post":
        constraints["body"] = "a=1"
    with engagement_scope(engagement_id) as conn:
        capability = _capability(conn, engagement_id, action=action,
                                 constraints=constraints)
        outcome = _dispatch(conn, engagement_id, capability,
                            sandbox=StubSandbox(), proxy_url=None)
    assert outcome.reason == PROXY_REQUIRED
