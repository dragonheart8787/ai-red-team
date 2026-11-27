"""D69-NC-2 (plan items 161, 162; ``docs/ADR_INLINE_DISPATCH_ALLOWLIST.md``): the network
allowlist of the inline dispatch.

Each case of ``CASES`` goes through the real ``propose_action`` and OPA on the test database, with
an allowing policy and a recording fake sandbox (it keeps the ``network_allowlist`` it was given,
and whether it was called at all; it never touches Docker). A dispatch case asserts that the
sandbox was called once with the expected allowlist; a not-started case asserts that the
proposal's stage is ``closed``, that it has no run, that the sandbox was not called, that
``outcome.run_id`` is ``None`` and that ``outcome.failure`` is the expected reason. Every case first
asserts that the policy allowed the proposal (``decision == "ALLOW"``); a case for which it did not
is invalid and says so. No exception may come out of ``propose_action``. A unit test of rule
R-d, outside the table, checks that ``DockerSandbox.run`` turns a non-CIDR allowlist into a
``NotStarted`` before any Docker object is used (a recording client stands for Docker).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope
from tests import scheduler_support as sup
from tests.task_support import attach_task
from tool_gateway.sandbox import DockerSandbox, NotStarted, SandboxResult

# BEGIN PREREGISTERED -- written before the first run; not to be changed after it (plan item 161).
#
# id: (scope object (type, value), action, target (type, value), the caller's network_allowlist or
#      None, expected): expected is ("dispatch", the allowlist the sandbox receives) or
#      ("not_started", the outcome's failure).
#
# D12 pins the reach of the rules to NETWORK_ACTIONS: web.get keeps the caller's allowlist,
# unchecked. When the rules are widened to more actions, this case is to be changed knowingly.
CASES = {
    "D1": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"), None,
           ("dispatch", ("10.82.0.0/24",))),
    "D2": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"), ["10.82.0.0/24"],
           ("dispatch", ("10.82.0.0/24",))),
    "D3": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"), ["10.82.0.0/16"],
           ("not_started", "allowlist_exceeds_scope")),
    "D4": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"), ["10.83.0.0/24"],
           ("not_started", "allowlist_exceeds_scope")),
    "D5": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"), ["10.82.0.0/28"],
           ("dispatch", ("10.82.0.0/28",))),
    "D6": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"), ["10.82.0.16/28"],
           ("not_started", "target_outside_allowlist")),
    "D7": (("ip", "10.82.0.10"), "network.scan", ("ip", "10.82.0.10"), None,
           ("not_started", "scope_narrower_than_sandbox_minimum")),      # SCOPE_TOO_NARROW
    "D8": (("fqdn", "*.lure.example"), "network.scan", ("fqdn", "dc99.lure.example"), None,
           ("not_started", "scope_type_has_no_network_range")),          # SCOPE_TYPE_NO_RANGE
    "D9": (("cidr", "10.82.0.0/30"), "network.scan", ("ip", "10.82.0.1"), None,
           ("not_started", "scope_narrower_than_sandbox_minimum")),      # SCOPE_TOO_NARROW
    "D10": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.0"), None,
            ("not_started", "target_is_reserved_address")),              # TARGET_RESERVED
    "D11": (("cidr", "10.82.0.0/24"), "network.scan", ("ip", "10.82.0.10"),
            ["dc99.lure.example"], ("not_started", "allowlist_invalid")),
    "D12": (("cidr", "10.82.0.0/24"), "web.get", ("ip", "10.82.0.10"), ["10.82.0.0/24"],
            ("dispatch", ("10.82.0.0/24",))),
}
# Before the repair: D2, D5 and D12 pass; the other nine fail (D1 receives ["10.82.0.10"]; D3, D4
# and D6 are dispatched; D7 to D10 are dispatched; D11 lets an exception out, or leaves the
# proposal at dispatching). The unit test of R-d fails too (a plain ValueError).
PASS_BEFORE_THE_REPAIR = ("D2", "D5", "D12")
# END PREREGISTERED

#: web.get's conventions, as ``tests/test_web_post_body.py`` uses them (lines 47, 86-97, 404-411).
WEB_PORT = 8080
WEB_PATH = "/inventory"
PROXY = "http://10.82.0.2:3128"
NMAP_STDOUT = "Nmap scan report for 10.82.0.10\nHost is up.\n"
HTTP_REPLY = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"


class RecordingSandbox:
    """Keeps the allowlist of every call; answers as the tool would. Never touches Docker."""

    def __init__(self, stdout: str):
        self.stdout = stdout
        self.allowlists: list[tuple[str, ...]] = []

    def run(self, **kwargs):
        allowlist = tuple(kwargs["network_allowlist"])
        self.allowlists.append(allowlist)
        return SandboxResult(0, self.stdout, "", False, 0.1, allowlist, "recording")


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global",
                    actions={"network.scan": ALLOW, "web.get": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _proposal(engagement_id, registry, scope, action, target):
    scope_type, scope_value = scope
    scope_id = f"SCOPE-NC2-{uuid.uuid4().hex[:8]}"
    registry.scope(scope_object_id=scope_id, type=scope_type, value=scope_value,
                   allowed_actions=[action])
    kind, value = target
    if action == "web.get":
        registry.metadata(
            asset_id=f"ASSET-NC2-{uuid.uuid4().hex[:8]}", identity_type=kind,
            identity_value=value, authority="AUTHORITATIVE", source="customer_declared",
            resource_class=["web_content"], data_class=["network_service"])
        proposal = ProposedAction(
            action="web.get",
            target={"logical_identity": {"type": kind, "value": value},
                    "port": WEB_PORT, "path": WEB_PATH},
            authorization={"source": "engagement_scope", "scope_object_id": scope_id},
            discovery={"source": "explicit_scope"}, writes_data=False, changes_state=False)
    else:
        proposal = sup.proposal_for(scope_id, host=value, action=action, target_type=kind)
    return attach_task(engagement_id, proposal)


def _row(engagement_id, proposal_id):
    with engagement_scope(engagement_id) as conn:
        stage = conn.execute(
            text("SELECT pipeline_stage FROM action_proposals WHERE proposal_id = :p"),
            {"p": proposal_id}).scalar_one()
        runs = conn.execute(
            text("SELECT status FROM tool_runs WHERE proposal_id = :p"),
            {"p": proposal_id}).scalars().all()
    return stage, runs


@pytest.mark.parametrize("case", list(CASES))
def test_a_case_of_the_inline_dispatch_allowlist(case, engagement_id, registry):
    scope, action, target, caller_allowlist, (kind, expected) = CASES[case]
    proposal = _proposal(engagement_id, registry, scope, action, target)
    sandbox = RecordingSandbox(HTTP_REPLY if action == "web.get" else NMAP_STDOUT)
    extra = {"proxy_url": PROXY} if action == "web.get" else {}
    if caller_allowlist is not None:
        extra["network_allowlist"] = caller_allowlist
    try:
        outcome = propose_action(
            engagement_id=engagement_id, proposal=proposal, reviewer=HonestFakeReviewer(),
            policy=_policy(), agent_id="worker-nc2", sandbox=sandbox,
            idempotency_key=f"nc2-{case}-{uuid.uuid4().hex[:8]}", **extra)
    except Exception as exc:  # noqa: BLE001 - no exception may come out of propose_action
        outcome = None
        escaped = f"{type(exc).__name__}: {exc}"
    else:
        escaped = None
    assert escaped is None, (case, "an exception came out of propose_action", escaped)
    assert outcome.decision == "ALLOW", (
        case, "INVALID CASE: the policy did not allow it", outcome.decision,
        outcome.deny_reasons, outcome.approval_reasons)
    stage, runs = _row(engagement_id, outcome.proposal_id)
    if kind == "dispatch":
        assert sandbox.allowlists == [expected], (case, sandbox.allowlists)
        assert outcome.run_id and outcome.evidence_id, (case, outcome.failure)
    else:
        assert sandbox.allowlists == [], (case, "the sandbox was called", sandbox.allowlists)
        assert outcome.run_id is None, (case, outcome.run_id)
        assert outcome.failure == expected, (case, outcome.failure)
        assert stage == "closed", (case, stage)
        assert runs == [], (case, runs)


class _RecordingClient:
    """Stands for the Docker client: records every attribute anything asks of it."""

    def __init__(self):
        self.asked: list[str] = []

    def __getattr__(self, name):
        self.asked.append(name)
        raise AssertionError(f"Docker was used: {name}")


def test_the_sandbox_turns_a_non_cidr_allowlist_into_not_started_before_docker():
    """R-d: ``validate_allowlist``'s ValueError becomes the base ``NotStarted``
    (``sandbox_not_started``), with its message, before any Docker object is touched."""
    client = _RecordingClient()
    sandbox = DockerSandbox(_client=client)
    try:
        sandbox.run(command=["true"], network_allowlist=["dc99.lure.example"],
                    max_duration_seconds=5, deadline_helper=None)
    except Exception as exc:  # noqa: BLE001 - which exception it is, is what is asserted
        raised = exc
    else:
        raised = None
    assert isinstance(raised, NotStarted), type(raised)
    assert raised.reason == "sandbox_not_started"
    assert "is not a CIDR" in str(raised)
    assert client.asked == []
