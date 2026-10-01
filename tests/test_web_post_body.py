"""How a proposal carries a ``web.post`` body, and the two halves of ACCEPTANCE 5.29.

``docs/D53_5_29_WEB_POST_BODY_ANALYSIS.md`` found that ``web.post`` could not be
reached through ``propose_action`` at all: ``execution_constraints`` carried
neither ``body`` nor ``content_type``, so ``http_post.build_plan`` raised on every
capability. The decision (5.29, option C): a body is *Worker-authored, constructed
test data*. It is never a real secret -- the D44 vault is the one sanctioned way a
real secret enters an execution path -- and that is enforced where it can be, at
propose time, by refusing (not redacting) a body that matches a known secret
*format*. Refusing before anything is persisted matters: a body that reached the
proposal row, the reviewer's prompt or the audit trail would already have leaked
to the surfaces the analysis (section 2.4) lists.

This file covers, in order: the carry (and that it did not widen anyone else's
constraints); the refusal, at propose time, with proof nothing was persisted,
reviewed or run; the false-positive controls (a normal form or JSON body, and
constructed test credentials, must pass); the approval route agreeing with the
ALLOW route (D30); and the end-to-end runs for both halves of 5.29 -- ``web.post``
with a body, and ``web.get``, which no committed test had driven past policy.
"""

from __future__ import annotations

import inspect
import json

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import execution_constraints, propose_action
from control_plane.capability.broker import Budget
from control_plane.evidence import redaction
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.state.db import engagement_scope
from tool_gateway.adapters import http_post
from tool_gateway.sandbox import SandboxResult

ALLOWED_CIDR = "10.87.0.0/24"
TARGET_IP = "10.87.0.10"
TARGET_PORT = 8080
PROXY = "http://10.87.0.2:3128"

#: Constructed by the test, never a real credential -- and shaped like no known
#: secret format, which is the whole point of the false-positive controls.
FORM_BODY = "username=alice&password=Test1234&csrf=abc123&comment=hello+world"
JSON_BODY = json.dumps(
    {"username": "alice", "password": "Test1234", "remember": True, "items": [1, 2, 3]}
)

#: One body per format ``redaction`` recognises by shape (its whole-match patterns).
#: Assembled from parts so this file does not itself contain a scannable secret.
_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"
_JWT = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0",
                 "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"])
_BEARER = "Bearer " + "abcdefghijklmnopqrstuvwxyz0123456789"
_PEM = ("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1"
        "\n-----END RSA " + "PRIVATE KEY-----")
SECRET_BODIES = {
    "aws-access-key-id": f"note={_AKIA}",
    "jwt-like-token": f"token_value={_JWT}",
    "bearer-token": f"authorization={_BEARER}",
    "private-key-block": f"key={_PEM}",
    "credential-in-url": "callback=https://svc-account:hunter2hunter2@internal.example/hook",
}


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------

def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset({"PII"}),
                    actions={"web.post": ALLOW, "web.get": ALLOW}),
        PolicyLayer(name="emergency_overlay"), PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _authorize(registry, engagement_id, *, classified=True):
    scope_id = f"SCOPE-{engagement_id[-10:]}"
    registry.scope(scope_object_id=scope_id, type="cidr", value=ALLOWED_CIDR,
                   allowed_actions=["web.post", "web.get"])
    if classified:
        registry.metadata(
            asset_id=f"ASSET-{engagement_id[-10:]}", identity_type="ip",
            identity_value=TARGET_IP, authority="AUTHORITATIVE",
            source="customer_declared", resource_class=["web_content"],
            data_class=["network_service"],
        )
    return scope_id


class _CurlStubSandbox:
    """Records what dispatch would run, and answers with a canned HTTP reply."""

    image = "cyberorch-tool:test"

    def __init__(self, reply="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"):
        self.runs: list[dict] = []
        self.reply = reply

    def run(self, **kwargs):
        self.runs.append(kwargs)
        return SandboxResult(
            exit_code=0, stdout=self.reply, stderr="", timed_out=False,
            duration_seconds=0.1, network_allowlist=list(kwargs["network_allowlist"]),
            image=self.image,
        )


class _SpyReviewer(HonestFakeReviewer):
    """Counts how often the reviewer LLM is shown a proposal."""

    def __init__(self):
        super().__init__(risk_hint="low")
        self.seen: list[ProposedAction] = []

    def review(self, *, proposal, canonical_target):
        self.seen.append(proposal)
        return super().review(proposal=proposal, canonical_target=canonical_target)


def _post_proposal(scope_id, **target_extra):
    return ProposedAction(
        action="web.post",
        target={"logical_identity": {"type": "ip", "value": TARGET_IP},
                "port": TARGET_PORT, "path": "/submit", **target_extra},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        writes_data=True, changes_state=True,
    )


def _propose(engagement_id, proposal, *, sandbox=None, reviewer=None):
    sandbox = sandbox if sandbox is not None else _CurlStubSandbox()
    reviewer = reviewer if reviewer is not None else _SpyReviewer()
    with engagement_scope(engagement_id) as conn:
        outcome = propose_action(
            conn, engagement_id=engagement_id, proposal=proposal, reviewer=reviewer,
            policy=_policy(), agent_id="worker-1", sandbox=sandbox,
            network_allowlist=[ALLOWED_CIDR], proxy_url=PROXY,
            budget=Budget(max_duration_seconds=60),
        )
    return outcome, sandbox, reviewer


def _rows(engagement_id, sql, **params):
    with engagement_scope(engagement_id) as conn:
        return conn.execute(text(sql), params).mappings().all()


# ---------------------------------------------------------------------------
# 1. The carry
# ---------------------------------------------------------------------------

def test_execution_constraints_carry_the_body_and_content_type():
    """The bug the D53 report named: neither key reached ``build_plan``."""
    constraints = execution_constraints(
        {"port": TARGET_PORT, "path": "/submit", "body": FORM_BODY,
         "content_type": "application/x-www-form-urlencoded"}, TARGET_IP)
    assert constraints["body"] == FORM_BODY
    assert constraints["content_type"] == "application/x-www-form-urlencoded"
    # ...and what it hands over is now enough for the adapter to build a plan.
    plan = http_post.build_plan(constraints=constraints, budget={}, target=TARGET_IP,
                                proxy_url=PROXY)
    assert plan.stdin == FORM_BODY


def test_execution_constraints_grow_no_body_keys_for_a_proposal_that_names_none():
    """Same rule as port/path/scheme: carried only when the proposal said so."""
    assert "body" not in execution_constraints({"port": 80}, TARGET_IP)
    assert "content_type" not in execution_constraints({"port": 80}, TARGET_IP)
    scan = execution_constraints({"ports": "22,80", "scan_type": "connect"}, TARGET_IP)
    assert set(scan) == {"host", "ports", "scan_type"}


# ---------------------------------------------------------------------------
# 2. The refusal, at propose time
# ---------------------------------------------------------------------------

def test_the_detector_is_the_redactors_own_pattern_list():
    """One list of secret shapes (the D25 rule): the detector reads the same
    patterns ``redact_snippet`` applies, so a format added there is refused here."""
    assert redaction.KNOWN_SECRET_FORMATS == tuple(
        label for label, _ in redaction._WHOLE_MATCH_PATTERNS)
    for label, body in SECRET_BODIES.items():
        assert label in redaction.detect_secret_formats(body), label
        # And the redactor, given the same text, handles the same shape.
        assert label in redaction.redact_snippet(body).patterns_matched, label


@pytest.mark.parametrize("label", sorted(SECRET_BODIES))
def test_a_body_in_a_known_secret_format_is_refused_at_propose_time(
    engagement_id, registry, label
):
    scope_id = _authorize(registry, engagement_id)
    body = SECRET_BODIES[label]
    outcome, sandbox, reviewer = _propose(
        engagement_id, _post_proposal(scope_id, body=body))

    assert outcome.decision == "DENY"
    assert "body_contains_secret_format" in outcome.deny_reasons
    assert label in outcome.failure          # names the format...
    assert body not in outcome.failure       # ...never the value
    # Nothing downstream of the refusal ran.
    assert sandbox.runs == []
    assert outcome.capability_id is None and outcome.run_id is None


@pytest.mark.parametrize("label", sorted(SECRET_BODIES))
def test_a_refused_body_is_never_persisted_reviewed_or_audited(
    engagement_id, registry, label
):
    """The analysis (2.4) lists where a carried body lands: the proposal row, the
    reviewer's prompt, the approval record, the audit trail. Refusing *before*
    ``_persist_proposal`` is what keeps a secret-shaped body off all of them --
    a check placed after the reviewer would have refused too late."""
    scope_id = _authorize(registry, engagement_id)
    body = SECRET_BODIES[label]
    _, _, reviewer = _propose(engagement_id, _post_proposal(scope_id, body=body))

    assert reviewer.seen == [], "the reviewer LLM was shown a secret-shaped body"
    assert _rows(engagement_id, "SELECT 1 FROM action_proposals") == []
    audit = _rows(engagement_id, "SELECT event_type, reasons, payload::text AS p "
                                 "FROM audit_log WHERE event_type LIKE 'proposal.%'")
    assert [r["event_type"] for r in audit] == ["proposal.rejected"]
    assert audit[0]["reasons"] == ["body_contains_secret_format"]
    assert body not in audit[0]["p"]
    assert label in audit[0]["p"]            # the format is recorded, the value is not


def test_a_secret_hidden_by_url_encoding_is_refused_too():
    """``application/x-www-form-urlencoded`` is a default content type, and
    ``Bearer%20<token>`` is the same bearer token. A detector that only read the
    raw string would be passed by the encoding alone."""
    from control_plane.api import function_api

    encoded = "authorization=Bearer%20" + "abcdefghijklmnopqrstuvwxyz0123456789"
    assert redaction.detect_secret_formats(encoded) == (), "the control: raw is blind"
    assert function_api.body_secret_formats(encoded) == ("bearer-token",)
    plus = "authorization=Bearer+" + "abcdefghijklmnopqrstuvwxyz0123456789"
    assert function_api.body_secret_formats(plus) == ("bearer-token",)


@pytest.mark.parametrize("bad, reason_fragment", [
    ({"body": {"user": "alice"}}, "must be a string"),
    ({"body": "x" * (http_post.MAX_REQUEST_BODY_BYTES + 1)}, "over the"),
    ({"body": "a=1", "content_type": "multipart/form-data"}, "is not one of"),
])
def test_a_body_the_adapter_would_refuse_is_refused_at_propose_time(
    engagement_id, registry, bad, reason_fragment
):
    """The size ceiling and content-type allowlist were already the adapter's;
    they now apply where the proposal enters, not only when a plan is built."""
    scope_id = _authorize(registry, engagement_id)
    outcome, sandbox, reviewer = _propose(engagement_id, _post_proposal(scope_id, **bad))
    assert outcome.decision == "DENY"
    assert outcome.deny_reasons == ("web_post_body_invalid",)
    assert reason_fragment in outcome.failure
    assert sandbox.runs == [] and reviewer.seen == []


# ---------------------------------------------------------------------------
# 3. No over-defence: normal bodies and constructed test values pass
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body, content_type", [
    (FORM_BODY, "application/x-www-form-urlencoded"),
    (JSON_BODY, "application/json"),
    ("hello, this is a plain text note", "text/plain"),
    # A constructed test credential is the intended use, in either common shape.
    ("username=alice&password=hunter2", "application/x-www-form-urlencoded"),
    ('{"password": "hunter2", "api_key": "test-key-0001"}', "application/json"),
    # Longer than the redactor's 160-column display cap: a cap is a display
    # backstop, not a secret format, and must not refuse an ordinary long body.
    ("field=" + "v" * 400, "application/x-www-form-urlencoded"),
    ("\n".join(f"line{i}=value{i}" for i in range(50)), "text/plain"),
])
def test_ordinary_and_constructed_bodies_are_not_refused(body, content_type):
    from control_plane.api import function_api
    assert function_api.body_secret_formats(body) == ()
    assert not redaction.detect_secret_formats(body)


def test_an_ordinary_body_runs_end_to_end_and_reaches_curl_unmodified(
    engagement_id, registry
):
    """Constructed values build a plan and run: ALLOW through the real entry point,
    the body on curl's stdin byte for byte (never redacted, never truncated -- what
    is approved is what is sent, D30), and the sigil fixed at ``@-``."""
    scope_id = _authorize(registry, engagement_id)
    body = FORM_BODY + "&pad=" + "v" * 400          # over 160 columns on purpose
    outcome, sandbox, reviewer = _propose(
        engagement_id,
        _post_proposal(scope_id, body=body, content_type="application/x-www-form-urlencoded"),
    )

    assert outcome.decision == "ALLOW", (outcome.deny_reasons, outcome.approval_reasons,
                                         outcome.failure)
    assert outcome.run_id and outcome.evidence_id
    assert len(sandbox.runs) == 1
    run = sandbox.runs[0]
    assert run["stdin"] == body
    command = run["command"]
    assert command[command.index("--request") + 1] == "POST"
    assert command[command.index("--data-binary") + 1] == "@-"
    assert "Content-Type: application/x-www-form-urlencoded" in command
    assert not any(body in part for part in command), "the body reached argv"
    assert len(reviewer.seen) == 1                    # the reviewer still sees it
    assert reviewer.seen[0].target["body"] == body

    (run_row,) = _rows(engagement_id, "SELECT tool, normalized_params FROM tool_runs")
    assert run_row["tool"] == "curl"
    assert run_row["normalized_params"]["body"] == body
    assert run_row["normalized_params"]["method"] == "POST"
    (evidence,) = _rows(engagement_id, "SELECT tool, derived_view FROM evidence")
    assert evidence["derived_view"]["untrusted_content"] is True
    started = _rows(engagement_id, "SELECT payload::text AS p FROM audit_log "
                                   "WHERE event_type = 'tool_run.started'")
    assert body not in started[0]["p"], "the body reached the started-run audit payload"


def test_two_different_bodies_are_two_different_runs(engagement_id, registry):
    """The body is in the fingerprint (http_post.as_params): a second POST with a
    different body must not dedup into the first."""
    scope_id = _authorize(registry, engagement_id)
    a, sandbox_a, _ = _propose(engagement_id, _post_proposal(scope_id, body="q=one"))
    b, sandbox_b, _ = _propose(engagement_id, _post_proposal(scope_id, body="q=two"))
    assert a.decision == b.decision == "ALLOW"
    assert len(sandbox_a.runs) == 1 and len(sandbox_b.runs) == 1
    assert a.run_id != b.run_id


# ---------------------------------------------------------------------------
# 4. The approval route describes the same body (D30)
# ---------------------------------------------------------------------------

def test_the_approval_route_carries_and_describes_the_same_body(engagement_id, registry):
    """An unclassified target sends web.post to HUMAN_APPROVAL. The approval record
    (section 4.7) and the capability granted from it are derived by the same
    ``execution_constraints`` call as the ALLOW route, from the *persisted* row --
    so the body survives the round trip through ``action_proposals.target``."""
    from control_plane.api import approvals

    scope_id = _authorize(registry, engagement_id, classified=False)
    outcome, sandbox, _ = _propose(
        engagement_id,
        _post_proposal(scope_id, body=FORM_BODY,
                       content_type="application/x-www-form-urlencoded"),
    )
    assert outcome.decision == "HUMAN_APPROVAL"
    assert sandbox.runs == []

    with engagement_scope(engagement_id) as conn:
        preview = approvals.preview_approval(conn, proposal_id=outcome.proposal_id)
        pending = approvals.list_pending_approvals(conn, engagement_id=engagement_id)
    # What the human is shown to approve carries the body...
    assert preview["constraints"]["body"] == FORM_BODY
    assert preview["constraints"]["content_type"] == "application/x-www-form-urlencoded"
    assert pending[0]["target"]["body"] == FORM_BODY

    # ...and the capability granted from it carries the very same one.
    with engagement_scope(engagement_id) as conn:
        granted = approvals.grant_approval(
            conn, engagement_id=engagement_id, proposal_id=outcome.proposal_id,
            approver="alice", approved_scope="this_proposal_only")
    assert granted.issued, granted.reasons
    (cap,) = _rows(engagement_id, "SELECT constraints FROM capabilities "
                                  "WHERE capability_id = :c", c=granted.capability_id)
    assert cap["constraints"]["body"] == FORM_BODY
    assert cap["constraints"]["content_type"] == "application/x-www-form-urlencoded"
    assert preview["constraints"]["body"] == cap["constraints"]["body"]


# ---------------------------------------------------------------------------
# 5. web.get, the other half of 5.29
# ---------------------------------------------------------------------------

def test_web_get_runs_end_to_end_through_propose_action(engagement_id, registry):
    """No committed test had driven ``web.get`` past the policy decision: both
    ``test_http_get.py`` and ``test_web_post.py`` used a sandbox that raises
    ``SandboxUnavailable`` ("dispatch is not what this test measures"). This one
    goes canonicalize -> authorize -> classify -> OPA -> broker -> Tool Gateway ->
    ``build_plan`` -> sandbox -> evidence, the chain D37 walked for ``web.render``."""
    scope_id = _authorize(registry, engagement_id)
    sandbox = _CurlStubSandbox(
        reply="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>inventory</html>")
    proposal = ProposedAction(
        action="web.get",
        target={"logical_identity": {"type": "ip", "value": TARGET_IP},
                "port": TARGET_PORT, "path": "/inventory"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        writes_data=False, changes_state=False,
    )
    outcome, sandbox, _ = _propose(engagement_id, proposal, sandbox=sandbox)

    assert outcome.decision == "ALLOW", (outcome.deny_reasons, outcome.approval_reasons,
                                         outcome.failure)
    assert outcome.run_id and outcome.evidence_id
    (run,) = sandbox.runs
    command = run["command"]
    assert command[command.index("--request") + 1] == "GET"
    assert command[-1] == f"http://{TARGET_IP}:{TARGET_PORT}/inventory"
    assert "--proxy" in command and PROXY in command
    assert "--data-binary" not in command and not run.get("stdin")
    (run_row,) = _rows(engagement_id, "SELECT tool, normalized_params FROM tool_runs")
    assert run_row["tool"] == "curl"
    assert run_row["normalized_params"]["method"] == "GET"
    assert run_row["normalized_params"]["url"].endswith("/inventory")
    (evidence,) = _rows(engagement_id, "SELECT derived_view FROM evidence")
    assert evidence["derived_view"]["status_code"] == 200
    assert evidence["derived_view"]["untrusted_content"] is True


def test_web_get_carries_no_body_even_if_a_proposal_names_one(engagement_id, registry):
    """``body`` is now a carried key, so the GET adapter must be shown to ignore it:
    a Worker cannot turn a GET into a request with a body by naming one."""
    scope_id = _authorize(registry, engagement_id)
    proposal = ProposedAction(
        action="web.get",
        target={"logical_identity": {"type": "ip", "value": TARGET_IP},
                "port": TARGET_PORT, "path": "/inventory", "body": "q=smuggled"},
        authorization={"source": "engagement_scope", "scope_object_id": scope_id},
        discovery={"source": "explicit_scope"},
        writes_data=False, changes_state=False,
    )
    outcome, sandbox, _ = _propose(engagement_id, proposal)
    assert outcome.decision == "ALLOW"
    (run,) = sandbox.runs
    assert "q=smuggled" not in " ".join(run["command"])
    assert not run.get("stdin")
    assert "--data-binary" not in run["command"]


# ---------------------------------------------------------------------------
# 6. What this is *not*: real credentials go through the D44 vault
# ---------------------------------------------------------------------------

def test_the_vault_has_no_delivery_path_for_a_web_post_body():
    """Pinned so the wording in the docs ("a real credential in a POST is not
    supported yet; the route is a D44 extension, not something this change
    provides") stays true, and fails loudly the day someone builds that route --
    at which point the docs, and section 2.4's surfaces, must be revisited."""
    from control_plane.orchestrator import dispatch
    from control_plane.vault import vault

    assert vault.CREDENTIAL_TYPES == ("ad_domain_bind", "git_token")
    source = inspect.getsource(dispatch.dispatch_scan)
    assert "credential_id" not in source and "vault" not in source, (
        "dispatch_scan now resolves a credential: the web.post analysis and "
        "ADR_CREDENTIAL_VAULT.md must be updated (ACCEPTANCE 5.29)")
