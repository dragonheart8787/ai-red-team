"""code.secrets through the real propose_action entry point, real container (D55, D47/D48).

Every layer of D42 and D43 was green and none had been driven through
``propose_action``, the one real entry point; D45 found four bugs the first time
one was. So the first Gitleaks test is the whole chain, once, for real:

    propose_action -> OPA -> Capability Broker -> dispatch_code_scan ->
    control-plane git fetch (bare, depth N) -> real gitleaks in a real container ->
    evidence write -> audit trail

with the repository the tool exists for: a secret that was committed and then
removed, present in **no file at the tip**. Reading the tree finds nothing.

Assertions are the ones each earlier tool learned to make rather than "it ran":
the constraint reached the built command (D37, D45), the resolved commit reached
the fingerprint (D43), the evidence id carries this tool's prefix (D53), and --
this tool's own -- the secret is nowhere: not in the raw artifact, not in the
derived view, not in any audit payload.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from agents.base_agent import ProposedAction
from agents.fake.adversarial_fake_reviewer import HonestFakeReviewer
from control_plane.api.function_api import propose_action
from control_plane.capability.broker import Budget
from control_plane.policy.layers import publish_policy_layer
from control_plane.policy.merge import ALLOW, PolicyLayer, merge_policy
from control_plane.registry.metadata_registry import register_metadata
from control_plane.registry.scope_registry import register_scope_object
from control_plane.state.db import engagement_scope, registry_admin_scope
from tests.gitleaks_support import (
    CANARY,
    HistoryRepo,
    history_only_secret_repo,
    real_sandbox,
    suppression_repo,
)
from tool_gateway.adapters import gitleaks

ACTOR = "test-harness"


@pytest.fixture(scope="module")
def sandbox():
    return real_sandbox()


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _policy():
    return merge_policy(
        PolicyLayer(name="baseline_global", data_deny=frozenset(), actions={"code.secrets": ALLOW}),
        PolicyLayer(name="emergency_overlay"),
        PolicyLayer(name="customer"),
        PolicyLayer(name="engagement"),
    )


def _setup(engagement_id: str, repo_value: str, *, classified: bool = True) -> str:
    """A real repo scope for ``code.secrets`` and, unless ``classified`` is False, the
    AUTHORITATIVE classification ``code.*`` requires -- real registry writes throughout."""
    scope_object_id = _uid("SCOPE")
    with registry_admin_scope(engagement_id) as conn:
        register_scope_object(
            conn, engagement_id=engagement_id, scope_object_id=scope_object_id,
            type="repo", value=repo_value, allowed_actions=[gitleaks.ACTION], actor=ACTOR,
        )
        if classified:
            register_metadata(
                conn, engagement_id=engagement_id, asset_id=_uid("ASSET"),
                identity_type="repo", identity_value=repo_value,
                authority="AUTHORITATIVE", source="customer_declared",
                resource_class=["source_code"], data_class=["proprietary_source"],
                actor=ACTOR,
            )
    with engagement_scope(engagement_id) as conn:
        publish_policy_layer(
            conn, engagement_id=engagement_id, layer="engagement", version=1,
            document={"actions": {gitleaks.ACTION: "ALLOW"}}, actor=ACTOR,
            scoped_to_engagement=True,
        )
    return scope_object_id


def _propose(engagement_id, sandbox, repo_value, scope_object_id, **target_extra):
    proposal = ProposedAction(
        action=gitleaks.ACTION,
        target={"logical_identity": {"type": "repo", "value": repo_value}, **target_extra},
        authorization={"source": "engagement_scope", "scope_object_id": scope_object_id},
        discovery={"source": "explicit_scope"},
        resources=("source_code",), expected_data=("finding",),
        reason="D55 permanent propose_action regression test",
    )
    with engagement_scope(engagement_id) as conn:
        return propose_action(
            conn, engagement_id=engagement_id, proposal=proposal,
            reviewer=HonestFakeReviewer(), policy=_policy(), agent_id="test-worker",
            actor=ACTOR, sandbox=sandbox, network_allowlist=["10.0.0.0/8"],
            budget=Budget(max_duration_seconds=90),
        )


def _run_row(engagement_id, run_id):
    with engagement_scope(engagement_id) as conn:
        return conn.execute(
            text("SELECT tool, tool_version, ruleset_version, normalized_params, "
                 "execution_context, status FROM tool_runs WHERE run_id = :r"),
            {"r": run_id},
        ).mappings().one()


def _view(engagement_id, evidence_id):
    with engagement_scope(engagement_id) as conn:
        return conn.execute(
            text("SELECT derived_view FROM evidence WHERE evidence_id = :e"),
            {"e": evidence_id},
        ).scalar_one()


def _everything_stored_about(engagement_id: str, evidence_id: str) -> str:
    """Every byte this run left in the system that a person or a model could read."""
    with engagement_scope(engagement_id) as conn:
        path = conn.execute(
            text("SELECT raw_artifact_path FROM evidence WHERE evidence_id = :e"),
            {"e": evidence_id},
        ).scalar_one()
        view = conn.execute(
            text("SELECT derived_view::text FROM evidence WHERE evidence_id = :e"),
            {"e": evidence_id},
        ).scalar_one()
        audit = conn.execute(
            text("SELECT string_agg(payload::text, ' ') FROM audit_log "
                 "WHERE engagement_id = :eng"),
            {"eng": engagement_id},
        ).scalar_one() or ""
    return Path(path).read_bytes().decode("utf-8", "replace") + view + audit


def test_code_secrets_runs_end_to_end_through_propose_action(engagement_id, sandbox, tmp_path):
    repo: HistoryRepo = history_only_secret_repo(tmp_path / "repo", filler_commits=3)
    scope_object_id = _setup(engagement_id, repo.scope_value)

    outcome = _propose(
        engagement_id, sandbox, repo.scope_value, scope_object_id, history_depth=20,
    )

    assert outcome.decision == "ALLOW", outcome.deny_reasons
    assert outcome.capability_id and outcome.run_id and outcome.evidence_id
    assert outcome.evidence_id.startswith("SECRETS-"), "EVIDENCE_PREFIX (D53)"

    # execution_constraints carried history_depth onto the issued capability (D37/D45 class)...
    with engagement_scope(engagement_id) as conn:
        constraints = conn.execute(
            text("SELECT constraints FROM capabilities WHERE capability_id = :c"),
            {"c": outcome.capability_id},
        ).scalar_one()
        command = conn.execute(
            text("SELECT payload->'command' FROM audit_log WHERE subject_id = :r "
                 "AND event_type = 'tool_run.started'"),
            {"r": outcome.run_id},
        ).scalar_one()
        events = [r[0] for r in conn.execute(
            text("SELECT event_type FROM audit_log WHERE subject_id = :r ORDER BY audit_id"),
            {"r": outcome.run_id},
        ).all()]
    assert constraints["history_depth"] == 20
    # ...and the depth is what the tool run recorded as its parameter, and every pinned
    # flag is in the command that was audited before it ran.
    row = _run_row(engagement_id, outcome.run_id)
    assert row["normalized_params"]["history_depth"] == 20
    for flag in ("--redact=100", "--ignore-gitleaks-allow", "--no-banner"):
        assert flag in command
    assert command[:2] == ["/usr/bin/gitleaks", "git"]

    # dispatch_code_scan, not dispatch_scan, was reached: only its fetch can populate these.
    assert row["tool"] == "gitleaks" and row["status"] == "succeeded", row
    assert row["tool_version"] == gitleaks.tool_version()
    assert row["ruleset_version"] == gitleaks.ruleset_version()
    assert row["execution_context"]["commit_sha"] == repo.tip
    assert row["execution_context"]["branch"] == "main"

    # The finding: history-only, at the commit that added it, and complete.
    view = _view(engagement_id, outcome.evidence_id)
    assert view["scan_complete"] is True and view["history_complete"] is True
    assert view["finding_count"] == 1 and view["findings_by_rule"] == {"github-pat": 1}
    note = view["notable_findings"][0]
    assert note["commit"] == repo.secret_commit and note["path"] == "config.env"
    assert repo.secret_commit != repo.tip
    assert view["untrusted_content"] is True and view["first_party_source_content"] is True

    # The secret is nowhere: raw artifact, derived view, every audit payload.
    stored = _everything_stored_about(engagement_id, outcome.evidence_id)
    assert CANARY not in stored and CANARY[4:] not in stored
    assert stored.count("github-pat") >= 1, "the control: the finding itself is recorded"

    # The audit trail: started before it finished, both about this run.
    assert events[0] == "tool_run.started" and "tool_run.succeeded" in events
    assert json.dumps(events)  # plain list of strings


def test_history_depth_decides_what_is_seen_and_the_view_says_so(engagement_id, sandbox, tmp_path):
    """A depth that cuts before the secret finds nothing -- and says the history was cut."""
    repo = history_only_secret_repo(tmp_path / "repo", filler_commits=6)
    scope_object_id = _setup(engagement_id, repo.scope_value)

    shallow = _propose(engagement_id, sandbox, repo.scope_value, scope_object_id, history_depth=3)
    assert shallow.decision == "ALLOW", shallow.deny_reasons
    view = _view(engagement_id, shallow.evidence_id)
    assert view["finding_count"] == 0
    assert view["scan_complete"] is True
    assert view["history_complete"] is False, (
        "'no findings' from a scan that stopped 4 commits short of the secret must not read "
        "as 'clean'"
    )

    deep = _propose(engagement_id, sandbox, repo.scope_value, scope_object_id, history_depth=50)
    assert deep.run_id != shallow.run_id, "a different depth is a different scan (fingerprint)"
    view = _view(engagement_id, deep.evidence_id)
    assert view["finding_count"] == 1 and view["history_complete"] is True

    # The default depth applies only when the proposal says nothing.
    default = _propose(engagement_id, sandbox, repo.scope_value, scope_object_id)
    assert default.decision == "ALLOW"
    assert _run_row(engagement_id, default.run_id)["normalized_params"]["history_depth"] == 100


def test_an_unclassified_repository_is_not_scanned_unattended(engagement_id, sandbox, tmp_path):
    """D43-3 carried (ADR §2), end to end: no classification -> a human, and no run."""
    repo = history_only_secret_repo(tmp_path / "repo")
    scope_object_id = _setup(engagement_id, repo.scope_value, classified=False)

    outcome = _propose(engagement_id, sandbox, repo.scope_value, scope_object_id)

    assert outcome.decision == "HUMAN_APPROVAL"
    assert "unknown_classification_for_action_class" in outcome.approval_reasons
    assert outcome.run_id is None


@pytest.mark.parametrize("channel", ["toml", "ignorefile", "inline"])
def test_a_repository_cannot_suppress_its_own_finding_through_the_real_pipeline(
    engagement_id, sandbox, tmp_path, channel,
):
    """The suppression carriers (tests/test_gitleaks_injection.py), through the production
    wiring rather than a helper that hard-codes the defences: `dispatch_code_scan` decides
    bare-or-not and the command, so this is the test that fails when *it* loses them."""
    repo = suppression_repo(tmp_path / "repo", channel)
    value = f"file://{repo}#main"
    scope_object_id = _setup(engagement_id, value)

    outcome = _propose(engagement_id, sandbox, value, scope_object_id)

    assert outcome.decision == "ALLOW", outcome.deny_reasons
    view = _view(engagement_id, outcome.evidence_id)
    assert view["finding_count"] == 1, f"a {channel} suppression hid the repository's secret"
    assert view["scan_complete"] is True
