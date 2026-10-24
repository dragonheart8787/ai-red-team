"""``publish --dry-run`` (D68 DP-15 record mode): every check of a publication, nothing published.

The drafted record-mode layer (``docs/D68_DP15_RECORD_MODE/layer_record_mode.json``) is
validated here the way the operator will validate it before publishing. Nothing in this module
publishes a layer: the database is compared before and after, and no audit record is written.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import text

from control_plane.policy.layers import PolicyLayerError, publish_policy_layer
from control_plane.policy.merge import (
    EmergencyOverlayError,
    PolicyLayer,
    merge_policy,
)
from control_plane.state.db import global_auditor_scope, global_policy_admin_scope
from scripts import manage_global_policy as tool

REPO = Path(__file__).resolve().parents[1]
DRAFT = REPO / "docs" / "D68_DP15_RECORD_MODE" / "layer_record_mode.json"
CLASSES = ["code.scan", "code.secrets", "network.scan"]


def state():
    """What a publication would change: layers (all, active), the newest id, the audit events of
    publications."""
    with global_policy_admin_scope() as conn:
        layers = tuple(conn.execute(text(
            "SELECT count(*), coalesce(max(id), 0), count(*) FILTER (WHERE active) "
            "FROM policy_layers")).one())
    with global_auditor_scope() as conn:
        audits = conn.execute(text(
            "SELECT count(*) FROM audit_log WHERE event_type = 'policy_layer.published'"
        )).scalar_one()
    return layers, audits


def dry(layer, document, actor="dry-run-test"):
    with global_policy_admin_scope() as conn:
        return publish_policy_layer(
            conn, engagement_id=None, layer=layer, version=1, document=document, actor=actor,
            scoped_to_engagement=False, dry_run=True)


def test_the_drafted_layer_lists_exactly_the_code_actions_and_network_scan_and_enforces_nothing():
    document = json.loads(DRAFT.read_text())
    assert document == {"goal_fit_actions": CLASSES}
    layer = PolicyLayer.from_document("emergency_overlay", document)
    empty = PolicyLayer(name="empty")
    effective = merge_policy(empty, layer, empty, empty)
    assert effective.goal_fit_actions == set(CLASSES)
    assert effective.goal_fit_enforce is False and effective.task_relation_enforce is False


def test_the_names_in_the_draft_are_the_gateways_own():
    """code.* are the two the tool gateway can run, and network.scan is one of the two nmap
    actions; a name that no adapter implements would list a class that never has traffic."""
    from tool_gateway.registry import ADAPTERS

    code = sorted(a for a in ADAPTERS if a.startswith("code."))
    assert code == ["code.scan", "code.secrets"]
    assert all(a in ADAPTERS for a in CLASSES)
    assert "network.recon" not in CLASSES and "ad.collect" not in CLASSES


@pytest.mark.parametrize("layer", ["emergency_overlay", "baseline_global"])
def test_a_dry_run_of_the_draft_is_accepted_and_changes_nothing(layer):
    before = state()
    assert dry(layer, json.loads(DRAFT.read_text())) == 0
    assert state() == before


def test_a_dry_run_moves_no_policy_version_and_so_voids_no_waiting_approval():
    """The policy version is the highest id among the active global layers (and the engagement's
    own): a publication raises it and voids every waiting approval (ACCEPTANCE 5.124). A dry run
    leaves the maximum where it was."""
    def version():
        with global_policy_admin_scope() as conn:
            return conn.execute(text(
                "SELECT coalesce(max(id), 0) FROM policy_layers "
                "WHERE active IS TRUE AND engagement_id IS NULL")).scalar_one()

    before = version()
    for layer in ("emergency_overlay", "baseline_global"):
        dry(layer, json.loads(DRAFT.read_text()))
    assert version() == before


def test_a_dry_run_refuses_what_a_publication_refuses():
    before = state()
    for layer, document, error in (
            ("emergency_overlay", {"goal_fit_actions": "code.scan"}, PolicyLayerError),
            ("emergency_overlay", {"goal_fit_actions": ["Code.Scan"]}, PolicyLayerError),
            ("emergency_overlay", {"goal_fit_actions": CLASSES, "goal_fit_enforce": "yes"},
             PolicyLayerError),
            # an overlay may only turn the switch on, so "enforce off" is not written into it
            ("emergency_overlay", {"goal_fit_actions": CLASSES, "goal_fit_enforce": False},
             EmergencyOverlayError),
            ("emergency_overlay", {"actions": {"network.scan": "ALLOW"}}, EmergencyOverlayError)):
        with pytest.raises(error):
            dry(layer, document)
    assert state() == before


def test_a_dry_run_hits_the_databases_own_checks_not_only_the_codes():
    """The overlay's tighten-only CHECK is the database's; the dry run reaches it by attempting the
    INSERT in a savepoint, so a document the code lets through but the table refuses fails here."""
    from sqlalchemy.exc import DBAPIError

    before = state()
    with pytest.raises(DBAPIError):
        with global_policy_admin_scope() as conn:
            attempt = conn.begin_nested()
            try:
                conn.execute(text(
                    "INSERT INTO policy_layers (layer, version, document, active) VALUES "
                    "('emergency_overlay', 1, '{\"actions\": {\"network.scan\": \"ALLOW\"}}', "
                    "TRUE)"))
            finally:
                attempt.rollback()
    assert state() == before


def run_cli(args, capsys):
    code = tool.main(args)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_command_line_dry_run_lists_the_classes_and_publishes_nothing(capsys):
    before = state()
    code, out, err = run_cli(
        ["publish", "--layer", "emergency_overlay", "--version", "1", "--document-file",
         str(DRAFT), "--actor", "dry-run-test", "--dry-run"], capsys)
    assert code == 0 and err == ""
    assert "DRY RUN" in out and "would be accepted" in out
    for action in CLASSES:
        assert action in out
    assert "goal_fit_enforce in this document: False" in out
    assert "Nothing was published, audited or changed." in out
    assert state() == before


def test_the_command_line_dry_run_does_not_ask_for_a_confirmation(capsys, monkeypatch):
    monkeypatch.setattr(tool, "_confirm", lambda *a, **k: pytest.fail("a dry run confirms nothing"))
    code, _, _ = run_cli(
        ["publish", "--layer", "emergency_overlay", "--version", "1", "--document",
         json.dumps({"goal_fit_actions": ["code.scan"]}), "--actor", "t", "--dry-run"], capsys)
    assert code == 0


def test_the_command_line_dry_run_refuses_a_bad_document_with_exit_one(capsys):
    before = state()
    code, out, err = run_cli(
        ["publish", "--layer", "emergency_overlay", "--version", "1", "--document",
         json.dumps({"goal_fit_actions": ["nope"]}), "--actor", "t", "--dry-run"], capsys)
    assert code == 1 and "refused" in err and out == ""
    assert state() == before


def test_without_the_flag_the_command_would_publish_so_the_dry_run_is_the_only_way_to_look(
        capsys, monkeypatch):
    """The real path is not run here. What is pinned: the dry run is a different branch, chosen by
    the flag, and a missing flag reaches the confirmation (which a test declines)."""
    monkeypatch.setattr(tool, "_confirm", lambda *a, **k: False)
    before = state()
    code, _, _ = run_cli(
        ["publish", "--layer", "emergency_overlay", "--version", "1", "--document-file",
         str(DRAFT), "--actor", "t"], capsys)
    assert code == 2 and state() == before                  # declined: still nothing published
