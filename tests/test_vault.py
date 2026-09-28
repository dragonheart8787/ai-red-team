"""Credential Vault (D44): storage, delivery modes, and audited secrecy.

Three things this file pins down:

* the role separation is real, not just documented — `cyberorch_app` cannot
  write a credential (`assert_credential_admin` refuses, and the database
  would refuse it too even without that check), `registry_admin` cannot
  read `credential_material` at all, matching `scope_registry`/
  `metadata_registry`'s own split (migration 0002) applied to a stricter
  category of data;
* `credential_type` genuinely selects a delivery mode rather than being
  decorative — `mount_for_run` refuses a `git_token` credential outright
  (ADR §4.3's whole point: a control-plane-only secret must not get a
  sandbox mount);
* every new audit event's payload is checked against the **actual secret
  bytes**, not a key name, matching `test_engagement_ca.py`'s own
  `test_provisioning_the_ca_is_audited_without_leaking_the_key` exactly (and
  the D30 standard the ADR cites for it: a check that cannot fail on the
  real mistake it claims to guard against proves nothing). A test that only
  asserted `"secret" not in payload` would pass on a payload that embedded
  the literal secret under a differently-named key.
"""

from __future__ import annotations

import os
import uuid

from sqlalchemy import text

from control_plane.state.db import (
    credential_admin_scope,
    engagement_scope,
    registry_admin_scope,
)
from control_plane.vault.vault import (
    VaultError,
    cleanup_mount,
    material_for,
    mount_for_run,
    store_credential,
)

REAL_SECRET = "hunter2_real_ldap_password_9f3c"  # noqa: S105 - synthetic test fixture
REAL_TOKEN = "ghp_synthetic_fake_token_1a2b3c"  # noqa: S105 - synthetic test fixture


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _store(conn_scope_engagement_id, *, credential_type: str, secret: str) -> str:
    credential_id = _uid("CRED")
    with credential_admin_scope(conn_scope_engagement_id) as conn:
        store_credential(
            conn, engagement_id=conn_scope_engagement_id, credential_id=credential_id,
            label="test credential", credential_type=credential_type, secret=secret,
            actor="test-harness",
        )
    return credential_id


def _payloads_for(engagement_id: str, event_type: str) -> list[dict]:
    with engagement_scope(engagement_id) as conn:
        rows = conn.execute(
            text("SELECT payload FROM audit_log WHERE engagement_id = :e "
                 "AND event_type = :t"),
            {"e": engagement_id, "t": event_type},
        ).mappings().all()
    return [r["payload"] for r in rows]


def test_cyberorch_app_cannot_store_a_credential(engagement_id):
    with engagement_scope(engagement_id) as conn:
        try:
            store_credential(
                conn, engagement_id=engagement_id, credential_id=_uid("CRED"),
                label="x", credential_type="ad_domain_bind", secret=REAL_SECRET,
                actor="test",
            )
            raise AssertionError("cyberorch_app must not be able to store a credential")
        except PermissionError as exc:
            assert "credential_admin" in str(exc)


def test_registry_admin_cannot_read_credential_material(engagement_id):
    _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET)
    with registry_admin_scope(engagement_id) as conn:
        try:
            conn.execute(text("SELECT * FROM credential_material")).all()
            raise AssertionError("registry_admin must not read credential_material")
        except Exception as exc:  # noqa: BLE001 - asserting the DB itself refuses
            assert "permission denied" in str(exc).lower()


def test_material_for_round_trips_a_git_token(engagement_id):
    credential_id = _store(engagement_id, credential_type="git_token", secret=REAL_TOKEN)
    with engagement_scope(engagement_id) as conn:
        material = material_for(conn, credential_id)
    assert material.credential_type == "git_token"
    assert material.fields["secret"] == REAL_TOKEN


def test_mount_for_run_writes_a_readable_file_and_cleanup_removes_it(engagement_id):
    credential_id = _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET)
    with engagement_scope(engagement_id) as conn:
        mounted = mount_for_run(
            conn, credential_id=credential_id, run_id=_uid("RUN"),
            engagement_id=engagement_id, actor="test",
        )
    try:
        assert mounted.credential_type == "ad_domain_bind"
        with open(mounted.host_path) as fh:
            assert fh.read() == REAL_SECRET
        # World-readable (D43's non-root-container-user lesson, applied from
        # the start rather than rediscovered).
        assert oct(os.stat(mounted.host_path).st_mode)[-3:] == "644"
    finally:
        cleanup_mount(mounted, engagement_id=engagement_id, actor="test", run_id="RUN")
    assert not os.path.exists(mounted.host_path)


def test_mount_for_run_refuses_a_git_token(engagement_id):
    """ADR §4.3's core claim: credential_type must select the delivery mode.

    A git_token has no sandbox-mount use case (D43-5's control-plane-side
    fetch never needs one) -- this is the negative control proving the
    interface actually enforces that, not merely documents it.
    """
    credential_id = _store(engagement_id, credential_type="git_token", secret=REAL_TOKEN)
    with engagement_scope(engagement_id) as conn:
        try:
            mount_for_run(
                conn, credential_id=credential_id, run_id=_uid("RUN"),
                engagement_id=engagement_id, actor="test",
            )
            raise AssertionError("mount_for_run must refuse a git_token credential")
        except VaultError as exc:
            assert "git_token" in str(exc)


def test_storing_a_credential_is_audited_without_leaking_the_secret(engagement_id):
    _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET)
    payloads = _payloads_for(engagement_id, "credential.stored")
    assert payloads, "credential.stored was not audited"
    for payload in payloads:
        rendered = str(payload)
        # The mutation-shaped check: the literal secret bytes, not a key
        # name. A payload that smuggled REAL_SECRET under an oddly-named
        # field would still fail this.
        assert REAL_SECRET not in rendered
    assert payloads[0]["credential_type"] == "ad_domain_bind"


def test_mounting_a_credential_is_audited_without_leaking_the_secret(engagement_id):
    credential_id = _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET)
    run_id = _uid("RUN")
    with engagement_scope(engagement_id) as conn:
        mounted = mount_for_run(
            conn, credential_id=credential_id, run_id=run_id,
            engagement_id=engagement_id, actor="test",
        )
    cleanup_mount(mounted, engagement_id=engagement_id, actor="test", run_id=run_id)

    payloads = _payloads_for(engagement_id, "credential.issued_to_run")
    assert payloads, "credential.issued_to_run was not audited"
    for payload in payloads:
        assert REAL_SECRET not in str(payload)


def test_a_cleanup_failure_is_itself_audited(engagement_id):
    """The mutation D44's own design requires: prove the failure path fires.

    Deleting the file before cleanup runs simulates whatever real failure
    (permissions, a second deletion, disk issues) `cleanup_mount` might hit
    -- `os.remove` raises `FileNotFoundError` (an `OSError` subclass) either
    way, so this exercises the real except branch, not a mocked one.
    """
    credential_id = _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET)
    run_id = _uid("RUN")
    with engagement_scope(engagement_id) as conn:
        mounted = mount_for_run(
            conn, credential_id=credential_id, run_id=run_id,
            engagement_id=engagement_id, actor="test",
        )
    os.remove(mounted.host_path)  # force the failure cleanup_mount will hit

    cleanup_mount(mounted, engagement_id=engagement_id, actor="test", run_id=run_id)

    payloads = _payloads_for(engagement_id, "credential.mount_cleanup_failed")
    assert payloads, "a cleanup failure must be audited, not silently swallowed"
    assert "error" in payloads[0]
