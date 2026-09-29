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

import pytest
from sqlalchemy import text

from control_plane.state.db import (
    credential_admin_scope,
    engagement_scope,
    registry_admin_scope,
)
from control_plane.vault import vault as vault_module
from control_plane.vault.vault import (
    AD_AUTH_MODES,
    VaultError,
    cleanup_mount,
    identity_for,
    material_for,
    mount_for_run,
    store_credential,
)
from tool_gateway.adapters import ad_collector

REAL_SECRET = "hunter2_real_ldap_password_9f3c"  # noqa: S105 - synthetic test fixture
REAL_TOKEN = "ghp_synthetic_fake_token_1a2b3c"  # noqa: S105 - synthetic test fixture


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


_UNSET = object()


def _store(conn_scope_engagement_id, *, credential_type: str, secret: str,
           username=_UNSET, auth_mode=_UNSET) -> str:
    """Store a credential. An ``ad_domain_bind`` one is a whole identity
    (D50-B), so it gets a username and mode *unless the test passes them*;
    a ``git_token`` carries none. A sentinel, not ``None``, marks "not passed"
    -- the refusal tests need to hand the vault an explicit ``None`` and have it
    arrive as one.
    """
    if credential_type == "ad_domain_bind":
        username = "svc-account" if username is _UNSET else username
        auth_mode = "password" if auth_mode is _UNSET else auth_mode
    else:
        username = None if username is _UNSET else username
        auth_mode = None if auth_mode is _UNSET else auth_mode
    credential_id = _uid("CRED")
    with credential_admin_scope(conn_scope_engagement_id) as conn:
        store_credential(
            conn, engagement_id=conn_scope_engagement_id, credential_id=credential_id,
            label="test credential", credential_type=credential_type, secret=secret,
            actor="test-harness", username=username, auth_mode=auth_mode,
        )
    return credential_id


def _store_expecting_refusal(engagement_id: str, **kwargs) -> str:
    """Attempt a store that must be refused; returns the refusal text."""
    try:
        _store(engagement_id, **kwargs)
    except VaultError as exc:
        return str(exc)
    raise AssertionError(f"the vault accepted a credential it should have refused: {kwargs!r}")


def _legacy_store(engagement_id: str, *, secret: str) -> str:
    """Write a credential exactly as D44 did before D50-B: an encrypted
    ``{"secret": ...}`` and nothing else. Reaches into the vault's own
    encryption helper on purpose -- the point is a row shaped like one that
    already exists in a deployed database, which ``store_credential`` can no
    longer produce.
    """
    credential_id = _uid("CRED")
    with credential_admin_scope(engagement_id) as conn:
        conn.execute(
            text("INSERT INTO credentials (credential_id, engagement_id, label) "
                 "VALUES (:c, :e, 'legacy')"),
            {"c": credential_id, "e": engagement_id},
        )
        conn.execute(
            text("INSERT INTO credential_material "
                 "(credential_id, engagement_id, credential_type, encrypted_material) "
                 "VALUES (:c, :e, 'ad_domain_bind', :m)"),
            {"c": credential_id, "e": engagement_id,
             "m": vault_module._encrypt_fields({"secret": secret})},  # noqa: SLF001
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


# ---------------------------------------------------------------------------
# D50-B: an ad_domain_bind credential is one indivisible identity
# ---------------------------------------------------------------------------

LM_NT = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_the_vault_and_the_adapter_agree_on_what_auth_modes_exist():
    """The vault does not import the adapter (it knows nothing of any tool), so
    this pins the two vocabularies together: a mode one accepts and the other
    does not would be a credential that stores fine and cannot be run.
    """
    assert set(AD_AUTH_MODES) == set(ad_collector.AUTH_MODES)


def test_an_ad_domain_bind_credential_round_trips_its_identity(engagement_id):
    credential_id = _store(
        engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET,
        username="alice", auth_mode="password",
    )
    with engagement_scope(engagement_id) as conn:
        identity = identity_for(conn, credential_id)
        material = material_for(conn, credential_id)
    assert (identity.username, identity.auth_mode) == ("alice", "password")
    # One encrypted object: the secret and the identity live together.
    assert material.fields == {
        "secret": REAL_SECRET, "username": "alice", "auth_mode": "password",
    }


def test_identity_for_never_returns_the_secret(engagement_id):
    credential_id = _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET)
    with engagement_scope(engagement_id) as conn:
        identity = identity_for(conn, credential_id)
    assert REAL_SECRET not in repr(identity)
    assert set(vars(identity)) == {"username", "auth_mode"}


@pytest.mark.parametrize(("label", "kwargs", "expected"), [
    pytest.param("no username", {"username": None, "auth_mode": "password"},
                 "must name the account", id="no-username"),
    pytest.param("blank username", {"username": "   ", "auth_mode": "password"},
                 "must name the account", id="blank-username"),
    pytest.param("no auth mode", {"username": "alice", "auth_mode": None},
                 "auth_mode", id="no-auth-mode"),
    pytest.param("unknown auth mode", {"username": "alice", "auth_mode": "kerberoast"},
                 "kerberoast", id="unknown-auth-mode"),
    pytest.param("NUL in username", {"username": "al\x00ice", "auth_mode": "password"},
                 "NUL", id="nul-username"),
])
def test_an_ad_domain_bind_credential_without_a_valid_identity_is_refused(
    engagement_id, label, kwargs, expected,
):
    message = _store_expecting_refusal(
        engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET, **kwargs)
    assert expected in message, label


@pytest.mark.parametrize(("secret", "expected"), [
    pytest.param("abc\n", "newline", id="trailing-newline"),
    pytest.param("ab\x00cd", "NUL", id="nul"),
])
def test_a_secret_that_could_not_reach_the_tool_byte_for_byte_is_refused(
    engagement_id, secret, expected,
):
    message = _store_expecting_refusal(
        engagement_id, credential_type="ad_domain_bind", secret=secret)
    assert expected in message


@pytest.mark.parametrize("secret", [
    pytest.param(LM_NT.split(":")[1], id="single-hash-no-lm-half"),
    pytest.param(LM_NT + "00", id="too-long"),
    pytest.param(LM_NT[:-1], id="too-short"),
    pytest.param("not-a-hash", id="garbage"),
    pytest.param(LM_NT.replace(":", ""), id="no-colon"),
    pytest.param("zz" + LM_NT[2:], id="non-hex"),
])
def test_a_hashes_mode_secret_must_be_exactly_lm_nt(engagement_id, secret):
    """The real tool crashes in main() on anything else, before any DNS or LDAP
    (D50). Refused at write, where the secret is visible, and the refusal never
    echoes it.
    """
    message = _store_expecting_refusal(
        engagement_id, credential_type="ad_domain_bind", secret=secret, auth_mode="hashes")
    assert "LM:NT" in message
    assert secret not in message


def test_a_well_formed_hash_is_accepted_in_either_case(engagement_id):
    for value in (LM_NT, LM_NT.upper()):
        credential_id = _store(
            engagement_id, credential_type="ad_domain_bind", secret=value,
            auth_mode="hashes")
        with engagement_scope(engagement_id) as conn:
            assert identity_for(conn, credential_id).auth_mode == "hashes"


def test_a_password_that_merely_looks_like_a_hash_is_still_a_password(engagement_id):
    """Shape is checked against the *stated* mode; nothing guesses a mode."""
    credential_id = _store(
        engagement_id, credential_type="ad_domain_bind", secret=LM_NT, auth_mode="password")
    with engagement_scope(engagement_id) as conn:
        assert identity_for(conn, credential_id).auth_mode == "password"


def test_a_git_token_carries_no_identity_and_is_refused_one(engagement_id):
    message = _store_expecting_refusal(
        engagement_id, credential_type="git_token", secret=REAL_TOKEN, username="alice")
    assert "carries no username or auth_mode" in message
    message = _store_expecting_refusal(
        engagement_id, credential_type="git_token", secret=REAL_TOKEN, auth_mode="password")
    assert "carries no username or auth_mode" in message


def test_identity_for_refuses_a_git_token(engagement_id):
    credential_id = _store(engagement_id, credential_type="git_token", secret=REAL_TOKEN)
    with engagement_scope(engagement_id) as conn:
        try:
            identity_for(conn, credential_id)
            raise AssertionError("a git_token binds no identity")
        except VaultError as exc:
            assert "git_token" in str(exc)


def test_a_credential_stored_before_identity_binding_is_refused_not_guessed(engagement_id):
    """The existing-data rule (D30/D11-7): a legacy credential holds only a
    secret, so *who it belongs to is unknown*. That reads as unknown -- never as
    'no identity needed' -- and is refused by both entry points rather than
    reconstructed or run without an account. Nothing is backfilled.
    """
    credential_id = _legacy_store(engagement_id, secret=REAL_SECRET)
    with engagement_scope(engagement_id) as conn:
        for call in (
            lambda: identity_for(conn, credential_id),
            lambda: mount_for_run(
                conn, credential_id=credential_id, run_id=_uid("RUN"),
                engagement_id=engagement_id, actor="test"),
        ):
            try:
                call()
                raise AssertionError("a legacy credential must not be usable")
            except VaultError as exc:
                assert "predates identity binding" in str(exc)
                assert "unknown, never 'none needed'" in str(exc).replace("\n", " ")
                assert REAL_SECRET not in str(exc)


def test_storing_an_ad_credential_audits_the_identity_but_never_the_secret(engagement_id):
    _store(engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET,
           username="alice", auth_mode="password")
    payload = _payloads_for(engagement_id, "credential.stored")[0]
    assert payload["username"] == "alice"
    assert payload["auth_mode"] == "password"
    assert REAL_SECRET not in str(payload)


def test_a_refused_store_writes_nothing(engagement_id):
    """Validation happens before either INSERT: a refused credential leaves no
    orphan `credentials` row and no audit event claiming it was stored.
    """
    before = len(_payloads_for(engagement_id, "credential.stored"))
    _store_expecting_refusal(
        engagement_id, credential_type="ad_domain_bind", secret=REAL_SECRET, username="   ")
    assert len(_payloads_for(engagement_id, "credential.stored")) == before
