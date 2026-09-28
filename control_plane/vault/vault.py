"""Credential storage and delivery (D44, `docs/ADR_CREDENTIAL_VAULT.md`).

Two delivery modes (D44-3), never one, because the two tools that need this
do not share a trust boundary (ADR §0/§4):

* :func:`material_for` — control-plane-local use only. The caller is a
  fully-trusted control-plane function (``git_fetch.fetch_repo``, the same
  trust tier as ``engagement_ca.mint_leaf_for_host``) that consumes the
  secret itself and never persists, logs, or hands it to a sandboxed
  process. Used for ``git_token`` (ADR §4.2): D43-5 already decided the
  repository is fetched control-plane-side, so this is the only case that
  applies to.
* :func:`mount_for_run` — sandbox file-mount delivery. Writes the secret to
  a per-dispatch host tempfile and returns its path for the caller to fold
  into ``DockerSandbox.run``'s ``source_mounts`` (D35's "path in argv,
  content only in a mounted file" principle, generalized). Used for
  ``ad_domain_bind`` (ADR §4.1): the LDAP bind happens inside the sandboxed
  ``bloodhound-python`` process itself, so the secret must reach that
  container's filesystem.

``credential_type`` decides which mode a given credential supports
(``CREDENTIAL_TYPES``) — calling the wrong one for a stored credential's
type is refused rather than silently doing the wrong thing, the same way
``dispatch_collection`` refuses a capability whose action does not match
the adapter it was routed to.

At rest (D44-1, Option A): ``credential_material.encrypted_material`` is a
Fernet token (AES-128-CBC + HMAC-SHA256) of a small JSON object, keyed by a
master key from the environment (never a fallback — ``control_plane.config
.require_env`` raises rather than silently working with a guessable
default, the same rule every other secret in this codebase already
follows). RLS (migration 0012) bounds *who can query the row at all*;
encryption bounds *what a successful query alone yields* — the two are
independent layers, deliberately, matching the ADR's own framing of why
this is a stronger design than `engagement_ca`'s RLS-only protection.

Write access is `credential_admin` alone (D44-2) — :func:`store_credential`
asserts it via :func:`control_plane.state.db.assert_credential_admin` before
touching either table, the same shape ``assert_registry_admin`` already
uses for the identical purpose.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Connection, text

from control_plane.audit.logger import record_audit
from control_plane.config import require_env
from control_plane.state.db import assert_credential_admin

#: The two shapes this Vault knows how to store and deliver. Adding a third
#: means deciding its delivery mode here, not inferring one from its name
#: at a call site — the same discipline `registry.ADAPTERS` applies to
#: routing an action to its adapter.
CREDENTIAL_TYPES = ("ad_domain_bind", "git_token")

#: World-readable, not world-writable. Matches the fix D43's
#: `git_fetch.fetch_repo` needed (`chmod a+rX`) after discovering
#: `tempfile.mkstemp`'s default 0600 is unreadable by a container's
#: non-root user once bind-mounted read-only -- applied here from the
#: start rather than rediscovered against a real image later.
_MOUNT_FILE_MODE = 0o644

_fernet_cache: Fernet | None = None


class VaultError(RuntimeError):
    """A credential could not be stored, read, or delivered."""


@dataclass(frozen=True)
class CredentialMaterial:
    """Decrypted material, for control-plane-local use only (:func:`material_for`).

    Never write this to disk, a log line, an audit payload, or hand it to
    anything that runs inside a sandbox -- that is what :func:`mount_for_run`
    is for.
    """

    credential_id: str
    credential_type: str
    fields: Mapping[str, str]


@dataclass(frozen=True)
class MountedCredential:
    """A secret written to a host tempfile, ready for a caller's own
    ``source_mounts`` mapping.

    Deliberately carries no opinion about the container-side path -- that is
    the adapter's own constant (mirroring how `CONTAINER_REPO_PATH` belongs
    to `semgrep.py`, not to `sandbox.py`), not something this generic module
    should know. The caller is responsible for calling
    :func:`cleanup_mount` exactly once, in a ``finally`` block, regardless
    of dispatch outcome (D44-5).
    """

    host_path: str
    credential_type: str


def _fernet() -> Fernet:
    """The Fernet instance for the master key, built once per process.

    ``VAULT_MASTER_KEY`` has no fallback, the same rule every other secret
    in this codebase follows (`control_plane/config.py`'s own docstring): a
    default that happens to work locally is a key nobody notices shipping.
    """
    global _fernet_cache
    if _fernet_cache is not None:
        return _fernet_cache
    key = require_env(
        "VAULT_MASTER_KEY",
        hint="Generate one with "
             "`python3 -c \"from cryptography.fernet import Fernet; "
             "print(Fernet.generate_key().decode())\"` and set it once per "
             "deployment -- rotating it makes every stored credential "
             "undecryptable.",
    )
    try:
        _fernet_cache = Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise VaultError(
            "VAULT_MASTER_KEY is not a valid Fernet key (expected 32 "
            "url-safe base64-encoded bytes)"
        ) from exc
    return _fernet_cache


def _encrypt_fields(fields: Mapping[str, str]) -> str:
    payload = json.dumps(dict(fields), sort_keys=True).encode()
    return _fernet().encrypt(payload).decode()


def _decrypt_fields(token: str) -> dict[str, str]:
    try:
        payload = _fernet().decrypt(token.encode())
    except InvalidToken as exc:
        raise VaultError(
            "credential material could not be decrypted -- wrong "
            "VAULT_MASTER_KEY, or the stored token is corrupt"
        ) from exc
    return json.loads(payload)


def store_credential(
    conn: Connection,
    *,
    engagement_id: str,
    credential_id: str,
    label: str,
    credential_type: str,
    secret: str,
    actor: str,
) -> None:
    """Store a new credential (D44-2: `credential_admin` only).

    ``secret`` is the one thing this Vault ever encrypts -- everything else
    a caller needs to build a real command (a domain username, an
    ``-p``/``--hashes`` choice) is a non-secret capability constraint the
    Worker/operator already supplies at proposal time, the same way
    ``ad_collector.build_plan`` already takes ``collection_methods`` as a
    constraint rather than something decrypted from stored material. That
    keeps this table's shape identical across every ``credential_type``
    (ADR §4.3) instead of growing type-specific plaintext columns.

    Rotation is a new ``credential_id`` (a new call to this function) and
    revoking the old one through the existing, already-tested
    ``revoke_credential`` cascade (D9) -- there is no update path here (see
    the migration's own docstring).
    """
    assert_credential_admin(conn)
    if credential_type not in CREDENTIAL_TYPES:
        raise VaultError(
            f"unknown credential_type {credential_type!r}; expected one of "
            f"{CREDENTIAL_TYPES}"
        )
    if not secret:
        raise VaultError("a credential's secret must not be empty")

    conn.execute(
        text("""
            INSERT INTO credentials (credential_id, engagement_id, label)
            VALUES (:cid, :eid, :label)
        """),
        {"cid": credential_id, "eid": engagement_id, "label": label},
    )
    conn.execute(
        text("""
            INSERT INTO credential_material
                (credential_id, engagement_id, credential_type, encrypted_material)
            VALUES (:cid, :eid, :ctype, :material)
        """),
        {
            "cid": credential_id, "eid": engagement_id, "ctype": credential_type,
            "material": _encrypt_fields({"secret": secret}),
        },
    )
    record_audit(
        engagement_id=engagement_id, actor=actor, event_type="credential.stored",
        subject_type="credential", subject_id=credential_id,
        # The label and type only -- never the secret, never even a
        # fragment of it. tests/test_vault.py pins this at the byte level
        # (D30/D44-6's standard: check the actual secret bytes, not a key
        # name), mirroring test_engagement_ca.py's own mutation test.
        payload={"credential_type": credential_type, "label": label},
    )


def _load_material(conn: Connection, credential_id: str) -> CredentialMaterial:
    row = conn.execute(
        text("SELECT credential_type, encrypted_material FROM credential_material "
             "WHERE credential_id = :cid"),
        {"cid": credential_id},
    ).mappings().one_or_none()
    if row is None:
        raise VaultError(f"no credential material stored for {credential_id!r}")
    fields = _decrypt_fields(row["encrypted_material"])
    return CredentialMaterial(
        credential_id=credential_id, credential_type=row["credential_type"],
        fields=fields,
    )


def material_for(conn: Connection, credential_id: str) -> CredentialMaterial:
    """Control-plane-local material (ADR §4.2/§4.3).

    **Never** pass what this returns to `DockerSandbox.run`, write it to
    disk, or include it in a log line or audit payload. It exists for a
    caller like `git_fetch.fetch_repo` that consumes a secret itself,
    inside the trusted control-plane process, and discards it.
    """
    return _load_material(conn, credential_id)


def mount_for_run(
    conn: Connection, *, credential_id: str, run_id: str, engagement_id: str,
    actor: str,
) -> MountedCredential:
    """Mint a per-dispatch, file-mounted copy for a sandboxed tool (ADR §4.1).

    Refuses a credential whose ``credential_type`` has no sandbox delivery
    mode (currently only ``ad_domain_bind`` does) -- calling this for a
    ``git_token`` would be exactly the mistake ADR §4.3 warns against: a
    control-plane-only secret does not need, and must not get, a sandbox
    mount.

    The caller owns cleanup: exactly one call to :func:`cleanup_mount`, in a
    ``finally`` block, regardless of dispatch outcome (D44-5) -- the same
    contract `git_fetch.fetch_repo`/`cleanup_repo` already established for
    D43's fetched repository.
    """
    material = _load_material(conn, credential_id)
    if material.credential_type != "ad_domain_bind":
        raise VaultError(
            f"credential_type {material.credential_type!r} has no sandbox "
            "mount delivery mode; use material_for() instead"
        )
    secret = material.fields.get("secret")
    if not secret:
        raise VaultError(f"credential {credential_id!r} has no 'secret' field")

    fd, path = tempfile.mkstemp(prefix="cyberorch-cred-")
    try:
        os.write(fd, secret.encode())
    finally:
        os.close(fd)
    os.chmod(path, _MOUNT_FILE_MODE)

    record_audit(
        engagement_id=engagement_id, actor=actor,
        event_type="credential.issued_to_run", subject_type="tool_run",
        subject_id=run_id,
        # credential_id and credential_type only -- the mounted file's path
        # is host-local and not itself sensitive, but the secret it holds
        # never appears here regardless.
        payload={"credential_id": credential_id, "credential_type": material.credential_type},
    )
    return MountedCredential(host_path=path, credential_type=material.credential_type)


def cleanup_mount(
    mounted: MountedCredential, *, engagement_id: str, actor: str, run_id: str,
) -> None:
    """Delete a mounted credential's on-disk copy (D44-5).

    Failure here is audited, not swallowed: a cleanup failure means a real
    secret is sitting on the control-plane host's disk longer than this
    system's own design says it should (ADR §3) -- silence would be the
    exact "audited machinery that did not actually run" gap
    ``control_plane/audit/logger.py``'s own docstring warns against for a
    failed audit write, applied to a failed cleanup instead.
    """
    try:
        os.remove(mounted.host_path)
    except OSError as exc:
        record_audit(
            engagement_id=engagement_id, actor=actor,
            event_type="credential.mount_cleanup_failed", subject_type="tool_run",
            subject_id=run_id, reasons=("cleanup_failed",),
            payload={"error": str(exc)},
        )
