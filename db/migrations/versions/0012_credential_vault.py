"""credential_material — encrypted secret storage for the Credential Vault (D44).

Implements D44-1 (Option A: an encrypted column in Postgres, not an external
secrets manager — `docs/ADR_CREDENTIAL_VAULT.md` §1.2 leans A for the same
"do not add infrastructure ahead of a measured need" reasoning D42-5 already
used to keep this system off Neo4j) and D44-2 (Option B: a new, dedicated
role rather than widening `registry_admin` — matching every prior instance
of this codebase adding a role instead of an existing one's blast radius).

Kept a separate table from `credentials`, not new columns on it, for the
same reason `engagement_ca` is a separate table from `engagements`: D42's
ADR found `credentials` "has never been anything else" than an identifier
and a revocation flag, and that stays true here — this table holds
everything else, one row per credential, 1:1 by `credential_id`.

No UPDATE grant anywhere, matching `engagement_ca`'s own reasoning
(migration 0009): a credential is written once. Rotation is a new
`credential_id` (a new `credentials` row plus a new `credential_material`
row) and revoking the old one through the existing, already-tested
`revoke_credential` cascade (D9) — reusing the cascade rather than adding an
in-place UPDATE path that would need its own revocation-adjacent story.

Role shape, mirroring the `scope_registry`/`metadata_registry` split
(migration 0002) exactly: `cyberorch_app` (the runtime role every dispatch
function connects as) keeps SELECT only — it must be able to read and
decrypt material to actually use a credential during a real dispatch, the
same way it already has SELECT on `scope_registry` to authorize against.
Write access (`credential_admin`, created in `db/roles.sql`) is the new,
narrow role: SELECT + INSERT on this table and on `credentials`, INSERT on
`audit_log` for `credential.stored`, and nothing else — it cannot read
`scope_registry`/`metadata_registry`, `registry_admin` cannot read this
table, and neither can bypass RLS.

`encrypted_material` is a Fernet token (AES-128-CBC + HMAC-SHA256, the
`cryptography` package this repo already depends on for
`control_plane/tls/engagement_ca.py`) of a small JSON object whose shape
depends on `credential_type` — never plaintext, and never a field this
migration's own grants alone would have protected on their own merit,
matching the doc's explicit design (RLS bounds who can query the row;
encryption bounds what a successful query alone yields).
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE credential_material (
    credential_id      TEXT PRIMARY KEY REFERENCES credentials(credential_id),
    engagement_id      TEXT NOT NULL REFERENCES engagements(engagement_id),
    credential_type    TEXT NOT NULL CHECK (credential_type IN ('ad_domain_bind', 'git_token')),
    encrypted_material TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
""")
    op.execute("COMMENT ON TABLE credential_material IS "
               "'D44: encrypted credential material. credential_type decides "
               "which control_plane.vault delivery mode applies (D44-3) -- "
               "control-plane-local material_for() for git_token, sandbox "
               "file-mount mount_for_run() for ad_domain_bind. "
               "encrypted_material is a Fernet token, never plaintext.';")
    op.execute("COMMENT ON COLUMN credential_material.credential_type IS "
               "'Plaintext by design: dispatch must pick a delivery mode "
               "before it can decrypt anything, so this cannot itself be "
               "inside the encrypted payload.';")

    # Same isolation as every engagement-scoped table (§8.6), FORCE so the
    # table owner (migration_owner) cannot read across the boundary either --
    # without FORCE, tests pass while production leaks, exactly the gap
    # engagement_ca's own migration (0009) named.
    op.execute("ALTER TABLE credential_material ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE credential_material FORCE ROW LEVEL SECURITY;")
    op.execute("""
CREATE POLICY engagement_isolation ON credential_material
    FOR ALL TO PUBLIC
    USING (engagement_id = cyberorch_current_engagement())
    WITH CHECK (engagement_id = cyberorch_current_engagement());
""")

    # The runtime role reads (and decrypts, application-side) to actually use
    # a credential during dispatch -- the same shape as its SELECT-only grant
    # on scope_registry/metadata_registry (migration 0002). It cannot write:
    # storing new material is credential_admin's job alone.
    op.execute("GRANT SELECT ON credential_material TO cyberorch_app;")

    # credential_admin: a new role, not registry_admin widened (D44-2). SELECT
    # + INSERT only here and on credentials -- no UPDATE (see module
    # docstring: rotation is a new credential_id, not an in-place rewrite),
    # no DELETE (history survives for the same reason scope_registry/
    # metadata_registry keep DELETE revoked -- an audit trail needs something
    # to point at).
    op.execute("GRANT USAGE ON SCHEMA public TO credential_admin;")
    op.execute("GRANT SELECT, INSERT ON credential_material TO credential_admin;")
    op.execute("GRANT SELECT, INSERT ON credentials TO credential_admin;")
    op.execute("GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() TO credential_admin;")

    # No audit_log grant here, unlike registry_admin's own migration (0002):
    # verified against control_plane/state/db.py's audit_scope()/
    # record_audit() -- every caller, regardless of its own connection's
    # role, audits through the cyberorch_app engine ("one write path rather
    # than one per caller role", its own docstring) rather than the caller's
    # own connection. A grant here would be unused, and D44-2's whole point
    # is not handing this role reach it does not need.

    # credential_admin needs to see which engagement it is registering a
    # credential for, same as registry_admin's own grant (migration 0010).
    op.execute("GRANT SELECT ON engagements TO credential_admin;")


def downgrade() -> None:
    op.execute("REVOKE ALL ON credential_material FROM cyberorch_app;")
    op.execute("REVOKE ALL ON credential_material FROM credential_admin;")
    op.execute("REVOKE ALL ON credentials FROM credential_admin;")
    op.execute("REVOKE ALL ON audit_log FROM credential_admin;")
    op.execute("REVOKE ALL ON engagements FROM credential_admin;")
    op.execute("REVOKE EXECUTE ON FUNCTION cyberorch_current_engagement() FROM credential_admin;")
    op.execute("REVOKE USAGE ON SCHEMA public FROM credential_admin;")
    op.execute("DROP TABLE IF EXISTS credential_material CASCADE;")
