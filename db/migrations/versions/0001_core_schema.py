"""Core schema (ARCHITECTURE.md §4) with §8.6 RLS and §4.4 append-only grants.

Revision ID: 0001
Revises:
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


# Every engagement-scoped table gets the same isolation policy (I4). policy_layers
# is the one exception: baseline_global and emergency_overlay rows are global and
# carry engagement_id IS NULL, so they must stay visible to every engagement.
ENGAGEMENT_SCOPED = [
    "engagements",
    "scope_registry",
    "metadata_registry",
    "tasks",
    "action_proposals",
    "credentials",
    "capabilities",
    "approvals",
    "tool_runs",
    "evidence",
    "findings",
    "provenance_edges",
    "audit_log",
]

# §4.4: raw evidence and the audit log are logically immutable. The application
# role gets INSERT + SELECT and nothing else, so "append-only" is a database
# privilege rather than a convention someone can forget. provenance_edges is
# treated the same way: an edge records how a belief was formed, and rewriting
# that history would defeat §8.10's whole purpose.
APPEND_ONLY = ["evidence", "audit_log", "provenance_edges"]


def upgrade() -> None:
    op.execute("""
CREATE TABLE engagements (
    engagement_id            TEXT PRIMARY KEY,
    customer_id              TEXT NOT NULL,
    status                   TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active','paused','completed','killed')),
    kill_switch_engaged      BOOLEAN NOT NULL DEFAULT FALSE,
    policy_snapshot_version  INTEGER NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON COLUMN engagements.policy_snapshot_version IS
    '§4.5: frozen pointer to the Baseline Global Snapshot in force at creation.';
""")

    # §4.5 Policy Pack layers. The emergency overlay exists to tighten globally in
    # a hurry, so the "it can only tighten" rule is enforced by the schema itself
    # rather than by whoever writes the overlay: no scope_allow key, and no action
    # may be set to ALLOW.
    op.execute("""
CREATE TABLE policy_layers (
    id             BIGSERIAL PRIMARY KEY,
    layer          TEXT NOT NULL CHECK (layer IN
                       ('baseline_global','emergency_overlay','customer','engagement')),
    version        INTEGER NOT NULL,
    engagement_id  TEXT REFERENCES engagements(engagement_id),
    customer_id    TEXT,
    document       JSONB NOT NULL,
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT emergency_overlay_can_only_tighten CHECK (
        layer <> 'emergency_overlay' OR (
            NOT (document ? 'scope_allow')
            AND NOT jsonb_path_exists(document, '$.actions.* ? (@ == "ALLOW")')
        )
    )
);
CREATE UNIQUE INDEX policy_layers_identity ON policy_layers
    (layer, version, COALESCE(engagement_id,''), COALESCE(customer_id,''));
""")

    # §4.1.5 typed scope objects. allowed_actions is per scope object, so an FQDN
    # authorization never implicitly authorizes an action class against the IP it
    # resolves to.
    op.execute("""
CREATE TABLE scope_registry (
    scope_object_id  TEXT PRIMARY KEY,
    engagement_id    TEXT NOT NULL REFERENCES engagements(engagement_id),
    type             TEXT NOT NULL CHECK (type IN
                         ('fqdn','cidr','ip','url','repo','ad_domain')),
    value            TEXT NOT NULL,
    allowed_actions  TEXT[] NOT NULL,
    version          INTEGER NOT NULL DEFAULT 1,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from       TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until      TIMESTAMPTZ,
    registered_by    TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scope_registry_lookup ON scope_registry (engagement_id, type, value);
""")

    # §5 Authoritative Metadata Registry. classification_authority is what makes
    # I6b enforceable: only AUTHORITATIVE may satisfy a privilege prerequisite,
    # while any tier may tighten. Several tiers can coexist for one identity —
    # an LLM_HINT row never overwrites the AUTHORITATIVE row, it sits beside it.
    op.execute("""
CREATE TABLE metadata_registry (
    asset_id                  TEXT PRIMARY KEY,
    engagement_id             TEXT NOT NULL REFERENCES engagements(engagement_id),
    identity_type             TEXT NOT NULL,
    identity_value            TEXT NOT NULL,
    resource_class            TEXT[] NOT NULL DEFAULT '{}',
    data_class                TEXT[] NOT NULL DEFAULT '{}',
    classification_source     TEXT NOT NULL,
    classification_authority  TEXT NOT NULL CHECK (classification_authority IN
                                  ('AUTHORITATIVE','OBSERVED','INFERRED','LLM_HINT')),
    classification_version    INTEGER NOT NULL DEFAULT 1,
    active                    BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from                TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX metadata_registry_identity ON metadata_registry
    (engagement_id, identity_type, identity_value, classification_authority);
""")

    # §4.2 / §6: lease_expires_at is what lets a background sweeper detect an
    # agent that claimed a task and then died.
    op.execute("""
CREATE TABLE tasks (
    task_id           TEXT PRIMARY KEY,
    engagement_id     TEXT NOT NULL REFERENCES engagements(engagement_id),
    goal              TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'queued' CHECK (status IN
                          ('queued','claimed','running','completed','failed','cancelled')),
    owner_agent_id    TEXT,
    lease_expires_at  TIMESTAMPTZ,
    created_by        TEXT NOT NULL,
    parent_task_id    TEXT REFERENCES tasks(task_id),
    overlaps_with     TEXT[] NOT NULL DEFAULT '{}',
    priority          INTEGER NOT NULL DEFAULT 0,
    result_summary    TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX tasks_claimable ON tasks (engagement_id, status, priority DESC, created_at);
""")

    # §4.1. "authorization" is quoted throughout: it is a PostgreSQL reserved
    # word, but renaming the column would break the correspondence with the §4.1
    # schema, and that correspondence is worth more than the quoting noise.
    # authorization and discovery are separate columns on purpose (I8):
    # discovery describes how a candidate target was found and may only trigger
    # escalation; authorization must point at a scope object and is the only
    # thing OPA reads when deciding whether the action is permitted.
    op.execute("""
CREATE TABLE action_proposals (
    proposal_id                   TEXT PRIMARY KEY,
    engagement_id                 TEXT NOT NULL REFERENCES engagements(engagement_id),
    task_id                       TEXT REFERENCES tasks(task_id),
    agent_id                      TEXT NOT NULL,
    request_idempotency_key       TEXT NOT NULL,
    dispatch_state                TEXT NOT NULL DEFAULT 'queued' CHECK (dispatch_state IN
                                      ('queued','dispatching','running','succeeded',
                                       'failed','unknown_outcome')),
    action                        TEXT NOT NULL,
    target                        JSONB NOT NULL,
    "authorization"               JSONB NOT NULL,
    discovery                     JSONB NOT NULL,
    resources                     TEXT[] NOT NULL DEFAULT '{}',
    expected_data                 TEXT[] NOT NULL DEFAULT '{}',
    possible_sensitive_data_hint  TEXT[] NOT NULL DEFAULT '{}',
    writes_data                   BOOLEAN NOT NULL DEFAULT FALSE,
    changes_state                 BOOLEAN NOT NULL DEFAULT FALSE,
    risk_hint                     TEXT,
    reason                        TEXT,
    requested_capability_ttl_seconds INTEGER,
    decision                      TEXT CHECK (decision IN
                                      ('ALLOW','DENY','HUMAN_APPROVAL')),
    decision_reasons              TEXT[] NOT NULL DEFAULT '{}',
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX action_proposals_idempotency ON action_proposals
    (engagement_id, request_idempotency_key);
COMMENT ON COLUMN action_proposals.possible_sensitive_data_hint IS
    '§4.1: AI semantic judgement. May tighten only — never evidence of "not sensitive".';
""")

    # §1.3.2 / §4.6: a revoked credential must invalidate outstanding capabilities,
    # so revocation state needs somewhere to live that renewal can consult (I9).
    op.execute("""
CREATE TABLE credentials (
    credential_id  TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
    label          TEXT NOT NULL,
    revoked        BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
""")

    # §4.7: approvals are capability-like and expire. A month-old approval must
    # not back today's proposal.
    op.execute("""
CREATE TABLE approvals (
    approval_id     TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL REFERENCES engagements(engagement_id),
    proposal_id     TEXT REFERENCES action_proposals(proposal_id),
    action_class    TEXT NOT NULL,
    resource        TEXT,
    constraints     JSONB NOT NULL DEFAULT '{}',
    valid_until     TIMESTAMPTZ NOT NULL,
    approved_by     TEXT NOT NULL,
    approved_scope  TEXT NOT NULL CHECK (approved_scope IN
                        ('this_proposal_only','this_task','this_resource')),
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
""")

    # §4.6. policy_version, approval_id and credential_id are recorded at issue
    # time precisely so renewal can re-check them instead of blindly extending
    # the lease.
    op.execute("""
CREATE TABLE capabilities (
    capability_id      TEXT PRIMARY KEY,
    engagement_id      TEXT NOT NULL REFERENCES engagements(engagement_id),
    agent_id           TEXT NOT NULL,
    proposal_id        TEXT REFERENCES action_proposals(proposal_id),
    action             TEXT NOT NULL,
    constraints        JSONB NOT NULL DEFAULT '{}',
    budget             JSONB NOT NULL DEFAULT '{}',
    requests_used      INTEGER NOT NULL DEFAULT 0 CHECK (requests_used >= 0),
    heartbeat_required BOOLEAN NOT NULL DEFAULT TRUE,
    revoked            BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason     TEXT,
    revoked_at         TIMESTAMPTZ,
    policy_version     INTEGER NOT NULL,
    approval_id        TEXT REFERENCES approvals(approval_id),
    credential_id      TEXT REFERENCES credentials(credential_id),
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_expires_at   TIMESTAMPTZ NOT NULL,
    last_heartbeat_at  TIMESTAMPTZ,
    renewal_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX capabilities_live ON capabilities (engagement_id, revoked, lease_expires_at);
""")

    # §7: the fingerprint carries tool_version, ruleset_version and
    # execution_context, so a new Nuclei template set or a different credential
    # is correctly treated as a different execution rather than a cache hit.
    op.execute("""
CREATE TABLE tool_runs (
    run_id                  TEXT PRIMARY KEY,
    engagement_id           TEXT NOT NULL REFERENCES engagements(engagement_id),
    proposal_id             TEXT REFERENCES action_proposals(proposal_id),
    capability_id           TEXT REFERENCES capabilities(capability_id),
    tool                    TEXT NOT NULL,
    tool_version            TEXT NOT NULL,
    ruleset_version         TEXT,
    normalized_target       TEXT NOT NULL,
    normalized_params       JSONB NOT NULL DEFAULT '{}',
    execution_context       JSONB NOT NULL DEFAULT '{}',
    execution_fingerprint   TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'queued' CHECK (status IN
                                ('queued','dispatching','running','succeeded',
                                 'failed','unknown_outcome')),
    network_allowlist       TEXT[] NOT NULL DEFAULT '{}',
    exit_code               INTEGER,
    fresh_until             TIMESTAMPTZ,
    started_at              TIMESTAMPTZ,
    finished_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX tool_runs_fingerprint ON tool_runs
    (engagement_id, execution_fingerprint, fresh_until);
""")

    # §4.4: one immutable raw artifact, plus a derived view that is the only
    # thing an LLM is ever shown. raw_logically_immutable is honest about what it
    # is — an application-level promise backed by the grants below, not a
    # cryptographic guarantee.
    op.execute("""
CREATE TABLE evidence (
    evidence_id             TEXT PRIMARY KEY,
    engagement_id           TEXT NOT NULL REFERENCES engagements(engagement_id),
    run_id                  TEXT REFERENCES tool_runs(run_id),
    type                    TEXT NOT NULL CHECK (type IN
                                ('tool_output','screenshot','log','http_transaction')),
    raw_artifact_path       TEXT NOT NULL,
    raw_sha256              TEXT NOT NULL,
    raw_logically_immutable BOOLEAN NOT NULL DEFAULT TRUE,
    raw_collected_at        TIMESTAMPTZ NOT NULL,
    derived_view            JSONB NOT NULL,
    tool                    TEXT NOT NULL,
    tool_version            TEXT NOT NULL,
    ruleset_version         TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON COLUMN evidence.derived_view IS
    '§4.4: the LLM-visible projection. Always carries untrusted_content: true.';
""")

    # §4.3. No confidence column: the weighted formula was withdrawn in v0.2 and
    # keeping the field would invite someone to reimplement it.
    op.execute("""
CREATE TABLE findings (
    finding_id             TEXT PRIMARY KEY,
    engagement_id          TEXT NOT NULL REFERENCES engagements(engagement_id),
    claim                  TEXT NOT NULL,
    state                  TEXT NOT NULL CHECK (state IN
                               ('candidate','hypothesis','pending_verification',
                                'verified','rejected','mitigated','accepted_risk')),
    evidence_strength      TEXT NOT NULL CHECK (evidence_strength IN ('E0','E1','E2','E3')),
    verifier_state         TEXT CHECK (verifier_state IN
                               ('confirmed','not_confirmed','insufficient_evidence',
                                'contradictory')),
    evidence_ids           TEXT[] NOT NULL DEFAULT '{}',
    affects                JSONB NOT NULL DEFAULT '{}',
    attack_path_ids        TEXT[] NOT NULL DEFAULT '{}',
    verification_conflict  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at           TIMESTAMPTZ
);
""")

    # §8.10 Provenance Graph — "why do we believe this?", kept separate from the
    # Security Graph. Postgres edges, no Neo4j (§9-D).
    op.execute("""
CREATE TABLE provenance_edges (
    id             BIGSERIAL PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(engagement_id),
    from_type      TEXT NOT NULL,
    from_id        TEXT NOT NULL,
    to_type        TEXT NOT NULL,
    to_id          TEXT NOT NULL,
    relation       TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX provenance_edges_forward ON provenance_edges
    (engagement_id, from_type, from_id);
CREATE INDEX provenance_edges_backward ON provenance_edges
    (engagement_id, to_type, to_id);
""")

    op.execute("""
CREATE TABLE audit_log (
    audit_id       BIGSERIAL PRIMARY KEY,
    engagement_id  TEXT NOT NULL,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor          TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    subject_type   TEXT,
    subject_id     TEXT,
    decision       TEXT,
    reasons        TEXT[] NOT NULL DEFAULT '{}',
    payload        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_engagement_ts ON audit_log (engagement_id, ts);
""")

    # ------------------------------------------------------------------
    # §8.6 Row-Level Security
    # ------------------------------------------------------------------
    # The current engagement travels in a session GUC that the repository layer
    # sets per transaction. current_setting(..., true) yields NULL when it is
    # unset, and `engagement_id = NULL` matches no rows — so forgetting to set it
    # fails closed rather than opening every engagement.
    op.execute("""
CREATE FUNCTION cyberorch_current_engagement() RETURNS TEXT
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('cyberorch.engagement_id', true), '')
$$;
""")

    for table in ENGAGEMENT_SCOPED:
        key = "engagement_id"
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        # Without FORCE, the table owner bypasses every policy below and the
        # tests would still pass while production leaked. §8.6 exists because of
        # exactly this half-done case.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
CREATE POLICY engagement_isolation ON {table}
    FOR ALL TO PUBLIC
    USING ({key} = cyberorch_current_engagement())
    WITH CHECK ({key} = cyberorch_current_engagement());
""")

    # Global policy layers (baseline/emergency) carry a NULL engagement_id and
    # must remain readable from inside any engagement.
    op.execute("ALTER TABLE policy_layers ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE policy_layers FORCE ROW LEVEL SECURITY;")
    op.execute("""
CREATE POLICY engagement_isolation ON policy_layers
    FOR ALL TO PUBLIC
    USING (engagement_id IS NULL OR engagement_id = cyberorch_current_engagement())
    WITH CHECK (engagement_id IS NULL OR engagement_id = cyberorch_current_engagement());
""")

    # ------------------------------------------------------------------
    # §4.4 / §8.6 grants for the runtime role
    # ------------------------------------------------------------------
    op.execute("GRANT USAGE ON SCHEMA public TO cyberorch_app;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
               "TO cyberorch_app;")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cyberorch_app;")

    for table in APPEND_ONLY:
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM cyberorch_app;")
        op.execute(f"GRANT INSERT, SELECT ON {table} TO cyberorch_app;")

    op.execute("GRANT EXECUTE ON FUNCTION cyberorch_current_engagement() TO cyberorch_app;")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS cyberorch_current_engagement() CASCADE;")
    for table in [
        "audit_log", "provenance_edges", "findings", "evidence", "tool_runs",
        "capabilities", "approvals", "credentials", "action_proposals", "tasks",
        "metadata_registry", "scope_registry", "policy_layers", "engagements",
    ]:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE;")
