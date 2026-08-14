"""SQLAlchemy Core table definitions mirroring db/migrations/versions/0001.

Core rather than ORM on purpose: the control plane issues small, explicit
statements (atomic check-and-increment in §8.5, ``FOR UPDATE SKIP LOCKED`` in
§6), and an identity map sitting between the code and those statements would
obscure exactly the behaviour that has to be exact.

The migration is the source of truth for constraints, grants and RLS. This
module only needs to describe columns well enough to build statements against;
tests/test_schema.py asserts the two stay in step.
"""

from __future__ import annotations

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()


def _ts(name: str, **kw) -> Column:
    return Column(name, DateTime(timezone=True), **kw)


engagements = Table(
    "engagements", metadata,
    Column("engagement_id", Text, primary_key=True),
    Column("customer_id", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("kill_switch_engaged", Boolean, nullable=False),
    Column("policy_snapshot_version", Integer, nullable=False),
    _ts("created_at"), _ts("updated_at"),
)

policy_layers = Table(
    "policy_layers", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("layer", Text, nullable=False),
    Column("version", Integer, nullable=False),
    Column("engagement_id", Text),
    Column("customer_id", Text),
    Column("document", JSONB, nullable=False),
    Column("active", Boolean, nullable=False),
    _ts("created_at"),
)

scope_registry = Table(
    "scope_registry", metadata,
    Column("scope_object_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("type", Text, nullable=False),
    Column("value", Text, nullable=False),
    Column("allowed_actions", ARRAY(Text), nullable=False),
    Column("version", Integer, nullable=False),
    Column("active", Boolean, nullable=False),
    _ts("valid_from"), _ts("valid_until"),
    Column("registered_by", Text, nullable=False),
    _ts("created_at"), _ts("updated_at"),
)

metadata_registry = Table(
    "metadata_registry", metadata,
    Column("asset_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("identity_type", Text, nullable=False),
    Column("identity_value", Text, nullable=False),
    Column("resource_class", ARRAY(Text), nullable=False),
    Column("data_class", ARRAY(Text), nullable=False),
    Column("classification_source", Text, nullable=False),
    Column("classification_authority", Text, nullable=False),
    Column("classification_version", Integer, nullable=False),
    Column("active", Boolean, nullable=False),
    _ts("valid_from"), _ts("created_at"), _ts("updated_at"),
)

tasks = Table(
    "tasks", metadata,
    Column("task_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("goal", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("owner_agent_id", Text),
    _ts("lease_expires_at"),
    Column("created_by", Text, nullable=False),
    Column("parent_task_id", Text),
    Column("overlaps_with", ARRAY(Text), nullable=False),
    Column("priority", Integer, nullable=False),
    Column("result_summary", Text),
    _ts("created_at"), _ts("updated_at"),
)

action_proposals = Table(
    "action_proposals", metadata,
    Column("proposal_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("task_id", Text),
    Column("agent_id", Text, nullable=False),
    Column("request_idempotency_key", Text, nullable=False),
    Column("dispatch_state", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("target", JSONB, nullable=False),
    # Reserved word in PostgreSQL; SQLAlchemy quotes it automatically.
    Column("authorization", JSONB, nullable=False),
    Column("discovery", JSONB, nullable=False),
    Column("resources", ARRAY(Text), nullable=False),
    Column("expected_data", ARRAY(Text), nullable=False),
    Column("possible_sensitive_data_hint", ARRAY(Text), nullable=False),
    Column("writes_data", Boolean, nullable=False),
    Column("changes_state", Boolean, nullable=False),
    Column("risk_hint", Text),
    Column("reason", Text),
    Column("requested_capability_ttl_seconds", Integer),
    Column("decision", Text),
    Column("decision_reasons", ARRAY(Text), nullable=False),
    _ts("created_at"), _ts("updated_at"),
)

credentials = Table(
    "credentials", metadata,
    Column("credential_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("label", Text, nullable=False),
    Column("revoked", Boolean, nullable=False),
    _ts("revoked_at"), _ts("created_at"),
)

approvals = Table(
    "approvals", metadata,
    Column("approval_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("proposal_id", Text),
    Column("action_class", Text, nullable=False),
    Column("resource", Text),
    Column("constraints", JSONB, nullable=False),
    _ts("valid_until", nullable=False),
    Column("approved_by", Text, nullable=False),
    Column("approved_scope", Text, nullable=False),
    Column("revoked", Boolean, nullable=False),
    _ts("revoked_at"), _ts("created_at"),
)

capabilities = Table(
    "capabilities", metadata,
    Column("capability_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("agent_id", Text, nullable=False),
    Column("proposal_id", Text),
    Column("action", Text, nullable=False),
    Column("constraints", JSONB, nullable=False),
    Column("budget", JSONB, nullable=False),
    Column("requests_used", Integer, nullable=False),
    Column("heartbeat_required", Boolean, nullable=False),
    Column("revoked", Boolean, nullable=False),
    Column("revoked_reason", Text),
    _ts("revoked_at"),
    Column("policy_version", Integer, nullable=False),
    Column("approval_id", Text),
    Column("credential_id", Text),
    _ts("issued_at"), _ts("lease_expires_at", nullable=False),
    _ts("last_heartbeat_at"),
    Column("renewal_count", Integer, nullable=False),
)

tool_runs = Table(
    "tool_runs", metadata,
    Column("run_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("proposal_id", Text),
    Column("capability_id", Text),
    Column("tool", Text, nullable=False),
    Column("tool_version", Text, nullable=False),
    Column("ruleset_version", Text),
    Column("normalized_target", Text, nullable=False),
    Column("normalized_params", JSONB, nullable=False),
    Column("execution_context", JSONB, nullable=False),
    Column("execution_fingerprint", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("network_allowlist", ARRAY(Text), nullable=False),
    Column("exit_code", Integer),
    _ts("fresh_until"), _ts("started_at"), _ts("finished_at"), _ts("created_at"),
)

evidence = Table(
    "evidence", metadata,
    Column("evidence_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("run_id", Text),
    Column("type", Text, nullable=False),
    Column("raw_artifact_path", Text, nullable=False),
    Column("raw_sha256", Text, nullable=False),
    Column("raw_logically_immutable", Boolean, nullable=False),
    _ts("raw_collected_at", nullable=False),
    Column("derived_view", JSONB, nullable=False),
    Column("tool", Text, nullable=False),
    Column("tool_version", Text, nullable=False),
    Column("ruleset_version", Text),
    _ts("created_at"),
)

findings = Table(
    "findings", metadata,
    Column("finding_id", Text, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("claim", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("evidence_strength", Text, nullable=False),
    Column("verifier_state", Text),
    Column("evidence_ids", ARRAY(Text), nullable=False),
    Column("affects", JSONB, nullable=False),
    Column("attack_path_ids", ARRAY(Text), nullable=False),
    Column("verification_conflict", Boolean, nullable=False),
    _ts("created_at"), _ts("confirmed_at"),
)

provenance_edges = Table(
    "provenance_edges", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    Column("from_type", Text, nullable=False),
    Column("from_id", Text, nullable=False),
    Column("to_type", Text, nullable=False),
    Column("to_id", Text, nullable=False),
    Column("relation", Text, nullable=False),
    _ts("created_at"),
)

audit_log = Table(
    "audit_log", metadata,
    Column("audit_id", BigInteger, primary_key=True),
    Column("engagement_id", Text, nullable=False),
    _ts("ts"),
    Column("actor", Text, nullable=False),
    Column("event_type", Text, nullable=False),
    Column("subject_type", Text),
    Column("subject_id", Text),
    Column("decision", Text),
    Column("reasons", ARRAY(Text), nullable=False),
    Column("payload", JSONB, nullable=False),
)
