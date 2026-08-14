-- GENERATED FILE — do not edit.
-- Produced by scripts/init_db.sh from db/migrations. Reference only;
-- grants and RLS live in the migration, which is the source of truth.
--
-- PostgreSQL database dump
--

\restrict 05NO7AnIxl62bN6aiF1ZXlkp3t5mxEWyUjIC6mHOoHn5a2n71f24AmTg4EjMZYf

-- Dumped from database version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: cyberorch_current_engagement(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cyberorch_current_engagement() RETURNS text
    LANGUAGE sql STABLE
    AS $$
    SELECT NULLIF(current_setting('cyberorch.engagement_id', true), '')
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: action_proposals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.action_proposals (
    proposal_id text NOT NULL,
    engagement_id text NOT NULL,
    task_id text,
    agent_id text NOT NULL,
    request_idempotency_key text NOT NULL,
    dispatch_state text DEFAULT 'queued'::text NOT NULL,
    action text NOT NULL,
    target jsonb NOT NULL,
    "authorization" jsonb NOT NULL,
    discovery jsonb NOT NULL,
    resources text[] DEFAULT '{}'::text[] NOT NULL,
    expected_data text[] DEFAULT '{}'::text[] NOT NULL,
    possible_sensitive_data_hint text[] DEFAULT '{}'::text[] NOT NULL,
    writes_data boolean DEFAULT false NOT NULL,
    changes_state boolean DEFAULT false NOT NULL,
    risk_hint text,
    reason text,
    requested_capability_ttl_seconds integer,
    decision text,
    decision_reasons text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_proposals_decision_check CHECK ((decision = ANY (ARRAY['ALLOW'::text, 'DENY'::text, 'HUMAN_APPROVAL'::text]))),
    CONSTRAINT action_proposals_dispatch_state_check CHECK ((dispatch_state = ANY (ARRAY['queued'::text, 'dispatching'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'unknown_outcome'::text])))
);

ALTER TABLE ONLY public.action_proposals FORCE ROW LEVEL SECURITY;


--
-- Name: COLUMN action_proposals.possible_sensitive_data_hint; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.action_proposals.possible_sensitive_data_hint IS '§4.1: AI semantic judgement. May tighten only — never evidence of "not sensitive".';


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approvals (
    approval_id text NOT NULL,
    engagement_id text NOT NULL,
    proposal_id text,
    action_class text NOT NULL,
    resource text,
    constraints jsonb DEFAULT '{}'::jsonb NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    approved_by text NOT NULL,
    approved_scope text NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT approvals_approved_scope_check CHECK ((approved_scope = ANY (ARRAY['this_proposal_only'::text, 'this_task'::text, 'this_resource'::text])))
);

ALTER TABLE ONLY public.approvals FORCE ROW LEVEL SECURITY;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    audit_id bigint NOT NULL,
    engagement_id text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    actor text NOT NULL,
    event_type text NOT NULL,
    subject_type text,
    subject_id text,
    decision text,
    reasons text[] DEFAULT '{}'::text[] NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL
);

ALTER TABLE ONLY public.audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_audit_id_seq OWNED BY public.audit_log.audit_id;


--
-- Name: capabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.capabilities (
    capability_id text NOT NULL,
    engagement_id text NOT NULL,
    agent_id text NOT NULL,
    proposal_id text,
    action text NOT NULL,
    constraints jsonb DEFAULT '{}'::jsonb NOT NULL,
    budget jsonb DEFAULT '{}'::jsonb NOT NULL,
    requests_used integer DEFAULT 0 NOT NULL,
    heartbeat_required boolean DEFAULT true NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    revoked_reason text,
    revoked_at timestamp with time zone,
    policy_version integer NOT NULL,
    approval_id text,
    credential_id text,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    last_heartbeat_at timestamp with time zone,
    renewal_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT capabilities_requests_used_check CHECK ((requests_used >= 0))
);

ALTER TABLE ONLY public.capabilities FORCE ROW LEVEL SECURITY;


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    credential_id text NOT NULL,
    engagement_id text NOT NULL,
    label text NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.credentials FORCE ROW LEVEL SECURITY;


--
-- Name: engagements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.engagements (
    engagement_id text NOT NULL,
    customer_id text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    kill_switch_engaged boolean DEFAULT false NOT NULL,
    policy_snapshot_version integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT engagements_status_check CHECK ((status = ANY (ARRAY['active'::text, 'paused'::text, 'completed'::text, 'killed'::text])))
);

ALTER TABLE ONLY public.engagements FORCE ROW LEVEL SECURITY;


--
-- Name: COLUMN engagements.policy_snapshot_version; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.engagements.policy_snapshot_version IS '§4.5: frozen pointer to the Baseline Global Snapshot in force at creation.';


--
-- Name: evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence (
    evidence_id text NOT NULL,
    engagement_id text NOT NULL,
    run_id text,
    type text NOT NULL,
    raw_artifact_path text NOT NULL,
    raw_sha256 text NOT NULL,
    raw_logically_immutable boolean DEFAULT true NOT NULL,
    raw_collected_at timestamp with time zone NOT NULL,
    derived_view jsonb NOT NULL,
    tool text NOT NULL,
    tool_version text NOT NULL,
    ruleset_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evidence_type_check CHECK ((type = ANY (ARRAY['tool_output'::text, 'screenshot'::text, 'log'::text, 'http_transaction'::text])))
);

ALTER TABLE ONLY public.evidence FORCE ROW LEVEL SECURITY;


--
-- Name: COLUMN evidence.derived_view; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.evidence.derived_view IS '§4.4: the LLM-visible projection. Always carries untrusted_content: true.';


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    finding_id text NOT NULL,
    engagement_id text NOT NULL,
    claim text NOT NULL,
    state text NOT NULL,
    evidence_strength text NOT NULL,
    verifier_state text,
    evidence_ids text[] DEFAULT '{}'::text[] NOT NULL,
    affects jsonb DEFAULT '{}'::jsonb NOT NULL,
    attack_path_ids text[] DEFAULT '{}'::text[] NOT NULL,
    verification_conflict boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    confirmed_at timestamp with time zone,
    CONSTRAINT findings_evidence_strength_check CHECK ((evidence_strength = ANY (ARRAY['E0'::text, 'E1'::text, 'E2'::text, 'E3'::text]))),
    CONSTRAINT findings_state_check CHECK ((state = ANY (ARRAY['candidate'::text, 'hypothesis'::text, 'pending_verification'::text, 'verified'::text, 'rejected'::text, 'mitigated'::text, 'accepted_risk'::text]))),
    CONSTRAINT findings_verifier_state_check CHECK ((verifier_state = ANY (ARRAY['confirmed'::text, 'not_confirmed'::text, 'insufficient_evidence'::text, 'contradictory'::text])))
);

ALTER TABLE ONLY public.findings FORCE ROW LEVEL SECURITY;


--
-- Name: metadata_registry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.metadata_registry (
    asset_id text NOT NULL,
    engagement_id text NOT NULL,
    identity_type text NOT NULL,
    identity_value text NOT NULL,
    resource_class text[] DEFAULT '{}'::text[] NOT NULL,
    data_class text[] DEFAULT '{}'::text[] NOT NULL,
    classification_source text NOT NULL,
    classification_authority text NOT NULL,
    classification_version integer DEFAULT 1 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT metadata_registry_classification_authority_check CHECK ((classification_authority = ANY (ARRAY['AUTHORITATIVE'::text, 'OBSERVED'::text, 'INFERRED'::text, 'LLM_HINT'::text])))
);

ALTER TABLE ONLY public.metadata_registry FORCE ROW LEVEL SECURITY;


--
-- Name: policy_layers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.policy_layers (
    id bigint NOT NULL,
    layer text NOT NULL,
    version integer NOT NULL,
    engagement_id text,
    customer_id text,
    document jsonb NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT emergency_overlay_can_only_tighten CHECK (((layer <> 'emergency_overlay'::text) OR ((NOT (document ? 'scope_allow'::text)) AND (NOT jsonb_path_exists(document, '$."actions".*?(@ == "ALLOW")'::jsonpath))))),
    CONSTRAINT policy_layers_layer_check CHECK ((layer = ANY (ARRAY['baseline_global'::text, 'emergency_overlay'::text, 'customer'::text, 'engagement'::text])))
);

ALTER TABLE ONLY public.policy_layers FORCE ROW LEVEL SECURITY;


--
-- Name: policy_layers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.policy_layers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: policy_layers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.policy_layers_id_seq OWNED BY public.policy_layers.id;


--
-- Name: provenance_edges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provenance_edges (
    id bigint NOT NULL,
    engagement_id text NOT NULL,
    from_type text NOT NULL,
    from_id text NOT NULL,
    to_type text NOT NULL,
    to_id text NOT NULL,
    relation text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.provenance_edges FORCE ROW LEVEL SECURITY;


--
-- Name: provenance_edges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.provenance_edges_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provenance_edges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.provenance_edges_id_seq OWNED BY public.provenance_edges.id;


--
-- Name: scope_registry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scope_registry (
    scope_object_id text NOT NULL,
    engagement_id text NOT NULL,
    type text NOT NULL,
    value text NOT NULL,
    allowed_actions text[] NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    registered_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scope_registry_type_check CHECK ((type = ANY (ARRAY['fqdn'::text, 'cidr'::text, 'ip'::text, 'url'::text, 'repo'::text, 'ad_domain'::text])))
);

ALTER TABLE ONLY public.scope_registry FORCE ROW LEVEL SECURITY;


--
-- Name: tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tasks (
    task_id text NOT NULL,
    engagement_id text NOT NULL,
    goal text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    owner_agent_id text,
    lease_expires_at timestamp with time zone,
    created_by text NOT NULL,
    parent_task_id text,
    overlaps_with text[] DEFAULT '{}'::text[] NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    result_summary text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tasks_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'claimed'::text, 'running'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])))
);

ALTER TABLE ONLY public.tasks FORCE ROW LEVEL SECURITY;


--
-- Name: tool_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tool_runs (
    run_id text NOT NULL,
    engagement_id text NOT NULL,
    proposal_id text,
    capability_id text,
    tool text NOT NULL,
    tool_version text NOT NULL,
    ruleset_version text,
    normalized_target text NOT NULL,
    normalized_params jsonb DEFAULT '{}'::jsonb NOT NULL,
    execution_context jsonb DEFAULT '{}'::jsonb NOT NULL,
    execution_fingerprint text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    network_allowlist text[] DEFAULT '{}'::text[] NOT NULL,
    exit_code integer,
    fresh_until timestamp with time zone,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tool_runs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'dispatching'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'unknown_outcome'::text])))
);

ALTER TABLE ONLY public.tool_runs FORCE ROW LEVEL SECURITY;


--
-- Name: audit_log audit_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN audit_id SET DEFAULT nextval('public.audit_log_audit_id_seq'::regclass);


--
-- Name: policy_layers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_layers ALTER COLUMN id SET DEFAULT nextval('public.policy_layers_id_seq'::regclass);


--
-- Name: provenance_edges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provenance_edges ALTER COLUMN id SET DEFAULT nextval('public.provenance_edges_id_seq'::regclass);


--
-- Name: action_proposals action_proposals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_proposals
    ADD CONSTRAINT action_proposals_pkey PRIMARY KEY (proposal_id);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: approvals approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_pkey PRIMARY KEY (approval_id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (audit_id);


--
-- Name: capabilities capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_pkey PRIMARY KEY (capability_id);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (credential_id);


--
-- Name: engagements engagements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.engagements
    ADD CONSTRAINT engagements_pkey PRIMARY KEY (engagement_id);


--
-- Name: evidence evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_pkey PRIMARY KEY (evidence_id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (finding_id);


--
-- Name: metadata_registry metadata_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metadata_registry
    ADD CONSTRAINT metadata_registry_pkey PRIMARY KEY (asset_id);


--
-- Name: policy_layers policy_layers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_layers
    ADD CONSTRAINT policy_layers_pkey PRIMARY KEY (id);


--
-- Name: provenance_edges provenance_edges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provenance_edges
    ADD CONSTRAINT provenance_edges_pkey PRIMARY KEY (id);


--
-- Name: scope_registry scope_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scope_registry
    ADD CONSTRAINT scope_registry_pkey PRIMARY KEY (scope_object_id);


--
-- Name: tasks tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (task_id);


--
-- Name: tool_runs tool_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_runs
    ADD CONSTRAINT tool_runs_pkey PRIMARY KEY (run_id);


--
-- Name: action_proposals_idempotency; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX action_proposals_idempotency ON public.action_proposals USING btree (engagement_id, request_idempotency_key);


--
-- Name: audit_log_engagement_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_engagement_ts ON public.audit_log USING btree (engagement_id, ts);


--
-- Name: capabilities_live; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX capabilities_live ON public.capabilities USING btree (engagement_id, revoked, lease_expires_at);


--
-- Name: metadata_registry_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX metadata_registry_identity ON public.metadata_registry USING btree (engagement_id, identity_type, identity_value, classification_authority);


--
-- Name: policy_layers_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX policy_layers_identity ON public.policy_layers USING btree (layer, version, COALESCE(engagement_id, ''::text), COALESCE(customer_id, ''::text));


--
-- Name: provenance_edges_backward; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX provenance_edges_backward ON public.provenance_edges USING btree (engagement_id, to_type, to_id);


--
-- Name: provenance_edges_forward; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX provenance_edges_forward ON public.provenance_edges USING btree (engagement_id, from_type, from_id);


--
-- Name: scope_registry_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scope_registry_lookup ON public.scope_registry USING btree (engagement_id, type, value);


--
-- Name: tasks_claimable; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_claimable ON public.tasks USING btree (engagement_id, status, priority DESC, created_at);


--
-- Name: tool_runs_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tool_runs_fingerprint ON public.tool_runs USING btree (engagement_id, execution_fingerprint, fresh_until);


--
-- Name: action_proposals action_proposals_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_proposals
    ADD CONSTRAINT action_proposals_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: action_proposals action_proposals_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_proposals
    ADD CONSTRAINT action_proposals_task_id_fkey FOREIGN KEY (task_id) REFERENCES public.tasks(task_id);


--
-- Name: approvals approvals_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: approvals approvals_proposal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES public.action_proposals(proposal_id);


--
-- Name: capabilities capabilities_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.approvals(approval_id);


--
-- Name: capabilities capabilities_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.credentials(credential_id);


--
-- Name: capabilities capabilities_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: capabilities capabilities_proposal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES public.action_proposals(proposal_id);


--
-- Name: credentials credentials_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: evidence evidence_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: evidence evidence_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence
    ADD CONSTRAINT evidence_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.tool_runs(run_id);


--
-- Name: findings findings_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: metadata_registry metadata_registry_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.metadata_registry
    ADD CONSTRAINT metadata_registry_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: policy_layers policy_layers_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.policy_layers
    ADD CONSTRAINT policy_layers_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: provenance_edges provenance_edges_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provenance_edges
    ADD CONSTRAINT provenance_edges_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: scope_registry scope_registry_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scope_registry
    ADD CONSTRAINT scope_registry_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: tasks tasks_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: tasks tasks_parent_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_parent_task_id_fkey FOREIGN KEY (parent_task_id) REFERENCES public.tasks(task_id);


--
-- Name: tool_runs tool_runs_capability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_runs
    ADD CONSTRAINT tool_runs_capability_id_fkey FOREIGN KEY (capability_id) REFERENCES public.capabilities(capability_id);


--
-- Name: tool_runs tool_runs_engagement_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_runs
    ADD CONSTRAINT tool_runs_engagement_id_fkey FOREIGN KEY (engagement_id) REFERENCES public.engagements(engagement_id);


--
-- Name: tool_runs tool_runs_proposal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_runs
    ADD CONSTRAINT tool_runs_proposal_id_fkey FOREIGN KEY (proposal_id) REFERENCES public.action_proposals(proposal_id);


--
-- Name: action_proposals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.action_proposals ENABLE ROW LEVEL SECURITY;

--
-- Name: approvals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.approvals ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: capabilities; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.capabilities ENABLE ROW LEVEL SECURITY;

--
-- Name: credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: action_proposals engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.action_proposals USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: approvals engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.approvals USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: audit_log engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.audit_log USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: capabilities engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.capabilities USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: credentials engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.credentials USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: engagements engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.engagements USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: evidence engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.evidence USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: findings engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.findings USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: metadata_registry engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.metadata_registry USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: policy_layers engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.policy_layers USING (((engagement_id IS NULL) OR (engagement_id = public.cyberorch_current_engagement()))) WITH CHECK (((engagement_id IS NULL) OR (engagement_id = public.cyberorch_current_engagement())));


--
-- Name: provenance_edges engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.provenance_edges USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: scope_registry engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.scope_registry USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: tasks engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.tasks USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: tool_runs engagement_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY engagement_isolation ON public.tool_runs USING ((engagement_id = public.cyberorch_current_engagement())) WITH CHECK ((engagement_id = public.cyberorch_current_engagement()));


--
-- Name: engagements; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.engagements ENABLE ROW LEVEL SECURITY;

--
-- Name: evidence; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;

--
-- Name: findings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

--
-- Name: metadata_registry; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.metadata_registry ENABLE ROW LEVEL SECURITY;

--
-- Name: policy_layers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.policy_layers ENABLE ROW LEVEL SECURITY;

--
-- Name: provenance_edges; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.provenance_edges ENABLE ROW LEVEL SECURITY;

--
-- Name: scope_registry; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scope_registry ENABLE ROW LEVEL SECURITY;

--
-- Name: tasks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tasks ENABLE ROW LEVEL SECURITY;

--
-- Name: tool_runs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tool_runs ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--

\unrestrict 05NO7AnIxl62bN6aiF1ZXlkp3t5mxEWyUjIC6mHOoHn5a2n71f24AmTg4EjMZYf

