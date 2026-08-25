# MVP-Kernel Acceptance Review

Against `docs/ARCHITECTURE.md` v0.3 §10 (MVP-Kernel scope) and §11 (invariants
and verification strategy).

**Verdict: GO.** MVP-Kernel meets §10's acceptance criteria and is ready to
merge to `main`. The reasoning is in [Go / No-Go](#go--no-go) at the end; the
evidence is everything above it.

Scope reminder — what §10 deliberately excludes, and what this review therefore
does not assess: no real LLM (Fake Planner / Fake Worker / Adversarial Fake
Reviewer only), no Neo4j, no Vector DB, no Egress Proxy, no multi-provider
abstraction, no Web Agent, no Playwright, no Approval UI.

> **Post-acceptance correction (D27), resolved (D28).** The stateful
> property-test suite this review credits throughout —
> `tests/stateful/test_capability_lifecycle.py`, the D9 deliverable — was
> **deleted at `7c9295f` (D17)**, bundled into an unrelated commit, and this
> document went on asserting coverage that had stopped running for three days.
> It is **restored and modernised as of D28**; see
> [§4.1](#41-stateful-coverage--lost-at-d17-restored-at-d28) for the incident
> record, the root cause, and what changed on the way back. The invariant table
> in §4 is accurate again. Kept rather than deleted because the failure mode —
> a record asserting coverage proves the assertion was written, not that the
> coverage exists — is the most useful thing this stage produced.

---

## 1. Scenario A — the ALLOW path end to end

§10: a target inside scope, correctly classified, proposed by an agent, allowed
by policy, executed in a confined sandbox, with evidence and provenance written
and the whole decision reconstructable from the audit log.

Everything runs through `propose_action()` — the single control-plane entry
point. No test wires the stages together by hand, because a test that assembles
the pipeline itself verifies the wiring the test wrote rather than the wiring
production uses.

File: `tests/scenarios/test_scenario_a_allow.py`

| Assertion | Test |
|---|---|
| Authorized scan runs; `tool_runs` + `evidence` written with sha256 digest and `raw_logically_immutable` | `test_scenario_a_authorized_scan_runs_and_writes_evidence` |
| Provenance chain written to `provenance_edges` and traversable — scope object → proposal, asset → proposal, proposal → capability → run → evidence | `test_scenario_a_provenance_chain_is_written_and_traversable` |
| The seven-event decision chain reconstructs from `audit_log` alone | `test_scenario_a_audit_trail_reconstructs_the_decision` |
| An honest reviewer may still escalate to HUMAN_APPROVAL — advisory input can tighten | `test_scenario_a_reviewer_may_still_escalate` |
| `reconstruct_decision` equals the raw whole-engagement query it replaced, minus exactly the registry-setup and task-lifecycle rows | `test_reconstruct_decision_matches_the_raw_audit_query_it_replaced` |

Supporting: `tests/test_dispatch.py` (dispatch state machine, evidence writeback,
UNKNOWN_OUTCOME), `tests/test_sandbox.py` (CIDR confinement at the kernel level).

## 2. Scenario B — the DENY path under an adversarial reviewer

§10: the target carries an AUTHORITATIVE classification on the deny list; the
Policy Reviewer reports low risk and no sensitive data; OPA denies anyway; no
network action occurs at all; the audit trail records both the denial and the
lie.

The distinguishing property is that this does not stop at "the function returned
DENY". A pipeline that returned DENY and then went on to issue a capability and
run a scan would satisfy that. The Capability Broker and the Tool Gateway are
wrapped in spies and their **call counts asserted to be zero** — "no capability
row exists" cannot distinguish "never called" from "called and declined", and
those are different systems.

File: `tests/scenarios/test_scenario_b_deny.py`

| Assertion | Test |
|---|---|
| I6b end to end: the reviewer lies, the decision does not move; denied on `forbidden_data`, not on something incidental | `test_scenario_b_adversarial_reviewer_cannot_downgrade_authoritative_deny` |
| Capability Broker call count is 0 | `test_scenario_b_capability_broker_is_never_called` |
| Tool Gateway call count is 0 | `test_scenario_b_tool_gateway_is_never_called` |
| No `tool_runs`, no `evidence`; the proposal is recorded as denied rather than absent | `test_scenario_b_leaves_no_run_or_evidence_behind` |
| Belt and braces (§8.3): the denied target has no route even had the three layers above been bypassed — `probe_egress` returns `network_unreachable` | `test_scenario_b_no_egress_is_possible_even_had_it_run` |
| The reviewer's claim recorded beside the classification it contradicts — the pair is the evidence | `test_scenario_b_audit_records_both_the_lie_and_the_reason_for_denial` |
| A denial is traced too: proposal linked to the scope object that authorized and the asset that denied | `test_scenario_b_records_provenance_for_the_denied_proposal` |
| The other route to the same bypass: an `LLM_HINT` row in the registry changes nothing (I6b, I6c) | `test_scenario_b_lower_tier_observation_cannot_dilute_the_deny` |

## 3. Scenario B′ — unknown classification (I10 at the integration layer)

Added after the pre-merge sweep found `writes_data` / `changes_state` covered on
the Rego side and on neither end of the wiring between them.

File: `tests/scenarios/test_unknown_classification.py`

| Assertion | Test |
|---|---|
| Each flag arrives in the OPA input as set on the proposal | `test_the_flag_reaches_the_policy_input` |
| A writing action on an unclassified target → HUMAN_APPROVAL, no capability, no run | `test_a_writing_action_on_an_unclassified_target_needs_a_human` |
| Control: same target, both flags false → ALLOW | `test_a_read_only_action_on_the_same_target_is_not_escalated` |
| Both flags together yield exactly one reason | `test_both_flags_together_still_escalate_once` |

---

## 4. Invariants I1–I10

Coverage level, tests, and whether that level is sufficient. The sufficiency
column is a judgement, not a default: not every invariant needs stateful
coverage, and the reasoning is given rather than assumed.

**Corrected at D27, restored at D28.** The `Stateful` column read ✅ for six
invariants when this review was written; every one of those cells became false at
`7c9295f` (D17) without anyone noticing, and was marked `✖ (was ✅)` at D27 while
the suite was missing. D28 restored the suite, so the ✅ marks below are true
again — and are now true of a suite that also covers §4.6's approval branch,
which the original never did. §4.1 records what happened and what changed.

| Inv | Stateful | Scenario | Unit | Principal tests | Sufficient? |
|---|:--:|:--:|:--:|---|---|
| **I1** Scope Safety | ✅ | ✅ | ✅ | `i1_live_capabilities_stay_in_scope`; `test_renewal_fails_once_the_authorizing_scope_object_is_retired`; `test_issue_is_refused_against_a_retired_scope_object`; `test_retiring_one_scope_object_leaves_capabilities_from_another_alone`; `test_broker_reads_scope_only_as_a_liveness_check` | **Yes.** The gap (a capability outliving its scope object) was found by the D9 state machine and closed by a three-part fix — `capabilities.scope_object_id` (migration 0004), `_check_scope_object_still_live`, and eager cascades — which `git log` confirms was never touched while the suite was missing. D28 mutation testing re-verified the machine catches removal of the eager cascade. The broker's *lazy* backstop is covered by unit tests rather than by the machine, for the reason recorded in the suite's docstring: the uncascaded path has no production caller. |
| **I2** Policy Monotonicity | ✅ | — | ✅ | `i2_policy_only_tightens`; `emergency_tighten` rule (via `publish_policy_layer`); `test_publishing_an_overlay_tightens_the_merged_policy`; `tests/test_merge_properties.py` (9 properties, 400 examples each) | **Yes.** Algebra covered by generated combinations; the operation covered end to end; and the whole-run invariant re-checks that the *effective* policy never shrank. Global publishes and `deactivate_policy_layer` stay out of the machine on purpose — see the suite docstring. |
| **I3** Capability Confinement | ✅ | — | ✅ | `i3_no_lease_outlives_its_budget`; `renew_repeatedly` control rule; `test_lease_never_exceeds_the_duration_budget`; `test_repeated_heartbeats_never_push_the_lease_past_the_budget` | **Yes.** Temporal by nature, so stateful is the right level: the bound is asserted after every step of a random walk, not only in a deterministic renewal sequence. |
| **I4** Engagement Isolation | — | — | ✅ | `test_cross_engagement_read_is_blocked`; `test_cannot_write_into_another_engagement`; `test_runtime_role_cannot_bypass_rls`; `test_registry_admin_cannot_bypass_rls`; `test_registry_admin_cannot_write_into_another_engagement`; `test_retire_scope_object_cannot_reach_into_another_engagement`; `test_revoke_credential_cannot_reach_into_another_engagement` | **Yes**, after re-checking. RLS is enforced by the database, so it holds for every operation rather than per code path — but the two-role `retire_scope_object` needed its own test, since existing coverage proved each role individually confined, not the pair. Mutation showed RLS is the load-bearing mechanism; the cascades' own `engagement_id` predicates are defence in depth. |
| **I5** Evidence Provenance | — | ✅ | ✅ | `test_scenario_a_provenance_chain_is_written_and_traversable`; `test_successful_scan_writes_evidence_run_and_state` | **Yes.** Fully verifiable within one decision chain; nothing about it is order-dependent, so forcing it into the state machine would cost runtime and prove nothing extra. |
| **I6a** Decision Non-Override | — | ✅ | ✅ | rego `test_ai_cannot_override_deny_via_misclassification`; `test_adversarial_reviewer_cannot_talk_a_pii_host_into_allow` | **Yes.** Same reasoning as I5 — a single decision suffices. The permanent adversarial fixture is the right instrument. |
| **I6b** Attribute Non-Escalation | — | ✅ | ✅ | Scenario B (8 tests); `test_scenario_b_lower_tier_observation_cannot_dilute_the_deny`; registry privilege tests | **Yes.** Enforced structurally too: `ReviewerOpinion` has no field able to assert a data class, and `cyberorch_app` holds no write on either registry. |
| **I6c** Trust Monotonicity | — | ✅ | ✅ | `test_scenario_b_lower_tier_observation_cannot_dilute_the_deny`; resolver precedence tests; rego `test_low_tier_hint_can_tighten_into_deny` | **Yes.** Same level as I6b. |
| **I7** Idempotent Dispatch | ✅ | — | ✅ | `duplicate_dispatch` rule; `test_a_second_identical_scan_is_deduplicated`; `test_the_same_host_scanned_for_different_ports_is_not_deduplicated` | **Yes.** Concurrency-shaped, so stateful matters here — the rule replays one idempotency key across arbitrary interleavings, and `event()` confirms both the first-claim and repeat-claim branches fire. |
| **I8** Authorization Provenance | ✅ | ✅ | ✅ | `i1_live_capabilities_stay_in_scope` (asserts every live capability records a scope object); `resolve_authorization` has no `discovery` parameter (asserted on the signature); `test_capability_records_the_scope_object_that_authorized_it`; `test_a_capability_with_no_recorded_scope_object_abstains`; rego discovery tests | **Yes.** Partly enforced by the type system: the information is not available to the function, which is stronger than remembering not to read it. |
| **I9** Revocation Safety | ✅ | — | ✅ | `i9_revocation_is_terminal`; `scope_retirement_is_precise`; five cascades (pause / kill switch / credential / scope / **approval**, new at D28); `test_revocation_has_no_way_back`; `test_the_kill_switch_cannot_be_undone` | **Yes.** This is the invariant §11 names as only findable in sequence, and it has the deepest stateful coverage: revoked capabilities are re-checked after *every* step, and `scope_retirement_is_precise` covers the "borrowed reason" case — a capability killed by the kill switch and later caught by a scope retirement must keep the earlier reason. D28 mutation testing confirmed a borrowed reason turns the suite red. |
| **I10** Fail-Closed Ambiguity | — | ✅ | ✅ | See table below | **Yes**, after the integration-layer gap was closed. |

### 4.1 Stateful coverage — lost at D17, restored at D28

**Status: restored.** `tests/stateful/` is back in the tree, runs at D9's scale
(300 examples × 30 steps), and covers one thing the original never did. This
section is kept as the incident record rather than deleted, because the failure
mode it documents is the most useful thing this stage produced.

**What happened.** `7c9295f` ("D17: say something useful when the CLI fails, and
mark §7's dedup boundary") deleted `tests/stateful/__init__.py` and
`tests/stateful/test_capability_lifecycle.py` as pure deletions — status `D`, no
rename — alongside unrelated edits to `agents/llm/headless.py`, two
`scripts/live_run/` files, `tests/test_dispatch.py` and
`tests/test_supervisor_boundary.py`. CI stayed green throughout, because a
deleted test does not fail; it stops guarding. For three days the pass/fail
signal was identical whether the suite existed or not.

**How it was found.** 2026-08-25, as a by-product of the D25 work: a stop-hook
flagged an untracked file, the file was `tests/stateful/test_capability_lifecycle.py`,
and tracing why a path with four commits of history showed as *untracked*
surfaced the deletion.

**Root cause: accidental, not a decision.** The commit message describes CLI
error reporting and dedup boundaries and never mentions removing a property-test
suite, closing instead with "567 tests, rego 34/34, ruff clean" — a count
reported as healthy. This document went on citing the suite as principal
coverage for six invariants and naming it by path; `hypothesis>=6.115` stayed in
`pyproject.toml`; `ARCHITECTURE.md` §3 still listed `stateful/` in the tree. A
deliberate removal would have taken at least one of those with it. The probable
mechanism is a `git add -A` after a container reclaim, at a moment when the slow,
database-backed directory was not on disk.

**Impact while it was missing — verified, not assumed.** Nothing was changed
while unguarded: `git log 7c9295f..HEAD` over `capability/broker.py` and
`orchestrator/engagement.py` returns nothing, and both were last touched *before*
the deletion (`26ff2af` and `86b18bb` respectively). The three-part I1 fix was
intact throughout, and the concrete bugs the machine found stayed covered by
single-operation tests. So the worse scenario — the fix silently broken during
the gap — did not occur. What was absent was the *method*: arbitrary interleaving
with invariants re-checked after every step.

**Two traps on the way back, both avoided.**

1. *The copy on disk was not the suite.* The file whose untracked status exposed
   the deletion was an earlier draft from during D9's development — 561 lines
   against 762, with no `retire_scope_object`/`revoke_credential`, no
   `SCOPE_OBJECT_DEACTIVATED`, no `scope_retirement_is_precise`, and one scope
   object rather than two. D9's own commit message says why the last one matters:
   *"With a single scope object 'revoke everything in the engagement' and 'revoke
   what this scope object authorized' are indistinguishable, and the over-broad
   implementation passes."* Restoring from disk would have produced a suite that
   looks right, passes, and cannot catch the over-broad cascade.
2. *D9's original was not the right revision either.* This document initially
   named `86b18bb` as the source to restore from. That was wrong, and it is the
   same mistake in a smaller form: two later commits changed the suite —
   `8b6af07` added the `event()` branch instrumentation and `26ff2af` moved
   `emergency_tighten` onto `publish_policy_layer`. **The authoritative revision
   is `26ff2af`**, the last before the deletion, and that is what D28 restored.

**What changed on the way back.** Every API the suite calls was re-checked
against the current tree; none had drifted, so the rules test what they always
tested. One rule was added — `expire_approval`, covering the one item on §4.6's
renewal checklist the original machine never drove, since capabilities were
issued with `approval_id` NULL. Three further candidates were considered and
deliberately rejected, with reasons recorded in the suite's own docstring: a
global policy-layer publish (D21) would perturb every other engagement sharing
the database; `deactivate_policy_layer` is a widening and would require
redefining what `i2_policy_only_tightens` means; and an uncascaded scope
deactivation has no production caller and would manufacture an I1 violation the
design has already closed.

**Verification.** 300 examples at 30 steps, `event()` statistics confirming every
meaningful branch fires rather than passing on air — the D9 lesson where
`deactivate_scope` fired 95 times in 100 examples and revoked nothing every time
while the suite reported success. Cascades are observed revoking 1–4
capabilities, `resume: REFUSED after kill switch` fires at 29%, and the new
`expire_approval` rule reaches outstanding capabilities in ~15% of examples.
Mutation testing turns the suite red for: the eager scope cascade removed, a
borrowed `revoked_reason` on the scope cascade, and the approval-expiry check
disabled.

### I9 — revocation reasons and their regression tests

The exact string recorded in `capabilities.revoked_reason`, per cascade.
Constants in `control_plane/capability/broker.py`.

| Operation | `revoked_reason` | Regression tests |
|---|---|---|
| `revoke_credential()` | `credential_revoked` | `test_revoking_a_credential_cascades_and_is_audited` (eager + audit); `test_revoking_a_credential_leaves_capabilities_holding_another_alone` (precision); `test_revoked_credential_then_heartbeat_revokes` (lazy backstop); `test_revoke_credential_cannot_reach_into_another_engagement` (I4) |
| `retire_scope_object()` | `scope_object_deactivated` | `test_retiring_a_scope_object_cascades_and_is_audited` (eager + audit); `test_renewal_fails_once_the_authorizing_scope_object_is_retired` (lazy backstop; the original D9 bug); `test_retiring_one_scope_object_leaves_capabilities_from_another_alone` (precision); `test_retire_scope_object_cannot_reach_into_another_engagement` (I4) |

Related, from the same scope check but distinct in meaning:
`scope_object_not_found` (also where RLS lands for another engagement's id) and
`scope_action_no_longer_allowed`
(`test_renewal_fails_when_the_action_is_withdrawn_from_the_scope_object`).

The stateful rule `scope_retirement_is_precise` additionally asserted that a
capability revoked by the scope cascade records `scope_object_deactivated` and
not a borrowed reason — a wrong reason sends an investigator to the wrong table.
That rule was absent between D17 and D28 (§4.1) and is running again. It is the
only thing that reaches the *contested* case: a capability revoked by one route
and later reached by another must keep the earlier reason, which needs two
cascades in one sequence and so is out of reach of any single-operation test. D28
mutation testing confirmed it has teeth — pointing the scope cascade at a
borrowed `POLICY_CHANGED` turns the suite red.

### I10 — every place an attribute can be UNKNOWN / CONFLICT / ERROR

| Site | Behaviour | Test |
|---|---|---|
| Two AUTHORITATIVE rows disagree | → `CONFLICT`, never a picked winner | `test_resolvers.py` — CONFLICT resolves to not-known |
| No AUTHORITATIVE row (or only lower tiers) | → `UNKNOWN`; lower tiers appear only as observations | resolver precedence tests |
| Per-action-class unknown handling | writing/state-changing actions → HUMAN_APPROVAL | rego `test_unknown_classification_blocks_actions_that_write`; **and** `tests/scenarios/test_unknown_classification.py` end to end |
| Dispatch crashed mid-flight | → `UNKNOWN_OUTCOME`, never auto-retried | `test_dispatch.py` UNKNOWN_OUTCOME group |
| OPA unavailable / malformed | → DENY + `policy_engine_unavailable` | `test_policy_engine.py` |
| Target cannot be canonicalized | → `CanonicalizationError`, refused | `test_canonicalizer.py` |
| Action no layer mentions | → DENY | `test_action_precedence_is_deny_dominant_and_fails_closed` |
| Scope object recorded as NULL on a capability | abstain — neither pass nor veto | `test_a_capability_with_no_recorded_scope_object_abstains` |

---

## 5. DEFERRED items

Each carries where it was found, why it is not being done now, and the
constraints that bind whoever implements it later. None blocks MVP-Kernel.

### 5.1 Hierarchical classification fallback — D3

`control_plane/canonicalizer/metadata.py`

Lookup is by exact canonical identity only. A URL does not inherit its host's
classification, an IP does not inherit its enclosing network's, a subdomain does
not inherit its parent's.

*Why not now:* ARCHITECTURE.md defines no inheritance semantics, and both
answers are wrong in a different direction — inheriting lets a statement about
`app.example.com` stand in for an unregistered path beneath it; not inheriting
means a host declared PII does not by itself protect those paths. Choosing
without a decision in the design would be inventing authorization semantics,
which is the one thing this module must not do. Nothing in MVP-Kernel is
blocked: Nmap targets are fqdn/ip/cidr, registered directly.

*Binding constraints:* (1) inherit only downward from an **AUTHORITATIVE**
parent — a parent at OBSERVED/INFERRED/LLM_HINT must never produce an inherited
classification, or inheritance becomes a second laundering route (I6b);
(2) inheritance may only **tighten**, never turn a child's UNKNOWN into "known
and therefore permitted" — only a row against the child's own identity can
satisfy a prerequisite (I6c); (3) it needs its **own tests**, not an extension
of the exact-match ones.

### 5.2 Enforcement against a non-Docker network — D6

`tool_gateway/sandbox.py`

The allowlisted CIDR is realized as a Docker-managed bridge subnet, so targets
must live inside it. That is genuine namespace-level enforcement — the tests
confirm the kernel returns `ENETUNREACH` for anything outside — and it is enough
for MVP-Kernel, where targets are containers.

*Why not now:* a real engagement's allowlist describes a customer's actual
network and would need a routed or macvlan network. **This has never been
exercised and no test covers it.**

*Binding constraints:* (1) the confinement tests must run **against the new
driver** — passing on a bridge says nothing about a macvlan; (2) confinement is
confirmed **with the kernel, never with the tool** — under `-Pn` a scanner
reports an unroutable target identically to a filtered one, so `probe_egress`
asks `connect()` and only `ENETUNREACH` means nothing left the namespace
(`EHOSTUNREACH` means traffic did leave); (3) if the environment cannot verify
it, fail explicitly rather than mock or skip.

### 5.3 `reconstruct_decision` does not walk back to the task — D8, documented in the pre-merge sweep

`control_plane/audit/query.py`

The chain follows subject ids **outward** — proposal → capabilities → runs →
evidence. It excludes `task.created` / `task.claimed` / `task.completed`, whose
subject is the task id, and the engagement's registry setup. So "why was this
allowed and what did it do" is answerable; "which agent was asked, and when" is
not (use `engagement_timeline` or `action_proposals.task_id`).

*Why not now:* extending it needs a decision the design does not record —
whether a task's events belong to *every* proposal that task produced, which
would make one task's claim appear in several chains and stop the chain being a
partition. MVP-Kernel's Fake Planner emits one proposal per task, so there is no
case to design against.

*Binding constraint:* whatever is chosen, `by_stage()` must remain a partition
of the chain's events, and the exact difference against the whole-engagement
query must stay pinned by a test.

### 5.4 `heartbeat_required` declared but not enforced — pre-merge sweep

`control_plane/capability/broker.py`, `db/migrations/versions/0005_*.py`

The column exists per §4.6, defaults TRUE, and is read by nothing. A capability
whose heartbeats stop currently lapses when its lease expires — safe, but slower
than §4.6 intends, which treats a missed heartbeat as an anomaly rather than an
expiry.

*Why not now:* two prerequisites are missing. There is **no scheduler** in
MVP-Kernel (`reconcile_stale_dispatches` is called by tests, not by anything
periodic), so a sweeper would have nothing to run it. And `last_heartbeat_at` is
only meaningful once an agent heartbeats on its own schedule rather than when a
test calls `renew_capability`; until then any staleness threshold is a number
invented to make a test pass.

*Binding constraint:* the column stays — the gap is in behaviour, not schema.
When implemented: sweep `heartbeat_required AND last_heartbeat_at < now() -
interval`, revoke with a **distinct reason**, and treat the miss as an anomaly.

### 5.5 `approvals` has no API — Phase 1 scope

`tests/test_capability_broker.py` (fixture), §4.7

`approvals.valid_until` and `approvals.revoked` are checked on every issue and
renewal; nothing in the control plane writes the table. Test rows are seeded
directly and annotated as test-only seeding.

*Why not now:* §4.7's Human Approval flow needs an Approval API and a
reviewer-facing surface, both explicitly out of MVP-Kernel scope. This is a
stage boundary, not the kill-switch pattern repeating — the *checking* is
covered; only the granting operation is absent.

*Binding constraint:* when the Approval API lands, `revoke_approval()` needs the
same treatment `revoke_credential()` got in D9 — an eager cascade over
capabilities holding that approval, with its own reason string and precision
test — and the fixture should call it instead of seeding rows.

### 5.6 `findings.state` and `findings.verification_conflict` — Phase 1 scope

`db/migrations/versions/0005_document_phase1_columns.py`

Declared, defaulted, read by nothing. MVP-Kernel produces evidence but never
promotes it to a finding, so there is no verification pass to disagree with
itself. `verification_conflict` is the I10 fail-closed case for findings.

*Why not now:* §8.10's finding-verification workflow is Phase 1. Columns are
kept and commented so a later tidying commit does not drop them, and so nobody
wires them up assuming the absent behaviour was a bug.

### 5.7 Emergency-overlay content is not randomized in the stateful test — pre-merge inventory

`tests/stateful/test_capability_lifecycle.py`

**Status: open again as of D28.** Between D17 and D28 this item described a
limitation of a rule inside a suite that did not exist (§4.1), and was marked
blocked. The suite is restored, so the item is live again and the reasoning below
is unchanged.

The `emergency_tighten` rule published a fixed-shape overlay (one `data_deny`
entry plus one action DENY). It varied only by counter, not by content.

*Why not now:* the algebra over varied content is covered by
`tests/test_merge_properties.py` at 400 generated combinations per property,
which reaches far more shapes than a state machine would. What the stateful rule
existed to test is the *interaction* — that publishing moves the policy version
and outstanding capabilities are re-checked — and that does not need varied
content. `test_merge_properties.py` is unaffected by the deletion and still runs,
so the algebra half of this argument holds today.

*Binding constraint:* if content is randomized, the generator must respect the
tighten-only rule, or the CHECK constraint will reject the write and the failure
will look like a state-machine bug rather than a generator bug.

### Deferred items found after this stage closed

This list is the record of what was deferred *at acceptance* and is left as it
stood. Later items are numbered from 11 in `DEFERRED_MVP0.md` — currently 11.1
(no way to ask which policy layers are in force) and 11.2 (audit attribution for
operations that belong to no engagement), both found by the D11 live run, plus
11.3 (two tasks are never compared) and 11.4 (a task goal is generated text on
the trusted side of another model's prompt), both found by the D17 Supervisor
run. The pointer is here because a canonical list that quietly stops being
canonical is how 11.1 happened in the first place.

---

## 6. Commit history and CI

Every commit was pushed individually and its CI run confirmed green before the
next began. Branch: `claude/mvp-kernel-cybersecurity-platform-su841g`.

| Commit | Deliverable / change |
|---|---|
| `4d8dd09` | D1 — repo skeleton (§3) |
| `503ec85` | D2 — core schema, alembic, role separation, RLS |
| `414dcd0` | D3 — target normalizer, Authorization Resolver, Metadata Resolver |
| `3c98689` | Fix — the suite silently skipped every DB-backed security test |
| `4f9c231` | CI — full suite against real PostgreSQL; skipped tests forbidden |
| `8e97200` | D4 — Rego policy, constraint algebra, `opa test` suites |
| `4eccfe3` | D4.5 — registry writes split into their own DB role (§5) |
| `b1a9bec` | Fix — soft-deleted classifications had no API and no coverage |
| `dc66f0f` | D5 — Capability Broker with re-authorizing heartbeat renewal (§4.6, I9) |
| `e9e7143` | Fix — audit records commit on their own connection (§4.4) |
| `11a9942` | D6 — Tool Gateway, Nmap in a CIDR-confined sandbox (§8.3, §7, §8.8) |
| `958eaf1` | D7 — fake agents, end-to-end Scenario A / Scenario B (§10) |
| `61eda9e` | D8 — audit coverage, query interface, failing loudly (§4.4) |
| `86b18bb` | D9 — stateful property tests, and the I1 gap they found (§11) |
| `0026be2` | Pin the `reconstruct_decision` refactor against the query it replaced |
| `8b6af07` | Sweep — measure which branches the stateful rules actually reach |
| `26ff2af` | Sweep #14 — `publish_policy_layer()` / `load_effective_policy()` (§4.5, I2) |
| `69013b2` | Sweep #15/#16 — `writes_data` / `changes_state` end to end (§5, I10) |
| `5d4373d` | I4 — confine D9's two cascades to their engagement |
| `6eca326` | I2 — property-test the §4.5 constraint algebra |
| `b6bf4c2` | Record what `reconstruct_decision` leaves out (§4.4) |

CI run ids for the final six (all `success`, 35/35 steps including
*Refuse to run with the skip escape hatch enabled* and *Assert nothing was
skipped*):

| Commit | Run |
|---|---|
| `8b6af07` | 32324570814 |
| `26ff2af` | 32326948169 |
| `69013b2` | 32327085357 |
| `5d4373d` | 32327190387 |
| `6eca326` | 32327564514 |
| `b6bf4c2` | 32327604311 |

## 7. Final scale

| Measure | Value |
|---|---|
| Python tests | **287 passed** |
| Skipped | **0** — enforced by CI, which fails if `CYBERORCH_ALLOW_DB_SKIP` is set and asserts on the junit XML |
| `opa test` | **28/28** |
| Stateful examples per run | **300**, step count 30, sequence length chosen by Hypothesis |
| `merge_policy` property examples | **400 per property × 9 properties** |
| Alembic migrations | **0005 (head)** |
| Lint | `ruff` clean |

The 0-skipped figure is load-bearing. An early version of this suite reported
"40 passed" while silently skipping 52 database-backed security tests; the
conftest now calls `pytest.fail` rather than `pytest.skip` unless an explicit
escape hatch is set, and CI refuses to run with that hatch enabled.

---

## 8. What the process caught, and why it is worth recording

Four defects of the same shape were found, each by a different technique, and
none by reading the code:

1. **The kill switch had no implementation** (D8). The broker had checked
   `status` and `kill_switch_engaged` on every issue and renewal since D5;
   nothing in the system could set them. Every test used raw SQL, so the
   behaviour was covered and the operation was not.
2. **The credential cascade existed only in a docstring** (D9). `revoke_capability`
   named "credential cascade" among its callers; nothing revoked a credential
   and nothing cascaded.
3. **A capability outlived its scope object** (D9, found by the state machine).
   The capability recorded the policy version, approval and credential it
   depended on — but not the scope object that authorized it, so the dependency
   was unrepresented and nothing could re-check it.
4. **`policy_layers` had no writer and effectively no reader** (pre-merge sweep).
   The stored Policy Pack and the enforced policy were unrelated artifacts: an
   overlay could be published perfectly and change no decision anywhere.

The common cause is that a test which manipulates state directly proves the
*check* works while saying nothing about whether the *operation* exists. The
countermeasure was structural: state transitions in the stateful test went
through public interfaces, and every rule emitted `event()` naming the branch it
took — after that instrumentation caught `deactivate_scope` firing 95 times in
100 examples and revoking nothing every time, while the suite reported success.

**D27/D28 postscript: the countermeasure lapsed and was restored.** The suite
carrying it was deleted at D17 and absent for three days (§4.1). The lesson
generalised further than its authors expected, and this document became the
fourth instance of it: a record asserting that something is covered proves the
assertion was written, not that the coverage still exists. The suite and its
`event()` instrumentation are back as of D28, and §4.1 keeps the record of how
the gap opened — including the two wrong revisions that were nearly restored
instead.

A fifth, softer finding is recorded honestly rather than quietly fixed:
`current_policy_version`'s docstring had claimed since D5 that deactivating a
layer does not move the version. It does. The reasoning behind the claim was
sound and the claim was false; the behaviour over-revokes on a widening, which
is the harmless direction, so the behaviour stands and the docstring was
corrected.

---

## Go / No-Go

**GO — merge to `main`.**

§10 asks for three things, and all three hold:

1. **Scenario A passes end to end** through the single control-plane entry
   point, with evidence, provenance and a reconstructable decision chain.
2. **Scenario B passes with an adversarial reviewer**, and passes in the strong
   form: the Broker and Gateway call counts are zero, so the kernel demonstrably
   *stopped* rather than proceeded-and-was-refused, and the reviewer's false
   claim is on the record beside the classification it contradicts.
3. **The invariants are verified at appropriate levels** — I1/I2/I3/I7/I9 under
   stateful property testing at 300 examples per run, I5/I6a-c within a single
   decision chain where they are fully determined, I4 by database-enforced RLS
   re-checked against every role and operation added since D2, I10 at every site
   where an attribute can be ambiguous.

> **D27/D28 note on point 3.** This verdict was correct when it was made, stopped
> being true at `7c9295f` (D17) after this stage had closed, and is true again as
> of D28 (§4.1). The GO decision is left as it stood — rewriting a past verdict to
> match later facts would destroy the record of what was known when — and point 3
> now also describes the tree today, against a suite that additionally covers
> §4.6's approval branch.

Nothing on the DEFERRED list blocks the stage. Items 5.1, 5.2 and 5.4 are
deliberate non-decisions where the design is silent and guessing would invent
semantics; 5.5 and 5.6 are Phase 1 scope boundaries; 5.3 and 5.7 are documented
limits with binding constraints on whoever lifts them.

The one caveat a reader should carry forward: **§5.2 is the only DEFERRED item
that is a real-deployment gap rather than a scope boundary.** Sandbox
confinement is proven against a Docker bridge network and has never been
exercised against the routed or macvlan network a real engagement would need.
That is fine for MVP-Kernel, whose targets are containers, and it must be
re-proven — against the new driver, with kernel-level evidence — before anything
points at a customer network.

Next stage is MVP-0: replacing the fake agents with a real LLM behind the same
`reviewer` argument. Nothing else in `propose_action` changes, which was the
point of building it this way.
