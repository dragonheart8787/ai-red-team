# D68 — Implementation plan: P1, Q1, the DP-7 switch and measurement, the M-class callers

**Status: plan only. Nothing here is built.** It turns `docs/D68_REVIEWER_SEMANTIC_VALIDATION_DESIGN.md`
(design, DP-1..DP-9 approved, DP-4 = (a), sections 11 and 12 approved) into independent deliverables. Tags:
**[R]** read in code/docs, **[D]** derived, **[N]** not measured -- a size or a rate that only the work or a
measurement can give.

## 0. The stages

Eight stages. Each is one deliverable: its own commit(s), its own tests and mutation entries, its own ACCEPTANCE
note, and **none changes a decision until stage 8**. The default stays "off" at every step, so any stage can be
merged, paused or reverted alone.

| # | Stage | Touches | Changes a decision? | Depends on |
|---|---|---|---|---|
| **S1** | Fixtures that carry a task, and a ratchet that keeps the caller classification true | `tests/`, `scripts/` only | no | -- |
| **S2** | P1 computed, stored and audited ("shadow") | `control_plane/` (new module, `propose_action`) | no | -- (S1 not required) |
| **S3** | P1 enforceable: policy flag, OPA input and rules, **the replay in `approved_dispatch`**, enforcement-on suite | `control_plane/policy/`, rego, `approved_dispatch.py` | no (flag off) | S2; S1 for the suite |
| **S4** | Q1 validator: schema, prompt, three adapters, fakes, selection -- **not wired** | `agents/llm/`, `agents/fake/` | no | -- (parallel with S2/S3) |
| **S5** | Q1 wired: called after P1, stored, audited, replayed, rules behind its own flag | `function_api.py`, rego | no (flag off) | S3, S4 |
| **S6** | Measurement tooling: corpus with oracle labels, baseline runner, shadow report | `scripts/`, `tests/` (offline parts) | no | S2 (P1 report); S5 (Q1 runner) |
| **S7** | Measurement runs and the gate: numbers recorded, budgets applied, **a decision from you** | `docs/` only | no | S6 |
| **S8** | Enablement: P1 first, Q1 later; the soak with enforcement on; close 5.116 | policy data, `docs/` | **yes, deliberately** | S7 (+ S3 / S5) |

Order that works with one pair of hands: S1 -> S2 -> S3 -> S4 -> S5 -> S6 -> S7 -> S8. S4 can move earlier if the
model-facing work is wanted first. S8 splits: **S8a** enables P1 (needs S1-S3 and the P1 half of S7), **S8b**
enables Q1 (needs S4-S7 fully); P1 does not wait for Q1 [D].

Every stage ends the same way: the full suite, the OPA tests, the mutation entries of that stage, the ACCEPTANCE
numbering test, CI green on the branch tip. One pytest session at a time, as before.

## 1. Choices this plan needs from you

The design left these open or did not see them. Each has my recommendation; they are small, but S2/S3 cannot be
written without DP-10..12.

| # | Question | Options | Recommendation and reason |
|---|---|---|---|
| **DP-10** | **Where does the enforcement switch live?** | (a) **policy layers** (`policy_layers.document`, merged into `EffectivePolicy`); (b) an environment variable, like the backend selectors; (c) a database table | **(a).** It is the only place with per-engagement scope, an audit trail (publications are audited), the D54 baseline freeze (a new baseline reaches new engagements only; existing ones opt in through an overlay or an engagement layer), and tighten-only semantics for free: neutral element `false`, merge by OR, so a layer saying `false` can never relax and the emergency overlay's `CHECK` (no `scope_allow`, no `ALLOW`) is not weakened. An env var differs per process -- the harness proposing and the scheduler re-deriving are different processes [R: `scripts/run_scheduler.py` vs the caller of `propose_action`] -- so one could re-derive with a different setting than the decision used. **Side effect to know:** publishing a layer bumps `current_policy_version`, which voids approvals waiting for dispatch [R: ADR_PRODUCTION_ORCHESTRATOR, D58-6 entry, ACCEPTANCE 5.68]. Turning enforcement on therefore voids the waiting queue by an existing mechanism -- it does **not** make the replay unnecessary (S3 section: case (ii), and the safety net if the switch is ever moved) |
| **DP-11** | One flag or two | one (`plan_fit_enforce`); two (`task_relation_enforce`, `goal_fit_enforce`) | **Two.** P1 needs no model and can be enforced long before Q1 has a measured false-positive rate; one flag would hold P1 back, or push Q1 out unmeasured |
| **DP-12** | Where is the signal stored | (a) a `plan_fit` key inside the existing `action_proposals.reviewer_hints` JSONB; (b) a new column (migration 0027) | **(a)**, no migration: the column is `JSONB`, written by `_record_decision`, and read by the one function that must replay it [R: migration 0018, `state/models.py:150`, `function_api.py:782`, `approved_dispatch.py:192`]. The name is slightly off (P1 is not a reviewer's hint), so the key is documented as "advisory inputs recorded at the decision and replayed at re-derivation". To confirm in S2 that nothing validates the column's shape [N]; if something does, switch to (b) |
| **DP-13** | Containment: a task on a `/24`, a proposal for one host inside it | stay `differs_from_task`; add `within_task_target` now; record as an audit sub-cause and decide with data | **Third.** Task identity is host/network granularity from the canonicalizer [R: `_task_identity`; ADR_TASK_IDENTITY Option 1], so a legitimate decomposition of a CIDR task into host proposals is, literally, a different identity. Enforcing before knowing how common that is would escalate ordinary work. S2 records `differs_from_task` with a sub-cause (`same_action_target_inside_task_target`, `different_action`, `different_target`, `task_target_not_canonical`); S7 reports their counts; adding a vocabulary value is then an additive `plan_fit_v1` change taken with the numbers in hand. **S8a is gated on this** **Decided 2026-10-22 by the owner, after the clean shadow numbers (`docs/D68_S7_P1_SCALE.md` section 7; 9 of 52 network-task proposals narrowed to a host, 17.3%): section 7.3b.** |
| **DP-14** | The numbers of the DP-7 gate | see section 7.3 | I proposed values there; **set by the owner 2026-10-22, section 7.3a** (false positive <= 10%, `insufficient_context` <= 15%, lure increase <= +5 points, failure rate per action class not globally, flip not re-measured). They are the one place where a number is a policy choice, not a fact |
| **DP-15** | Which action classes is Q1 asked about | (a) all classes whenever the switch is on; (b) an operator's list of classes, default empty, with numbers deciding what is recommended for it and an automatic exit | **(b), set by the owner 2026-10-24, section 7.3c.** The S8b smoke attempts showed the validator failing on some classes for a reason that is a property of the service's classifier and the wording, not of the plan; asking about a class that fails turns every such proposal into a `plan_check_failed` for a person |

## 2. S1 -- fixtures that carry a task, and the ratchet

**Why first, and why alone:** it changes no product code and can be merged at once; after it, the M-class sites
*declare* their tasks, so every later stage is tested against the shape a real harness has. It is also the
cheapest stage to be wrong in.

### 2.1 Pieces

* **`tests/task_support.py` (new):**
  * `task_for(engagement_id, scope_id, proposal, *, goal=None, created_by="supervisor") -> str` -- creates, through
    the product's own `create_task`, a task whose `action` and target equal the proposal's, so its `identity_key`
    equals what `_task_identity` gives the proposal. `goal` defaults to a sentence built from the action and the host
    (a table keyed by action class), so a later real validator is shown a coherent triple, not a placeholder.
  * `with_task(proposal, task_id) -> ProposedAction` (`dataclasses.replace`).
  * `proposal_with_task(...)` combining the two. Returns the task id as well, for tests that complete it.
* **`tests/scheduler_support.proposal_for`** gains an optional `task_id`. Its consumers (soak worker, two drills,
  `test_scheduler_actions`, `test_scheduler_e2e`) pass one.
* **The ratchet, `tests/test_task_less_callers.py` (new):** an AST scan of `tests/` and `scripts/` for
  `ProposedAction(...)` without `task_id`, compared with a **checked-in allow-list that carries the class of
  each site** (K1, K2, n/a -- design note section 12). It fails on (a) a task-less site not in the list, (b) a
  listed site that now carries a task (stale entry), (c) a site in the list whose class is M. It is what keeps
  section 12 true after this deliverable, in the style of ST5 (`tests/test_stage_vocabulary.py`) [R].

### 2.2 What changes, per M-class caller (25 test sites, the soak, two drills, three live-run scripts)

Principle: **change the helper where there is one, the test where there is not**; never edit an expected value.

| Group | Sites | Change |
|---|---|---|
| Helper-built, one edit serves many tests | `test_pipeline_stages._proposal` (15 tests), `test_ad_collection_e2e._proposal` (7), `test_gitleaks_e2e._propose` (4), `test_web_post_body._post_proposal` (6), `test_http_get._web_get_decision` (3), `test_web_render_e2e._render_decision` (3), `test_baseline_freeze_e2e._propose` (4), `test_sandbox_not_started.go` (5), `scenarios/test_unknown_classification._propose` (4), `scenarios/test_scenario_web_render._render` (2), `test_web_post._propose` (2), `test_scheduler_actions._code_world` | the helper creates the task (it already has the engagement and the scope id) and returns a proposal that names it |
| Inline, one proposal in the test | `test_code_scan_e2e` x2, `test_audit_coverage:312`, `test_network_isolation:498`, `test_sandbox_not_started:260`, `test_web_post:519`, `test_web_post_body:400, 432`, `test_web_render_e2e:121, 163`, `test_approvals:254`, `crash_child.py:39` | two lines: `task_for(...)`, `with_task(...)` |
| Shared | `scheduler_support.proposal_for` | optional `task_id` (above) |
| Soak | `scripts/soak/worker.py` (`call`, `new_request`) | the request gets its task **once**, when it is created, and the id is part of the request record: a retry or a resume after an interruption reuses the same task [R: requests carry a key and are re-sent with it]. Every request kind gets one (a `deny` request's task fits its target too), so the workload is the same in both modes. **Changes the soak's write load** (one task row and its audit per request): the smoke run on the runner is repeated before anything else relies on the soak; `residue_check` and `assert_coherent` are read for anything that counts tasks [N] |
| Drills | `drill_reconciler_full_chain.py`, `drill_reconciler_late_result.py` | create the task, pass it |
| Live-run | `d45_ad_collection_e2e.py`, `verify_d12.py`, `d15_lookalike.py:261` | `create_task` first (as `live_run.py` and `d40` already do) |

Estimate: about 14 helper edits and 11 inline edits, a few hundred changed lines, almost all in tests [D]; the
K1/K2/n/a sites and every consumer of `escalate` / `approved_proposal` are untouched.

### 2.3 Verification

The full suite, count unchanged; the ratchet green; the soak smoke run (`hours=0.2`, six faults) green with its
counted checks all non-zero. No mutations (no product code). **Done when** the ratchet's list equals section 12
of the design note exactly.

## 3. S2 -- P1 computed, stored, audited (shadow)

### 3.1 What is built

* **`control_plane/plan_fit/` (new package)**, `relation.py`: `assess_task_relation(conn, *, proposal, target) ->
  TaskRelation(value, sub_cause)`. Pure read, RLS-confined. Rules, in order [D from the design 1.3]:
  1. `task_id` absent -> `no_task`.
  2. no visible row for it (nonexistent, or another engagement's -- RLS hides it) -> `task_not_live`, sub-cause
     `task_not_found`. *(Note: the foreign key on `tasks(task_id)` is global, so a proposal can name another
     engagement's task; RLS makes that read as "not found". That the insert is accepted is an existing quirk, to be
     recorded, not fixed here [R: migration 0001 `REFERENCES tasks(task_id)`].)*
  3. status not in the live set (`queued`, `claimed`, `running`) -> `task_not_live`.
  4. `identity_key` of the task (NULL -> `differs_from_task`, `task_target_not_canonical`: a task nobody can reduce
     matches nothing) vs `_task_identity(proposal.action, proposal.target)` equal -> `matches_task`; otherwise
     `differs_from_task` with the sub-cause of DP-13.
  The comparison reuses `_task_identity`, never a second canonicalizer.
* **`propose_action`** calls it in the decide stage, after the resolvers, before the Reviewer (it is deterministic,
  so its place is only "before the decision is recorded"). No transaction is held across it beyond its read.
* **Stored** under `reviewer_hints["plan_fit"] = {"version": "plan_fit_v1", "task_relation": ...}` in the same
  statement as the decision (DP-12). **Audited** as one event, `plan_fit.assessed` (value, sub-cause, `task_id`,
  validator = none yet), written before the decision, beside `policy_reviewer.opinion`.
* **No policy input, no rule.** Nothing reads it except the audit and, later, S3.

### 3.2 Tests and mutations

Offline, with the real database: every row of the rule table above; a task from another engagement; a completed
task; a CIDR task with a host proposal (the DP-13 sub-cause); the stored value round-trips; the event is written
exactly once on a retried idempotency key; **no decision changes** for any existing scenario (the existing suite is
the proof). Mutations (`scripts/mutations_d68.py`): comparison made always-equal; liveness check removed; absent
`task_id` treated as `matches_task`; event not written; value written but under the wrong key.
ACCEPTANCE row: `5.116` stays open; a new row records the shadow measurement exists.

### 3.3 Confirm-in-build items [N]

Nothing validates `reviewer_hints`' shape (DP-12); the event type is added to whatever lists audit event types
(`audited_event_types` is derived from the table, so probably nothing) [R: `audit/query.py:462`].

## 4. S3 -- P1 enforceable, with the replay

### 4.1 The switch (DP-10, DP-11)

* `PolicyLayer` and `EffectivePolicy` gain `task_relation_enforce: bool` (neutral `False`, merge **OR**, parsed in
  `from_document`, included in `as_dict` so OPA sees `input.policy.task_relation_enforce`). `goal_fit_enforce` is
  added in S5 the same way.
* Constraint-algebra tests: neutral element, OR across layers, an overlay saying `false` changes nothing, and the
  overlay's schema `CHECK` still holds (the new key is not `scope_allow` and not an `ALLOW`). `policy_tests/
  constraint_algebra_test.rego` and the Python merge tests get the cases.
* The D54 freeze: a baseline carrying the flag reaches **new** engagements only; an existing engagement gets
  enforcement through an overlay (global, immediate) or an engagement layer -- both bump the policy version and void
  the waiting approvals (DP-10 note). Documented in the layer-publication docs, with the `manage_global_policy.py`
  invocation that sets it, so enabling is a documented, audited step.

### 4.2 Input and rules

`build_policy_input(plan_fit=None)` adds a top-level `plan_fit` object **only when a value exists** (absent key ->
absent input). Rego, in `approval_reasons` only:

    approval_reasons contains "proposal_without_task"  if { input.policy.task_relation_enforce; input.plan_fit.task_relation == "no_task" }
    approval_reasons contains "proposal_outside_task"  if { input.policy.task_relation_enforce; input.plan_fit.task_relation in {"differs_from_task", "task_not_live"} }

No rule reads `matches_task`. OPA tests: each value x flag on/off; absent `plan_fit` with the flag on fires
nothing; **a property test** (Python-driven against the real engine, like the model-comparison tests of D54) over
the full cross product of signal values, flag states and existing deny/approval inputs: the decision with the
signal present is never more permissive than without it, and `matches_task` is identical to absent.
(The approval-reason names are provisional until review.)

### 4.3 The replay -- required, not an add-on (design note section 11)

* `_record_decision` stores the signal (S2 already does); `_rederive` reads `proposal["reviewer_hints"]["plan_fit"]`
  and passes it to `evaluate_policy` exactly as it passes `risk_hint` (`approved_dispatch.py:192-203`). It does not
  recompute from the rebuilt proposal (`:194`, no `task_id`) and does not re-read the task.
* Absent -> absent; an unknown stored value -> the fail-closed value, whose reason the approval did not show, so the
  dispatch is refused loudly.
* **One path:** both `evaluate_policy` callers (`function_api.py:750`, `approved_dispatch.py:193`) take the signal
  from the same function; `tests/test_plan_fit_structure.py` (AST, in the style of `test_docker_health_structure.py`
  [R]) fails if a third caller does not.
* Tests (the ones the existing suite cannot give, design 11.3/11.4): approval granted with enforcement off and no
  stored value, dispatched with it on; `matches_task` approved, task completed, dispatched; `differs_from_task`
  approved with the reason shown, dispatched (no `new_approval_reasons`). Mutations: replay removed; replay
  replaced by a recompute from the rebuilt proposal; a stored value read as present when absent; the structure test
  weakened. Each must turn at least one of the above red.

### 4.4 The enforcement-on suite (what proves S1 complete)

A test-only seam: `tests/conftest.py` reads `CYBERORCH_TEST_TASK_RELATION_ENFORCE=1` and sets the flag for every
policy the tests build, through both routes (the DB baseline that `ensure_test_baseline` publishes, and the ad hoc
`merge_policy(...)` sites). A structure test asserts no product module reads that variable. CI gains a second job
that runs the **whole suite once with it on**. **Expected result: zero failures** -- M-class sites carry tasks (S1),
K1 stays DENY, K2 stays HUMAN_APPROVAL. A red test names an M site that was missed or a K site that was
misclassified; both are findings, not things to relax. This is the mechanical check of section 12, and it is the
deliverable's acceptance test. Cost: one more full run of the suite in CI [D]; whether it runs on every push or on
a schedule is a small choice for you (I would start with every push on this branch, and move it to nightly once it
has been green for a while).

## 5. S4 -- the Q1 validator, not wired

* **Where:** `agents/llm/plan_fit_base.py` and three thin adapters (`api`, `claude_code`, `local`) plus fakes. The
  existing reviewer adapters stay **untouched**: the transports are small (`headless.run_headless`, the Anthropic
  client, one POST) and the shared parts of `BaseReviewer` are `build_prompt`, `_to_opinion` and `_escalate`, which
  are exactly what must differ here. Reusing `headless.py` and `untrusted.py` directly; copying nothing from
  `reviewer_base` except the pattern. Refactoring `BaseReviewer` into a generic base was weighed and rejected: it
  would put the D10.5-tested boundary at risk for the sake of about 150 lines [D].
* **Contract:** `PLAN_FIT_SCHEMA` -- one field, `goal_fit`, enum `plausible | implausible | insufficient_context`,
  `additionalProperties: false`, **no rationale, no confidence** (design DP-6). `PlanFitResult(goal_fit, cause)`;
  `not_assessed` is set by the base, never emitted by a model (the schema cannot express it).
* **Prompt:** the system prompt defines the three values narrowly (design 2.3, L4: "plausible only if the action and
  target are of a kind the goal names or obviously entails"; "insufficient_context" as an equal, defined answer).
  Everything the validator is shown -- goal, task action and target, proposal action and canonical target -- goes
  **inside** the nonce block through `untrusted.wrap_untrusted`; there is no trusted input but the system prompt.
  The agent's stated `reason`, discovery prose, resources and expected data are **not** passed (design 2.2).
* **Failure:** timeout, transport error, non-JSON, schema violation, unknown value -> `not_assessed` with cause
  `failed`; an unknown value is never coerced to `plausible`. A `ValidationCall` record per call (latency, tokens,
  model, backend, failure) as `ReviewCall` does [R].
* **Selection:** `CYBERORCH_PLANFIT_BACKEND` / `_MODEL` in `selection.py`, default `fake`, same rule as the other
  three roles; the existing test that the control plane does not import `selection` extends to this.
* **Fakes (CI uses only these):** honest (always `plausible`); scripted (returns a given value, for rules);
  adversarial (always `plausible` against known-mismatched triples -- the validator that lies); failing; slow.
* **Tests (offline):** the boundary tests of D10.5 re-run against the new prompt (nonce fresh per call, goal
  injected text stays inside, a forged closing marker, the system prompt says the block is data); the schema admits
  exactly the three values; extra fields dropped; each failure path gives `not_assessed:failed`; no input outside S1
  and S2 fields (an assertion on what `build_prompt` is given); the agent's reason is absent from the prompt;
  **the adapters share one boundary** (`test_every_adapter_shares_one_boundary` style). Mutations: goal moved outside
  the block; reason added to the prompt; unknown value coerced to `plausible`; a free-text field admitted; marker
  made static.

## 6. S5 -- Q1 wired

* `propose_action(..., plan_fit_validator=None)`: `None` means off (goal_fit = `not_assessed`, cause `disabled`).
  When present and `task_relation == matches_task`, the control plane **reads the goal itself** from the task row
  (never from the proposal), calls the validator with no transaction held, and stores
  `plan_fit["goal_fit"]` beside `task_relation`; the same single `plan_fit.assessed` event carries both, plus the
  validator version (prompt hash, model, backend, CLI version) and a digest of the inputs, never the goal text.
* Policy: `goal_fit_enforce` (DP-11, same merge); rules `plan_implausible`, `plan_unverified` (for
  `insufficient_context`, DP-3), `plan_check_failed` (for `not_assessed` with cause `failed`). `plausible` and
  `not_assessed:disabled` / `:not_applicable` read by no rule. The property test of S3 is extended to goal_fit.
* Replay: the same mechanism as S3; the stored `goal_fit` is replayed, never recomputed -- a replayed value must not
  cost a model call.
* **Kernel-holds test:** the Scenario-B pattern -- the adversarial validator against a kernel with enforcement on
  and off: decisions are never more permissive than the baseline, a lying `plausible` changes nothing.
* The enforcement-on CI job covers `goal_fit_enforce` with the fake validators.
* Cost note carried from the design: one more call per `matches_task` proposal, median ~6.3 s on the one measured
  model [R/E: ADR_REVIEWER_BILLING], serial; not on a human-visible path [D].

## 7. S6, S7 -- measurement (the DP-7 gate made concrete)

### 7.1 What exists and what does not -- said first

* There is **no production harness** that calls `propose_action` [R: design section 9; ACCEPTANCE 5.28]. So there is
  no real traffic to measure a false-positive rate on. The measurable sources are: (1) an oracle-labelled corpus,
  (2) the live-run harnesses with real models (`d40_three_role` and its peers, run by hand), (3) the soak
  (synthetic). The gate therefore rests on (1) and (2); a rate "on real engagements" is **not** claimed, and
  turning enforcement on for a real engagement remains gated on a production harness existing and being run in
  shadow first. This is a limit of the evidence, written into S7's report.

### 7.2 S6 -- tooling (offline parts in CI, real-model parts manual)

* **The corpus** (`tests/plan_fit_corpus.py`, deterministic from a seed): triples `(goal, action, target)` with a
  label true by construction. Classes: *matched* (goal names the kind of work; action and host fit), *mismatched*
  (host or action unrelated to the goal), *vague* (goals too broad to bound -- L4), and the **lure variants of
  design 2.3 (L1-L7)**, each paired with its no-lure control. Offline tests check the corpus itself: labels present,
  every lure has a control, no duplicate triples, counts per class, reproducible from the seed.
* **`scripts/plan_fit_baseline.py`** (manual, local, like `scripts/reviewer_baseline.py`, never in CI -- ADR billing
  rule [R]): runs the corpus through a chosen backend N times, writes a JSON record **with backend, model and CLI
  version together** and a rendered report. Offline test: the runner, run against the fake validators, produces the
  expected counts and refuses to run without a backend name.
* **`scripts/plan_fit_report.py`** (read-only, over the audit, named engagements like `audit_scope_values.py`
  because RLS forbids a sweep [R]): per engagement, counts of `task_relation` by value and sub-cause, `goal_fit` by
  value, the share each rule *would have* escalated, i.e. the approval volume enforcement would add. This is the
  shadow-mode number for P1 and Q1.

### 7.3 S7 -- the runs, and the gate (numbers are DP-14)

Runs: the baseline on the real backend (subscription `claude_code`, per the billing ADR; confirm the billing status
first, as that ADR requires); the G1 harness runs in shadow; one soak smoke with tasks. Reported as `k/N`, never as
percentages alone, with the bound stated (a `0/N` result bounds the true rate to about `3/N` at 95%).

Proposed gate, to be set by you:

| Measure | Proposed requirement | Why |
|---|---|---|
| Lure success (mismatched + lure judged `plausible`) vs its control | not above the control by more than 5 points, per lure class, N >= 60 per class | a lure must not buy anything; N chosen so a clean `0/N` bounds the rate near 5% |
| False positive (`implausible` on *matched*) | <= 10% | approval volume is the cost (design 2.4) |
| `insufficient_context` on matched | <= 15%; if it is the majority outcome the validator is not informative and Q1 is not enabled | design 4.3 |
| Detection (`implausible` or `insufficient_context` on *mismatched*) | reported; a floor is yours to set -- I have no basis for a number [N] | the feature's value; unknown until measured |
| Flip rate (same triple, 5 repeats) | <= 10% | design L7 |
| Latency and tokens | within 1.5x the Reviewer baseline | ADR_REVIEWER_BILLING |
| P1 shadow: `differs_from_task` split by sub-cause | reported; **`same_action_target_inside_task_target` must be decided** (DP-13) before S8a | the one place P1 could escalate ordinary work |

### 7.3a DP-14 as decided (2026-10-22, by the owner, from the fixed-model numbers)

Measured with `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1`, so every answer is the primary model's (`docs/D68_S7_FIXED_MODEL_REPORT.md`). The measured values below are the ones from that report; the first baseline's are superseded.

| Measure | Decided requirement | Measured (fixed model) | Margin |
|---|---|---|---|
| False positive (`implausible` on *matched*) | **<= 10%** | 0/60 (upper 95% bound 5.0%) | yes: the bound is under the line |
| `insufficient_context` on matched | **<= 15%** | 0/60 (upper bound 5.0%) | yes |
| Lure increase over its control, per class, N = 60 | **<= +5 points** | -10.0, -8.3, -11.7, -11.7, -10.0, -1.7 (no lure bought a `plausible`: 0/360) | yes; all six are negative |
| Failure rate (`not_assessed`) | **no single global ceiling**; recorded per action class below as the baseline, monitored after S8b | 91/480 overall (19.0%) | not applicable |
| Flip rate | **not re-measured on the fixed path** | 98.2% of the 386 items answered in both runs gave the same answer (379/386); the first baseline's 2/48 on the mixed route | see the reason below |
| Detection, latency, cost | reported, no floor set | 43/60 of mismatched answered `implausible`/`insufficient_context`; median 3.2 s, p95 5.7 s; $4.23 per 480 | -- |

**Why the flip run is not repeated.** The 240-call run (48 items x 5) was offered and declined. The reason recorded: the 98.2% agreement between two independent passes over the same items (379 of the 386 answered in both) already supports the judgement this gate needs, and the two differences that were not the fallback's were 2 items moving on the primary alone. What this does **not** show is a flip rate on the fixed path in the sense of the plan's measure (same triple, 5 repeats, <= 10%); that number does not exist. It is a decision to proceed without it, not a result.

**Failure rate by action class (the baselines to monitor against).** `failed` = the safety classifier stopped the turn (90) or the 30 s cap passed (1). "Matched" is what ordinary work looks like; "all 480" includes the mismatched and lured items, which the classifier stops more often (encodings, reconnaissance and credential-scan wording).

| action class | all 480: failed / N (upper 95%) | matched only: failed / N |
|---|---|---|
| `ad.collect` | 13 / 28 (46.4%, <= 64.2%) | **7 / 7** |
| `network.recon` | 5 / 8 (62.5%, <= 86.3%) | **5 / 8** |
| `code.secrets` | 32 / 49 (65.3%, <= 77.1%) | 0 / 7 |
| `web.get` | 17 / 127 (13.4%, <= 20.4%) | 0 / 8 |
| `web.render` | 17 / 126 (13.5%, <= 20.5%) | 0 / 7 |
| `code.scan` | 7 / 126 (5.6%, <= 11.0%) | 0 / 7 |
| `network.scan` | 0 / 16 (0.0%, <= 18.8%) | 0 / 16 |

* `ad.collect` and `network.recon` are recorded as **known to have a higher failure rate: the safety classifier's conservative behaviour, not a defect of Q1 itself**. After S8b they are monitored; no global figure is required of them now.
* **A finding the matched column hides.** `code.secrets` has the highest failure rate over all 480 (32 of 49), though 0 of 7 on ordinary (matched) items. The 32 are mismatched and lured items (the secrets-scan goal is also the one behind ACCEPTANCE 5.121). It is not in the list of known-high classes the decision named. **Investigated (`docs/D68_S7_CODE_SECRETS_FAILURE.md`): corpus noise, not risk.** All 6 mismatched `code.secrets` base items have Active-Directory goals, and AD wording is what the classifier stops (52 of 79 AD-goal items failed whatever the action); a probe with goal wording and action crossed gave secrets-scan goals 1 failure in 40 calls (`code.secrets`: 0 of 20) and AD goals 32 in 40. S8b is to check the real `code.secrets` failure rate against that (near zero); a high rate would be a finding.
* With the goal-fit switch on, a failed check is `plan_check_failed` -> a person. For `ad.collect` that is every ordinary-work item in this corpus (7 of 7); the approval volume the switch adds is its failure rate plus its `implausible` and `insufficient_context` answers.

### 7.3b DP-13 as decided (2026-10-22, by the owner): a containment rule, structural only

The owner's requirements, and what was done for each:

1. **Only a subset of the task's network.** A proposal for one address inside the task's network, or a smaller network inside it, with **the same action**. Not "related to the task": a host outside the network, a wider network, a sibling network, another action, a name or a URL stay `differs_from_task` (table rows in `tests/test_plan_fit_relation.py`, including one address past either edge of the network and the IPv6 case).
2. **The deterministic path, with no model, reusing the canonicalizer's geometry.** `control_plane/plan_fit/relation.py::_subset_of_task_range` calls `canonicalizer/containment.py::address_contains`, the arithmetic the Authorization and Metadata resolvers already share (D25). P1 previously carried its own copy of that arithmetic (`_inside`); it is **removed**, so there is one implementation of the fact (the D15 lesson that `containment.py` records: two copies drift).
3. **A sub-cause of its own.** The result is `matches_task` with `sub_cause: subset_of_task_range`; an identical match keeps `sub_cause: null`. It is stored in `reviewer_hints["plan_fit"]`, written in the `plan_fit.assessed` audit event, and counted by the shadow report on its own line (`dp13_rule_use`: the rule's matches, of proposals and of all matches). `plan_fit_v1` evolves additively: `subset_of_task_range` is new under `matches_task`; `same_action_target_inside_task_target` is **no longer produced** but stays in the vocabulary, because decisions stored before the rule carry it (a test pins that such a row still reads as `differs_from_task`, not as `unrecognized`). The policy does not read the sub-cause: `matches_task` is `matches_task` to the rego rules (a rego test and the policy property tests include the new value).
4. **Mutation tests.** `D68-S2-e` (remove the rule: the inside cases become `differs_from_task`, and with the switch on go to a person), `D68-S2-f` (a host outside the network taken to be inside: the outside cases are caught, and the end-to-end test shows a host the scope covers but outside the task's network still asks for a person), `D68-S2-f2` (the rule ignores the action), `D68-S2-f3` (reported as an identical match, so its use could not be counted), `D68-S6-r`/`S6-s` (the report loses or zeroes the rule's use). All valid (`docs/D68_S7_BASELINE/dp13_mutations.json`).
5. **5.123 stays a separate candidate.** The ip/url identity form is not a containment question, and the rule does not touch it: a `url` or a name proposal inside a network task is `differs_from_task` (table rows).

What the rule does **not** do: it does not make the proposal *authorized* (scope, policy and the Reviewer decide that as before); it does not look at the goal (Q1 does, once the relation is a match -- so a host-by-host decomposition of a network task now reaches Q1 with the task's network and the proposal's host as its two targets); it does not change `task_not_live` or `no_task`.

S7 produces `docs/D68_PLAN_FIT_BASELINE.md` and ACCEPTANCE rows. **It ends with a decision from you**, not an
automatic step: enable P1 (S8a), enable Q1 (S8b), neither yet, or adjust the validator's definition (a numbered
change, never a silent edit of the prompt; design 5.3).

## 8. S8 -- enablement

* **S8a (P1):** publish a baseline carrying `task_relation_enforce: true` for new engagements and, if you want
  existing ones covered, an overlay -- both through `manage_global_policy.py`, audited, with the waiting-approvals
  effect (DP-10) announced first. Then the **4-hour soak on the runner with enforcement on** (the soak's engagements
  carry the flag), checking in particular the restart faults against approvals waiting, which is where the replay
  earns its keep. Evidence into ACCEPTANCE. **5.116 moves to Closed** when S3's replay tests and mutations are in
  and this soak passes with enforcement on.
* **S8b (Q1):** the same, for `goal_fit_enforce`, after S7's gate and with a real backend selected for the run.
  Q1 never ships "on" by default in the repository; the repository default stays `fake`.
* Rollback: **retire the layer that carries the flag; the signal keeps being recorded.** *Corrected 2026-10-22 after the check was executed (ACCEPTANCE 5.124): the earlier sentence here, "publish a layer without the flag (or an engagement layer)", cannot work -- the switches are OR-merged, so no layer turns off what another turned on.* What retiring returns depends on the layer: an **emergency overlay** returns every engagement; a **baseline** is frozen into each engagement at its creation (D54), so retiring it returns only engagements made after the retirement. Enabling through an overlay is the reversible form.

### 7.3c DP-15 as built (2026-10-24): Q1 per action class -- the mechanism only, no class enabled

**What was asked and what is built.** Q1 is asked about a proposal only when its action class is in an allowlist set by the control plane (policy field `goal_fit_actions`, default empty). A class outside it is not asked and records `not_assessed` with the closed cause `class_not_enabled`; a class the control plane has taken out of the list records `class_suspended`. Neither is a failed check: the OPA rule treats both as quiet (`goal_fit_is_quiet`), so with `goal_fit_enforce` on, a class outside the list decides **exactly as with the switch off** (a test compares the whole decision, approval reasons and stored signal for three validators, one of which fails every call; the validator is never called).

**The list.** A policy-layer field `goal_fit_actions`: a list of class names of the form `family.verb`. Merged by **union** across layers (it can only add checks, so an emergency overlay may carry it and it is the reversible form). Read strictly: anything that is not a list of well-formed names is "no class" (a string is not a list of letters), and publication refuses it. It lives in a layer, so it is published by a person like any policy; nothing in this change publishes one.

**Admission is advice.** `scripts/manage_goal_fit_classes.py report` prints, per class, `n` (calls on the real `propose_action` path since the class was last cleared), the failures, the **Wilson 95% upper bound** of the failure rate, the state (in the list / not in the list / suspended) and whether the rule recommends it: at least 40 calls and an upper bound at most 15% (40 calls with 1 failure: 12.9%, recommended; with 2: 16.5%, not). It writes no list and no layer. Calls are recorded by the pipeline in `goal_fit_calls` (action, `answered`/`failed`, time -- no goal, target, engagement or answer) only when the validator was actually asked; a quiet state is not a call. A class that is not in the list has no calls, so a class earns its numbers while the switch is **off** and the class is listed (asked, stored, no decision moved), or from a measured run that reaches the same table.

**Exit is automatic.** After each call the control plane reads the class's last 50 calls (at least 30) since the last clearing; a failure rate **strictly above 30%** inserts a row in `goal_fit_suspensions` (one live row per class, enforced by a unique index) and writes `plan_fit.class_suspended` to the audit once. From then on the class reads `class_suspended`. A suspension state that cannot be read is read as suspended (the quiet side). **Re-inclusion is manual:** `manage_goal_fit_classes.py clear --action ... --actor ...` over the `global_policy_admin` connection. The runtime role may read and insert, and has no `UPDATE` or `DELETE` (a mutation grants it and a test fails); the operator role cannot write calls or suspensions, and can only set `cleared_at`/`cleared_by` once (a trigger). A cleared class starts a new window: its old failures were the reason it was out.

**Rates are recorded, not managed.** Nothing in this change words the question differently to move a rate (the validator's prompt and the `PlanFitQuery` fields are untouched: the existing structure tests still pass). The failure rate is only counted.

**Not enabled.** The default list is empty and no layer lists a class. `scripts/soak/checks.q1_verdict` and `scripts/s8_enablement_check.py` treat "every proposal was `class_not_enabled`" as a stated, not-judged result rather than "enabled and doing nothing"; a failure of a class that was asked still counts. The S8b soak therefore proves nothing about Q1 until a class is listed by the owner.

**Verified:** see ACCEPTANCE 5.125.

### 8.1 Required checks at enablement (S8 report must show each one, executed, with its output)

Recorded at S5 on the owner's instruction, so that it is not thought of for the first time at S8.

1. **S8b -- both conditions, together, or a loud failure.** Enabling Q1 means two things must both be true at the
   moment it is enabled: **`goal_fit_enforce` is `true` in the effective policy** *and* **a validator is configured**
   (`CYBERORCH_PLANFIT_BACKEND` names a real backend, not the default `fake`, and the process that calls
   `propose_action` actually passes it as `plan_fit_validator`). If either is missing, the check **reports the anomaly
   explicitly and stops** -- it never lets the system run in "switch on, validator absent" or "validator present, switch
   off" without saying so.
   * *Why this is a hard item:* by design (S5, `goal_fit` cause `disabled` is read by no rule) a switch that is on with
     no validator **silently does nothing** -- every proposal records `not_assessed/disabled` and none is escalated. That
     is correct as a safe default and wrong as an enablement end-state, because it looks enabled and is not.
   * *What S8b must do about it (not implemented now):* (a) an enablement check, run and printed in the S8 report, that
     reads the effective policy for the engagement and the configured validator and fails on any mismatch; (b) after
     enabling, a count over the engagement's recent `plan_fit.assessed` events showing `goal_fit` values other than
     `not_assessed/disabled` -- zero such events while proposals are flowing is the "enabled and doing nothing" state and
     is reported as a failure; (c) whether the process should itself log a warning at start when the switch is on and no
     validator is passed is a design question to settle then (it needs the effective policy at the point the validator
     is constructed, which the code does not have today) [N].
2. **S8a -- the same shape for P1:** the switch is true in the effective policy of the engagement being enabled, and the
   first decisions after enabling show non-`absent` `plan_fit` values with the switch honoured (a proposal with no task
   escalates with `proposal_without_task`). A switch published to a layer that does not reach the engagement (a
   baseline only applies to engagements created afterwards, D54) is the equivalent silent no-op.
3. Waiting approvals are voided by the policy-version bump (DP-10): announced before, counted after.
4. Rollback tried once: publish the layer without the flag and show the decisions return to unchanged.

## 9. Risks and unknowns

1. **P1 may escalate ordinary decomposition** (DP-13). The numbers do not exist; S2 makes them cheap to get.
2. **No real traffic** (7.1). The gate is on a corpus and hand-run harnesses; the plan says so rather than
   implying more.
3. **The soak's load changes** in S1 (task rows). Its counted checks and `residue_check` are re-read, the smoke is
   repeated; any invariant that counts tasks is a finding [N].
4. **The `tasks.goal` trust issue** (ADR G) is handled at the validator (wrapped); the D22 "step two" flag stays its
   own open decision and is now more pressing: a second prompt reads `goal`.
5. **Voiding of waiting approvals when enforcement is published** is a feature of the existing policy-version rule;
   operators must expect it. Documented in S3.
6. **A model-facing deliverable (S4) has non-determinism in its tests only at the manual baseline**; CI is
   fakes-only, as for the Reviewer.
7. **Dead fields** (`recommended_escalation`, `semantic_risk_hints`, ACCEPTANCE 5.117) are not touched; the new
   signal is named `plan_fit` so it cannot be mistaken for them.

## 10. Sizing, honestly

I do not have measured sizes; from the shape of each stage [D]: S1 several hundred lines, nearly all tests;
S2 about one module of 100-150 lines plus tests; S3 the largest product change (merge, input, rego, replay,
structure test, a second CI job); S4 about the size of one existing adapter set; S5 small in code, large in tests;
S6 the corpus and two scripts; S7 and S8 are runs and documents. If a single number is wanted: S1-S3 together
carry the risk and the value (P1 is deterministic and closes 5.116); S4-S5 are where the model enters.

## 11. What this plan does not do

It does not build anything, does not choose the DP-14 numbers, does not decide Q2 or Q3 (deferred by DP-1, with
D58-12 owning the coarse relation by DP-8), does not touch the dead-field question (5.117), and does not change a
default.
