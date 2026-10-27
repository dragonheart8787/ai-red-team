# D69 -- The production harness (the proposing side): design checkpoint

**Status: design only. Nothing is built: no code, no test, no script, no migration.** Written 2026-10-27.
No decision is taken here. Every decision point lists its options, what each costs, and a
recommendation, and is marked **pending the owner** (待負責人). A recommendation is a lean, not a decision.

Tags: **[R]** read (a file, a document or a search result, with the place named); **[E]** executed (run
by me); **[D]** derived (reasoned from [R] facts, not observed); **[N]** not established. This note ran
nothing against a database, a daemon or a model, so it has no [E] about the system: everything about
the current system is [R], and anything that would need a run to be known is [N]. A [D] is never to be
quoted as a fact.

Rules this note keeps, stated once:

* A call stopped by the service's safety classifier (a Worker, a Supervisor, a Reviewer or a validator
  call) is a **failure, recorded and fail-closed**. Nothing in this note proposes rewording a prompt,
  a goal or an input, or cutting the inputs differently, to lower a failure rate (the owner's rule for
  DP-15, ACCEPTANCE 5.125 and `docs/D68_DP15_RECORD_MODE/stage1/OUTCOME.md`).
* Nothing here opens `task_relation_enforce` or `goal_fit_enforce`, publishes a layer, or changes a
  registered file.
* Numbers are cited, not re-derived; a number's source is named.

## 0. What I checked first (read-only), and what it found

**0a. Is the requeue sweep still unbuilt after D62? -- Yes, as far as the tree shows. [R]**
Search: `git grep -n -E 'lease_expires_at|requeue|re-queue|sweeper' -- control_plane agents scripts tool_gateway db/migrations`
(mutation catalogues and vendored Rust excluded). Results that concern **tasks**: `tasks.lease_expires_at` is
*written* by `claim_task` (`control_plane/api/function_api.py:245`, `now() + interval '5 minutes'`) and
*read* only by `query_tasks` for display (`function_api.py:1252`). Every other `lease_expires_at` hit is
the **capability** lease (`control_plane/capability/broker.py`, the reconciler's reader SQL in migrations
0023/0024, `reconciler/config.py:64`'s `lease_grace_s`). `grep` for `tasks` in `control_plane/reconciler/*.py`
finds nothing, and the scheduler reads `action_proposals` stages, not tasks [R]. The documents agree:
`docs/D62_SCHEDULER_V0_DESIGN.md` section 1 lists "requeue sweeper" under *Not built*, and
`docs/ADR_PRODUCTION_ORCHESTRATOR.md` section 0.2 premise 6 says "No code reads `tasks.lease_expires_at`
for requeue". The ADR's later addenda and the index table do not claim it was built.
*Limit:* I did not run anything, so "unbuilt" is "no code in the tree does it", [R], not an observation.

**0b. How is the web console started? -- No start script exists in the repository. [R]**
`control_plane/web/app.py:61` is `app = FastAPI(`; the module has no `__main__` and its docstring gives no
command. `uvicorn` appears in `pyproject.toml` (a dependency) and in a comment in
`control_plane/web/static/index.html`, and nowhere in `Makefile`, `scripts/`, `.github/` or the README
(`git grep -n -i -E 'uvicorn|web\.app'`). No compose, systemd or Procfile exists (`git ls-files`).
How an operator runs it is **[N]**: by convention it would be `uvicorn control_plane.web.app:app` [D],
but the repository does not say so.

**0c. After a `claim_task` lease lapses, does anything re-enqueue the task? -- No code does. [R]**
Same evidence as 0a: `claim_task` selects only `status = 'queued'` (`function_api.py:248`), and no
statement anywhere sets a `claimed` task back to `queued`. A task claimed by a Worker that then dies stays
`claimed` until something completes it. [D] consequence for this design: the harness must either complete
every task it claims on every exit path or accept that a crash strands it (section 5).

**What exists today, for orientation. [R]**

| Piece | Where |
|---|---|
| Supervisor interface, `plan(state, candidates) -> list[ProposedTask] \| None` | `agents/llm/supervisor_base.py:431` (`BaseSupervisor`) |
| Worker interface, `propose(task, candidates, observations, task_id) -> ProposedAction \| None` | `agents/llm/worker_base.py:604` (`BaseWorker`); `task_id` defaults to `None` |
| Reviewer interface | `agents/base_agent.py:89` (`PolicyReviewer`), `agents/llm/reviewer_base.py` (`BaseReviewer`) |
| `create_task`, `claim_task`, `complete_task`, `propose_action`, `query_state`, `query_tasks`, `query_findings`, `query_evidence` | `control_plane/api/function_api.py:167, 235, 268, 510, 1195, 1286, 1346, 1181` |
| `load_effective_policy` | `control_plane/policy/layers.py:638` |
| `create_engagement`, `pause_engagement`, `resume_engagement`, `engage_kill_switch`, `revoke_credential` | `control_plane/orchestrator/engagement.py:122, 222, 244, 279, 329` |
| The only multi-step loop with the three real roles | `scripts/live_run/d40_three_role.py` (`main_run`, `run_task`): one engagement, one thread, synchronous (`docs/ADR_PRODUCTION_ORCHESTRATOR.md` section 0.1) |
| The scheduler (dispatches *approved* proposals; never proposes) | `scripts/run_scheduler.py`, `control_plane/scheduler/*` |
| A task for a proposal, as a harness would create it (test helper) | `tests/task_support.py:47, 61` (`task_for`, `attach_task`) |
| `build_state` / `candidates_for` (the Supervisor's input, and the scope objects offered) | **scripts only**: `scripts/live_run/d17_supervisor.py:184, 222`, `d40_three_role.py:270`. No production equivalent. |

**Does anything shipped call `propose_action`? No.** Search: `git grep -n -E '\bpropose_action\b' -- control_plane agents tool_gateway`
returns the definition (`function_api.py:510`) and docstrings or comments; no call. Outside those three
directories the callers are `scripts/` (live runs, drills, soak, DP-15 measurement) [R]. This repeats design
note `docs/D68_REVIEWER_SEMANTIC_VALIDATION_DESIGN.md` section 9.1 and still holds.

## 1. Scope: what v0 does, what it does not, and where it runs

**Facts.**
* The scheduler is deliberately narrow: it dispatches approved proposals of *enrolled* engagements, serially,
  holds a singleton Postgres advisory lock (`control_plane/scheduler/lock.py`, `LOCK_KEY = 0x0D62_5C4E_D000_0001`),
  reads through a column-narrowed role (`scheduler_reader`) and sees metadata only (D58-3), and its design
  states "No module under `agents/` or `tool_gateway/` imports `control_plane.scheduler`"
  (`docs/D62_SCHEDULER_V0_DESIGN.md` section 4, the numbered rules after "Module layout", rule 5) [R]. It supports four actions:
  `("network.scan", "network.recon", "code.scan", "code.secrets")` (`control_plane/scheduler/vocab.py:58`) [R].
* The enrolment list is written only by an operator CLI (`scripts/manage_scheduler_enrollment.py`, role
  `scheduler_admin`) [R].
* A proposing loop reads content (goals, evidence, model output) and calls models; the scheduler is built so
  that it does neither [R: the two documents above].
* `propose_action` dispatches an `ALLOW` inline, in the same call, and leaves a `HUMAN_APPROVAL` for a person
  and then for the scheduler (`function_api.py:510`; ADR addendum D61) [R].

**v0 does (candidate).** For each engagement in a list: build the Supervisor's input, call the Supervisor,
turn its plan into tasks (`create_task`), and for each task claim it, build the Worker's observations, call
the Worker, load the effective policy, call `propose_action` with `task_id`, record the outcome, complete the
task. Serial. [D]

**v0 does not do (candidate).** Credentialed actions (section 6); concurrency or quotas (section 7); planning
memory or a closed-directions ledger (D58-12, NOT built); the failure ladder (D58-6, NOT built: v0 stops
instead, section 5); requeue of stranded tasks (0a/0c); any use of `ad.collect`; any switch change; any
Q1 measurement (closed by the owner on 2026-10-27, section 8). [D]

**Decision D69-1: where does the proposing loop run?** *Pending the owner.*

| Option | What | Cost |
|---|---|---|
| (A) A separate process with its own advisory lock key and its own CLI | The proposer and the dispatcher cannot corrupt each other's invariants [D]; the scheduler's narrow role and import fence stay as they are | Two resident processes to operate; both may start containers, so two engagements on one address range can meet `NetworkInUse` (D59: the dispatcher must treat it as "retry later") [D]; the start order is a convention (as the reconciler/scheduler order is, `run_reconciler.py` docstring) [R] |
| (B) The same process as the scheduler | One process, one lock | Breaks the scheduler's design: model calls and content reading inside the metadata-only service, and the fence rule above [D]; a model hang blocks dispatch [D] |
| (C) No resident loop: an operator-run, bounded command per engagement (as `d40` is today) | Smallest change; nothing resident | It is the thing that already exists; ACCEPTANCE 5.28 and 5.51 name "a production harness" as not existing, and a hand-run script is not one by the wording used there [D] |

*Recommendation [D]:* (A). *Sub-decision D69-1b, pending the owner:* does the proposing loop reuse the
scheduler's enrolment list or have its own? Reusing needs a role that may read it (the list is writable
only by `scheduler_admin`; read access for another role is a grant I did not check [N]); an own list
means a second operator act per engagement. *Lean:* an own list, so that enrolling an engagement for
dispatch never silently starts proposals in it [D].

## 2. Where tasks come from

**Facts.**
* `ProposedTask` is `goal`, `target` (a dict), `action`, `scope_object_id`, `priority` (`agents/base_agent.py:23`) [R].
* `create_task` computes `canonical_target, identity_key = _task_identity(task.action, task.target)`, inserts the
  row, marks any live task with the same `identity_key` as overlapping (never drops it), and writes
  `task.created` with the `identity_key` (`function_api.py:181-232`) [R].
* The Supervisor "is neither checked against anything": its output is a task, which "goes into the `tasks`
  table, a Worker later claims it, and only the proposal that Worker eventually writes meets the policy
  kernel" (`agents/llm/supervisor_base.py` module docstring) [R]. Its schema closes `action`, `target_type`
  and `scope_object_id` to enums built per call; the description of `target_value` now requires a prefix for a
  network (`supervisor_base.py:301-310`) [R].
* ACCEPTANCE 5.122: the planner wrote prefix-less `cidr` targets in 58 of 187 network tasks; cause read from
  the code: the schema description "does not require a prefix"; the producer-side fix cut it to 0 of 52 in
  one re-run (one planner model, one scenario); **the canonicalizer still reads a bare `cidr` as a `/32` and
  `create_task` accepts one**, so a planner that ignores the description writes the same task [R].
* The Supervisor's input in `d40` is built by script functions (`build_state`, `candidates_for`) [R];
  there is no production builder.
* `claim_task` takes a lease of 5 minutes and nothing re-enqueues (0c) [R].

**Decision D69-2a: who produces tasks in v0?** *Pending the owner.*
(A) the Supervisor, per round, as in `d40` -- the realistic path; costs a model call per round and
carries the Supervisor's failure modes (5.122; non-stable `status_assessment`, `d40` finding 4 [R: ADR
section 4.1]). (B) Operator-supplied tasks only (a file or a CLI), no Supervisor -- removes one model from
the loop and makes P1's population operator-shaped, not planner-shaped [D]. (C) Both, with the origin
recorded. *Lean [D]:* (A) for the shadow that matters (section 8), because the question P1 answers is about
what a planner and a Worker do together; (B) is a legitimate first smoke of the loop's plumbing.

**Decision D69-2b: how is 5.122 not repeated?** *Pending the owner.* The lesson is that the schema text is
the producer's contract and a vague sentence in it became 58 wrong tasks. Options:
(1) a deterministic check in the harness before `create_task`: a `cidr` target without a prefix length is
refused and the task is not created (counted, recorded, not retried with different wording);
(2) the same check in `create_task` itself (the owner's open question in 5.122); (3) neither, rely on the
description. Cost: (1) is local to the new code and leaves the canonicalizer's `/32` reading as it is;
(2) changes a function every caller uses and needs its own tests and mutations; (3) is what failed. A
separate rule for every future change to a prompt or schema description of a role the harness runs: it
is a numbered change with a pinned test and a re-run of the P1 shadow, never a silent edit (the rule the
plan already states for the validator, `D68_IMPLEMENTATION_PLAN.md` 7.3). *Lean [D]:* (1) now, (2) as a
separate decision of the owner's.

**What the task carries.** `goal`, `action`, `canonical_target`, `identity_key`, `scope_object_id`,
`created_by` (= the Supervisor's `agent_id`) and the audit event [R]. P1 compares a proposal's action and
canonical identity with the task's (`docs/D68_REVIEWER_SEMANTIC_VALIDATION_DESIGN.md` sections 1.2, 1.3) [R];
which is why the identity a task is stored under decides what P1 later calls a mismatch [D] (5.122, 5.123).

## 3. The Observation builder (ACCEPTANCE 5.28)

**Facts.**
* `Observation` has `source`, `description`, `content` (target-produced, inside the nonce block) and three
  fields "filled by the harness ... the Worker never asserts them": `evidence_id`, `run_id` and
  `observed_identities` ("the canonical identities the tool *structurally* reported ... as opposed to text it
  merely echoed in a banner") (`worker_base.py:137-166`) [R].
* `_discovery_provenance` computes `introduced_by_untrusted`: not an offered scope object, not in any
  `observed_identities`, but named in an observation's content => the target is introduced by untrusted
  text and escalates (`worker_base.py:494-585`) [R]. An identity string is matched through `_untyped_keys`,
  which tries the raw form and several canonical types, including repo forms [R].
* The only builder today is test/script code. `d40` builds one `Observation` per prior target with
  `observed_identities=(target_value,)` -- the *requested* target, which "makes the requested target observed
  by construction" (5.28) [R: `d40_three_role.py:366-372`, ACCEPTANCE 5.28].
* What each tool's evidence view contains [R, from the adapters; one view per tool]:

| Tool (action) | Structural fields in `derived_view` | Echoed / untrusted |
|---|---|---|
| nmap (`network.scan`, `network.recon`) | `hosts` (list), `ports`, `open_ports` (`nmap.py:252-258`) | banners, service strings (`untrusted_content: True`) |
| HTTP (`web.get`, `web.post`) / browser (`web.render`) | `status_code`, `headers`, `body_excerpt`, `location_header`; the endpoint actually reached is described in `worker_base` as the structural identity | `candidate_targets` (extracted from the body: "Discovery input, not authorization", `_http.py:315`) |
| AD collector (`ad.collect`) | graph `nodes` of `{identity_type, identity_value, kind}` (`ad_collector.py:499`) | -- |
| semgrep / gitleaks (`code.scan`, `code.secrets`) | **[N]** I did not read their derived views | scanned source is untrusted |

* ACCEPTANCE 5.27 (decided at D54): a Security Graph node "is evidence that a directory contains a record; it
  is not evidence that the host or identity it names is alive or reachable, and it is never by itself
  'established'"; a harness filling `observed_identities` from graph rows "must include an identity only when a
  *structural observation* of that same identity also exists in this engagement" [R: quoted from the row's
  first sentences; the rest of the row was not re-read here, [N]].
* ACCEPTANCE 5.28's trigger: "the first time D42 or any future tool constructs `Observation` objects in a real
  harness, this must be re-verified end to end -- an evidence row through the real builder, a lure in an
  in-range spelling in its untrusted content, through `propose_action`, ending in `HUMAN_APPROVAL`" [R].

**This design satisfies that trigger** [D]: the harness would be the first production code to construct
`Observation` objects.

**Decision D69-3a: what goes into `observed_identities`, per tool?** *Pending the owner.* Candidates, each a
rule from a row of the table above:
(1) nmap: each address in `hosts` (canonical form) and, if the policy compares ports, host:port forms [N: which
form the comparison uses was not read]. (2) HTTP / browser: the host (and URL) the transaction actually
reached; never a `candidate_targets` entry. (3) AD graph: per 5.27, a node's identity only when a structural
observation of the same identity exists in this engagement. (4) `code.*`: **[N]** needs the views read first.
Cost of each rule: too wide a set turns a lure into an "observed" identity and silences the escalation
(fails open); too narrow a set escalates ordinary work to a person (fails closed, costs approvals). *Lean
[D]:* the narrowest rule each row of the table supports, stated per tool in code and pinned by a test per
tool; and `observed_identities=(task target,)` as `d40` does is not carried over.

**Decision D69-3b: how is the end-to-end re-verification done?** *Pending the owner.* The candidate shape,
per tool, in the style of D13/D15 and D45-D48 (real entry points, no hand-built `Observation`):
a real run of the tool in a lab engagement -> the evidence row -> the **real builder** -> an observation set
-> a Worker shown it (or a scripted Worker that proposes the lure, since the property under test is the
deterministic provenance, not the model) -> `propose_action` with a lure in an in-range spelling in the
untrusted content -> the decision must be `HUMAN_APPROVAL` with `introduced_by_untrusted` true; and the
mirror case (an identity the tool did observe) must not escalate on discovery grounds. Each case is a test
that fails when the builder puts the lure's identity into `observed_identities` (a mutation to write when
code exists). A scripted Worker avoids a model call in the check, [D]. *Lean [D]:* scripted Worker for
the property tests, plus one recorded run with the real Worker as an observation, not as the test.

## 4. Loading the policy for the decision stage (ACCEPTANCE 5.51)

**Facts.** `propose_action` takes the policy as an argument; nothing in production assembles one for it.
The scheduler's execution step calls `load_effective_policy` for *dispatch* only (5.51's update). The
freeze of the baseline (5.20) "lives in that function and nowhere else", so a decision made under a policy
assembled any other way would not carry it [R]. `d40` loads it with `load_effective_policy(conn, engagement_id)`
inside `engagement_scope` immediately before `propose_action` (`d40_three_role.py:412`) [R]. 5.51 says a
production harness "must obtain the policy through `load_effective_policy` (or the one predicate it reads)".
The ADR records a read-then-use gap between loading and deciding (X15), read, not executed [R/N].

**Decision D69-4: how is "only through `load_effective_policy`" pinned?** *Pending the owner.*
(A) The harness has one function that loads the policy and nothing else in the module can reach
`propose_action` except through it; an AST test (the style already used: `test_task_less_callers`, and
`test_a_live_run_publishes_its_baseline_before_it_creates_its_engagement` named in 5.51) fails if the
`policy=` argument of any `propose_action` call in the harness is anything but that function's result.
(B) Additionally, a runtime assertion that the policy object carries a marker only that function sets [D].
(C) Move the loading inside `propose_action` (changes the signature every caller and test uses) -- larger
than this deliverable. Costs: (A) is a static guarantee only; (B) adds a field to a value object; (C) is a
change to the pipeline. *Lean [D]:* (A), with (B) only if the owner wants a runtime guarantee. A policy
loaded per proposal, not cached, as the scheduler does [R: D62 design].

## 5. Failure behaviour

**Facts.**
* D58-6 (the failure ladder) and D58-6b are **NOT built**; the ADR index says v0 "stops the whole service
  on any fault it cannot account for (a temporary simplification)" about the scheduler [R]. The scheduler's
  stop model: it does not restart or reconnect; any lost connection, lost lock, unreachable Docker,
  unwritable audit record or unexpected error ends it with a distinct exit code (`scripts/run_scheduler.py`
  docstring: 0 signal / `--once`, 1 unexpected, 2 lock held, 3 audit, 4 DB lost, 5 Docker lost, 6 lock lost,
  7 a dispatched proposal still `approved`) [R].
* ACCEPTANCE 5.120: an exception escaping `propose_action` (found with `LocalReviewer`'s `IndexError`)
  leaves **one proposal at `received`**, no decision, no capability, no run; a retry **under the same
  idempotency key** resumes and completes it once; one nobody retries is abandoned by the reconciler in
  `state-only` (`undecided_past_grace`); nothing can proceed from `received` [R].
* `propose_action(idempotency_key=...)`: a second call with the same key finds the first, "carries on from the
  next stage, never repeating one that committed"; a key reused for a different action or target is refused;
  the ADR (D60 addendum) says an orchestrator "must pass an `idempotency_key` (derived from task and attempt)
  on every `propose_action`" [R].
* In `d40`, a Worker that returns no proposal ends the task as "worker declined to propose an action"
  (`complete_task`), and the loop continues [R: `d40_three_role.py:381-392`].
* A call stopped by the classifier: in S7 and DP-15 such a call is recorded as a failure (`not_assessed/failed`
  for the validator, "a stopped call recorded as a failure" for the baselines) [R]. With Q1 on, a failed
  validator call becomes `plan_check_failed`, i.e. a person [R: ACCEPTANCE 5.118, S8b report].

**Decision D69-5a: the closed list of faults v0 accounts for, and the stop for everything else.**
*Pending the owner.* Candidate classification [D], by analogy with the scheduler:

| Outcome | v0 treatment (candidate) |
|---|---|
| `propose_action` returns an outcome (`ALLOW`, `DENY`, `HUMAN_APPROVAL`, with or without `failure`) | recorded; task completed with the outcome as its summary; continue |
| Supervisor returns `None` / refuses / the call failed (including a classifier stop) | no tasks created this round; the failure and its kind recorded; **no re-ask**; continue to the next engagement or round |
| Worker returns `None` / refuses / the call failed (including a classifier stop) | no proposal; task completed as declined with the failure kind; **no re-ask** |
| `create_task` refused by the harness's own check (D69-2b) | counted, task not created |
| An exception from `propose_action` or any call not on this list | **stop the service** with a distinct exit code; the proposal left at `received` is the reconciler's or a deliberate retry's |
| DB connection lost, lock lost, audit write failed, Docker unreachable (if dispatch inline needs it) | stop, distinct exit codes, as the scheduler |

*Retry of a stopped model call:* options (a) never re-ask in v0; (b) re-ask the same unchanged input a
bounded number of times, every attempt counted. (b) changes what a "failure rate" means (a retry is a
resample, and DP-15's lesson is that sampling rules must be fixed before looking) [D]. *Lean [D]:* (a).

**Decision D69-5d: a bound on failed rounds.** *Pending the owner.* 5a's table says "continue" on a failed
Supervisor or Worker call with no bound; a run of consecutive total failures would loop silently [D].
Options: (a) a hard cap on rounds and on model calls per run, the values registered before the first run;
(b) in addition to (a), stop when N consecutive rounds each produced zero tasks and every model call in
them failed, N registered before the first run and not adjusted from data; (c) no cap, rely on the report.
*Lean [D]:* (a)+(b). Whether to stop does not depend on the kind of failure: a classifier stop counts as a
failure like any other and is not re-asked.

**Decision D69-5b: a proposal stranded at `received`.** *Pending the owner.* Options: (1) stop the service and let a person
decide (the fault may be deterministic; the scheduler's reasoning for "do not restart blindly" applies,
[D]); (2) retry once under the same idempotency key, then stop; (3) leave it to the reconciler. *Lean [D]:*
(1) in v0. Note the key must be derived from the task and the attempt, so a restart does not make a second
proposal for the same task [R: ADR D60 addendum].

**Decision D69-5c: a task claimed and never completed (0c).** *Pending the owner.* The loop completes every task it claims on
every path it controls; a crash between claim and complete strands the task in `claimed` and nothing
requeues it [R]. Options: accept and report (a restart does not pick it up); a manual operator query
(`query_tasks` shows `lease_expires_at`) [R]; build the sweeper (outside this deliverable). *Lean [D]:*
accept in v0 and register the gap (section 12).

## 6. Credentials (D58-15 is NOT built)

**Facts.** ACCEPTANCE 5.57: an approved `ad.collect` carries a credential-less capability and is refused by
`dispatch_collection` as `unbuildable_plan` before any container exists; "nothing runs without a credential".
`propose_action(credential_id=...)` is "the caller's job to supply ... this function does not choose one on
its own initiative" (`function_api.py:565-568`). The scheduler dispatches only the four actions in
`SUPPORTED_ACTIONS`, and skips anything else with `action_not_supported_v0` [R]. ACCEPTANCE 5.59 notes that
`code.*` on private repositories has 5.57's limit [R].

**Decision D69-6: how does v0 exclude credentialed actions, fail-closed?** *Pending the owner.* Options
for the set of actions v0 may propose: (A) the scheduler's four -- `SUPPORTED_ACTIONS = ("network.scan", "network.recon", "code.scan",
"code.secrets")`, `control_plane/scheduler/vocab.py:58` [R] -- so that anything a human approves can be
dispatched [D]; D69-3a's HTTP/browser rules cannot be verified in v0 if the action set excludes `web.*` [D]; (B) the four plus the `web.*` actions that `propose_action` can dispatch inline on `ALLOW`
(they need an egress proxy and CA; an approved `web.*` proposal would be skipped by the scheduler and wait
forever [D]); (C) everything except `ad.collect`. Mechanism, whichever set: a closed allowlist in the
harness applied at three points -- the scope candidates offered to the Supervisor and the Worker (their
schema enums are built from them, so the model is not offered the action), a refusal of a task whose action
is outside the list before `create_task`, and a refusal of a proposal whose action is outside the list
before `propose_action` -- and the harness never passes `credential_id`. A violation at the second or third
point is a counted refusal, not a retry. *Lean [D]:* (A), `ad.collect` excluded by construction, with the
private-repository limit of `code.*` stated in the operator documentation. The offered candidates are also
checked in-process, not only requested through the schema's enum: `BaseWorker._to_proposal` raises `WorkerRefusal`
for a `scope_object_id` not among the offered candidates (`agents/llm/worker_base.py:677-683`) and for an
`action` not in the *selected* candidate's `allowed_actions` (`worker_base.py:694-700`); `BaseSupervisor._to_tasks`
does the same per task and refuses the whole reply (`agents/llm/supervisor_base.py:518-523`, `529-536`); a
refusal makes the call fail with no proposal and no tasks (`worker_base.py:761-779`, `_refuse`;
`claude_code_headless_worker.py:108`; `claude_code_headless_supervisor.py:105`) [R]. So an action left out of the
candidates' `allowed_actions` is refused in-process by these two classes [R]. Not read: whether every
Worker or Supervisor implementation (the fakes in `agents/fake/`) makes the same check **[N]**; and these checks
are no substitute for the harness's own refusals at `create_task` and `propose_action` (points 2 and 3), which
remain a defence-in-depth choice [D].

## 7. Concurrency and quotas

**Facts.** The scheduler is serial (concurrency 1) [R]. `Budget.max_concurrency` is carried and recorded and
read by nothing in `control_plane`, `tool_gateway` or `agents` (`capability/broker.py:119-136` is the only
place it appears; `git grep -n max_concurrency -- control_plane tool_gateway agents`) [R]; the ADR (premise 1)
says the same. D58-13 (resource quotas) is NOT built [R]. D59: two engagements are never live on one Docker
network; same-range engagements serialize and the orchestrator must treat `NetworkInUse` as "retry later"
[R]. The connection pool saturated at 15 concurrent in-flight steps in an earlier experiment (ADR E8) [R,
not re-run]; D60 reduced X6 to a stage's transaction and re-measured "12 concurrent fine, 25 started
together fail 9, cleanly" [R: ADR D60 addendum]. The shared LLM backend has no rate limit applied by this
system (ADR section 4.2) [R].

**Decision D69-7: concurrency in v0.** *Pending the owner.* (A) Serial, one task at a time across all
engagements -- predictable, easy to reason about; slow [D]. (B) One task at a time per engagement, engagements
in parallel -- needs a cap, the pool ceiling, and the `NetworkInUse` handling. (C) Wire `max_concurrency`
-- outside this deliverable. *Lean [D]:* (A). *Stance on `max_concurrency`:* v0 documents that the field
is unread and does not rely on it; a run's concurrency is a property of the harness, stated in its
start-up banner, not of the capability. Because the dispatcher is another process that also starts
containers (D69-1 option A), "serial" holds for the proposer, not for the system [D].

## 8. Relation to P1 and Q1

**Facts.**
* `BaseWorker.propose(task_id=None)` makes omission the default; with `task_relation_enforce` on, every
  `no_task` escalates (DP-4 (a)) [R]. With it off, `plan_fit` is still computed, stored and audited, and no
  decision changes (ACCEPTANCE 5.118 S2) [R].
* The shadow tooling exists: `control_plane/plan_fit/shadow.py` and `scripts/plan_fit_report.py` (read-only
  over named engagements: relation and goal-fit counts, the DP-13 line, how many `ALLOW` decisions each of
  P1 / Q1 / both would send to a human, by reason) [R: 5.118 S6].
* The plan's rule: "turning enforcement on for a real engagement remains gated on a production harness
  existing and being run in shadow first" (`D68_IMPLEMENTATION_PLAN.md` 7.1) [R]. The wording is the plan's;
  what "shadow" means concretely is not defined there beyond the tooling above [R/N].
* P1 is on nowhere by default; S8a enabled it only in a CI soak whose workload is synthetic (every request
  names a task made from itself) [R: `D68_S8A_REPORT.md` sections 1, 3, 6].
* Q1: stage 1 did not meet C1; `goal_fit_enforce` stays off; "any further measurement is a new
  pre-registration on new data that attaches this result" (OUTCOME.md; owner, 2026-10-27) [R]. The class list
  is empty by default, so a class outside it is not asked [R: 5.125].

**Rules of the harness (candidate) [D].** (1) Every `propose_action` carries a `task_id` of a task that
exists in the engagement, was created by the harness this run, and is claimed; a proposal whose
`task_id` is `None` is a bug, refused before the call and counted, whatever the switch. (2) A structure test of
the style of `tests/test_task_less_callers.py` covers the harness module: a construction of `ProposedAction`
without a task is a failing test. (3) The harness never sets, publishes or asks for a switch.

**Decision D69-8a: what does "run in shadow first" mean?** *Pending the owner.* Options: (A) the harness runs
with both switches off against engagements in a lab for a registered period, and P1's shadow report is the
measurement; no person sees any P1 reason; (B) the same, plus a registered comparison against the synthetic
scale runs (`D68_S7_P1_SCALE.md`); (C) shadow = the 4-hour CI soak with the harness inside it. *Lean [D]:*
(A) with the population and look rules registered before the first run. Q1 stays out of the shadow unless
the owner opens a new registration (it would need its own sampling rules; DP-15 stage 1 is the precedent).

**Candidate measurements for the shadow (no threshold set, none proposed).**
1. Relation share: of proposals, how many `matches_task` (and with sub-cause `subset_of_task_range`),
   `differs_from_task` (by sub-cause), `task_not_live`, `no_task` [R: the shadow report prints these].
2. The share of `ALLOW` decisions that enforcement would have sent to a person, by reason (the report's
   existing line).
3. Supervisor-side: tasks planned, tasks refused by the harness's own check (D69-2b), `overlaps_with` counts.
4. Model-call outcomes by role: answered, failed with kind (classifier stop, transport, other), cost and
   latency -- recorded, not tuned.
5. Observation-side: how many proposals were escalated on `introduced_by_untrusted`, per tool (the 5.28
   mechanism in use).
6. Stranded states: tasks left `claimed`, proposals left at `received`.

**Candidate fields of a pre-registration** (fields, not values): unit of analysis (proposal, task,
engagement); the population and how engagements are chosen; number of engagements, rounds and tasks, fixed
beforehand; roles, models, aliases, CLI version, fallback setting, and the digests of the prompts and schema
descriptions of each role (the `PROMPT_DIGEST` practice of DP-15); the action set (D69-6); lab or real
targets; what counts as a failure (a classifier stop counts, no re-ask); caps (calls, cost, minutes) and stop
rules; the number and timing of looks and a ledger of looks; the reading rule written before the data; the
registering commit and hashes of every registered file, and a guard in the runner that refuses to start
if they differ (the `integrity()` guard of `scripts/dp15_stage1_run.py`) [R/D: the practice exists; reusing it
is a design choice of the owner's].

## 9. Operations: start, stop, kill

**Facts.**
* Scheduler: `python scripts/run_scheduler.py [--interval 5] [--once]`; SIGINT/SIGTERM set a stop event;
  exit codes as in section 5 [R]. Reconciler: `scripts/run_reconciler.py --mode dry-run|state-only ...`;
  irreversible categories need a person typing a phrase at a terminal; "There is no `--yes`" [R].
* There is no compose, systemd or supervisor definition for any of them (0b, `git ls-files`) [R]. Start
  order is a convention, not a check (`run_reconciler.py` docstring) [R].
* Pause and kill: `pause_engagement`, `resume_engagement`, `engage_kill_switch` change database rows
  (`engagement.py:222-279`). The pipeline checks them at every stage boundary of `propose_action` (ADR D60
  addendum; ACCEPTANCE 5.53), and the scheduler defers (`engagement_paused`, `engagement_killed`) [R].
* **The kill switch does not stop a running container.** ACCEPTANCE 5.24: "nothing stops the container";
  revoking only flips a row checked at issue and renewal time; the ADR index: "D58-16 ... NOT built (the
  kill switch does not stop a running container)". Docker containers are labelled with their `run_id` and
  `container.kill()` is already used for the timeout, so killing on revoke is "scoped, known work", not
  built [R]. A run is bounded only by its `max_duration_seconds` (global ceiling 1,800 s, built, 5.76) [R].
* The headless adapters run the `claude` CLI as a subprocess (`agents/llm/headless.py:175`) [R]; I found no
  code that checks the kill switch between a model call's start and its end, so a model call in flight is not
  interrupted [D: absence in a search is not shown].
* The web console runs as `app` with two writes (approve, deny); how it is started is not in the repository
  (0b) [R/N].

**What the harness would do, candidate [D].** An operator CLI analogous to the scheduler's: `--interval`,
`--once`, a start-up banner (database, migration head, the two switches' effective values, the action
set, the engagements, the role models); SIGINT/SIGTERM finish the current task and exit 0; the
advisory lock under its own key; before each round and each task, read the engagement's pause/kill state and
stop proposing for it; no attempt to stop an in-flight container (the harness does not own it). The
harness's own behaviour on a kill is stated plainly: **after a kill, a container that is already running
continues until its budget ends [R: 5.24], and a model call that has already started finishes [D].**

**Decision D69-9: what is claimed about kill in the operator document?** *Pending the owner.* Options: (A)
state exactly the above and nothing more; (B) build the active kill (D58-16 / 5.24 option B) before the
harness is used on a real engagement -- outside this deliverable; (C) do not run the harness unattended
until (B). *Lean [D]:* (A) now, with (C) as the owner's call for real engagements.

## 10. Language fit (no conclusion assumed)

The component is orchestration glue: it waits on a subprocess (the model CLI), the database and the
pipeline's own synchronous calls, and moves small records between them [D]. Its correctness risk is in
*what it submits*, not in memory handling [D]. Nothing was measured: no CPU, latency or memory figure for a
harness exists, so performance claims are **[N]**.

| Criterion | Python (the code base's language, `requires-python >= 3.12`, `pyproject.toml`) | Rust |
|---|---|---|
| Reuse of the pipeline | Calls `function_api`, `load_effective_policy`, the roles and `create_engagement` directly, in-process [R: how `d40` and the scheduler do it] | The pipeline is Python; a Rust harness needs an API boundary that does not exist (the web console has no propose route, and adding one widens the surface, `control_plane/web/app.py` docstring) or an embedded interpreter [D] |
| Existing guards | AST ratchets, the structure tests and the mutation framework (`scripts/mutations_*.py`, `scripts/mutation_check.py`) are Python and already cover the neighbouring modules [R] | Would need its own equivalents [D] |
| Precedent | The scheduler, the reconciler and the soak driver are Python [R] | One Rust program ships: the in-container deadline helper (`tool_gateway/deadline/`), chosen over C and Go for a 430 KB static binary and a reproducible hash, because it is PID 1 of a tool container (`docs/D65A_CONTAINER_DEADLINE_DESIGN.md` section 3) [R]. Those criteria do not apply to a resident orchestrator [D]; whether CI carries a Rust toolchain for it was not read here **[N]** |
| Failure surface | Dynamic typing; exceptions escape (5.120 is of this kind) [R] | A type system and exhaustive matches would encode the closed fault list of section 5 [D]; the cost is the boundary above |
| Operating | Same interpreter and virtualenv as the rest | A second build artifact to pin, hash and ship [D] |

*Lean [D]:* Python for v0, on reuse and existing guards; revisit only if a measured need appears (for
example a concurrency requirement, D69-7 (B)). *Pending the owner.*

## 11. Falsifiable acceptance for v0 (candidates; no threshold)

Each states what observation would refute it. Written for a harness that does not exist; none was run.

1. *Every proposal carries a live task.* Over a run, the count of `action_proposals` created by the harness with
   a `task_id` that is NULL, belongs to another engagement, or is not `claimed` at submission is 0. Refuted by one
   such row.
2. *The policy comes from `load_effective_policy`.* An AST test over the harness module fails when any
   `propose_action` call receives a `policy` not produced by the one loader; a mutation that passes a stale or
   hand-built policy must be caught.
3. *Observation provenance (5.28's trigger).* For each action in the v0 set, the end-to-end case of D69-3b ends in
   `HUMAN_APPROVAL` with `introduced_by_untrusted` true, and its mirror does not escalate on discovery grounds.
   Refuted by a lure that reaches `ALLOW`.
4. *No credentialed action.* The count of proposals or tasks with an action outside the allowlist (D69-6), or
   with a `credential_id`, is 0; the three refusal points each have a test that fails when removed.
5. *Closed fault list.* A fault outside section 5's list stops the service with a distinct exit code and a
   record; an injected exception from `propose_action` leaves exactly the 5.120 state and the service stops.
6. *No re-ask on a classifier stop.* A scripted Worker and Supervisor that report a stop yield one call each, a
   recorded failure, and no second call.
7. *Kill and pause.* After `engage_kill_switch`, the harness starts no new round or task for that engagement
   (a test counts `propose_action` calls after the switch), and the operator document states what is not
   stopped (section 9).
8. *Restart.* `kill -9` of the harness at each point between claim and complete leaves no second task and no
   second proposal for the same work after a restart, using the task-and-attempt idempotency key; the stranded
   `claimed` task of 0c is the known residue and is reported, not hidden.
9. *Serial.* Two harness instances cannot run at once (the lock); a second exits at once with its own code.
10. *Soak.* A soak run with the harness inside it ends with no finding on the existing soak checks (the
    `p1_enforcement` check applies only when the switch is on) -- refuted by any finding; this says nothing
    about real traffic (`D68_S8A_REPORT.md` section 6).
11. *The shadow's measurements (section 8) are produced by the existing report without a change to it* -- refuted
    if the report cannot read the harness's engagements.

Mutations: when code exists, each of 1-9 needs a mutation that breaks it and is caught; this note writes none
because it adds no code.

## 12. To register (待登記) -- listed only; nothing is written to any existing file

1. **ACCEPTANCE 5.28** -- update when built: the trigger of 5.28 is met only when a real harness exists; this design is its
   precondition [D]. The row's "re-verify end to end" would become an acceptance item (11.3) [D].
2. **ACCEPTANCE 5.51** -- update when built: the "re-verify when a production harness is written" clause
   becomes acceptance item 11.2.
3. **A new row (number to be assigned by the owner's process), Class B, Open:** *no code requeues a `claimed`
   task whose lease lapsed* (0a/0c). It is currently recorded only in the ADR (section 0.2 premise 6, section
   0.3) and in the D62 design's "Not built" list, not as an ACCEPTANCE row [R: I did not find one; the
   search was by phrase, so a row under other words is possible, [N]].
4. **A new row, Class C:** *the web console has no documented start command* (0b).
5. **ACCEPTANCE 5.122** -- append, if D69-2b (1) is chosen: the harness-side prefix check; leave the
   canonicalizer question open.
6. **ACCEPTANCE 5.118 / `D68_IMPLEMENTATION_PLAN.md` 7.1** -- the sentence "gated on a production harness existing
   and being run in shadow first" needs the definition chosen in D69-8a.
7. **ADR_PRODUCTION_ORCHESTRATOR.md index** -- a row for the proposing side, which the ADR's decision list does
   not contain as a separate item (D58-12 "planning" is the nearest) [R/N].
8. **ACCEPTANCE 5.24 / D58-16** -- unchanged; the operator document of D69-9 would repeat, if D69-9 (A) is chosen [D], that the kill does
   not stop a running container.
9. **Pre-registration for the shadow (D69-8a)** -- a new document with the fields of section 8, registered by
   a commit before the first run, with guards as in DP-15.
10. **Open questions for the owner**, in order of what blocks what [D]: D69-1 (where it runs) -> D69-6 (action
    set) -> D69-3a (identities per tool; needs the `code.*` views read) -> D69-2a/2b -> D69-5a/5b -> D69-5d -> D69-4 ->
    D69-7 -> D69-8a -> D69-9 -> the language (section 10).
