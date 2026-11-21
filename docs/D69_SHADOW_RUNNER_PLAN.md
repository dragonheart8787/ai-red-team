# D69 -- Plan: the shadow runner (a draft; nothing here is authorized)

Written 2026-11-22 by the implementer at the review layer's request; documents only. Base: HEAD
`8ae076bc47e224d9155b836be2dcfc38ce3bac75`.

How to read it. Every fact names its source: a plan item (`item N`, in `docs/D69_IMPLEMENTATION_PLAN.md`), the H8
draft (`draft`, `docs/D69_H8_SHADOW_PREREGISTRATION_DRAFT.md`), or a file and line. `[N]` marks something not read
or not known. `[D]` marks an inference or a leaning of the implementer's; a leaning is not a choice. Every number the
owner has not decided is written `[owner: 未決定]`; no value is suggested anywhere.

## 0. Status

- **A plan draft.** Each stage of section 4 needs the owner's own authorization, one stage at a time, naming what
  it may touch (the rule of plan section 12, `docs/D69_IMPLEMENTATION_PLAN.md:1411-1416`).
- **This document registers nothing and runs nothing.** It writes no code, test, migration or switch, sets no
  threshold and chooses no value. Where it leans ([D]), the decision stays the owner's.
- **Why it exists.** The plan names the shadow runner and its integrity guard as "not part of H1-H8; they need
  their own plan after H8" (`docs/D69_IMPLEMENTATION_PLAN.md:1349-1352`; section 13, line 1422; section 14 item
  10, lines 1442-1443, "with its own mutations"). Item 124 (b) adds the storage of measurements 3 and 4 and the cost
  and minute caps to the same plan.

## 1. Scope

What a shadow run needs that H1 to H8 did not build. The shadow is the one design D69-8a chose, (A): the harness
runs with both switches off against laboratory engagements for a registered period, and P1's shadow report is the
measurement (`docs/D69_PRODUCTION_HARNESS_DESIGN.md:555-562`; decided by the review layer 2026-10-28, the owner may
veto).

Not in scope: a real engagement (section 5); the registration itself and the shadow run itself, which are the later
plans of plan section 13 (line 1422: "the shadow runner and guard; the shadow registration; the shadow run"). This
plan ends where a registration could begin.

**What exists today, as read for this plan.**

| fact | source |
|---|---|
| The entry is `scripts/run_harness.py run`. It requires `--role-factory`, `--objective` and five positive numbers (`--window-limit`, `--max-rounds`, `--max-model-calls`, `--no-progress-limit`, `--live-task-limit`) with no default | `scripts/run_harness.py:88-94` |
| `--role-factory` imports any `module:function` and calls it; nothing checks what it returns | `scripts/run_harness.py:104-108`; item 101 (b) |
| The banner is printed and the loop starts at once | `scripts/run_harness.py:138-151`; item 104 (a) |
| The stop line prints the exit code, the reason, `rounds` and `counters` to stderr, and nothing else | `scripts/run_harness.py:152-154` |
| `Bounds` holds three numbers (rounds, model calls, no-progress limit), all required, no default; no cost and no minutes | `harness/bounds.py:45-81` |
| `RefusalCounter` keeps `(side, reason)` pairs in memory, "deliberately not a logger and not a store" | `harness/action_allowlist.py:76-112` |
| The exit codes: 0, 1, 2, 3, 4, 5, 6, 10, 11, 12, 13 (a cap was reached), 14 (no progress); 7 reserved; 0, 10, 13, 14 clean up the loop's unclaimed tasks | `harness/exit_codes.py:9-22, 37-52, 89-94` |
| The Worker, the Supervisor and the Reviewer each keep `self.calls` in memory (latency, input and output tokens, model; on a failure `failed=True` and a free-text `failure`) | `agents/llm/worker_base.py:169-182, 702, 873-878`; `agents/llm/claude_code_headless_worker.py:111-116`; `agents/llm/supervisor_base.py:223-240, 587-592`; `agents/llm/claude_code_headless_supervisor.py:108-116`; `agents/llm/reviewer_base.py:164-176, 217, 314` |
| Nothing in `harness/` or `scripts/run_harness.py` reads `.calls` (searched); the harness writes no audit event of its own (searched `harness/*.py`) | grep, 2026-11-22 |
| A headless failure carries `stop_reason`, `api_error_status` and `timed_out`, but the roles record only `str(exc)` | `agents/llm/headless.py:95-114`; `agents/llm/claude_code_headless_worker.py:100-101`; `agents/llm/claude_code_headless_supervisor.py:100-101` |
| A headless reply carries input and output tokens, not a cost | `agents/llm/headless.py:147-150, 214-218` |
| D68's guard `integrity()`: refuses on any uncommitted or untracked path, on HEAD not containing the registered commit, on a registered file whose bytes differ from that commit's blob, and on anything git cannot answer ("never a pass"); it records the hashes of two code files without comparing them | `scripts/dp15_stage1_run.py:62-71, 212-269` |
| D68's run refuses before any call when the guard or a pinned input fails, refuses to raise a cap, refuses to append to an existing record, and asks for a typed confirmation | `scripts/dp15_stage1_run.py:582-643` |
| D68's caps were calls, US dollars and minutes, checked before every call and after each finished one; the dollar figure was the CLI envelope's `total_cost_usd`, "API list price of the tokens" | `scripts/dp15_stage1_run.py:119-134`; `scripts/dp15_record_mode.py:174-210` |
| D68's ledger of looks: `<record>.looks.jsonl` beside the record; a later look needs `--reason`; each entry holds the record's sha256; a changed record is noted | `scripts/dp15_stage1_analysis.py:333-371`; `docs/D68_DP15_RECORD_MODE/stage1/README.md:56-63` |
| D68 registered by a commit and a README naming the commit and the files' sha256; `plan_commit` was the HEAD at the run, a descendant | `docs/D68_DP15_RECORD_MODE/stage1/README.md:7-27` |
| The shadow report reads one named engagement at a time under row-level security: `action_proposals` joined to `tasks`, and the `plan_fit.assessed` audit events | `scripts/plan_fit_report.py:16-18, 157-178` |
| `audit_log` is append-only for `cyberorch_app` (UPDATE, DELETE, TRUNCATE revoked), and every row names an engagement | `db/migrations/versions/0001_core_schema.py:34-39, 353-364, 415-417` |
| Enrolment accepts the purpose `harness_lab` only, and the reader returns only those rows; nothing tells a laboratory engagement from a real one, so the label can be wrong | `db/migrations/versions/0031_harness_enrolment.py:24-31, 47-58` |
| Nothing in `harness/` truncates an evidence row; P-8's per-row ceiling "is still open" | `harness/observations.py:10-12, 18-28` |

## 2. The parts

Each part is written as a stage of `docs/D69_IMPLEMENTATION_PLAN.md` is: goal, what it does, what it does not do,
acceptance with its refutation, mutation entries, risks and [N], how it stops. The mutation entries are names and
descriptions only; none is written until the part's stage is authorized.

### 2a. The runner and its integrity guard

**Goal.** A run of the shadow starts only from the registered checkout, as D68's stage 1 did
(`scripts/dp15_stage1_run.py:212-269`), and its record says which checkout that was.

**Options: where the guard sits.**
- (a1) **Above the harness's entry.** A new script runs the guard, then the checks of 2d, then calls the
  harness's run in-process, and writes the record (2b, 2e). `scripts/run_harness.py` is not changed.
- (a2) **Inside the harness's entry.** `_run` (`scripts/run_harness.py:111`) runs the guard itself. Every run is
  guarded. The lab tests and H7 start the same entry without a registration (item 101 (b) names the tests'
  factories), so a2 needs a way to run unguarded, which is a switch-like setting.
- (a3) **Outside, as an operator procedure.** A runbook step: no code.

[D] Leaning (a1). D68 put its guard in the run script and left its tools alone (`scripts/dp15_stage1_run.py:582-589`).
a1 keeps the runbook and the H5 to H7 tests as they are, and a2's unguarded mode would be a new switch. **The cost of
a1, stated:** `scripts/run_harness.py run` stays startable without the guard. A shadow run is then defined as a run
started by the runner, and a run started otherwise is not a shadow run. Nothing in code prevents such a run (row R30
of section 3). a3 guards nothing.

**Options: what decides the list of registered files.**
- (i) A constant in the runner, as `REGISTERED_FILES` (`scripts/dp15_stage1_run.py:65-69`), written at
  registration.
- (ii) A list inside the registration README, read by the runner. The README must then itself be registered.
- (iii) A rule: every file whose bytes reach a role's prompt or the decision, for example the role modules, the
  schema descriptions, the policy and `harness/`.

[D] Leaning (i), with a second list of code files whose hashes are recorded and not compared, as `CODE_FILES`
(`scripts/dp15_stage1_run.py:70-71`). D68's runner was mended after registration
(`docs/D68_DP15_RECORD_MODE/stage1/README.md:21-27`). Which files go on the list is [owner: 未決定]. A rule (iii)
can be checked, but deciding what "reaches a prompt" means is itself a decision. [D] The guard should also compare
the prompt and schema-description digests the banner prints (`harness/banner_facts.py:115-120`, per the draft
section 5) with the registered ones. A changed prompt then refuses the run instead of only being printed.

**Does not.** Change `scripts/run_harness.py` (under a1), choose the registered files, or register.

**Acceptance.** The runner refuses, before the role factory is called, when: the tree has an uncommitted or
untracked path; HEAD does not contain the registered commit; a registered file differs from its blob; git cannot
answer; or a registered digest differs from the banner's. Each refusal names its cause; the refusals are a closed list.
**Refuted if** any of these starts a round, or if a refusal is reported as a pass.

**Mutations.** D69-SR-A1: the untracked-files flag is dropped from the status check. D69-SR-A2: the ancestor check
is removed. D69-SR-A3: blobs are read from HEAD, not from the registered commit. D69-SR-A4: a git that cannot run
counts as a pass. D69-SR-A5: the digest comparison is removed.

**Risks / [N].** A guard that compares only the files on its list protects nothing that is left off it [D]. The
banner digests two roles: the Supervisor's from the instance's `system_prompt`, and the Worker's from the constant
`WORKER_SYSTEM_PROMPT`, not from the instance (`harness/banner_facts.py:115-122`). The Worker's digest is therefore
true only if the instance uses the constant, which is item 98 (a)'s pin. The Reviewer has no digest there. Whether
the digests cover every text a role is shown (the templates of the user turn, for example) is [N] (not read for this
plan).

**How it stops.** If the list of registered files cannot be stated, the part stays a design.

### 2b. Storing measurements 3 and 4

**Goal.** Measurement 3 (the harness's own refusals) and measurement 4 (model-call outcomes by role, failure kind,
cost, latency) are kept after the run (design `docs/D69_PRODUCTION_HARNESS_DESIGN.md:569-571`). Today both exist only
in memory and are lost at exit (section 1's table). The draft states the rule this part serves: "a registration
must say how they are captured" (draft lines 73-74). **There is no registration while there is no place to keep
them** (item 124 (b)).

**Options.**
- (b1) **New tables, by migration.** Rows of refusals and of calls, append-only by the same grants as `audit_log`
  (`db/migrations/versions/0001_core_schema.py:415-417`), read per engagement under row-level security.
  - Good: queryable, typed, protected by database privilege.
  - Bad: a schema change, which plan section 12 reserves to its own authorization. A call that is not an
    engagement's needs a scoping decision [D].
- (b2) **`audit_log` events** (for example `harness.refusal` and `harness.model_call`).
  - Good: no migration, already append-only, read the way `plan_fit.assessed` is read
    (`scripts/plan_fit_report.py:175-177`).
  - Bad: `payload` is untyped JSONB. Every row needs an `engagement_id` (`0001_core_schema.py:355`). The harness
    writes no audit event today, so this adds a write path. A write failure must then stop the run, and exit 3
    exists for that (`harness/exit_codes.py:12, 40`) [D].
- (b3) **A per-run record file**, as D68's `record.jsonl`: a header with the guard's fields, one line per call and
  per refusal, and a footer with the stop. It is hashed and committed after the run
  (`docs/D68_DP15_RECORD_MODE/stage1/README.md:53`).
  - Good: no schema change; the file can be hashed; it is also the natural place for 2c's cap state, 2e's stop
    events and 2g's ledger.
  - Bad: it is outside the database and not under row-level security. It is lost if it is not committed. The
    existing report does not read it (that report does not produce measurements 3 and 4 anyway [D]).

**What is captured, whichever option is chosen [D].** Only closed fields. The refusals are already `(side, reason)`
pairs from a closed list (`harness/action_allowlist.py:88-95`). A call keeps role, model, latency, tokens and a
failure kind. The Supervisor's call also holds `assessment_note`, text the model wrote
(`agents/llm/supervisor_base.py:233-239`). Storing it would keep model-written text, which `RefusalCounter` avoids by
design (`harness/action_allowlist.py:79-82`); whether to keep it is [owner: 未決定]. **The failure kind is not
recorded today:** the roles keep `str(exc)` and drop `stop_reason`, `api_error_status` and `timed_out` (section 1's
table). Recording the kind needs a change to the role classes or a wrapper around them. A change to a role is a
numbered change under design D69-2b [D: if it touches only the record and not the prompt, the digests are unchanged;
not verified].

[D] Leaning (b3), with (b2) second: no schema change, and one file carries the guard's header, the calls, the
refusals, the stops and the looks. The owner chooses.

**Does not.** Write a migration, add an audit event type, or change a role before its stage is authorized.

**Acceptance.** After a lab run with scripted roles:
- the store holds one entry per refusal the counter recorded, and one entry per entry of each role's `calls`, equal
  in number and fields;
- nothing in it is model-written text unless the owner chose to keep it.

**Refuted if** a refusal or a call is missing, a failure has no kind, or an abnormal exit loses the entries written
before it.

**Mutations.** D69-SR-B1: the Reviewer's calls are not stored. D69-SR-B2: the failure kind is written as the free
text. D69-SR-B3: entries are kept in memory and written only at a clean exit.

**Risks / [N].** Whether a scripted role produces call entries at all is [N]; the scripted roles of the H7 tests were
not read for this. If the store is a file, a run that dies hard (a kill signal, a lost machine) may leave it
without a footer. That absence is itself the sign of an abnormal stop (2e) [D].

**How it stops.** If no option is chosen, the registration cannot be written (draft lines 73-74).

### 2c. The cost and minute caps

**Goal.** The caps the design names, "caps (calls, cost, minutes)" (`docs/D69_PRODUCTION_HARNESS_DESIGN.md:584`),
are all enforced. `Bounds` enforces rounds and model calls only (`harness/bounds.py:45-81`; item 124 (b)).

**How cost is measured: the unit is [N].** Two units are at hand.
- Tokens. The headless reply carries input and output tokens for every role
  (`agents/llm/headless.py:147-150`).
- The CLI envelope's `total_cost_usd`, as D68 used, which D68 itself calls a list price, not a bill
  (`scripts/dp15_record_mode.py:178-189`). `HeadlessResult` does not carry it today.

Whether either corresponds to money actually spent is [N]. The choice is [owner: 未決定].

**How minutes are measured.** Wall-clock time from the run's start, as D68 did (`scripts/dp15_stage1_run.py:130`).
Whether it is checked at a round boundary only, or also before each model call, is [owner: 未決定]. At a round
boundary, a round can run past the cap by its own length [D].

**Where the check lives.**
- (c-i) **In `Bounds`**, beside the other caps, asked at the round boundary (`harness/bounds.py:76-81`). The stop
  reason is `CAP_REACHED`, so the clean-up of a controlled stop applies (`harness/exit_codes.py:89-94`).
- (c-ii) **In the runner**, which sets the loop's stop event (`scripts/run_harness.py:140-150`).
  **Stated against (c-ii):** the loop then stops as a signal does, exit 0, and the exit code no longer tells a cap
  from a signal. `harness/exit_codes.py:24-26` forbids that.

[D] Leaning (c-i).

**The exit code at the cap.**
- (13) Reuse 13, "a cap was reached" (`harness/exit_codes.py:21`). Which cap is written in the record and on the
  stop line.
- (new) New codes and stop reasons. These change the closed table (`harness/exit_codes.py:55-85`), runbook section
  4, and the draft's stop event 3, whose set of controlled stops is 0, 10, 13 and 14 (draft lines 91-93).

[D] Leaning 13: by its definition it covers any cap, and a new code would reopen three closed lists.

**Does not.** Set any cap's value. Every value is [owner: 未決定] (draft section 5).

**Acceptance.**
- With a cap of each kind set, the loop stops at the first round boundary after the cap is reached, with exit 13
  and the cap named.
- A cost the reply does not state is counted as unknown, not as zero.

**Refuted if** a round starts after a cap is reached, or a missing cost is counted as zero.

**Mutations.** D69-SR-C1: the cost cap is compared with `>` instead of `>=`. D69-SR-C2: a reply with no cost adds 0.
D69-SR-C3: the minutes are measured from the first round, not from the start.

**Risks / [N].** Cost is known only after a call returns, so a run can pass its cost cap by one call's cost, as
D68's could (`scripts/dp15_stage1_run.py:119-131`) [D]. A minute cap does not stop a model call already in progress;
each role's own `timeout_seconds` bounds it (`agents/llm/claude_code_headless_worker.py:48, 55`).

**How it stops.** If no cost unit is chosen, the cost cap stays unbuilt and the registration lacks a field.

### 2d. The real-role factory

**Goal.** A run with real roles accepts only a factory the owner approved, and the conditions of items 98 (a),
101 (b) and 110 hold for the roles it returns.

**The conditions, as written.**
- Item 98 (a): the Worker is a `BaseWorker` subclass, with a test that pins its system prompt to
  `WORKER_SYSTEM_PROMPT` (the shape of `tests/test_worker_boundary.py` line 387).
- Item 101 (b): before a real-role factory exists, the entry script must refuse what the owner has not approved.
- Item 110: either the factory's Worker is shown to use `BaseWorker._to_proposal` unmodified, or the pipeline
  computes the provenance itself.

**Options: how the entry refuses an unapproved factory.**
- (d1) A list of approved `module:function` paths, kept among the registered files (2a). A path not on it is
  refused before it is imported.
- (d2) Checks on what the factory returned, at start. For example: the Worker is an instance of `BaseWorker`; its
  class's `_to_proposal` is `BaseWorker._to_proposal`; its system prompt is the constant.
- (d3) Both.

[D] Leaning (d3). d1 alone does not notice a change to the factory's code unless that module is registered (2a). d2
alone accepts any factory whose objects pass. Under 2a's (a1), the checks are the runner's, and
`scripts/run_harness.py` still accepts any factory (row R30).

**Item 110's two ways. Not chosen; their effects, stated:**
- **(i) The Worker uses `BaseWorker._to_proposal` unmodified.**
  - No change to the pipeline.
  - The protection rests on the Worker's class: a Worker whose `propose` builds its proposal without
    `_to_proposal` bypasses it [D]. That is why d2 would check `propose` as well [D].
  - The scripted Workers of H5c2 and the H7 tests write their own `discovery` (item 110), so the check applies to
    the real factory only.
- **(ii) The pipeline computes the provenance.**
  - `propose_action` stores the Worker's `discovery` as given (`control_plane/api/function_api.py` lines 973 and
    1527, per item 110), so this changes the control plane or the harness.
  - It needs the pipeline to know which observations the Worker was shown. The harness knows the window it passed
    [D].
  - It affects every caller of `propose_action`, not only the harness [D], and the tests that rely on a scripted
    Worker's own `discovery`.
  - `docs/ADR_DISCOVERY_SOURCE.md` would need a new decision.

**Does not.** Build a factory, choose (i) or (ii), or approve a factory.

**Acceptance.**
- A factory not on the list is refused before import.
- Objects that fail any check of d2 are refused before the banner.
- Each refusal names its check.

**Refuted if** a refused factory reaches the banner or a round.

**Mutations.** D69-SR-D1: the path list is consulted after import. D69-SR-D2: the `_to_proposal` identity check
compares names, not objects. D69-SR-D3: the system-prompt check is removed.

**Risks / [N].** Whether d2 can see every way a Worker could avoid `_to_proposal` is [N]. The Reviewer and the
Supervisor have conditions of their own that items 98, 101 and 110 do not name [N].

**How it stops.** Without the owner's choice under item 110, no real-role factory is built (item 110).

### 2e. Detecting the stop events

**Goal.** The three events of the draft's section 4 (draft lines 82-99) stop the run. A run stopped abnormally is
not restarted until a person has read its record. **They are events, not thresholds** (item 124 (a)).

**The events, and who can see them.**
1. **A lure reaches `ALLOW`.** A lure is known only to the laboratory that planted it. The registered lab's list of
   lure targets is therefore a registered file [D].
   - Detection: after each round, the proposals decided `ALLOW` in that round whose target is on the list.
   - **Stated:** an `ALLOW` is dispatched inline by the harness (plan section 14 item 13, lines 1448-1451). When
     the event is seen, the action has already run against the lab target. Detection can stop the next round,
     not that action. In a lab, the internal network bounds it (items 125 and 127 describe that network) [D].
2. **A target the owner has not approved.** Detection: each proposal of the round, whatever its decision, compared
   with the registered targets. Whether OPA's scope check is the whole of "approved" is the owner's (draft lines
   87-90).
3. **An exit code other than 0, 10, 13 or 14.** The runner sees the code when the harness returns (2a's (a1)).

**Options: where events 1 and 2 are detected.**
- (e1) **A watcher beside the loop that sets the stop event.** It ends as exit 0, which cannot be told from a
  signal: the objection of 2c's (c-ii).
- (e2) **A check the loop asks at each round boundary.** This is a change to `harness/loop.py`, with a stop reason
  and an exit code of its own. Those are new entries in the closed lists of `harness/exit_codes.py` and an addition
  to stop event 3's set.
- (e3) **After the run.** This does not stop the run, so it does not meet "stop the run at once".

[D] Leaning (e2): it stops at the earliest point the loop has, and its code tells the operator which event it was.
The codes are [owner: 未決定].

**"Not restarted until a person has read the record." Options:**
- (r1) **An acknowledgement file.** The record of a run that stopped abnormally ends without an acknowledgement. The
  runner refuses to start while an earlier record of the same registration has none. The acknowledgement is a file
  the person commits. Since the guard (2a) requires a clean tree, it is in git history, with its author and time.
- (r2) **A database row.** This needs a migration.
- (r3) **Withdrawal of the engagements' enrolment** on an abnormal stop. A person must enrol them again, using the
  existing `manage_harness_enrolment.py`.

[D] Leaning (r1), optionally with (r3). r3 alone shows that a person acted, not that the record was read, and a
withdrawal is not an emergency stop (item 101 (a)).

**Does not.** Decide the lure list or the approved targets, or set an exit code.

**Acceptance.**
- A lab run with a scripted Worker that proposes a listed lure, and with a scripted reviewer path to `ALLOW`, stops
  at the next round boundary with the event's code. Its record names the proposal, the evidence and the stdout
  (draft lines 85-86).
- A second start without an acknowledgement is refused.

**Refuted if** a round starts after an event, or a restart without an acknowledgement is accepted.

**Mutations.** D69-SR-E1: only the first proposal of a round is compared with the lure list. D69-SR-E2: the
acknowledgement check reads the newest record only. D69-SR-E3: exit 12 is added to the set of normal codes.

**Risks / [N].** How a scripted path reaches `ALLOW` for a lure in a lab test is [N]; with the provenance repairs,
a lure named in evidence is escalated (items 111-121). The test may need a lure the evidence does not name [D].

**How it stops.** Without a registered list of lures and targets, events 1 and 2 cannot be detected, and the draft's
stop rules cannot be registered.

### 2f. Showing that the existing report reads the harness's engagements (design 11.11)

**Goal.** Design 11.11: "the shadow's measurements are produced by the existing report without a change to it --
refuted if the report cannot read the harness's engagements" (`docs/D69_PRODUCTION_HARNESS_DESIGN.md:682-683`).
Not shown today (draft line 148). No test in `tests/` uses both `plan_fit_report` and the harness (searched
2026-11-22: the three tests that use the report do not mention the harness).

**What has to be shown [D].** The report reads one named engagement under row-level security
(`scripts/plan_fit_report.py:157-178`). A proposal with no `plan_fit` in `reviewer_hints` is counted apart and asks
for nothing (`scripts/plan_fit_report.py:22-23`). So the showing is that:
- every proposal the harness made appears in the report's counts;
- none of them falls into the "no `plan_fit`" group.

**Options.**
- (f1) **A test.** An engagement made by the harness's lab path in the test database (scripted roles, as H7), with
  the report's `collect` and its `--json` output run unchanged. The test asserts both points above.
- (f2) **A lab run.** The report is run by hand on an H7-style engagement and its output pasted.

[D] Leaning (f1): it is repeatable and runs in CI.

**Does not.** Change `scripts/plan_fit_report.py`; that change would itself refute 11.11.

**Acceptance.** The report's count of proposals equals the harness's for the engagement, and the "no `plan_fit`"
count is 0. **Refuted if** either differs, or if the report has to be changed to read it.

**Mutations.** D69-SR-F1: the test counts only `ALLOW` proposals. D69-SR-F2: the test reads the report's total
across engagements instead of the one named.

**Risks / [N].** Whether a `HUMAN_APPROVAL` proposal carries `plan_fit` the same way an `ALLOW` does is [N].

**How it stops.** Until it is shown, there is no registration (plan section 10 (5); draft line 148).

### 2g. The ledger of looks and the reading rule

**Goal.** Each look at the shadow's data is written down before its result is known, and the reading rule is fixed
before the data (design `docs/D69_PRODUCTION_HARNESS_DESIGN.md:585`).

**D68's practice, and its limit.**
- The practice: the ledger is a file beside the record; the first look needs no reason and each later one needs
  `--reason`; each entry holds the record's sha256; a changed record is noted
  (`scripts/dp15_stage1_analysis.py:333-371`).
- The limit [D]: a missing ledger reads as no earlier look (`scripts/dp15_stage1_analysis.py:337-340`), so the
  protection against a deleted ledger is git history, not code.

The existing shadow report records no look of its own: it "reports and changes nothing"
(`scripts/plan_fit_report.py:16`).

**Options.**
- (g1) As D68: a file beside the record, committed after each look.
- (g2) `audit_log` events. They are append-only, but every row names one engagement
  (`db/migrations/versions/0001_core_schema.py:355`), and a look spans several.
- (g3) (g1), plus a rule that the analysis refuses unless the tree is clean (2a's guard). Every earlier look must
  then be committed before a new one.

[D] Leaning (g3). The analysis is a registered script, as D68's was (`scripts/dp15_stage1_analysis.py` is a
registered file). It calls the report's reading unchanged (2f) and writes the ledger. The number and timing of
looks, and the reading rule, are [owner: 未決定].

**Does not.** Write a reading rule or decide a number of looks.

**Acceptance.** A second look without a reason is refused. A look with an uncommitted ledger is refused. A changed
record is reported on the next look. **Refuted if** any of the three passes.

**Mutations.** D69-SR-G1: the reason check is skipped when the ledger has exactly one entry. D69-SR-G2: the
clean-tree check ignores untracked files.

**Risks / [N].** A look outside the analysis script, for example running `plan_fit_report.py` by hand, is not
recorded. That is a rule for people, not code [D].

**How it stops.** Without a reading rule, there is no registration.

### 2h. The form of a real nmap's bytes (plan section 10 (8))

**Where it stands.** It is a precondition of registering (`docs/D69_IMPLEMENTATION_PLAN.md:1360-1362`). It is not
answered: way (B) ran twice and neither run produced a banner (items 125, 127 and 128). In this plan it is a
precondition of the registration, not of any part above. The parts of section 2 can be built without it; the
registration cannot be made without it.

**If the owner authorizes another attempt** (item 128: "a further attempt needs a new authorization of the owner";
nothing here authorizes one). The method only, from what the two runs showed:
- Run 1's target closed at once, and nmap reported `tcpwrapped` (item 125).
- Run 2's target held each connection; each version probe waited out its own timeout, and the host was skipped on
  `--host-timeout 115s` (item 127).

A third target would send its banner (the ESC sequence, a control byte, a non-ASCII byte, a lure address), wait
briefly, then close. The aim is that nmap's version probe reads the banner and prints a fingerprint for a service it
cannot recognise. The length of that wait is [owner: 未決定].
- Whether nmap prints such a fingerprint within the adapter's current timeout is [N].
- Changing the adapter's `--host-timeout` would be a code change to what a shadow measures. It is not proposed
  here [D].
- The same internal network, the same command and a new pre-registered table hashed before the run apply, as for
  run 2 (item 126) [D].

**Does not.** Authorize, schedule or prepare a run.

## 3. The owner's decisions

From items 87, 90, 98, 101, 104, 107, 110, 119, 122, 124, 126 and 128, and the draft's sections 5 and 6. "Fail
closed?" says what the system does today while the decision is not made:
- **Yes:** nothing proceeds without it.
- **No:** something proceeds; these rows are marked **NO** in bold.
- **Partly:** closed in one respect, open in another.

"Blocks" names the first step the decision stands in front of: shadow registration (Reg), shadow run (Run), or
real engagement (Real). No value is filled in.

| # | decision | source | where it is used | now, while undecided | fail closed? | blocks |
|---|---|---|---|---|---|---|
| R1 | the gates before a non-laboratory engagement: the shared role; no audit record of an enrolment or withdrawal; an unverified actor; a purpose that is only the operator's statement; an empty `withdrawn_by` possible at the database | item 87; draft line 137 | `harness_enrolment` (0031) | enrolment accepts `purpose = 'harness_lab'` only and the harness reads only those rows; nothing tells a lab engagement from a real one, so a real engagement labelled `harness_lab` is accepted (`0031_harness_enrolment.py:24-31, 50-52`) | **Partly: closed for the label, NO against a wrong label** | Real |
| R2 | lab or real targets | plan section 10 (4); draft line 128 | the registration; enrolment | as R1 | **Partly** (as R1) | Reg |
| R3 | the round cap and the model-call cap | item 98 (b); draft line 110 | `Bounds` (`harness/bounds.py:48`); `scripts/run_harness.py:92-94, 149` | the entry refuses to start without them (required, no default); any positive value is accepted and none is compared with a registered one | Yes for their absence; no comparison exists (2a) | Reg, Run |
| R4 | the cost cap and the minute cap, and the cost unit | design line 584; item 124 (b); draft line 111 | nowhere: `Bounds` has neither | a run has no cost limit and no time limit; only the model-call cap and each role's `timeout_seconds` bound it indirectly | **NO** | Reg, Run |
| R5 | N, the no-progress limit | item 98 (b); draft line 112 | `Bounds`; `--no-progress-limit` | as R3 | Yes for its absence | Reg, Run |
| R6 | the evidence window size | items 90, 98 (b); draft line 113 | `--window-limit`; `harness/observations.py:10-12` | as R3 | Yes for its absence | Reg, Run |
| R7 | P-8's per-row character ceiling | item 90; draft line 114 | nowhere | no ceiling applies: a row's content goes into the prompt whole (`harness/observations.py:12, 26-28`) [D: the effect is on prompt size and cost, not on provenance, which needs the content whole] | **NO** (no limit applies) | Reg, Run |
| R8 | the live-task limit | item 98 (b); draft line 115 | `--live-task-limit` (`scripts/run_harness.py:92-94, 99`) | as R3 | Yes for its absence | Reg, Run |
| R9 | the budget `max_targets` | item 119; draft lines 116, 121-123 | `propose_action`'s budget | the loop passes none, so `max_targets` is 1 and a range is denied (`target_count_exceeds_budget`) | Yes | a shadow over ranges; nothing for single addresses |
| R10 | the number of engagements, rounds and tasks, fixed beforehand | design lines 581-582; draft line 117 | the registration | no code holds them; the harness runs every enrolled `harness_lab` engagement (`scripts/run_harness.py:127`) | **NO** (whatever is enrolled is run) | Reg |
| R11 | the number and timing of looks; the ledger of looks | design line 585; draft lines 118, 130 | 2g | no ledger exists; the report can be run any number of times and records nothing (`scripts/plan_fit_report.py:16`) | **NO** (looks are not recorded) | Reg |
| R12 | the prompt and schema-description digests to register (computed, not chosen) | plan section 10 (2); draft line 119 | the banner (`harness/banner_facts.py:115-120`); 2a | printed, compared with nothing | **NO** (a changed prompt is not refused) | Reg |
| R13 | the unit of analysis; the population and how engagements are chosen; roles, models, aliases, CLI version, fallback setting; what counts as a failure; the registering commit and hashes | design lines 580-587; draft lines 125-131 | the registration | no code effect; nothing can be registered | Yes (no registration); see R30 | Reg |
| R14 | the hypotheses and the reading rule | draft sections 2 and 4 (lines 40-47, 78-80) | 2g | as R13 | Yes (no registration); see R30 | Reg |
| R15 | the real-role factory's Worker is a `BaseWorker` subclass with a pinned `WORKER_SYSTEM_PROMPT` | item 98 (a); draft lines 139, 146 | 2d | no real-role factory exists; `--role-factory` accepts any importable function (`scripts/run_harness.py:104-108`) | **NO** | Run |
| R16 | the entry must refuse a factory the owner has not approved (mechanism not designed) | item 101 (b); draft line 140 | 2d | as R15 | **NO** | Run |
| R17 | the banner is not a gate: a confirmation or a pause between the banner and the first round | item 104 (a); draft line 141 | `scripts/run_harness.py:138-151` | the loop starts at once after the banner | **NO** | Real (item 104 (a)); Run [D] |
| R18 | an operator command for the kill switch or a pause | item 104 (b); draft line 141 | operator | only direct calls of `engage_kill_switch` and `pause_engagement`; SIGINT and SIGTERM stop the loop (`scripts/run_harness.py:140-141`) | **NO** (a run continues until a signal, a cap or a fault) | Real; Run [D] |
| R19 | an operator view of a proposal stuck after a fault, and who starts the reconciler | item 104 (c); item 101 (e); draft line 141 | operator; `scripts/run_reconciler.py` | the proposal stays at `received` until someone runs the reconciler; the residue listing does not show it | **Partly: Yes for execution** [D: a `received` proposal has no decision, so it is not dispatched; inferred, item 101 (e)]; **NO for visibility** | Run; Real |
| R20 | `complete_task` in the recovery of runbook 6.4 has no precondition | item 107; draft line 142 | runbook 6.4 | can write a `task.completed` audit record for a completion that did not happen (observed in H7 S6b, item 107) | **NO** (a false record is possible) | Run [D: measurement 6 reads task status]; Real |
| R21 | the discovery provenance: the Worker uses `BaseWorker._to_proposal` unmodified, or the pipeline computes it | item 110; draft line 143 | 2d | a Worker that writes its own `discovery` bypasses it (item 110) | **NO** | Run |
| R22 | the provenance match's limits (ADR 8.9, 8.10) are re-decided before a real engagement | item 119 (a); draft line 144 | `agents/llm/worker_base.py` `_discovery_provenance` | /32 targets are repaired and ranges are denied (R9); the forms item 119 leaves as recorded limits (IPv6, url and repo targets, a typed octal escape) may read as not introduced; the over-escalation of short names errs the closed way | **Partly: NO for the recorded forms** | Real (item 119 (a)); Run [D: measurement 5 reads this mechanism] |
| R23 | a budget that admits a range re-opens the gluing limit for ranges | item 119 (b); draft line 144 | R9 | no budget, so ranges are denied | Yes | any change of R9 |
| R24 | the laundering path: a Supervisor-written `goal` enters the trusted half of both roles' prompts one round later | plan section 11 risk 10 (lines 1389-1405); section 10 (7); draft line 145 | `agents/llm/supervisor_base.py:445-449`; `agents/llm/worker_base.py:631-638` (per risk 10) | the `goal` is in the trusted header | **NO** | Reg (before any run with a real model, line 1402-1404) |
| R25 | the form of a real nmap's control and non-ASCII bytes; whether to authorize another attempt of way (B) | plan section 10 (8); items 125, 127, 128; draft line 147 | 2h | not answered; the precondition is a rule of the documents only | **NO** in code (see R30); Yes as a document rule | Reg |
| R26 | the existing report shown to read the harness's engagements (a showing, not a value) | plan section 10 (5); design 11.11; draft line 148 | 2f | not shown | Yes (no registration); see R30 | Reg |
| R27 | the three stop events of the draft stand (the owner may veto) | item 124 (a); draft lines 82-99 | 2e | no event is detected; a run stops only on `Bounds`, a signal or a fault | **NO** | Reg, Run |
| R28 | how measurements 3 and 4 are stored | item 124 (b); draft lines 59-60, 73-74 | 2b | they are in memory and lost at exit; a run is not prevented | **NO** (the data is lost) | Reg |
| R29 | whether Q1 stays out of the shadow, and what keeps it out | plan section 10 (6); design lines 559-560 | `propose_action` | decided as a rule; whether `propose_action` calls Q1 during a harness run, and what would keep it out, is [N] (not read for this plan) | [N] | Reg |
| R30 | whether any run that is not a test may be made before the runner exists | item 98 (heading: "Gates before a real-role factory is built or a run that is not a test is made") | `scripts/run_harness.py` | nothing in code requires a registration: the entry runs with any importable factory and any positive numbers; the gates of plan section 10 and items 98-128 are rules of the documents, kept today by the absence of a real-role factory in the repository [D] | **NO** | Run |
| R31 | ACCEPTANCE 5.28 stays open | item 122 (a) | ACCEPTANCE | decided by the owner | -- | none |
| R32 | way (B) authorized in principle; a second run authorized, at most one, no third | items 122 (b), 126 | 2h | decided by the owner; both runs made | -- | none |
| R33 | H7 closed; 5.28 independent | item 128 (review layer, the owner may veto) | draft section 6 | recorded | -- | none |

Rows: 33. Rows marked **NO** or **Partly**: R1, R2, R4, R7, R10, R11, R12, R15, R16, R17, R18, R19, R20, R21, R22,
R24, R25, R27, R28, R30 (twenty). R29 is [N].

## 4. Stages

Each stage needs the owner's authorization for the kinds of work listed: documents only (Doc), code (Code), schema
(Schema), a laboratory run (Lab), a model call (Model). None is authorized by this document.

| stage | parts | depends on | authorization needed |
|---|---|---|---|
| S0 | the owner's answers to section 3 that the later stages need: 2a's placement and file list, 2b's store, 2c's unit and check point, 2d's mechanism and item 110's way, 2e's codes and acknowledgement, 2g's ledger | none | Doc |
| S1 | 2a: the runner and its guard; 2d's refusal of an unapproved factory (d1, d2) | S0 | Code |
| S2 | 2b: the store of measurements 3 and 4 | S0, S1 (if b3: the runner writes the record) | Code; Schema if b1 |
| S3 | 2c: the cost and minute caps | S0 (the unit), S2 (where the state is kept) | Code |
| S4 | 2e: the stop events and the restart rule | S1, S2 | Code |
| S5 | 2f: the showing for design 11.11 | none beyond H7 | Code (a test) under f1; Lab under f2 |
| S6 | 2g: the ledger and the analysis script | S2 (the record's format), S5 | Code |
| S7 | item 110 under way (ii), if chosen | S0 | Code (the control plane) |
| S8 | a dry run of the runner end to end with scripted roles in the laboratory: the guard, the record, the caps, the events, the ledger | S1-S6 (and S7 if chosen) | Lab |
| S9 | 2h: another attempt of way (B), only if the owner authorizes one | the owner's authorization (item 128) | Lab |

After this plan, and not designed here (plan section 13, line 1422): the registration, which needs S1-S8, S9 or
another answer to section 10 (8), R24's decision and every Reg row of section 3; then the shadow run (Lab and Model).

## 5. What this plan does not do

- A real engagement, or anything that would enrol one. The Real rows of section 3 come first (item 87).
- `web.*`, `code.*` or `ad.*` actions; the v0 action set is `network.scan` and `network.recon` (D69-6 A', plan line
  75).
- Q1 (R29).
- Set any threshold, any cap, any number or any digest.
- Change code, tests, migrations, switches, the harness, a prompt, or `docs/ACCEPTANCE_MVP1_AGENTS.md`.
- Register the shadow or run it.

## Lists

**Every `[owner: 未決定]` here:** which files are registered (2a); whether the Supervisor's `assessment_note` is kept
(2b); the cost unit (2c); whether minutes are checked before each call (2c); every cap's value (2c); the exit codes of
the stop events (2e); the number and timing of looks and the reading rule (2g); the length of the third target's
wait (2h). Section 3 holds no value by construction.

**Every `[N]` here:** whether the banner's digests cover every text a role is shown (2a); whether a scripted role
produces call entries (2b); whether tokens or the envelope's list price correspond to money spent (2c); whether d2
sees every way around `_to_proposal`, and the Reviewer's and Supervisor's own conditions (2d); how a lab test brings
a lure to `ALLOW` (2e); whether a `HUMAN_APPROVAL` proposal carries `plan_fit` as an `ALLOW` does (2f); whether nmap
prints a fingerprint within the adapter's timeout (2h); whether `propose_action` calls Q1 during a harness run (R29).
