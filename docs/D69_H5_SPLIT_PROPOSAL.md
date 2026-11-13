# D69 H5: a proposal for splitting the stage

[2026-11-13 review layer, under the owner's standing delegation; the owner may veto] **This document is a proposal, not a decision.** It authorizes no implementation, chooses no
value, and changes nothing in `docs/D69_IMPLEMENTATION_PLAN.md` or the design document. Every choice below is
marked **[proposal]**. What has already been decided by the owner or by the review layer is quoted, with its source,
and marked **[decided]**. Facts are tagged [R] (read, with the original text or a file and line), [D] (derived,
reasoned from facts) or [N] (not measured, not found, or not read). Line numbers refer to
`docs/D69_IMPLEMENTATION_PLAN.md` ("plan") and `docs/D69_PRODUCTION_HARNESS_DESIGN.md` ("design") as of
commit `53138ab`, and to `docs/D69_H1_REPORT.md` ("H1 report").

## 0. What was read

* Plan section 6, **H5** in full: `L1121`-`L1227`, including the pieces (`L1126`-`L1145`), H5b (`L1147`), the
  tests (`L1151`-`L1165`), the mutation list H5-1 to H5-10 (`L1167`-`L1176`), ACCEPTANCE and risks (`L1178`-`L1182`), the
  two 2026-10-29 verification notes (`L1184`-`L1221`), and the mutation candidate moved from H4 (`L1223`).
* Plan section 1: the P-1 to P-8 table (`L65`-`L80`) and every "Chosen by the review layer" line (`L81`-`L165`),
  P-8 and its chosen lines (`L166`-`L240`), the foreign-task stop rule and its correction (`L241`-`L265`), the start-up check,
  its two limits and its per-engagement scope (`L266`-`L294`), the mutation candidates H5-11 to H5-16 (`L295`-`L330`), and the
  `result_summary` closed-vocabulary rule (`L316`-`L330`).
* Plan section 7 (H6, `L1229`-`L1266`) and section 11 (risks, `L1372`-`L1408`); section 14, items 3, 5, 12, 17 to 23, 26, 30, 36,
  37 and 39 to 45 (`L1431`-`L1579`).
* Design D69-1 and D69-1b (`L100`-`L114`), D69-4 (`L364`-`L376`), section 5 with D69-5a, 5b, 5c and 5d (`L377`-`L442`), D69-7
  (`L509`-`L529`), section 9 with D69-9 and its 2026-11-04 superseded note (`L590`-`L627`), and the falsifiable acceptance of
  section 11 (`L652`-`L686`).
* H1 report item 6 (`complete_task`'s preconditions and whether anything requeues, `L180`-`L233`) and item 8 (what today's
  `complete_task` callers write, `L269`-`L302`).
* Code read for this document: `control_plane/scheduler/lock.py:26`, the docstring of `scripts/run_scheduler.py`,
  `control_plane/api/function_api.py:527-663` (`propose_action` and its idempotency key), `db/migrations/versions/0001_core_schema.py:166,189`,
  `db/migrations/versions/0019_scheduler.py`, `tests/test_migrations_roundtrip.py`, and the `harness/` package as of `53138ab`.

## 1. The facts

### 1.1 What the plan lists for H5

Pieces, quoted from `L1126`-`L1145` [R]:

1. "An operator command analogous to `scripts/run_scheduler.py` (`--interval`, `--once`, `SIGINT`/`SIGTERM` finish the
   current task and exit 0), with its **own advisory lock key** ... and distinct exit codes in the style of the scheduler's
   (lock held, DB lost, audit failed, Docker unreachable, unexpected, cap reached, no-progress stop)".
2. "**Its own enrolment list** (P-3), read each tick; an engagement not in it is never touched."
3. The per-tick, per-engagement serial sequence: "read pause/kill state; H4's task source; for each task `claim_task`, build
   observations (H3), the Worker call, the allowlist refusal (H2), `load_effective_policy` immediately before `propose_action`
   through **one loader function** (D69-4 (A)), `propose_action` with `task_id` and an idempotency key **derived from the task
   and the attempt**, then `complete_task` on every path the loop controls."
4. The closed fault list (design D69-5a): "a returned outcome is recorded and the task completed; a Supervisor or Worker
   `None`/refusal/failed call (a classifier stop included) is recorded with its kind, **no re-ask**; anything else stops the
   service".
5. The bound (D69-5d (a)+(b)): "a hard cap on rounds and on model calls per run, and a stop after **N consecutive rounds that each
   produced zero tasks with every model call failing**; both values are written down before the first run and are not adjusted
   from data."
6. A start-up banner: "database, migration head, the effective values of the two switches, the action set, the engagements, the
   role models and CLI version, and the digests of the Supervisor and Worker prompts and schema descriptions".
7. "Task claimed and never completed (D69-5c): accepted and reported; no requeue is built here."

**H5b (only if P-3 (a))** (`L1147`): "The enrolment table, its writer role and operator CLI, a migration with a round-trip test ...
and a grant test. It is its own commit and its own acceptance." P-3 (a) is chosen (`L152`), so H5b exists.

Chosen lines that add to the pieces, quoted [decided]:
* The start-up check (`L266`-`L278`): "Before claiming anything, the loop lists the engagement's tasks read-only through
  `query_state(conn, engagement_id=..., task_status=("queued", "claimed", "running"))` ... **any** row returned is foreign: the
  loop **refuses to start**, with its own exit code distinct from the claim-time one, claims nothing, proposes nothing, and reports
  the rows for a person." Its scope (`L288`): the check runs "before the first claim **for each engagement**, including one
  enrolled later, not once at process start."
* The foreign-task backstop (`L241`-`L246`): when the loop claims a task whose id is not in this process's own in-memory set it
  "**stops immediately**, with its own exit code distinct from the others", does not propose, does not complete, and reports it.
* `result_summary` (`L316`-`L324`): "assembled from a fixed set of tokens (the decision, kernel-generated reason codes, and ids ...)
  and never from tool output, a model's words, or `ActionOutcome`'s free-text fields".
* The Supervisor's input (`L216`-`L228`): the round reads the evidence window once; the task source and the Worker's observation
  set use that one snapshot; "the harness proposes only for tasks it itself created in the current run"; "v0's Supervisor input
  carries no `findings` at all."
* Design D69-7 (A), `L529`: "chosen: D69-7 (A), serial." Design D69-9 (A), `L625`: "describe the kill's limits as they are."

### 1.2 The tests the plan lists

`L1151`-`L1165` [R]: scripted Supervisor and Worker, "the pipeline with a fake sandbox and the test database", and one test per
item of design section 11 that the loop owns: 1 (every proposal carries a live task), 2 (policy via the loader; an AST test), 5 (a
fault outside the list stops the service; an injected exception from `propose_action` leaves the 5.120 state), 6 (a stopped call is one
call and one recorded failure), 7 (after `engage_kill_switch` no new round or task), 8 (`kill -9` between claim and complete, then
restart, leaves no second task or proposal), 9 (a second instance exits at once with its own code); plus the caps, the
consecutive-zero-task stop, the banner fields, the signal handling, and a structure test as in `tests/test_task_less_callers.py`.

### 1.3 The mutations the plan lists: seventeen, with their sources

| id | what it breaks | named test (as written) | plan line |
|---|---|---|---|
| H5-1 | `propose_action` called with `task_id=None` or another engagement's task | test 1 | `L1168` |
| H5-2 | the policy passed to `propose_action` is stale or hand-built | the AST test (2) | `L1169` |
| H5-3 | an exception from `propose_action` is swallowed and the loop continues | test 5 | `L1170` |
| H5-4 | a stopped Worker or Supervisor call is asked again | test 6 | `L1171` |
| H5-5 | the pause/kill check removed | test 7 | `L1172` |
| H5-6 | the idempotency key not derived from task and attempt (a fresh key per call) | test 8 | `L1173` |
| H5-7 | the lock key shared with the scheduler, or the second instance does not exit | test 9 | `L1174` |
| H5-8 | the round/call cap removed | the cap test | `L1175` |
| H5-9 | the consecutive-zero-task stop removed | its test | `L1175` |
| H5-10 | a task claimed and left uncompleted on a refusal path | the completion test | `L1176` |
| H5-11 | `result_summary` built with a free-text field of `ActionOutcome` folded in | a closed-vocabulary test | `L325` |
| H5-12 | the start-up check is removed altogether | seed one queued task; the loop must refuse to start | `L295` |
| H5-13 | the claim-time backstop removed while the start-up check stays | a task appears between check and claim | `L295` |
| H5-14 | the start-up check runs **after** the first claim | no `tasks` row written when the loop refuses to start | `L295` |
| H5-15 | the start-up check runs once at process start, not per engagement | a later-enrolled engagement holding a queued task | `L305` |
| H5-16 | `candidates_from_registry` returns the registry's scope objects without the allowlist filter | a test against the real registry in the test database | `L310` |
| (moved) | after a restart the harness proposes again for a task it finds already created by an earlier run | a restart test; no second proposal for that `task_id` | `L1223` |

The plan names the moved candidate without a number: "Name provisional (the catalogue's H4-7 is a different entry)". **[proposal]** this
document numbers it **H5-17**. No H5 mutation exists in `scripts/mutations_d69.py` today [R: the catalogue holds H2-1 to H2-8b, H3-a to
H3-p and H4-1 to H4-18, forty-four entries].

### 1.4 The stop codes the plan implies

Named in the plan, `L1127`-`L1130` [R]: lock held, DB lost, audit failed, Docker unreachable, unexpected, cap reached, no-progress
stop (seven). Added by chosen lines: the claim-time foreign-task stop and the start-up refusal (two, each "its own exit code distinct"), and
the exit-0 stop by signal or `--once` (`L1127`-`L1128`). A fault outside the closed list stops the service "with a distinct exit code"
(design `L408`-`L413`, the table), which the plan folds into "unexpected". **No numbers, no meanings beyond these names, and no code
list exist anywhere**; the plan says "in the style of the scheduler's". The scheduler's own table is [R: docstring of `scripts/run_scheduler.py`]:

```
Exit status: 0 stopped by signal / ``--once`` done, 1 unexpected error, 2 another instance holds the
lock, 3 audit record could not be written, 4 database connection lost, 5 Docker unreachable,
6 lock lost, 7 a dispatched proposal was still ``approved`` afterwards.
```

### 1.5 What H2, H3 and H4 already provide [R: the `harness/` package at `53138ab`]

| module | what it gives H5 | tests |
|---|---|---|
| `harness/action_allowlist.py` (H2, plus two lines each from H4 and the H4 follow-up) | `ALLOWED_ACTIONS`; `candidates_from_scope_objects`; `check_task_action` and `check_proposal_action`; `RefusalCounter` (side and closed reason); four reason codes | `tests/test_harness_action_allowlist.py`, 9 mutations (H2) |
| `harness/registry_view.py` (H2) | `candidates_from_registry(conn)` | **untested** (plan section 14 item 22) |
| `harness/observations.py` (H3) | `read_evidence_window(conn, *, limit)` (limit required); `observation_from_evidence`; `observations_from_window` | `tests/test_harness_observations.py`, `tests/test_harness_observations_db.py`, 16 mutations (H3) |
| `harness/round_snapshot.py` (H4) | `take_round_snapshot(conn, *, limit)`; `RoundSnapshot.supervisor_evidence()` and `.observations_for_task()`; `build_state_summary` | `tests/test_harness_task_source.py` |
| `harness/task_source.py` (H4) | `plan_and_create_tasks` (one plan, three filters, one transaction per task); `RunTaskLedger`; `PlanOutcome` with a closed failure vocabulary | `tests/test_harness_task_source.py`, `tests/test_harness_task_source_db.py`, 19 mutations (H4) |

### 1.6 What does not exist yet [R: nothing of it is in `harness/`]

The loop and its operator command; the enrolment list, its read interface and its table; the start-up check and the claim-time
backstop; any call to `claim_task`, `complete_task` or `propose_action`; the one policy-loader function; the idempotency-key derivation;
the advisory lock; the exit-code table; the banner; signal handling; the round and call bounds; the pause/kill read; the builder of
`result_summary`; the Worker step (observations in, `check_proposal_action`, a recorded refusal); and every H5 mutation.

## 2. The split

### 2.1 What the stages should be separated by [D]

Three things differ between the pieces: whether a test needs the database, whether it needs a migration (the heaviest and least
reversible step: plan section 11, risk 1, `L1374`-`L1376`), and whether it needs a process boundary (a second instance, `kill -9`).
The plan already separates the migration: H5b is "its own commit and its own acceptance" (`L1147`).

### 2.2 Two ways to cut a and c

**Option 1 (as asked).** H5a: the components that need no database. H5b: the enrolment table and its migration, grants and CLI.
H5c: the loop, assembled, with the test database and a fake sandbox.

**Option 2 [proposal, recommended].** The same three stages, with the boundary between a and c moved: H5a also contains the loop's
**control flow**, written against narrow ports (a small protocol with `list_live_tasks`, `claim`, `load_policy`, `propose`, `complete`,
`engagement_state`, `enrolled_engagements`, each returning plain values), tested with recording fakes. H5c then writes the real adapters of
those ports over `engagement_scope` and the function API, and tests the **real states**: the tasks table, the 5.120 state, the lock,
the signal, the restart.

*Why [D]:* the bugs the H5-12 to H5-15 and H5-10 family describe are about the **order and completeness of calls** (the check before the first
claim; a `complete` on every path); a fake that records its calls catches them in milliseconds and without a database, which makes H5c's
tests about what only the database can show. *Cost [D]:* a fake can drift from the real function (for example `claim_task` writes the
`claimed` row before the loop sees an id, plan `L254`-`L259`); so H5c must run the same scenario list against the real adapters, and the
mutations that concern a write (H5-14's "no `tasks` row written") are assigned to H5c. *If Option 1 is chosen* the control-flow loop, the
Worker step and the signal wrapper move from H5a to H5c, and H5-2, H5-10 and H5-12 to H5-15 move with them; nothing else in this document
changes.

### 2.3 H5a: the components and the loop's control flow (no database, no Docker, no model)

* **Goal.** Everything the loop decides, with nothing it reads or writes.
* **Pieces [proposal] (names provisional).**
  (a1) the stop-code table and the mapping from outcome to code; (a2) the `result_summary` builder and a validator for the closed
  vocabulary; (a3) the idempotency-key derivation; (a4) the bounds as a small state machine (round cap, call cap, consecutive zero-task
  rounds with every call failing); (a5) the start-up decision (any live row means refuse; a full page counts as found, never as "that was
  all", plan `L281`-`L286`) and the claim-time ownership check against `RunTaskLedger`; (a6) the banner as a pure formatter of a dict of facts,
  with its required field list; (a7) the enrolment read interface (a protocol) and an in-memory fake; (a8) the Worker step: observations
  in, one Worker call, `check_proposal_action`, a recorded refusal, no re-ask; (a9) the signal wrapper (a stop event checked between tasks,
  as the scheduler's is checked at the top of its tick, plan `L1212`-`L1217`); (a10) the loop's control flow against the ports.
* **Does not.** Touch the database, start Docker, call a model, add an operator command, or write a migration.
* **Tests.** Scripted Supervisor and Worker; recording fakes. Design tests 2, 5 (control-flow half), 6, 7 (control-flow half), 8 (control-flow half)
  and the caps, the zero-task stop, the banner fields, the signal handling, and the structure test as in `tests/test_task_less_callers.py`.
* **Mutations assigned.** H5-2, H5-4 (the Worker half; the Supervisor half is already H4-2 and H4-14), H5-6 (the derivation), H5-8, H5-9, H5-10,
  H5-11, H5-12, H5-13, H5-14 (the order), H5-15, plus the new ones in 2.7 below that belong to a1 to a10.
* **Authorization needed.** New files under `harness/` and `tests/`, and appended entries in `scripts/mutations_d69.py`. No database, no Docker,
  no new role, no migration. [R: the shared `conftest.py` starts a database-dependent fixture for every test, so a running Postgres is still needed to run the
  tests; it is not used by them.]
* **Stop conditions.** An H5a mutation not caught by its named test (except "unexpressible"); a need to change an existing file other than
  `scripts/mutations_d69.py`; a full-suite failure or an image-error split other than 2/16/4/2; an AST test that cannot be written without
  adding a parameter to production code.
* **Depends on.** H2, H3 and H4 (done).
* **Size [D].** Basis: H4 added 249 lines of code, 896 lines of tests and 105 lines of mutations (19 entries, about 5.5 lines each) for four
  pieces. H5a has ten pieces, so by that ratio roughly 500 to 800 lines of code and 1,500 to 2,500 lines of tests, 20 to 30 mutation entries. Not measured.

### 2.4 H5b: the enrolment table, its writer role, the operator CLI

* **Goal.** The harness's own enrolment list [decided: design `L114`, "chosen: D69-1 (A), a separate process; D69-1b, the harness's own enrolment list";
  plan `L152`, "P-3 (a): the enrolment table with its own operator CLI"].
* **Pieces [proposal].** A migration (the next revision after `0030_goal_fit_report_views.py`), a global table with row-level security in the pattern of
  `scheduler_enrollment` [R: `db/migrations/versions/0019_scheduler.py`: global, "no engagement GUC", a unique index on the live row, FORCE ROW LEVEL SECURITY,
  an admin policy for all and a reader policy for SELECT, a guard trigger on UPDATE]; a writer role; a read grant for the role the loop connects as (P-1 (a): `cyberorch_app`,
  plan `L88`); the operator CLI after `scripts/manage_scheduler_enrollment.py`; the DB-backed implementation of H5a's read interface.
* **Does not.** Start the loop, claim a task, call a model.
* **Tests.** The round-trip test and the grant test (plan `L1147`): `tests/test_migrations_roundtrip.py` and `tests/test_migrations_rls_writes.py` exist for this.
  [R: `tests/test_migrations_roundtrip.py` names `scheduler_enrollment` at lines 27, 131, 216, 228, 272 and 756, so a new table is likely to need edits to that existing file; the
  authorization must name it.]
* **Mutations assigned.** None of H5-1 to H5-17 belongs here. **[proposal]** new ones in 2.7: the guard trigger removed; the reader able to write; the table not in the round-trip set.
* **Authorization needed.** A migration (a new revision), a new database role and its grants, edits to `tests/test_migrations_roundtrip.py` and probably
  `tests/test_migrations_rls_writes.py` and `control_plane/state/db.py` (the scheduler's roles are wired there: `control_plane/state/db.py` names `scheduler_enrollment`),
  the test database, and an operator step to create the role outside the tests. No Docker.
* **Stop conditions.** A migration that does not round-trip; a grant that lets the reader write; a change needed to an existing migration; a full-suite failure.
* **Depends on.** The owner's confirmation of P-1 (a) for the new table (the choice "holds only as long as H1's own reading confirms the same", plan `L88`-`L97`), and nothing
  in the code of H5a or H5c: "H5 is written against a read interface for the enrolment list, with an in-memory fake used by every H5 test that is not H5b itself" (plan `L152`-`L156`).
* **Size [D].** Basis: `0019_scheduler.py` and its CLI and tests. Roughly 100 to 150 lines of migration, 150 to 250 of CLI, 400 to 600 of tests, 5 to 8 mutations. Not measured.

### 2.5 H5c: the real adapters, the operator command and the process-level tests

* **Goal.** The loop over the real pipeline and the test database, with a fake sandbox.
* **Pieces [proposal].** The real ports over `engagement_scope` and the function API; the one policy-loader function (design D69-4 (A), `L375`: "one loader function pinned by an AST test");
  the operator command; the advisory lock on its own key and its watchdog; the exit codes wired to the a1 table; the banner printed with real values; the pause/kill read; the
  start-up check against `query_state`; the signal wiring.
* **Does not.** Call a model, start a real container, publish a layer, set a switch, requeue tasks, run more than one task at a time, stop a container, start the web console.
* **Tests.** Design tests 1, 5 (the 5.120 state), 7 (counting `propose_action` calls after `engage_kill_switch`), 8 (`kill -9` between claim and complete, then restart; a second instance
  exits at once), 9; the same scenario list as H5a run against the real adapters; and the real-registry test of `candidates_from_registry` (H5-16).
* **Mutations assigned.** H5-1, H5-3, H5-5, H5-7, H5-16, H5-17 (the moved restart candidate), plus the real-state re-runs and wiring mutations in 2.7.
* **Authorization needed.** The test database; a fake sandbox passed explicitly, because `propose_action` builds a real `DockerSandbox` when `sandbox=None` [R: plan `L1203`-`L1211`,
  `control_plane/orchestrator/dispatch.py:844-845`]; subprocesses of the command for the `kill -9` and second-instance tests; edits only inside the harness files, new test files and
  `scripts/mutations_d69.py`. No Docker for the tests, no model, no nmap.
* **Stop conditions.** An H5c mutation not caught; a test that needs a model or a real container; the pipeline needing a change to pass a test; a full-suite failure; an image-error split other than 2/16/4/2.
* **Depends on.** H5a done. H5b done **before the loop is run outside a test** (plan `L152`-`L156`), not before H5c's tests.
* **Size [D].** Basis as for H5a. Roughly 300 to 600 lines of code, 1,200 to 2,000 lines of tests, 8 to 12 mutations. Not measured.

### 2.6 Assignment of the seventeen, one stage each

```
H5-1  H5c    needs the real action_proposals rows (design test 1)
H5-2  H5a    an AST test over the loop module; needs no database
H5-3  H5c    the 5.120 state is real; H5a holds a control-flow companion test (not required)
H5-4  H5a    the Worker half (the Supervisor half is H4-2 and H4-14)
H5-5  H5c    design test 7 counts propose_action calls after engage_kill_switch, a database state
H5-6  H5a    the derivation; H5c adds the wiring mutation H5-26 (below)
H5-7  H5c    an advisory lock is a database object
H5-8  H5a    the bounds state machine; H5-20 below is the wiring
H5-9  H5a    the same
H5-10 H5a    a complete on every path is control flow; H5-25 below is the real-state re-run in H5c
H5-11 H5a    the builder and its validator
H5-12 H5a    control flow with a fake that records order
H5-13 H5a    the same
H5-14 H5a    the order of check and claim; H5-25 adds "no tasks row written" in H5c
H5-15 H5a    the per-engagement scope, with an enrolment fake that adds an engagement later
H5-16 H5c    the real registry in the test database
H5-17 H5c    needs a process restart
```

No mutation is left out. [proposal] H5-16 could move to H5b if the owner wants every test that merely reads the database kept out of the loop's stage; it was kept in H5c because the loop is its only caller.

### 2.7 New mutations [proposal]; ids are proposed numbers, names provisional

```
H5-18  H5a  two different outcomes map to the same exit code                      -> the table test
H5-19  H5a  the key derivation ignores the task id                                -> the derivation test
H5-20  H5a  the loop ignores the bounds' stop                                      -> the cap and zero-task loop tests
H5-21  H5a  the signal wrapper stops in the middle of a task                       -> the signal test
H5-22  H5a  a full page is read as "that was all of them"                          -> the start-up decision test
H5-23  H5a  the result_summary builder accepts a token outside the vocabulary      -> the builder test
H5-24  H5a  the banner omits a required field                                      -> the banner test
H5-25  H5c  the start-up check on the real database writes a row                   -> the "no tasks row written" test
H5-26  H5c  the real adapter passes a key not produced by the derivation           -> the restart/idempotency test
H5-27  H5b  the enrolment table's guard trigger removed                            -> the round-trip or grant test
H5-28  H5b  the reader role is granted write                                       -> the grant test
```

## 3. Questions that cross the stages (all **pending the owner**; each with its options, cost and a [proposal])

### 3.1 The stop codes: numbers and meanings

*Facts.* 1.4 above. *Options:* (A) the scheduler's numbers for the meanings the two share (0 signal or `--once`; 1 unexpected; 2 lock held; 3 audit; 4 DB lost; 5 Docker unreachable;
6 lock lost) and harness-specific codes from 10 up; (B) a fresh table from 0; (C) names only. *Cost:* (A) leaves two overlapping tables, and the scheduler's 7 ("a dispatched proposal was still
`approved`") has no harness meaning, so it is left unused rather than reused; (B) means an operator who runs both reads two tables with different numbers; (C) is not testable as an exit status.
**[proposal] (A):** 10 the start-up check refused; 11 a foreign task was claimed; 12 a fault outside the list, including an exception from `propose_action` (design D69-5b (1), "stop the service and
let a person decide"); 13 the round or call cap was reached; 14 the consecutive-zero-task stop. The table lives in one module (a1) and one test asserts it is injective.

### 3.2 "Consecutive zero tasks" and the empty plan

*Facts.* The rule as written is "N consecutive rounds that each produced zero tasks **with every model call failing**" (plan `L1139`-`L1141`; design `L418`-`L424`). H4's test T15 pins that a Supervisor
that returns `[]` is **not** a planning failure (`outcome.failure is None`); "it is not a decision" (the test's docstring). So a round with an empty plan has zero tasks but a call that succeeded, and
under the written rule it does **not** count towards the stop. A Supervisor that answers `[]` forever is then bounded only by the cap (a). *Options:* (A) keep the rule as written; the cap bounds it;
(B) count rounds with zero tasks whatever the reason (this drops "every model call failing" and stops a legitimately idle engagement); (C) keep (A) and add a second counter, consecutive empty plans,
with its own N. *Cost:* (A) is the least sensitive; (B) changes a chosen line; (C) adds a number that must be registered before the first non-test run. **[proposal] (A) for H5**, because it is what the
chosen line says and the cap bounds it; (C) is offered if the owner does not want an idle loop to run to its cap. The values of the cap and of N are **[N]**, left blank, registered before the first non-test run.

### 3.3 The banner

*Facts.* Plan `L1141`-`L1143` lists the fields in prose. **[proposal]** the field list: the database (host, name, role), the migration head, the effective values of the two switches, the action set (`ALLOWED_ACTIONS`),
the enrolled engagements, the role models and the CLI version, the digests of the Supervisor and Worker prompts and schema descriptions (needed by section 10 / H8), the window `limit`, the caps and N (or "not set"),
and the lock key. Never printed: a credential or the contents of `.env`. *Options for where it goes:* (A) standard output only; (B) standard output and an audit record. *Cost:* (B) needs a new audit event type,
which is a change to `control_plane` and to the audit-coverage test, outside the harness. **[proposal] (A) in v0.** Whether the digests need an audit record for H8 is **[N]** until H8's list is worked.

### 3.4 SIGTERM during an ALLOW dispatch

*Facts.* [R: plan `L1184`-`L1202`, Verification A] "the loop's call to `propose_action` for an ALLOW blocks until that tool run's evidence is committed or the call fails"; [R: plan `L1212`-`L1221`,
Verification H] the scheduler's SIGTERM handling "sets a `threading.Event` that is checked only at the top of its tick loop"; so "'finish the current task' under SIGTERM can take as long as one dispatch's own
duration -- bounded, as H6 already states, by the recorded budget ceiling (ACCEPTANCE 5.24, 1,800 s)", where the bound is [D]. The chosen line says "`SIGINT`/`SIGTERM` finish the current task and exit 0" [decided, plan `L1127`].
*Options:* (A) as chosen; (B) a second signal forces an exit; (C) a bounded wait, then a distinct exit code. *Cost:* (B) and (C) leave a proposal mid-pipeline, which is the 5.120 state ("one proposal at `received`") and cannot
stop the container either [R: design `L596`-`L601`, 5.24]. **[proposal] (A)**, with H6 stating the 1,800 s bound as [D].

### 3.5 The idempotency key

*Facts.* [R: `propose_action` default] `key = idempotency_key or f"idem-{proposal_id}"` (`function_api.py:623`): left unset, **every call gets a fresh key**, which is exactly H5-6. The column is `TEXT NOT NULL`, unique on
`(engagement_id, request_idempotency_key)` (`0001_core_schema.py:166,189`); a key reused "for a different action or target is refused" (`function_api.py:658-663`). The ADR says the key is "derived from task and attempt"
(design `L388`-`L394`). *Options:* (A) readable, `h5:<task_id>:<attempt>`; (B) a hash of the same fields. *Cost:* (A) is greppable and has no length question; (B) hides what the key says. **[proposal] (A)**, `attempt` starting at 1.
Observation [D]: in v0 there is no in-process retry (D69-5b (1): stop and let a person decide), and the start-up check refuses a restart on an engagement with live tasks, so the `attempt` never exceeds 1 and design test 8
passes through the start-up check; the key is defence in depth, and H5-6 and H5-26 pin it so that it stays so if a retry is ever added.

### 3.6 The harness's advisory lock key

*Facts.* [R: `control_plane/scheduler/lock.py:26`] `LOCK_KEY = 0x0D62_5C4E_D000_0001`; a second instance exits at once (design `L677`, test 9). *Options:* (A) a fixed constant of the same shape with the stage number
changed, **`0x0D69_5C4E_D000_0001`**; (B) a hash of a string; (C) one key per engagement. *Cost:* (A) is readable and trivially different from the scheduler's; (B) is opaque; (C) allows two instances on different engagements, which D69-7 (A)
(serial across all engagements, `L529`) forbids. **[proposal] (A).** A test imports the scheduler's constant and asserts inequality (a test may import it; `harness/` itself may not, plan `L144`-`L150`). The value is the owner's to confirm; it is not registered anywhere yet.

### 3.7 Leftover live tasks at start, and H6's recovery text

*Facts.* [decided, plan `L266`-`L278`] the loop refuses to start, reports the rows, and "**H6 must write the recovery down**: a new engagement, or a person clearing or completing the leftover tasks by hand". [R: H1 report item 6, `L180`-`L233`]
`complete_task` has no preconditions, and nothing returns a claimed task to `queued`. [N] no operator tool in this repository completes or clears a task; "by hand" is today a direct call or SQL. *Options:* (A) as chosen: refuse, report, H6 documents the manual
recovery; (B) in addition a read-only listing subcommand for the leftovers; (C) a clearing subcommand that completes them with a closed-vocabulary summary. *Cost:* (B) is small and adds no write path; (C) is a write path outside the chosen lines and
`complete_task` accepts any task. **[proposal] (A) plus (B)**; (C) only if the owner asks, as its own stage. Whether an operator can in practice do the manual recovery with the credentials they hold is **[N]** and belongs in H6's preflight.

### 3.8 Duplicate planning, and how the caps relate

*Facts.* H4 gives the Supervisor empty `tasks` and `decisions` (`build_state_summary` defaults; the laundering path is pending the owner, plan section 11 risk 10, `L1389`-`L1403`, with the gate "before any run that uses a real model"). So each round the Supervisor
may plan the same work again; `create_task` "marks -- never drops -- any in-flight task it overlaps" [R: its docstring] and the pipeline "deduplicates the redundant *execution* downstream". A round yields at most `MAX_TASKS = 8` tasks [R:
`agents/llm/supervisor_base.py:105`]. With R rounds and no call cap, calls are at most R Supervisor calls plus 8R Worker calls, that is, 9R [D]; so a **call cap below 9R binds before the round cap**. *Options:* (A) keep `tasks` and `decisions` empty in H5 (scripted
roles) and rely on the caps; duplicates are visible in the overlap counts (design `L569`); (B) feed the task ledger back once the owner has decided the laundering path (it puts `TaskRecord.goal`, free text, into the trusted header); (C) feed ids and statuses only.
*Cost:* (A) accepts repeated work; (B) is gated; (C) changes what a `TaskRecord` carries. **[proposal] (A) for H5; (B) or (C) after the owner's decision on the laundering path.** The cap values are **[N]**, blank, registered before the first non-test run.

### 3.9 Open points that H5c's own preflight must read [N]

Which function the harness reads pause and kill state with (the scheduler "defers `engagement_paused`, `engagement_killed`", design `L598`-`L600`; the function itself was not read for this document); where `NetworkInUse` is raised and whether `propose_action` surfaces it as an
exception or an outcome (no occurrence in `control_plane/*.py` by `grep -rn NetworkInUse control_plane --include=*.py`; plan risk 6, `L1385`-`L1387`, calls the harness's treatment of it "H5's open point"; as an exception it would stop the service under D69-5a); and the exact
text of the 5.120 state's audit records, which test 5 compares.

## 4. Risks and [N]

* [R] The loop's call to `propose_action` for an ALLOW blocks, so the whole loop is as slow as one dispatch; "the worst-case duration of that block remains **[N]**" (plan `L1193` and `L1203`).
* [R] The harness process itself needs a reachable Docker daemon when the sandbox is not injected (plan `L1203`-`L1211`); the tests inject one.
* [R] A claim cannot be undone: `claim_task` "takes no `task_id` and no creator filter", and nothing returns a task to `queued` (H1 report item 6); the start-up check exists because of it.
* [D] Option 2's fakes can drift from the real functions; H5c's same-scenario run is the control.
* [D] `H5-14` is the mutation that matters most (plan `L295`-`L303`); it is split between the order (H5a) and the real write (H5c) here, and **both** halves must exist or the ordering bug is caught only with a fake.
* [N] How many approvals the scan-type rule will cost in a loop (plan section 11 risk 2); the size of the caps; the window `limit`; the number of leftover tasks a real engagement will have; the size of every stage above.
* [N] Whether H5b's new role and the changes to `control_plane/state/db.py` can be made without touching an existing migration; whether `tests/test_migrations_rls_writes.py` needs edits.

## 5. What this proposal does not do

It authorizes **no implementation** and **no stage**: each of H5a, H5b and H5c, if the owner agrees to any split at all, still needs its own explicit authorization naming what it may touch. It does **not** choose
P-8's numbers: the evidence window's row ceiling and any per-row character ceiling are still the owner's, they are needed only before the first non-test run, and the window size is a required parameter of
`take_round_snapshot` and `read_evidence_window`, so nothing here picks one. It does not choose the caps, N, a lock-key value or a stop-code table; each is a **[proposal]** above and **pending the owner**. It
does not change the plan: section 6 of the plan, its mutation list and its section 14 stand as written, and this file is cited from section 14 item 45 only if the owner asks.
