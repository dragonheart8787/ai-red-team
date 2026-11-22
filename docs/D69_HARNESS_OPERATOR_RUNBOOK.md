# D69 harness operator runbook (H6)

Written 2026-11-18 against commit `06f6a96b10cdb23527e62b816a1855f5627a9218` (H5 complete as code).
It is for **laboratory engagements only** and for the scripted roles the tests use. Nothing in it
makes the harness fit for a real engagement (section 1).

How to read the tags. Every fact names where it comes from.

* `item NN` is an item of `docs/D69_IMPLEMENTATION_PLAN.md`; `file:line` is a line of that file at
  the commit above. **[R]** read there. **[run]** shown by a command run for this runbook (item
  102 says which). **[D]** my own derivation from what I read, not shown by running.
  **[N]** not read.
* A step that was **not executed** says so: "Not run; H7 verifies (未執行,H7 驗證)". Every step that
  writes (register, withdraw, run, recovery, the reconciler) was of this kind when this runbook was
  written, when only `--help`, `manage_harness_enrolment.py list` and `run_harness.py residue` had
  been run. H7 ran the steps a section marks "Run in H7 (已執行,H7)", with the values it observed.
* Where the repository has no operator command for something, this runbook says so and lists it as
  a gap. It invents no command.

## 1. Scope and status

1. **Laboratory only.** Registration takes one purpose, `harness_lab`; the database accepts no
   other and the loop's reader returns only rows with it [R `harness/enrolment_db.py:30-36`, item
   82]. The purpose is the operator's statement, not a control: nothing in the system tells a
   laboratory engagement from a real one [R item 82].
2. **There is no factory of real roles and no real sandbox.** `--role-factory` takes the dotted path
   of a function that returns `supervisor`, `worker`, `reviewer` and `sandbox`; the script builds no
   model role and no real sandbox [R `scripts/run_harness.py:16-19`, `--help`]. The only factory in
   the repository is the tests' scripted one, `tests/harness_h5c2_roles.py` (a test fixture, not an
   operator tool) [R, D].
3. **Not for any real engagement.** The gates below are pending the owner; none is decided. Each is
   re-decided before the first real engagement.
   * Item 87: (a) the shared role: `cyberorch_app` can change the enrolment table (item 61); (b) no
     audit record of an enrolment or a withdrawal (item 86 b); (c) the actor is unverified (86 a);
     (d) the purpose is only the operator's statement (item 82); (e) an empty `withdrawn_by` is
     possible at the database (86 c).
   * Item 98 (a): the factory's Worker must be a `BaseWorker` subclass with a test pinning the
     system prompt it sends to be `WORKER_SYSTEM_PROMPT` (the shape of
     `tests/test_worker_boundary.py:387`), so that the banner's Worker digest is true (item 95 a).
   * Item 98 (b): the numbers registered before the first run that is not a test are the caps, N,
     the window limit, the live-task limit (`LIVE_TASK_LIMIT`, 200, is only the adapter's constructor
     default, `harness/loop_adapter.py:65`; the script requires the number) and P-8's numbers (item
     90). The banner's values are those of the start (item 96 a).
   * Item 101 (b): `--role-factory` accepts any importable function and checks nothing about what it
     returns; before a real-role factory exists the script must refuse what the owner has not
     approved (the mechanism is not designed).
   * Design D69-9 (A), chosen: the kill switch does not stop a running container and a model call
     that has started finishes (`docs/D69_PRODUCTION_HARNESS_DESIGN.md:602-610, 626`).

## 2. Before each run

### 2.1 List the enrolment and compare it with the banner (item 88)

```
python scripts/manage_harness_enrolment.py list
```

Shows every registration, live and withdrawn, oldest first, one line each: `#id engagement
purpose=… registered by … at …  [live]` or `[withdrawn by … at …]` [R `scripts/manage_harness_enrolment.py:127-138`].
Only `[live]` rows count. On the test database it printed `no registrations` and exited 0 [run].

Then read the `engagements:` line of the banner when the run starts (section 3.3). It is the list the
loop will visit, in that order (item 97) [R]. The reader's order is registration time, then id
[R `harness/enrolment_db.py:32-36`]. If the banner's list is not the live rows you expected,
**stop the run at once** (section 5.1).

The banner is **not a gate**: it is printed and the loop starts immediately; there is no pause and
no confirmation after it [R `scripts/run_harness.py:138-152`]. A round may already be under way when
you read it.

### 2.2 What the table's actor is (items 86 a, b)

The actor in the table is what the operator typed with `--actor`. It is checked only for its form
(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`) and proves nothing about who typed it [R item 86 a,
`scripts/manage_harness_enrolment.py:54-55`]. The CLI writes **no audit record** of an enrolment or
a withdrawal; the table records who (as typed) and when [R item 86 b, `--help`]. Do not treat the
table as evidence of who enrolled what.

### 2.3 Register an engagement

```
python scripts/manage_harness_enrolment.py register --engagement ENG-… --purpose harness_lab \
    --actor <your name> [--yes]
```

Argument names checked against `register --help` [run]: `--engagement`, `--purpose`, `--actor`
(all required) and `--yes`. Without `--yes` it prints what will happen and waits for you to type
`REGISTER` on a terminal; with no terminal it refuses (exit 2). `--yes` means a person has already
decided [R `--help`, `:80-93`, `:157-169`]. Exit status: 0 done, 1 refused, 2 not confirmed or an
argument-parser error [R `--help`]. Refusals the database gives: `no such engagement`, `already
registered` [R `:99-112`]; a purpose other than `harness_lab` is refused by the CLI itself, before
the database (`refused: --purpose is one of harness_lab`, exit 1; the database's `purpose refused`
is only the fallback behind it) [R `:144-154`]. The engagement must already exist. Run in H7
(已執行,H7; `tests/test_harness_h7_lab.py`, S1): with no terminal and no `--yes` it printed
`refusing: no terminal to confirm on …` and exited 2, writing nothing; with `--yes` it exited 0 and
printed `registered <engagement> (harness_lab)`; a second registration exited 1 with `refused:
already registered`; an engagement that does not exist exited 1 with `refused: no such engagement`;
`--purpose production` exited 1 with the CLI's own refusal.

### 2.4 Withdraw an engagement

```
python scripts/manage_harness_enrolment.py withdraw --engagement ENG-… --actor <your name> [--yes]
```

Arguments checked against `withdraw --help` [run]. It asks for `WITHDRAW`; a withdrawal of an
engagement that is not live is refused (`not currently registered`) [R `:115-121`, `:172-183`]. The
confirmation text says "The loop will not visit it again; tasks it already created stay as they
are" [R `:174`]. That is true **from the next round**; it does not stop the round in progress
(section 5.2). Run in H7 (已執行,H7; S2): `--yes` withdrew it (exit 0, `withdrawn <engagement>`),
`list` then showed `[withdrawn by <actor> at <time>]`, a second withdrawal exited 1 with `refused:
not currently registered`, and with no terminal and no `--yes` it exited 2 and left the
registration live.

### 2.5 Look at what a previous run left

```
python scripts/run_harness.py residue --live-task-limit N
```

Any live task on an enrolled engagement makes the next start refuse with exit 10 (section 4). Read
section 6 first.

### 2.6 Environment

The scripts read `DATABASE_URL` and the other settings from the environment or `.env`
(`load_dotenv()` is called in both) [R `scripts/run_harness.py:169`]. The harness connects as
`cyberorch_app` [R `harness/lock.py:12-14`]. The database must be reachable before `run`.

## 3. Start

### 3.1 The command

```
python scripts/run_harness.py run \
    --role-factory MODULE:FUNCTION --objective TEXT \
    --window-limit N --max-rounds N --max-model-calls N \
    --no-progress-limit N --live-task-limit N [--once] [--lock-watchdog-interval S]
```

Names checked against `run --help` [run]. Every bound is **required and has no default** and must be
a positive integer: a missing or bad one is an argument-parser error before the lock is taken
[R `--help`, item 90, item 98]. The numbers are the owner's and are written down before a run that
is not a test (item 98 b); this runbook gives none.

| argument | meaning | note |
|---|---|---|
| `--role-factory` | `module:function` giving the roles | only the tests' scripted factory exists (section 1). Only a factory in `APPROVED_ROLE_FACTORIES` (`scripts/run_harness.py`) is accepted; any other is refused with exit 10 and is not imported (item 131) |
| `--objective` | the objective the Supervisor is shown | free text |
| `--window-limit` | the evidence window (rows) the snapshot reads | P-8's number (item 90) |
| `--max-rounds` | round cap | reaching it is exit 13 |
| `--max-model-calls` | cap on Supervisor, Worker and `propose` calls together | reaching it is exit 13 [R `harness/loop.py:35-38`] |
| `--no-progress-limit` | rounds in a row without a proposal reaching `propose` | reaching it is exit 14 |
| `--live-task-limit` | most live tasks one engagement may hold before `live_tasks` refuses to answer | decides exit 12 against 10 when exceeded (item 96 c); **not on the banner** |
| `--once` | one round, then stop (exit 0) | `harness/loop.py:171-172` |
| `--lock-watchdog-interval` | seconds between looks at the lock, default 2.0 | not a cap |

It does not restart itself or reconnect [R `--help`]. Run in H7 (已執行,H7; S3, S4, S5, S7) with the
scripted roles: `run --once` on two enrolled engagements exited 0, standard output was the eleven
field lines in the order of the table below, and the last line of standard error was
`harness stopped (exit 0): reason=signal_or_once …`.

### 3.2 What happens, in order

[R `scripts/run_harness.py:113-157`] (1) take the harness lock (exit 2 if another instance holds it,
exit 4 if the database cannot be reached); (2) call the role factory (exit 1 if it raises; the
exception text is not printed); (3) read the enrolment **once**; (4) collect the banner's facts
(exit 10 if they cannot be stated); (5) print the banner to standard output; (6) install the
SIGINT and SIGTERM handlers; (7) start the lock watchdog; (8) run the loop; (9) print one line to
standard error: `harness stopped (exit N): reason=… rounds=… counters=…`.

A signal received between process start and step 6 is handled by the default handler and ends the
process; no task has been claimed at that point and the lock is released by the end of the session
[R item 96 g].

### 3.3 The banner: eleven fields, one line each, in this order

[R `harness/banner.py:5-29, 38-41`; sources `harness/banner_facts.py`]. The banner is a **start-up
snapshot** (item 96 a): its values do not change if policy changes during the run.

| field | meaning | where it comes from |
|---|---|---|
| `database` | `host=… name=… role=…`; never the password | `DATABASE_URL` parts, `banner_facts.py:73-77` |
| `migration_head` | the migration the database is at | `alembic_version`, `:60-65` |
| `switches` | `task_relation_enforce`, `goal_fit_enforce` | the effective policy of the enrolled engagements, `:80-91`; no engagement enrolled, or engagements that disagree, is no banner and exit 10 |
| `action_set` | `network.scan, network.recon` | `ALLOWED_ACTIONS`, `harness/action_allowlist.py:49` |
| `engagements` | the engagements the loop visits, in order | the single read of step (3), `run_harness.py:127` |
| `role_models` | `model` of Supervisor, Worker, reviewer; `(not set)` if none | `:125-126` |
| `cli_version` | the project version | `pyproject.toml`, `:94-103` |
| `prompt_digests` | SHA-256 of the Supervisor prompt with its plan schema, and of the Worker prompt with its proposal schema | `:106-122` |
| `window_limit` | the argument | |
| `caps` | `max_rounds`, `max_model_calls`, `no_progress_limit` | the arguments |
| `lock_key` | `0x0D69_5C4E_D000_0001` | `harness/lock.py:39` |

Cautions. The Worker digest is made over the module constant `WORKER_SYSTEM_PROMPT`; that is the
prompt actually sent only for the repo's headless adapter, and nothing guarantees it for a Worker a
factory supplies (item 95 a). `live_task_limit` is not on the banner (item 96 c).

### 3.4 A new enrolment needs a restart (item 97)

The loop visits the banner's engagements that are still enrolled. An engagement enrolled after the
start is never visited; you see it only by restarting and reading the banner [R item 97,
`harness/frozen_enrolment.py`].

### 3.5 One instance at a time

The lock is a Postgres session advisory lock on its own connection; a second instance exits with 2
before it reads anything. It guards against an accident and is not an authorization mechanism
[R `harness/lock.py:1-25`, item 96 f].

## 4. Exit codes

The exit status is the loop's reason, except that a lost lock is 6 [R `scripts/run_harness.py:152`].
"Cleans up" means the loop completes, as `not_run`, the tasks it **created and never claimed**
(`harness/exit_codes.py:86-112`, `harness/loop.py:286-297`); a task claimed and in flight finishes
through its own path first.

| code | meaning | cleans up | what the operator does next |
|---|---|---|---|
| 0 | stopped by SIGINT/SIGTERM, or `--once` finished a round [R `loop.py:171-179`] | yes | nothing; run `residue` to confirm it is empty |
| 1 | the role factory raised (stderr: `refused: the role factory failed (<ExceptionName>)`) [R `run_harness.py:121-125`]; also any exception nothing caught (a traceback) [D] | no (nothing was started, or unknown) | after a traceback, run `residue` before anything else |
| 2 | two meanings: another instance holds the lock (stderr: `refused: another instance holds the harness lock`) [R `:117-119`], **or** an argument-parser error (usage text) [R `--help`; the entry tests assert `SystemExit 2`] | no (nothing read) | read stderr to tell which; for the lock, find the other instance |
| 3, 5 | named in `exit_codes.py`; **no code in `harness/` or `scripts/run_harness.py` returns them** (searched with grep) [D: absence in a search is not shown] | — | a 3 or 5 is probably not this script's |
| 4 | the database cannot be reached when the lock is asked for (stderr: `refused: the database cannot be reached (<ExceptionName>)`); the driver text is not printed [R `:111-116`] | no (nothing read) | bring the database up. A database lost **during** a run is 6 (the lock's session dies with it) or 12, not 4 [D, `lock.py:92-107`, `loop.py:334-335`] |
| 6 | the lock was lost; no port is called again, nothing is written after the loss; a call already in flight cannot be interrupted [R `lock.py:15-21`, `run_harness.py:152`] | no | claimed task stays claimed, the rest queued: `residue`, then section 6.4; find why the session was lost |
| 7 | reserved; a 7 is not ours [R `exit_codes.py:16, 52`] | — | |
| 10 | two causes. (a) The banner's facts cannot be stated: stderr `refused: …` (no engagement enrolled; engagements disagree on a switch; no project version) and **nothing started** [R `run_harness.py:131-137`]. (b) The start-up check found a live (queued, claimed, running) task on an engagement at its first visit: no `refused:` line, final line `reason=startup_check_refused` [R `loop.py:197-202`]. Also (item 131): only a factory in `APPROVED_ROLE_FACTORIES` is accepted; any other is refused with exit 10 (stderr `refused: the role factory is not an approved one`), before the lock is taken and without being imported | yes (a controlled stop) | (a) fix the enrolment or the policy; (b) `residue`, section 6.4 |
| 11 | a task that is not the loop's own was claimed [R `loop.py:239-240`] | no | the foreign task is now `claimed` by the Worker's agent id and is not completed; `residue`; find who else creates tasks on that engagement |
| 12 | a fault outside the closed list: an exception from `propose_action`, a key conflict, more live tasks than `--live-task-limit`, any exception of a port [R `loop.py:268-269, 334-335`, item 96 c] | no | one claimed task and the rest queued, and possibly a proposal left at `received` (section 6.2); `residue`, section 6.4 |
| 13 | the round cap or the model-call cap was reached [R `loop.py:165-166, 209-210, 248-250, 261-263`] | yes | nothing unless the numbers are wrong; a task claimed when the call cap hit is completed `not_run` |
| 14 | `--no-progress-limit` rounds in a row without a proposal reaching `propose` (a DENY counts as one) [R `loop.py:31-33`, item 60] | yes | look at why no proposal is made (the Supervisor plans nothing, the engagement is skipped) |

## 5. Stopping

### 5.1 SIGINT and SIGTERM

The handler only sets a flag. The loop reads it at safe points: before a round, between
engagements and before a claim, and **not** between a task's `work`, `propose` and `complete`. A
signal in the middle of a task is seen after that task has been completed with the pipeline's
answer; then the tasks the loop created and never claimed are completed as `not_run`, and the
process exits 0 [R `harness/signals.py:1-12`, `harness/loop.py:40-52`; tested by
`tests/test_harness_h5c2_signal.py`: the in-flight task ends `DENY`, two others `not_run`].

How long a stop takes is the length of the call in flight (a model call or a container run); the
harness sets no timer of its own and cannot interrupt a call in flight [D, `lock.py:20-21`,
design:602-610]. A second signal only sets the same flag [D]. `kill -9` is not a stop: it leaves
what a fault leaves (section 6), and the lock is released when the session ends.

### 5.2 A withdrawal is not an emergency stop (items 96 b, 101 a)

An engagement withdrawn during a round has that round's processing completed, **including
proposals for it**: the loop read its list before the round and the later steps look only at
`accepts_work`, not at enrolment. It is not visited from the next round. The withdrawal test's
visit sequence is `[first, second, first, first]`
(`tests/test_harness_h5c2_frozen.py`, `test_an_engagement_withdrawn_after_the_start_is_not_visited_from_the_next_round`).
The stop for an engagement is its kill switch.

### 5.3 The engagement's kill switch and pause

The loop reads the engagement's state with `get_engagement` at three places: before each Supervisor
call, before each claim and before each `propose_action`; an engagement that does not accept work
(`status == active` and no kill switch) is skipped and counted, and a task found not accepted after
a claim is completed `not_run` [R item 54, `harness/loop.py:186, 233, 257`,
`control_plane/orchestrator/engagement.py:104-105`]. The check before `propose_action` is the only
thing that stops a killed engagement from reaching the Reviewer's model call, because the pipeline
does not read the state at its early stages [R item 54].

**There is no operator command that engages the kill switch or pauses an engagement.** The functions
are `engage_kill_switch(conn, *, engagement_id, actor, reason)` and `pause_engagement(...)` in
`control_plane/orchestrator/engagement.py:279, 222`; no script of `scripts/` calls them (searched
with grep); the tests call `engage_kill_switch` on an `engagement_scope` connection
(`tests/test_harness_h5c1_support.py:222-224`). **No operator command; a direct function call is
needed. This is a gap** (section 7). The kill switch is one-way: `resume_engagement` is refused
afterwards [R `engagement.py:257-266, 279-298`]. It does not stop a container already running or a
model call already started (design D69-9 (A), `D69_PRODUCTION_HARNESS_DESIGN.md:602-610, 626`).
Run in H7 (已執行,H7; S7) for a kill engaged **before** the start, by a direct call of
`engage_kill_switch`: `run --once` exited 0, printed the banner, its `counters` showed
`'skipped_engagement': 1`, and no task and no proposal was created; the same engagement without
`--once` (`--no-progress-limit 2`) stopped with exit 14, `reason=no_progress`,
`'skipped_engagement': 2`. A kill engaged **during** a run (the three checks) was not run in H7; the
tests of H5c1 cover it in-process (item 89, H5-5). The pause was not run.

## 6. Residue: what a run leaves behind

### 6.1 The listing

```
python scripts/run_harness.py residue --live-task-limit N
```

Output on the test database [run]:

```
0 live task(s)
Nothing in this repository completes, requeues or clears the tasks another run left; this listing changes nothing. A person completes them by hand (H6 writes the recovery down).
```

With tasks, the first line is the **total** over all enrolled engagements and each task is one line:
`<engagement> <task_id> status=<queued|claimed|running> owner=<agent or None> lease_expires_at=<time>`
[R `harness/residue_listing.py:69-77`]. It reads in a read-only transaction and prints no task goal
[R `:5-12, 42-58`].

* **The limit is per engagement** (`list_residue`: "at most `limit` for each"), not for the total
  [R `:42-45`]. An engagement whose lines number exactly `--live-task-limit` may have more: list
  again with a larger number (item 96 d, made exact here).
* **Only currently enrolled engagements are listed** [R `run_harness.py:160-161`]. The leftovers of
  an engagement you have withdrawn do not show; list before you withdraw.
* `claimed` tasks carry a lease of five minutes (`function_api.py:245`). I found no code that
  requeues a task whose lease lapsed [D: absence in a search], so a claimed task stays claimed.
  `running` is set by no function of the product (item 92 b).

### 6.2 After a fault: the proposal that is left stuck

(a) **Where it stops.** `propose_action` commits the proposal row at stage `received` before
anything else (`function_api.py:622-646`) and calls the Reviewer later, in the decision stage
(`:797`). A fault there (the H5-3 test raises inside the reviewer) leaves the proposal `received`
with **no decision**. The H5-3 test asserts `stage in stages.UNDECIDED_STAGES and decision is None`
(`tests/test_harness_h5c1_pipeline.py:141`; `UNDECIDED_STAGES = (RECEIVED, ABANDONED)`,
`control_plane/orchestrator/stages.py:89`) and that no capability and no run exist. Straight after a
fault the stage is `received`: observed in H7 (S4; a reviewer that raises, run as a process, read as
`cyberorch_app` in a read-only transaction): `pipeline_stage` `received`, `decision` null,
`stage_detail` null, no capability and no run for it; the queued tasks of that plan have no proposal
at all.

(b) **What closes it in the product.** The reconciler (D64): rule R6 abandons a `received` proposal
with no decision once it has stood for `RECONCILER_STAGE_GRACE_S` (`stage` becomes `abandoned`,
detail `undecided_past_grace`) [R `control_plane/reconciler/plan.py:124-131`; `.env.example:29`
gives 3600 s; the code's floor is 300 s, `control_plane/reconciler/config.py:17, 158`]. It is a
**separate script the operator starts**: `python scripts/run_reconciler.py --mode state-only`
(`--mode dry-run` reads and prints what it would do and changes nothing) [R
`scripts/run_reconciler.py:1-30`]. It needs its own `RECONCILER_*` settings and a missing one makes
it refuse to start (exit 8) [R `:31-32`]. **Nothing starts it for you** (no compose or service
definition; the start order is a convention) [R design:590-600], **and nothing in `harness/`
refers to it** (searched with grep). So the proposal is closed only if someone runs the reconciler.
The repository's test clean-up (`residue.finish_test`) is for tests and does not count.

(c) **The listing does not show it.** `residue` lists tasks only (`query_state` with
`decision_limit=0`) [R `residue_listing.py:49-58`, `decision_limit=0` at `:53`]. The one view of such a proposal is the
reconciler's dry run, and only after the grace has passed. Run in H7 (已執行,H7; S4, S9): the
listing named no proposal; `run_reconciler.py --mode dry-run --once --engagement <id>`, with the
`RECONCILER_*` values of `.env.example`, printed only its summary line for the fresh proposal
(inside the grace: `"outcomes": {}`, `"summary": {}`); after the proposal's `stage_updated_at` was
set back (the grace is at least 300 s; the test moves the time as `tests/reconciler_support.py`
does, so a real wait was not observed) it printed `{"kind": "abandon", "outcome": "dry_run",
"reason_code": "undecided_past_grace", "subject_id": "<proposal>", …}` and changed nothing.
`--mode state-only --once --engagement <id>` with no `--enable` needed no terminal, exited 0, printed
the same line with `"outcome": "done"`, and the proposal was then `abandoned` with `stage_detail`
`undecided_past_grace`.

(d) **The same key again.** The loop sends each key once: `h5:<task_id>:1`, no retry
[R `harness/loop.py:97-98`]. If a caller sends the same key while the proposal is `received` with
the same action and target, `propose_action` finds it and resumes at its stage, which runs the
decision stage: a **new Reviewer call and a new decision** [R `function_api.py:625-690`; run in H7,
S9b: one Reviewer call, the same proposal id, decision `DENY` (the test database's neutral
baseline), stage `closed`]. A different action or target under the key is refused (`idempotency_key_reused_with_a_different_request`,
`:651-664`). Once the proposal is `abandoned` the call is answered `abandoned` and a new key must
be used [R `:1144-1147`]. After you complete the task as `not_run` (6.4), `complete_task` changes
the `tasks` row only [R `:268-279`]; the proposal stays as it is. The loop never sends that key
again: a completed task is not claimed again and a new task has a new id and key. The start-up
check reads tasks only (`loop_adapter.py:143-152`), so a stuck proposal does not block a start.
Whether a stuck `received` proposal affects the de-duplication of a later proposal for the same
work: **[N]** not read. Once the reconciler had abandoned the proposal, the same key was answered
`DENY` with failure `abandoned` and reason `abandoned_before_decision`, and no Reviewer was called
(run in H7, S9b; 已執行,H7).

### 6.3 No command clears tasks, and why

No command of this repository completes, requeues or clears the tasks another run left. The
decision of record is "A plus B": the start-up check refuses a start (A) and the listing shows what
there is (B); a clearing tool is not part of it (item 47, 3.7; item 49) [R]. Tests pin it: only
`scripts/live_run/` scripts name `complete_task`
(`tests/test_harness_h5c2_residue.py`, `test_no_script_but_the_live_run_ones_names_complete_task_so_none_clears_leftovers`)
and only the adapter names it in `harness/` (the m2 allowance of `tests/test_harness_task_source.py`
and `tests/test_harness_h5c1_structure.py`). v0 builds no tool.

### 6.4 Recovering by hand

Run in H7 (已執行,H7; S6, S6b): the Python block of step 5, taken from this file as it stands and
run in a separate process for each task the listing showed, with the steps around it as the tests did
them (list, complete, list, start again). This calls the function the adapter itself calls
(`harness/loop_adapter.py:221-224`); it is not a new tool.

1. **Make sure no harness process is running.** The lock is released when its session ends. A
   running instance would still be writing.
2. **List.** `python scripts/run_harness.py residue --live-task-limit N`. Note each task id and
   status. The engagement must still be enrolled for it to be listed (6.1).
3. **Decide per task.** A task the fault happened on is `claimed`; the rest of that plan is
   `queued`. `complete_task` has no precondition on status, lease or owner: its `UPDATE` matches on
   `task_id` alone, inside the engagement's row-level security [R `function_api.py:268-279`]. It
   does not check that a row matched. Observed in H7 (S6b): the snippet run on a task already
   completed as `DENY` set it to `not_run` and wrote a second `task.completed` record; run on a
   mistyped id it changed no row and still wrote one `task.completed` record. Check the id against
   the listing; the snippet overwrites the summary of a task that is already completed.
4. **Complete with the word `not_run`.** It is the loop's own word for a task that did not reach
   a proposal (`harness/result_summary.py:53`); the loop refuses any other word, but `complete_task`
   itself stores any string [R `result_summary.py:3-4`, `loop.py:131-135`]. Use exactly `not_run`.
   Caution: for the task a fault in `propose_action` happened on, `not_run` says no action ran. No
   command shows how far its proposal got; a read-only query does (SQL, as `cyberorch_app` on an
   `engagement_scope` connection in a read-only transaction), by the key the loop sent,
   `h5:<task_id>:1`: `SELECT p.proposal_id, p.pipeline_stage, p.decision, p.stage_detail, (SELECT
   count(*) FROM capabilities c WHERE c.proposal_id = p.proposal_id) AS capabilities, (SELECT
   count(*) FROM tool_runs r WHERE r.proposal_id = p.proposal_id) AS runs FROM action_proposals p
   WHERE p.request_idempotency_key = :k`. Observed in H7 (S4, S8): after a reviewer fault,
   `received`, decision null, 0 capabilities, 0 runs (no decision was made, so no action ran); for a
   task whose proposal was decided `DENY`: `closed`, `DENY`, `decision_DENY`, 0, 0. A proposal with a
   capability or a run is the case in which `not_run` may not be true; H7 did not produce one (its
   tests have no ALLOW path), so that was not observed. `query_state`'s counts are not per task.
5. **The call.** With the repository's environment loaded:

   ```python
   from control_plane.config import load_dotenv
   from control_plane.state.db import engagement_scope
   from control_plane.api.function_api import complete_task

   load_dotenv()
   with engagement_scope("ENG-…") as conn:          # commits on success, as cyberorch_app
       complete_task(conn, engagement_id="ENG-…", task_id="…",
                     result_summary="not_run", actor="<your name>")
   ```

   `actor` is free text and is written into the audit record `task.completed` with the summary
   (`function_api.py:268-279`). The loop's own actor is `harness` (`loop_adapter.py:68`); write your
   own name, not that one. Like the enrolment actor it is not verified (item 86 a) [D].
6. **Confirm.** Run `residue` again: `0 live task(s)` for the engagement (it must still be
   enrolled). Then the next start's check passes.
7. **The stuck proposal (6.2)** is separate: it is closed by the reconciler or it stays.

## 7. Known limits (each mapped to its item)

| item | the limit | where in this runbook |
|---|---|---|
| 86 a | the actor is free input in both operator CLIs, unverified | 2.2, 6.4 |
| 86 b | the harness CLI writes no audit record | 2.2 |
| 86 c | `withdrawn_by` has no non-empty CHECK at the database | 1 |
| 86 d | the structure test of the table's writer scans only five directories | not an operator matter |
| 86 e | a process that dies mid-test can leave a live enrolment row | not an operator matter |
| 96 a | banner values are start-up values | 3.3 |
| 96 b | a withdrawal mid-round: the round is carried out; `finish` does not look at enrolment | 5.2 |
| 96 c | `live_task_limit` is not on the banner; it decides 12 against 10 | 3.1, 4 |
| 96 d | `list_residue` truncates silently at the limit | 6.1 (limit is per engagement) |
| 96 e | the same key asked again returns the executed shape, counted as executed though nothing ran | 6.2 (d) |
| 96 f | the lock guards against accidents only; a call in flight cannot be interrupted | 3.5, 5.1 |
| 96 g | a SIGTERM before the handlers are installed ends the process | 3.2 |
| 101 a | a withdrawal is not an emergency stop | 5.2 |
| 101 b | `--role-factory` checks nothing about what it returns | 1 |
| 101 c | the Worker's own `reason` text on an executed proposal is not shown to reach the outcome | not an operator matter |
| 101 d | the six rows of the new residue tests are closed by the test machinery | not an operator matter |
| 101 e | what a fault in `propose_action` leaves stuck, and what closes it | 6.2 |

**Found while writing this runbook** (new; recorded in item 102, not fixed): (i) exit status 2
means both "another instance holds the lock" and "an argument-parser error"; (ii) `residue` lists
only currently enrolled engagements, so a withdrawn engagement's leftovers are not shown; (iii) the
`residue` limit is per engagement, so the header count alone does not show truncation; (iv) the
banner is printed and the loop starts at once, so comparing it with the enrolment cannot prevent a
round; (v) the withdrawal confirmation says the loop "will not visit it again", true only from the
next round; (vi) `complete_task` does not check that a row matched; (vii) no code requeues a task
whose five-minute lease lapsed [D]; (viii) there is no operator command for the kill switch or for a
pause.

## 8. What this runbook does not cover

* **Real models:** there is no factory of real Supervisor, Worker or reviewer roles (items 87, 98).
* **A real sandbox:** the script builds none; the sandbox in a run is whatever the factory returns
  (item 101 b).
* **A real engagement:** the gates of section 1 are not decided; nothing here makes one allowed.
* **P-8's numbers:** the evidence window's row and per-row character limits and the caps and N stay
  the owner's and are registered before the first run that is not a test (items 90, 98).
* **The laundering path:** a Supervisor-written task `goal`, possibly shaped by untrusted evidence,
  is shown back to the Supervisor inside the trusted header in later rounds; the plan does not
  address it and it is pending the owner (`docs/D69_IMPLEMENTATION_PLAN.md:1389-1405`).
