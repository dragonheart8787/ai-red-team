# D62 — Scheduler v0 (D58-1/2/3/4): design note, checkpoint 1

Status: **proposed — nothing here is built.** Items marked ⚑ need your decision before
implementation. Everything below was checked against the tree at `HEAD` (D58-8 closeout, CI 145
green) and each factual claim says how: **[R]** read in the source, **[E]** executed.

## 0. D58-7 — status

**Done, merged, CI green** — it was not skipped. Commit `adc4632` (independent, CI run 144):
`NotStarted` (`DaemonUnreachable`, `ImageNotPresent`, `NetworkNotAvailable`) marks failures that are
provably before any container exists, and dispatch records them `failed`/retryable. That covers
exactly the remaining case you describe — the daemon unreachable before a container exists — and the
cached-client raw `ConnectionError` (X5). `UNKNOWN_OUTCOME` is now only for what cannot be placed;
nothing from `container.start()` onwards is retyped. One housekeeping commit followed (`docs:` only):
that deliverable had been labelled "D62" in its commit message and report, and D62 is now the
scheduler, so the report file, ACCEPTANCE 5.58 and the ADR addendum say **D58-7**. The adc4632 commit
message still says D62 (it is pushed); nothing else does.

## 1. Scope, restated as constraints on the design

One job: for **enrolled** engagements, find approved-and-not-yet-dispatched proposals
(`pipeline_stage = 'approved'`, D61) and call `dispatch_approved` for each. Level-triggered, stateless
between ticks, serial (concurrency 1), no policy cache (the *execution step* loads the effective
policy when it decides, via `load_effective_policy`, and passes it to `dispatch_approved(policy=…)`).
Not built: planning (D58-12), failure ladder (D58-6), reconciler (D58-9), requeue sweeper,
credential selection (D58-15/16), quotas (D58-13).

**One fact the brief did not anticipate, and a decision it forces (⚑ D-0).** `dispatch_approved` needs
runtime context that is not stored with a proposal: `network_allowlist`, a sandbox, and for `web.*` an
egress proxy URL / CA / SPKI. The scheduler has to supply it, and nothing in `control_plane/` builds a
per-engagement proxy today (only harness scripts do). What *is* derivable from committed rows: for
`network.*`, `dispatch_scan` defaults the allowlist to the target itself (`allowlist = network_allowlist
or [target]` [R: `dispatch.py:583`]) — so no extra context is needed. `web.*` is refused without a
proxy (`registry.requires_proxy` [R]); `ad.collect` is refused without a credential (ACCEPTANCE 5.57).
**Proposal: v0 dispatches `network.*` only** (the e2e test's action), and *skips with a recorded
reason* (`scheduler.skipped`, §5) any approved proposal whose action it cannot supply context for.
`code.scan`/`code.secrets` need no extra context either and could be added, but I have not run them
through a scheduler path and would add them only with their own test. ⚑ **(a) `network.*` only
(recommended) / (b) also `code.*`.**

## 2. D58-1/A — the enrollment record

### 2.1 What the ADR prescribes [R: §2.2 Option A, §2.5]

Explicit enrollment by the operator; the service iterates the enrolled list and opens a scope per id
(a **positive allowlist**: an engagement never enrolled is never touched, by construction); an enrolled
id with no `engagements` row is an **error, not an empty queue**; the service **audits its enrollment
list at start** (global scope). The ADR says enrollment is "a configuration the operator owns" and
leaves where it is stored, and which identity writes it, open.

### 2.2 Storage and writer — the options ⚑ D-1

| | Where | Writer | Verdict |
|---|---|---|---|
| **1 (recommended)** | new **global table** `scheduler_enrollment` | new role **`scheduler_admin`**, used only by an operator CLI | meets every constraint; changes are queryable and audited |
| 2 | same table | reuse `global_policy_admin` | **rejected** — widens an existing role's grant (your constraint) |
| 3 | an env var / file the service reads at start | the operator, outside the DB | no new role, but no DB-side record, no per-change audit through the DB, tamper = edit a file, change needs a restart; the ADR itself lists "lives outside the database" as a cost |
| 4 | table, writer = `migration_owner` from the CLI | owner | **rejected** — the DDL owner is not an operator-action role |

Why a *table* and not a column on `engagements`: every table, `engagements` included, is `FORCE ROW
LEVEL SECURITY` keyed to the engagement GUC [E: ADR §2.1], so no role can enumerate engagements; a
flag there is unreadable by a scheduler that is meant to start from "which ids".

**Design of option 1.**

```
scheduler_enrollment(
  enrollment_id  bigserial PK,
  engagement_id  text NOT NULL REFERENCES engagements(engagement_id),
  enrolled_by    text NOT NULL,
  enrolled_at    timestamptz NOT NULL DEFAULT now(),
  withdrawn_by   text,
  withdrawn_at   timestamptz )
UNIQUE (engagement_id) WHERE withdrawn_at IS NULL     -- one live enrollment per id
```

* **FK to `engagements(engagement_id)`: yes.** I first assumed an FK would fail, because every table
  (`engagements` included) is `FORCE ROW LEVEL SECURITY` and the owner sees zero engagements with no
  GUC [E: `count(*) = 0`]. **Executed instead: it works** — referential-integrity checks bypass row
  security (documented Postgres behaviour; a probe table owned by `migration_owner` accepted a real
  engagement id and raised `ForeignKeyViolation` for `ENG-NOPE`). So `enroll` of a nonexistent id is
  refused by the database, and the ADR's "enrolled but nonexistent" case becomes a defensive runtime
  check (`missing` in `scheduler.started`) rather than a state the table can hold. Cost, stated: the
  FK error is an existence oracle for whoever holds `scheduler_admin` (an operator role). **To confirm
  in the migration test:** that the insert also works for `scheduler_admin` itself, not only the owner.
* History is kept: enrollment is append-only; withdrawal sets `withdrawn_*`. A trigger (the 0018
  pattern) forbids changing anything else and forbids un-withdrawing.
* **Grants:** `scheduler_admin`: SELECT, INSERT, UPDATE(`withdrawn_by`,`withdrawn_at`) on this table,
  the sequence, nothing else — it reads no engagement, writes no audit table. `scheduler_reader`
  (§3): SELECT. **`cyberorch_app`: no grant of any kind on this table**, and the scheduler's own role
  has no write. RLS is enabled and forced on the table with policies written **per role**
  (`TO scheduler_admin`, `TO scheduler_reader`) — not the engagement-GUC policy, because the reader
  must list ids without one. A role with no policy sees nothing.
* **CLI `scripts/manage_scheduler_enrollment.py`** (`list`, `enroll`, `withdraw`), modelled on
  `manage_global_policy.py`: confirmation by typed word on a terminal, refuses with no TTY, `--yes`
  only for scripted provisioning; opens `scheduler_admin_scope()`, which nothing else may import (an
  AST test, like `tests/test_global_policy_admin.py`). Each change writes a `scope='global'` audit
  record — `scheduler.enrolled` / `scheduler.withdrawn` — through the ordinary audit path. **These two
  events are the CLI's, not the service's**, so the service's own vocabulary (§6) stays about the
  service. (They need to join the closed list below: 2 more global events.)
* Cost, stated: the reader can list the **enrolled** ids without a GUC. That is strictly less than
  ADR option B (all engagements), and it is the point of enrollment, but it is a new thing a leaked
  reader credential reveals. Engagement ids carry no customer name (`customer_id` is not stored here).

## 3. D58-3 — the narrow read role

**`scheduler_reader`**: `LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION`, owns
nothing, column-level `SELECT` only, no `INSERT`/`UPDATE`/`DELETE` anywhere (`ui_reader` and
`global_auditor` are the precedents [R: `db/roles.sql`, 0008, 0007]). `engagement_isolation` is
`FOR ALL TO PUBLIC`, so it applies to the new role unchanged: with no GUC it sees zero rows, with
GUC = E it sees only E. The scheduler therefore reads each enrolled engagement through its own scope
— the same self-declared-selector property the ADR §2.1 describes, *narrowed to enrolled ids by the
enrollment read and to columns by the grants*.

### 3.1 Columns ⚑ D-2

The ADR §2.4 "yes" rows cover `engagements`, `tasks`, `capabilities`, `tool_runs`,
`action_proposals`. **What v0 actually reads** is much smaller. Two choices:

* **(i) recommended — grant exactly what v0 reads**, each later feature adds its own migration:

| Table | Columns | Why v0 reads it |
|---|---|---|
| `scheduler_enrollment` | all | the allowlist |
| `engagements` | `engagement_id`, `status`, `kill_switch_engaged` | defer on pause/kill; detect "enrolled but missing" |
| `action_proposals` | `proposal_id`, `engagement_id`, `action`, `pipeline_stage`, `stage_updated_at` | find `approved`; ordering; skip unsupported actions; count `dispatching` at start |
| `audit_log` | `audit_id`, `engagement_id`, `ts`, `event_type`, `subject_id`, `payload` — **plus a restrictive policy** `TO scheduler_reader USING (scope='engagement' AND event_type LIKE 'scheduler.%')` | the "previous disposition" of an engagement/proposal, derived from the scheduler's own earlier events (§5.3) so ticks hold no state |

  Not granted in v0 although the ADR marks them "yes": `tasks.*`, `capabilities.*`, `tool_runs.*`,
  `action_proposals.decision`, `decision_reasons`, `dispatch_state`, `stage_detail`.
* **(ii)** grant the whole ADR "yes" list now, so later phases need no migration. Wider than v0 uses;
  contrary to "don't widen ahead of need".

### 3.2 `approvals` ⚑ D-3 (your question)

You lean toward `approval_id`, `proposal_id`, `valid_until`, `revoked` readable and `snapshot`,
`constraints`, `approved_scope` not. **I agree on the split, and recommend granting none of it in v0.**
v0 does not need it: if an approval expired or was revoked, `dispatch_approved` refuses at the broker
and *closes* the proposal (`capability_refused:approval_expired`), and an expired approval can never
become valid again — migration 0018's trigger forbids extending `valid_until`. So a pre-filter would
only change *who* closes the proposal, not the outcome, and an `approvals` grant would exist to save
one clean refusal. If you want the pre-filter anyway (so the scheduler emits `skipped` instead of
closing), the list is exactly yours: `approval_id`, `proposal_id`, `valid_until`, `revoked` — and the
join key is `action_proposals.stage_detail`, which would then also need granting; I would rather not.
⚑ **none (recommended) / your four columns.**

### 3.3 (a) `credential_id` column grant exposes the value ⚑ D-4

Correct: a column grant on `capabilities.credential_id` reveals *which* credential, not "is there one".
**v0 does not read `capabilities` at all, so nothing is exposed.** If a later feature needs "is a
credential involved", the answer is a **view** (`security_invoker = true`, so RLS and the GUC still
apply under the reader's identity) exposing `credential_id IS NOT NULL AS has_credential`, with the
reader granted the view and **not** the base column. I would write that in the migration that needs it
and not before. ⚑ **view when needed (recommended) / accept the column.**

### 3.4 (b) is `decision_reasons` a closed vocabulary? ⚑ D-5

[R + E] **By construction today, yes; by enforcement, no.** The values come from
`decision.deny_reasons + approval_reasons`. Every Rego reason is a string *literal*
(`deny_reasons contains "target_out_of_scope"` … 11 deny reasons, 5 approval reasons) and
`grep sprintf|concat` over `authz.rego` finds nothing; the Python side adds only the constant
`policy_engine_unavailable`. But the column is `TEXT[]` with no `CHECK`, so a future rule that
interpolates (e.g. a target into a reason) would put free text in it silently. **v0 does not read the
column** (not in §3.1), so v0 does not depend on the answer. Recommendation: do not grant it now; when
something needs it, add a test that every Rego reason is a literal and every stored value is in the
literal set. (`stage_detail` is *not* closed — it carries `dedup_hit:<run_id>`, broker reason lists —
and is also not granted.) ⚑ **confirm: not granted in v0; vocabulary test when it is.**

## 4. Two connections in one process; how the decision path cannot reach the execution one

Process: one scheduler. Connections:

| Name | Role | Used by | Never reachable from |
|---|---|---|---|
| `reader` | `scheduler_reader` (pooled, short, scoped per enrolled engagement) | `decide.py` | — |
| `lock` | `scheduler_reader` (one dedicated, long-lived, autocommit) | `lock.py` | `execute.py` |
| `app` | `cyberorch_app` | `execute.py` (`engagement_scope` → `load_effective_policy` → `dispatch_approved`, which opens its own scopes) and `emit.py` (audit writes) | `decide.py` |

**Module layout** (`control_plane/scheduler/`): `decide.py` (pure derivation from reader rows to a list
of `Decision` values — no I/O except the reader), `execute.py` (`Decision` → one dispatch), `emit.py`
(typed audit emission with the payload whitelist), `lock.py`, `service.py` (the loop: wires the four and
nothing else), plus `scripts/run_scheduler.py`. `Decision` is a frozen dataclass of **ids and enum
codes only** — that is all that crosses from `decide` to `execute`.

**Structural guarantee** — an AST test, in the style of
`test_the_sandbox_unavailable_handler_is_preceded_by_…` and `tests/test_global_policy_admin.py`:
1. `decide.py` imports nothing from `control_plane.state.db` except `scheduler_reader_scope`; it
   imports neither `engagement_scope`, `audit_scope`, `get_engine`, nor `function_api`,
   `approved_dispatch`, `approvals`, `dispatch`, `broker`, `vault`.
2. `execute.py` imports `engagement_scope` and `dispatch_approved` but **not** `scheduler_reader_scope`.
3. Only `service.py` imports both, and it passes only `Decision` objects between them (a function
   signature check: no function in `decide` returns, and none in `execute` accepts, a `Connection`).
4. `scheduler_admin_scope` / `scheduler_admin_url` are imported by the enrollment CLI only (like
   `global_policy_admin_scope`).
5. No module under `agents/` or `tool_gateway/` imports `control_plane.scheduler`.

`dispatch_approved` takes **no connection** (D60/D61 design), so even `execute.py` hands the pipeline
ids, not a connection. **Connection strings:** `scheduler_reader_url()` and `scheduler_admin_url()` in
`state/db.py` via `require_env` — no fallback, an instruction in the error, like every other role.

## 5. D58-2 — the singleton lock

**Mechanism.** A Postgres **session advisory lock** (`pg_try_advisory_lock(<fixed bigint key>)`) taken
on the dedicated `lock` connection at startup. A session lock is released by the server when the
session ends, so it cannot outlive a dead process; no table, no heartbeat row, no TTL to tune. A second
instance's `pg_try_advisory_lock` returns false → it writes `scheduler.start_refused` (global) and
exits non-zero **before** reading enrollment or doing anything else.

**"Lost connection = lost lock = stop dispatching."**
* The lock connection is never used for anything else. Before **every** dispatch (not every tick) and
  once more at the end of each, `lock.py` verifies the lock is still *held* on that same session:
  `SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid = pg_backend_pid() AND objid = … AND
  granted` — an error, or no row, is "lost".
* A watchdog thread runs the same check every 2 s, because a dispatch can run for minutes (the whole
  `max_duration_seconds` of a container). It cannot stop an in-flight container (that is D44-7/D58-16);
  it sets a flag so **no further dispatch starts** and the service exits non-zero once the in-flight one
  returns. TCP keepalives are set on the connection so a dead peer is noticed in seconds, not hours.
* Why the unavoidable overlap is safe: a successor can only start once the server has released the lock
  (session gone). The predecessor's in-flight proposal is already past `approved` (`capability_issued`
  or `dispatching`), so the successor does not see it as approved; and the stage transition itself is a
  conditional UPDATE — two dispatchers still run the tool once (tested in D61).
* What it does **not** protect against: another role taking the same advisory key (a DoS, not a
  safety problem); the lock is a guard against accidents, not an authorization mechanism.

Tests: second instance refused; `pg_terminate_backend()` on the lock session ⇒ no further dispatch and a
non-zero exit; mutation: lock removed ⇒ the two-instance test goes red.

## 6. D58-4 — the audit vocabulary ⚑ D-6

Governing rule (D24, ADR §2.5): a scheduler act is audited **iff** it causes, prevents or delays an
action or changes who may act; bookkeeping is not. Ticks, polls and "nothing to do" are never audited.
Closed list, **exactly what v0 emits** (any other `scheduler.*` is a bug and the emitter refuses it):

| Event | Scope | Emitted when | Payload (ids and reason codes **only**) |
|---|---|---|---|
| `scheduler.started` | global | once, after the lock is held, before the first tick | `instance_id`, `enrolled` (ids), `missing` (enrolled ids with no `engagements` row), `dispatching` ({id: count}), `approved_waiting` ({id: count}) |
| `scheduler.stopped` | global | on every exit the service can still record | `instance_id`, `reason_code` ∈ {`signal`, `lock_lost`, `db_lost`, `docker_lost`, `audit_failed`¹, `dispatch_did_not_advance`, `unexpected_error`} |
| `scheduler.start_refused` | global | a second instance | `instance_id`, `reason_code` = `lock_held` |
| `scheduler.enrolled` / `scheduler.withdrawn` | global | **by the CLI**, not the service | `engagement_id`, `by` |
| `scheduler.dispatched` | engagement | written **before** the call to `dispatch_approved`: the decision to dispatch | `proposal_id`, `reason_code` = `approved_and_idle` |
| `scheduler.deferred` | engagement | edge: first tick on which an engagement with ≥1 approved proposal cannot be served | `reason_code` ∈ {`engagement_paused`, `engagement_killed`, `engagement_not_active`}, `waiting_count` |
| `scheduler.resumed` | engagement | edge: the engagement is servable again after a `deferred` | `deferred_seconds`, `waiting_count` |
| `scheduler.skipped` | engagement | once per proposal whose action v0 does not dispatch | `proposal_id`, `reason_code` ∈ {`action_not_supported_v0`} |

¹ best-effort: if the audit cannot be written, `stopped` cannot be either; a `started` with no matching
`stopped` is how an unclean death reads.

`scheduler.dispatched` has the name you asked for but its meaning is "handed to `dispatch_approved`":
it is written first so that *audit failure ⇒ no action* (§7). If the process dies between the record and
the call, the restart dispatches the still-`approved` proposal and writes a second `dispatched` — two
decisions, one run (the stage UPDATE guarantees the run). Outcomes are **not** repeated by the
scheduler: `capability.issued`, `tool_run.*`, `approval.revalidation_failed` and the stage already say
what happened. The pipeline events carry the same `proposal_id` as subject, so `reconstruct_decision`
reads the scheduler's decision as part of the chain (the event types are added to
`audit/query.py`'s table).

### 6.1 Edge-triggered without memory (⚑ D-7)

"Stateless between ticks" and "edge-triggered" conflict unless the previous disposition is *derived*.
It is derived from the scheduler's own earlier audit events, read through `scheduler_reader` (the
restricted `audit_log` grant, §3.1):

* engagement disposition = the latest `scheduler.deferred`/`scheduler.resumed` for that engagement;
* "already skipped" = a `scheduler.skipped` whose `subject_id` is that proposal.

A restart therefore does not re-emit, and no process memory is involved. **Coalesce count:** a per-tick
counter would be state (or a write per tick). Proposal: `resumed` carries **`deferred_seconds`** (from the
`deferred` event's `ts`) instead of "N ticks". Alternative: an in-memory tick counter, accurate only
within one process lifetime. ⚑ **seconds (recommended) / in-memory ticks.**

`deferred` is emitted only when something is *waiting* (an engagement paused with nothing approved
delays nothing). A `killed` engagement stays deferred for good and its approved proposals stay
`approved`: v0 neither closes nor re-routes them (that is the reconciler's, D58-9, and
`awaiting-dispatch --older-than` already finds them).

## 7. v0 failure handling — and the no-repeat argument ⚑ D-8

| Condition | v0 behaviour | Exit |
|---|---|---|
| audit write fails (`AuditWriteError`) | the decision is **not** executed; stop (L3) | 3 |
| reader / lock / app connection lost; Postgres restart | stop, no reconnect | 4 |
| Docker unreachable | **checked before each dispatch** (a ping outside the pipeline); stop | 5 |
| any other exception | best-effort `stopped(unexpected_error)`; stop; log the exception *type* only | 1 |
| lock lost | no further dispatch starts; stop when the in-flight one returns | 6 |
| `dispatch_approved` returns and the proposal is **still** `approved` | anomaly → stop (`dispatch_did_not_advance`) | 7 |
| second instance | refuse | 2 |

No auto-restart is part of v0 (a process supervisor should not restart it blindly — a deterministic
bug would repeat once per restart, one attempt each).

**Does a proposal get retried every tick? No — I traced every way out of `dispatch_approved`.** A
proposal is selected only while its stage is `approved`, and the call leaves it there only in cases that
stop the service:

* executed → `recorded`; refused at re-validation → `closed`; refused by the broker (approval expired,
  kill switch, scope, policy version) → `closed` (`capability_refused:…`); refused before a run
  (`unbuildable_plan`, `network_unavailable`, `docker_unreachable`, …) → `closed`; crash after the
  issue → `capability_issued`/`dispatching` — none is `approved`, so none is selected again.
* the stage UPDATE rolled back (DB loss mid-issue) → still `approved`, **but** the DB loss stops the
  service before another tick.
* **found while tracing:** `dispatch_approved` returns early *without moving the stage* for
  `approval_missing` (an `approved` row with no `stage_detail`) and `unknown_proposal`. The first would
  be picked again every tick forever. Hence the last row: after each call the scheduler re-reads the
  stage and **treats "still approved" as an anomaly and stops**, rather than skipping it silently or
  looping.

**Two consequences you should see, both from fail-closed choices already made:**
1. A refusal *closes* the proposal (the operator re-proposes and re-approves). A lapsed approval
   (expiry cannot be undone) is the right thing to close; **but a Docker outage between my pre-check
   and the dispatch also closes it** (`docker_unreachable`, retryable *in principle* by D58-7, but a
   closed proposal is not re-selected). The pre-check narrows the window to milliseconds; closing it
   fully needs "reopen on a retryable failure", which is D58-6's ladder. Recorded as a known v0 gap.
2. Engagement status is re-read immediately before each dispatch (not only at tick start), to keep the
   "paused/killed → deferred, not closed" window to one query.

## 8. Startup observation (your item 7)

After the lock and before the first tick, `scheduler.started` carries `dispatching: {engagement_id:
count}` — proposals at `pipeline_stage = 'dispatching'` in each enrolled engagement — plus
`approved_waiting` and `missing`. Observation only: nothing is changed, closed, retried or reconciled.
(`dispatching` is the stage a crash leaves behind; `reconcile_stale_dispatches` is the existing tool and
stays manual.)

## 9. Implementation plan (checkpoint 2), for planning only

* `db/roles.sql` + `scripts/init_db.sh`: `scheduler_reader`, `scheduler_admin` (passwords, `.env` lines,
  URLs). CI runs `./scripts/init_db.sh` from a clean database, so provisioning there needs no workflow
  change [R: `test.yml`].
* Migration `0019`: `scheduler_enrollment` (+ trigger, RLS per role), column grants, the restrictive
  `audit_log` policy for the reader, `GRANT EXECUTE … cyberorch_current_engagement()`.
* `state/db.py`: `scheduler_reader_scope(engagement_id)`, `scheduler_admin_scope()`, the URL functions.
* `control_plane/scheduler/{decide,execute,emit,lock,service}.py`, `scripts/run_scheduler.py`,
  `scripts/manage_scheduler_enrollment.py`.
* Tests exactly as listed in your §三.3, plus the exit-code table (§7) and the "still approved ⇒ stop"
  anomaly; mutations: lock removed, enrollment check removed, reader granted one content column,
  payload whitelist relaxed.

## 10. Decisions I need from you

| # | Question | Recommended |
|---|---|---|
| D-0 | v0 action coverage | `network.*` only; others `skipped` and visible |
| D-1 | enrollment storage/writer | global table + new `scheduler_admin` role + CLI |
| D-2 | reader columns | exactly what v0 reads (§3.1 table), not the whole ADR "yes" list |
| D-3 | `approvals` columns | none in v0 (your four columns if you want the pre-filter) |
| D-4 | `credential_id` | no grant in v0; a `security_invoker` view when needed |
| D-5 | `decision_reasons` | closed by construction, not enforced; not granted; vocabulary test when it is |
| D-6 | audit vocabulary | the closed list in §6 (incl. `skipped`, `deferred`, `resumed`) |
| D-7 | edge state & coalesce | derived from own audit events (`audit_log` read grant with restrictive policy); `deferred_seconds`, not tick counts |
| D-8 | failure table & "still approved ⇒ stop" | as §7, with the Docker-close gap recorded as a known v0 limitation |
