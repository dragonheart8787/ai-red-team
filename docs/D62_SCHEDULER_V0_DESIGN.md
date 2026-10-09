# D62 — Scheduler v0 (D58-1/2/3/4): design note, checkpoint 1

> **Revision 2 (after review).** Changes A, B, C and the `action` finding supersede the text they touch;
> they are collected in **§11** and the affected tables (§3.1, §6, §10) have been edited to match.

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
**Revised (B): v0 dispatches exactly `network.scan`, `network.recon`, `code.scan`, `code.secrets`** —
explicit names, no wildcard (a wildcard would widen v0 silently when a `network.xxx` is added). Everything
else is `skipped` with a recorded reason. `code.*` was left out of my first proposal for one reason only:
*I had not run it through a scheduler path*. It is **not** a `dispatch_approved` limitation — verified by
executing it: an approved `code.scan` reaches `dispatch_code_scan` (`_dispatch_for_action` routes by the
adapter's `NEEDS_DISPATCH`, the same as the ALLOW path). Its real limit is the one in ACCEPTANCE 5.57: an
approval names no credential, so a **private** repository fails to fetch (`repo_fetch_failed`) and the
proposal closes; only credential-less (public) repositories can succeed. Recorded as a candidate beside 5.57.

**New finding that changes the execution step (⚑ D-9).** I earlier claimed `network.*` needs no extra
runtime context because `dispatch_scan` defaults the allowlist to the target. **Executed, that is wrong for
an IP target:** a `/32` allowlist builds a one-address Docker network and `container.start()` fails with
*"no available IPv4 addresses"* (the raw error that then escapes — see §7 and the D58-7 follow-up). The
execution step therefore **derives `network_allowlist`** from the proposal's authorized scope object
(`action_proposals.authorized_scope_object_id` → `scope_registry`, read by `execute.py` on the `cyberorch_app`
connection, never by `decide.py`).

*What Docker accepts (measured, real daemon, internal bridge):* a `/32` fits **0** containers, `/31` **1**,
`/30` **1**, `/29` **5**, `/28` **≥ 8**. Docker reserves the network address, the gateway (first host) and the
broadcast address, and the target must be a container attached to this network, so the scanner plus the
target need **at least a `/29`**.

| Authorizing scope type | `network_allowlist` | Otherwise skip with |
|---|---|---|
| `cidr` (IPv4), prefix ≤ /29 | the scope's value | `scope_narrower_than_sandbox_minimum` (/30, /31, /32) |
| `ip` (IPv4) | smallest aligned block from /29 up to the cap (proposed **/27**) in which the address is not the block's network, gateway (first host) or broadcast address | `no_usable_block_for_address` |
| `fqdn`, `url`, `ad_domain`, `repo` for a `network.*` action | none derivable | `scope_type_has_no_network_range` |
| any IPv6 scope | not supported in v0 (not tested) | `ipv6_not_supported_v0` |
| `code.*` (any scope) | not needed (no network) | — |

Then, for any `network.*` proposal whose **target is a single IP**: if that address is the **network, first-host
(gateway) or broadcast address of the chosen block** it is skipped with `target_is_reserved_address` — it would
fail with "Address already in use" at container creation (measured: a target pinned at `.1` or `.7` of a `/29`
fails; `.5` works, target and scanner both). A CIDR *target* is not checked (a range naturally contains them).
This applies to a CIDR scope too (a target of `.1` or `.255` in a `/24`).

*Measured coverage of the single-IP derivation* (fraction of the 256 last-octet values that get a usable block,
by block cap): /29 62.5% · /28 81.2% · **/27 90.6%** · /26 95.3% · /25 97.7% · /24 98.8%. The 3/256 = 1.2% that
never do are last octets `.0`, `.1`, `.255` (reserved in every aligned block); an explicit gateway in
`DockerSandbox.ensure_network` would rescue them — a `tool_gateway` change, not v0.

*What this is worth in practice — the evidence, not only the conclusion.* Method: every call in `tests/`,
`scripts/`, `agents/` that registers a scope object enabled for `network.*`, found with `ast` (not a regex),
and its `value` argument resolved through the syntax tree — a literal, a module constant, a name imported from
another module, or a loop variable over a literal collection. I first resolved only 19 of the 41 `cidr` sites by
regex and called the other 22 "named constants"; that was not evidence, so they were resolved properly. Result:

| `cidr` registration sites | count | how the value is spelled | does it dispatch a tool? |
|---|---|---|---|
| `/24` | **38** | 34 string literals; 3 through the constant `ALLOWED_CIDR = "10.79.0.0/24"`; 1 loop over `SCOPE_CIDRS = {"10.90.0.0/24", "10.91.0.0/24"}` | yes — used as-is |
| `/25` | **1** | literal | yes — used as-is |
| a parametrized unit test (`tests/test_resolvers.py`) | 1 | a table of lookalikes: `/24` ×2, `/25`, `/26`, `/28` and one `/32` | no — only checks containment, never dispatches |
| `'not-a-network'` | 1 | a deliberately invalid string in a negative test | no — the registration is expected to fail |
| **total** | **41** | | |

Other scope types in the same sweep: **4 `fqdn`** (skipped: `scope_type_has_no_network_range`), **0 `ip`**.
So the only `cidr` scope narrower than a `/29` anywhere in the repository is the one `/32` in a unit test that
never dispatches; **every `cidr` scope that is used to run a tool is a `/24` (38) or the one `/25`, and is
used as-is.** `ip` scopes are derived as above, but nothing in the repository registered one for a tool run
before this deliverable; the new tests in `tests/test_scheduler_skips.py` and `tests/test_scheduler_allowlist.py`
are now the only things that exercise one (they add `/30`, `/31`, `/32`, `/29` and `ip` registrations on purpose,
so a later re-count of the tree will be higher than 41; the table above is the count *before* D62's tests).

*Cost, stated:* for an `ip` scope the allowlist (and so the Docker network, `tool_runs.network_allowlist`, the
fingerprint and D59's same-range serialization) is a block **wider than the one authorized address**; the
command still names only the target and an internal bridge reaches only containers someone attached, but it is a
widening and is recorded as one. The clean fix — keep the authorized `/32` as the allowlist and let the sandbox
choose its own pool — is a `tool_gateway` change for a separate deliverable.
⚑ **confirm: derivation table, cap /27, and the widening for `ip` scopes.**

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

* **(i) recommended — grant exactly what v0 reads** (revised: A and the `action` finding):

| Object | Columns | Why v0 reads it |
|---|---|---|
| `scheduler_enrollment` | all (6) | the allowlist |
| `engagements` | `engagement_id`, `status`, `kill_switch_engaged` | defer on pause/kill; detect "missing" |
| **view `scheduler_proposals`** (definer view; reader has **no** grant on `action_proposals`) | `proposal_id`, `engagement_id`, `pipeline_stage`, `stage_updated_at`, `action_class` | find `approved`; ordering; count stuck stages |
| `scheduler_state` | `engagement_id`, `proposal_id`, `kind`, `disposition`, `reason_code`, `since` | previous disposition (§6.1) — replaces the `audit_log` grant |
| **`audit_log`** | **none** | — |

  `action_class` is `CASE WHEN action IN (<the registered action names>) THEN action ELSE 'other' END`:
  a closed vocabulary enforced by the database (see §11, finding on `action`).
  Not granted in v0 although the ADR marks them "yes": `tasks.*`, `capabilities.*`, `tool_runs.*`, and on
  `action_proposals`: `action` itself, `decision`, `decision_reasons`, `dispatch_state`, `stage_detail`.
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
| `scheduler.skipped` | engagement | once per proposal v0 does not dispatch (recorded in `scheduler_state`) | `proposal_id`, `reason_code` ∈ {`action_not_supported_v0`, `scope_type_has_no_network_range`, `scope_narrower_than_sandbox_minimum`, `no_usable_block_for_address`, `target_is_reserved_address`, `ipv6_not_supported_v0`} |

¹ best-effort: if the audit cannot be written, `stopped` cannot be either; a `started` with no matching
`stopped` is how an unclean death reads.

**What `scheduler.dispatched` means (C).** It means **"the scheduler decided to attempt a dispatch"** — it
does **not** assert that anything ran. The outcome is whatever the pipeline events say
(`capability.issued`, `tool_run.started`, …, or `approval.revalidation_failed`); a `dispatched` with none of
them behind it is a decision that was interrupted or refused, not an execution. It is written first so that
*audit failure ⇒ no action* (§7). If the process dies between the record and the call, the restart finds the
proposal still `approved` and writes a second `dispatched` — two decisions, one run (the stage UPDATE
guarantees the run). To make that case visible at startup, the service records a `dispatch_decided` row in
`scheduler_state` after the audit event and before the call (§8). Outcomes are not repeated by the scheduler.
The pipeline events carry the same `proposal_id` as subject, so `reconstruct_decision` reads the scheduler's
decision as part of the chain (the event types are added to `audit/query.py`'s table).

### 6.1 Edge-triggered without memory (⚑ D-7, revised by A)

"Stateless between ticks" and "edge-triggered" conflict unless the previous disposition is persisted. It is
persisted in a **small table of closed vocabulary**, not read back out of the audit log:

```
scheduler_state(
  engagement_id  text NOT NULL REFERENCES engagements(engagement_id),
  proposal_id    text REFERENCES action_proposals(proposal_id),      -- NULL = engagement-level row
  kind           text NOT NULL CHECK (kind IN ('engagement','proposal')),
  disposition    text NOT NULL CHECK (disposition IN ('served','deferred','skipped','dispatch_decided')),
  reason_code    text CHECK (reason_code IN ('engagement_paused','engagement_killed','engagement_not_active',
                    'action_not_supported_v0','scope_type_has_no_network_range',
                    'scope_narrower_than_sandbox_minimum','no_usable_block_for_address',
                    'target_is_reserved_address','ipv6_not_supported_v0','approved_and_idle')),
  since          timestamptz NOT NULL DEFAULT now(),
  -- the pairs that may exist, nothing else:
  CHECK ((kind='engagement' AND proposal_id IS NULL AND disposition IN ('served','deferred'))
      OR (kind='proposal'   AND proposal_id IS NOT NULL AND disposition IN ('skipped','dispatch_decided'))),
  UNIQUE (engagement_id, COALESCE(proposal_id, '')) )
```

Every column is an id, a timestamp or a `CHECK`-closed code — **no column can hold free text**, which is the
property the `audit_log.payload` grant could not give. **Who writes it:** a **third new role,
`scheduler_state_writer`** — `SELECT, INSERT, UPDATE` on this one table and nothing else; not
`cyberorch_app`, not `scheduler_reader`, not `scheduler_admin`. Both it and the reader are bound to one
engagement per transaction by the ordinary `engagement_isolation` policy, so the writer cannot write
another engagement's row. Cost, stated: the process now holds three database credentials (reader, state
writer, app) — each does one thing, and the AST test (§4) keeps `decide.py` away from the last two.

Per tick, for each enrolled engagement, `decide.py` reads the state row(s) and the live facts and emits
transitions; `service.py` applies each as **audit event first, then state row** (the audit-before-act rule).
A crash between the two re-emits the event after restart — a duplicate `deferred`, never a lost one.
Restarts do not re-emit otherwise (the row survives). **Coalesce:** `resumed` carries `deferred_seconds`
(`now - since` from the row) — no per-tick counter, no extra write per tick.

**Skipped proposals stay visible.** A skipped proposal is not closed: it stays `approved` until its approval
lapses (and after that, listed as lapsed), because closing it is a decision the operator or the reconciler
makes, not the scheduler. `scripts/approvals.py awaiting-dispatch` therefore lists each of them with its
**`skip_reason`** and `skipped_since`: the CLI reads the queue as today (`cyberorch_app`, engagement scope) and
joins `scheduler_state` rows (`kind='proposal'`, `disposition='skipped'`) read over the `scheduler_reader`
connection — no grant on `scheduler_state` is added to `cyberorch_app`. The event `scheduler.skipped` carries the
same code; the code is the operator's only explanation (the reason is derived from scope content the reader
cannot see, so it cannot be recomputed from the reader side).

`deferred` is emitted only when something is *waiting*. A `killed` engagement stays deferred for good and its
approved proposals stay `approved` (reconciler's, D58-9; `awaiting-dispatch --older-than` finds them).

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

**Raw errors from `start()` (found by probe, then traced).** The probe showed a raw docker `APIError`
escaping `dispatch_approved` with the proposal left at `dispatching`. Traced to its position: it is raised by
`container.start()` in `DockerSandbox.run` — **after** `containers.create` (the only call D58-7 had wrapped) and
**before any process existed** (inspected: `Status: created`, `Pid: 0`, `StartedAt` the zero time). That is an exit
D58-7 missed, not a scheduler matter; it is fixed and tested on its own (`ContainerStartRefused`, a `NotStarted`,
recorded `failed` / stage `closed` / `container_start_refused`; own commit, §11). It is typed **only** when the
daemon answered with an error *and* an inspection shows the container never ran; a lost connection or an
inspection that fails stays untyped. For the scheduler, any *other* exception from `start()` onwards is still "any
other exception": best-effort `stopped(unexpected_error)`, stop (exit 1); the proposal is at `dispatching`, not
`approved`, so it is not retried and is the reconciler's.

**Two consequences you should see, both from fail-closed choices already made:**
1. A refusal *closes* the proposal (the operator re-proposes and re-approves). A lapsed approval
   (expiry cannot be undone) is the right thing to close; **but a Docker outage between my pre-check
   and the dispatch also closes it** (`docker_unreachable`, retryable *in principle* by D58-7, but a
   closed proposal is not re-selected). The pre-check narrows the window to milliseconds; closing it
   fully needs "reopen on a retryable failure", which is D58-6's ladder. Recorded as a known v0 gap.
   *Labelled as infrastructure, not policy:* the close reason is the sandbox's own code in `stage_detail`
   (`docker_unreachable`, `tool_image_missing`, `network_unavailable`…) and the audit event is
   `tool_run.refused` with reasons `(sandbox_not_started, <code>)` — distinguishable from
   `capability_refused:…` and `approval_revalidation_failed:…` (policy/approval).
   *Why it is not put back to `approved`:* (i) there is no `closed → approved` transition — stages only move
   forward by conditional UPDATE, and one that moves back must itself be an audited, guarded act; (ii) the
   run row and a consumed capability already exist, and the approval may have lapsed meanwhile, so a re-run
   needs a fresh capability and a fresh validity check; (iii) the only safe trigger is the typed `NotStarted`
   proof, and getting that wrong for an `unknown_outcome` would run a tool that already ran (I7). That
   machinery is the D58-6 ladder; v0 does not guess at it.
2. Engagement status is re-read immediately before each dispatch (not only at tick start), to keep the
   "paused/killed → deferred, not closed" window to one query.

## 8. Startup observation (your item 7, extended by C)

After the lock and before the first tick, `scheduler.started` carries, per enrolled engagement and as counts
only: `dispatching` (stage `dispatching`), `capability_issued` (issued, never dispatched), `approved_waiting`
(stage `approved`) and **`approved_redispatch`** — the subset of `approved` that has a `dispatch_decided` row,
i.e. a decision to dispatch was recorded and no pipeline stage followed (the crash-between case), plus
`missing`. Observation only: nothing is changed, closed, retried or reconciled. (`reconcile_stale_dispatches`
stays manual.)

## 9. Implementation plan (checkpoint 2), for planning only

* `db/roles.sql` + `scripts/init_db.sh`: `scheduler_reader`, `scheduler_admin`, `scheduler_state_writer` (passwords, `.env` lines,
  URLs). CI runs `./scripts/init_db.sh` from a clean database, so provisioning there needs no workflow
  change [R: `test.yml`].
* Migration `0019`: `scheduler_enrollment` (+ trigger, RLS per role), `scheduler_state` (+ `engagement_isolation`),
  the `scheduler_proposals` view, column grants, `GRANT EXECUTE … cyberorch_current_engagement()`. No `audit_log`
  grant of any kind.
* `state/db.py`: `scheduler_reader_scope(engagement_id)`, `scheduler_admin_scope()`, the URL functions.
* `control_plane/scheduler/{decide,execute,emit,lock,service}.py`, `scripts/run_scheduler.py`,
  `scripts/manage_scheduler_enrollment.py`.
* Tests exactly as listed in your §三.3, plus the exit-code table (§7) and the "still approved ⇒ stop"
  anomaly; mutations: lock removed, enrollment check removed, reader granted one content column,
  payload whitelist relaxed.

## 10. Decisions (status after review)

| # | Decision | Status |
|---|---|---|
| D-0 | v0 actions: `network.scan`, `network.recon`, `code.scan`, `code.secrets` (explicit names); others `skipped` | revised (B); private-repo limit recorded |
| D-1 | `scheduler_enrollment` + `scheduler_admin` + operator CLI (typed confirmation on a TTY, refuses without one, `--yes` only for scripted provisioning — same as `manage_global_policy.py`) | approved |
| D-2 | reader: smallest grant (§3.1), **no `audit_log`, no `action_proposals` base table** | approved, revised (A) |
| D-3 | `approvals`: none | approved |
| D-4 | `credential_id`: none in v0; `security_invoker` view when needed | approved |
| D-5 | `decision_reasons`: not granted; **candidate: D58-12 needs it to tell `policy_engine_unavailable` apart — add a CHECK or vocabulary test first** | approved + candidate |
| D-6 | audit vocabulary (§6); `dispatched` = "decided to attempt" | approved, wording fixed (C) |
| D-7 | previous disposition in `scheduler_state` (closed vocabulary); writer = new `scheduler_state_writer` | revised (A) — **needs your confirmation** |
| D-8 | failure table; known Docker-close gap; infra labelling and why-not-`approved` added | approved |
| D-9 | execution step derives `network_allowlist` from the authorized scope (§1 table: cidr as-is if ≥ /29; ip → smallest usable block up to /27); concrete skip codes; reserved-address skip | **needs your confirmation** (cap /27; the widening for `ip` scopes) |

## 11. Revisions after review

* **A.** `audit_log.payload` is not granted; in fact nothing on `audit_log` is. Previous disposition lives in
  `scheduler_state` (§6.1), a table whose every column is an id, a timestamp or a CHECK-closed code, written
  by a dedicated `scheduler_state_writer`. This survives restarts, so a restart does not re-emit `deferred`.
* **B.** See §1: `code.*` was excluded only for lack of a scheduler-path test, not by any `dispatch_approved`
  limit (executed: it routes to `dispatch_code_scan`). Explicit action names, no wildcard.
* **C.** See §6 and §8.
* **Finding on `action` (your supplementary item).** *Verified by executing it:* `action_proposals.action` is
  **free text**. `_persist_proposal` stores whatever the agent sent before any registry or policy check (a
  237-character string beginning `zz.IGNORE-PREVIOUS; goal: …` was stored verbatim and then DENYed); the
  column is `TEXT` with no CHECK. So `action` is **not** a closed vocabulary, and granting it would hand
  agent-controlled text to the scheduler. Hence the view `scheduler_proposals`: the database itself maps any
  unregistered name to `'other'`. *Verified by executing:* a definer view over `action_proposals` still obeys
  the engagement GUC (0 rows with no GUC, 1 with its own, 0 with another). **Structural test:** the view's
  name list must equal `set(tool_gateway.registry.ADAPTERS)` exactly (a new adapter without a migration to
  the view fails the test; mutation: add a name to the view only), and no scheduler module may read
  `action` from any other source.
* **`stage_detail`.** Not granted. Wording fixed per review: *no known path writes free text into it* (I read
  every write site; I did not compare against real historical data).
* **Round 3 (skip codes, reserved addresses, the raw error, the numbers).** Skip reasons are now six concrete codes
  (§1, §6, §6.1) and `awaiting-dispatch` lists them (§6.1). A single-IP target that is the network, gateway or
  broadcast address of its block is skipped (§1). The raw `APIError` is located and fixed in D58-7's follow-up
  (§7). The CIDR numbers are re-derived with every constant resolved (§1).
