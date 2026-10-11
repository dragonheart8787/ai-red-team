# D64 — The reconciler (D58-9): design checkpoint

**Status: design only.** No code, migration or test is written or changed by this document. Everything below
the line "Decisions" is a proposal waiting for answers; nothing is built until they are given.

**How claims are tagged.** `[R]` read in the code at this commit; `[E]` executed here, on this machine, with the
experiment named in §6; `[D]` taken from an older document (named); `[N]` not verified — knowledge or reasoning
that I have not checked against this system.

## 0. In one page

The scheduler (D62 v0) **observes** stuck proposals and acts on none of them: `scheduler.started` reports how
many are `dispatching` and `capability_issued`, then goes on `[R]`. Nothing else in the tree repairs a crash:
`reconcile_stale_dispatches` is called by tests only `[R]`, and nothing sweeps a container, a network or a file
`[R][E]`. What the experiments added to what was already written down:

* **A killed control plane leaves a tool container running past its budget.** The run's `max_duration_seconds`
  is enforced by the control plane's own `container.wait(timeout)`; there is no timer inside the container. A
  container started with a 5 s budget was still running 25 s after its parent was `kill -9`'d `[E: E5]`.
* **An orphaned egress proxy holds its network against every other engagement** (`NetworkInUse`), keeps
  running, and leaves its **TLS leaf certificate and private key** in `/tmp`; `remove_network` quietly does
  nothing while it is attached `[E: E4]`.
* **The sandbox's networks use the allowlist itself as their subnet**, so the daemon's default address pool
  (30 networks, then "fully subnetted") is *not* what limits them; 1,100 `/29` networks were created without a
  refusal. What does bind is **overlap**: a network left behind for a `/24` makes a later `/29` inside it fail
  with `NetworkRangeConflict` until someone removes it `[E: E1–E3]`.
* **Three of the four "stuck" states are not all stuck.** An `approved` proposal whose approval has expired
  *is* resolved by the scheduler (the broker refuses, the proposal closes) `[E: E7]`; an `approved` proposal in a
  **killed** engagement stays `approved` for ever, deferred once and never closed `[E: E8]`; a
  `capability_issued` proposal whose lease has lapsed is closed by a *resumed* `propose_action` that nothing
  calls, and `reconcile_stale_dispatches` does not see it `[E: E6]`.
* **A consequence of migration 0021 for this design:** a proposal stuck at `received` (a crash before the
  decision) can no longer be closed without a decision — the CHECK refuses it — so the reconciler cannot
  clean those up unless a decision is made about that (D64-5).

The proposal, in short (each is argued below and listed as a decision in §5): a **separate process** with its
**own database role** and **its own lock**, split like the scheduler into a read-only *plan* side and an *act*
side; **never** resumes, re-runs, re-issues or re-proposes anything (I7 and D58-6 stay where they are); acts on
Docker **only** on objects whose labels are confirmed by the database; audits **actions taken**, edge-triggered
by the fact that the state it changed cannot be found again.

## 1. Scope: what residue, and the safe thing to do with each

### 1.1 The residues, their cause, and what handles them today

| # | Residue | How it arises | Handled today | Evidence |
|---|---|---|---|---|
| R1 | proposal at `dispatching` (run row `running`), control plane gone | crash/kill/DB loss after the run row commits (D60) | `reconcile_stale_dispatches`, **tests only**: marks `dispatch_state`/`tool_runs` `unknown_outcome`, stage → `recorded`/`unknown_outcome`, audit `dispatch.unknown_outcome` (`requires_human_review`) | `[R]` `dispatch.py:1464`; callers `[R]` grep |
| R2 | the tool **container** of R1 still running | the control plane enforces `max_duration_seconds`, not the container | nothing | `[R]` `sandbox.py` `container.wait(timeout)`; `[E: E5]` |
| R3 | proposal at `capability_issued`, lease lapsed | crash between issue and dispatch | a **resumed** `propose_action` closes it (`capability_not_live`); nobody resumes; `reconcile_stale_dispatches` returns `[]` | `[E: E6]` |
| R4 | `approved`, approval expired/revoked | a human's yes outlives its validity | **resolved by the scheduler** if the engagement is servable (broker refuses → `closed: capability_refused:approval_expired`); not resolved if unenrolled | `[E: E7]`; `[R]` `approved_dispatch.py` |
| R5 | `approved`, engagement **killed** (one-way) | kill after approval | scheduler records `deferred` once and never closes it | `[E: E8]`; kill is one-way `[R]` `engagement.py:279` |
| R6 | `received` / `decided`, no further stage | crash in the decision stage or before issue | a resumed `propose_action` with the same key; nothing resumes | `[D]` D60 report §3; `[R]` `_drive` |
| R7 | orphan **egress proxy** container | control plane dies between `start_egress_proxy` and `stop_egress_proxy` | nothing | `[E: E4]`; `[D]` D59 report |
| R8 | sandbox **networks** | one per allowlist, never removed in production | `remove_network()` — **no caller** in `control_plane` | `[R]` grep; `[D]` ADR D58-13 |
| R9 | host **files**: credential mounts (`cyberorch-cred-*`, mode 0644) and proxy TLS leaf files (`cyberorch-tls-*`, 0600) | killed between write and the `finally` | nothing | `[E: E4]` (tls); `[D]` ADR X14/E12 (cred) |
| R10 | task claims with expired leases (X7) | worker dies holding a claim | nothing (`claim_task` never requeues) | `[D]` ADR X7 |

R10 is a different table with no tool run behind it and no I7 risk; it is **left out of this checkpoint** (a
small separate deliverable), and noted so that it is not forgotten.

### 1.2 R1/R2 — a stale dispatch (I7: never re-run)

**What `reconcile_stale_dispatches` does `[R]`:** for one engagement, rows whose `dispatch_state` is in
`IN_FLIGHT = (dispatching, running)` and `updated_at` older than a threshold become `unknown_outcome`; their
`tool_runs` rows too; the stage advances `dispatching → recorded` with detail `unknown_outcome`; one audit record
per proposal. It never starts anything.

**What is missing:**

1. **It looks at `dispatch_state`, not at Docker.** It cannot tell "the container finished and the control plane
   died before recording" from "the container is still running". For the second it declares an outcome unknown
   while the tool may still be acting, and nothing ends it (R2).
2. **No threshold can be right without the run's budget.** `max_duration_seconds` lives in
   `capabilities.budget` (default 600) `[R]`, not on `tool_runs`; the caller picks `older_than_seconds` by hand.
3. **It is per engagement and needs that engagement's connection** `[R]`; nothing enumerates engagements.
4. **It is not wired to anything.**

**Safe approach (proposal).** A dispatch is *overdue* when `now > stage_updated_at + budget.max_duration_seconds
+ G` (G a grace, see D64-3): a live dispatch is bounded by `container.wait(timeout)` plus the kill and the
recording, so past that point the process that started it is gone or stalled. For an overdue dispatch:

1. find the container(s) by the label `cyberorch.run_id` (not by name: tool containers have random names `[E: E5]`);
2. if one is running → **kill it** (it is ours and past its budget), keep the exited container for a retention
   window so a human can read its output (D64-4), then remove it later;
3. mark the run and the proposal `unknown_outcome`, stage `recorded` (the existing function's job) with
   `requires_human_review`;
4. **never** call `dispatch_*`, `propose_action`, `dispatch_approved` — the ladder to *try again* is D58-6.

The kill-and-remove is the one new *destructive* act on a thing the tool may still be doing; I7 forbids a silent
re-execution, not stopping an overdue process, and the kill switch's own gap (it does not stop a running
container, D44-7/D58-16 `[D]`) is the same gap seen from the other side.

### 1.3 R3 — `capability_issued`, lease lapsed

Nothing was started (the stage precedes `dispatching`, so there is no run row `[R]` `stages.py`; the resume in E6 made 0 container calls `[E]`), the capability can never be used
(its lease is the deadline `[R]` `broker.py`), and a resumed `propose_action` would end by closing it with
`capability_not_live` `[E: E6]`. **Safe action:** close it the same way — `closed`, detail `capability_not_live`,
conditional on `pipeline_stage = 'capability_issued'` and `lease_expires_at < now()` — which is exactly what the
resume would do, so the two cannot disagree. It is *known* not-run, so it is retryable by a re-proposal (D58-6).

### 1.4 R4/R5/R6 — `approved` and the early stages

* **R4 (approval expired/revoked):** the scheduler already resolves it when the engagement is servable `[E: E7]`.
  The gap is only for engagements the scheduler does not serve. A reconciler could close them, but it would be
  doing the dispatcher's job by a different route. *Proposal:* reconcile R4 only for rows the scheduler **cannot
  reach** (engagement not enrolled, or killed), with the broker's own reason (`approval_expired`).
* **R5 (killed engagement):** kill is one-way, so these can never run. *Proposal:* close with
  `engagement_killed` — data hygiene, and it takes them off the scheduler's "waiting" counts. A **paused**
  engagement is *not* touched: pause is reversible.
* **R6:** `received` and `decided` are resumable only by a caller holding the original arguments (reviewer,
  policy) — the reconciler does not. `decided` (an ALLOW, no capability) may be closed (`abandoned_after_decision`);
  **`received` cannot be closed** without a decision (0021) — see D64-5.
* `awaiting_approval` is a person's, not a fault; untouched.

### 1.5 R7–R9 — orphan resources

**Measured, not estimated (§6):**

| Question | Answer |
|---|---|
| How many networks can the daemon's **default pool** give? | **30** beyond the default bridge (14 × /16 from 172.18.0.0 to 172.31.0.0, then 16 × /20 from 192.168.0.0 to 192.168.240.0), then "all predefined address pools have been fully subnetted" `[E: E1]` |
| Does the sandbox use that pool? | **No.** Every sandbox network is created with an explicit subnet: the allowlist `[R]` `ensure_network`. So the 30 is irrelevant to `network.*` dispatch. |
| How many sandbox networks can exist? | **1,100 `/29` internal networks were created with no refusal** `[E: E2]`; creation cost grows (50 → 1.4 s, 400 → 17 s, 1,000 → 61 s cumulative), removal of the 1,100 took 189 s. No ceiling was reached; one may exist beyond that `[N]`. |
| What does bind? | **Overlap.** A leftover `/24` network makes a later `/29` inside it fail with `NetworkRangeConflict`; removing the `/24` makes it creatable `[E: E3]`. Overlap, not count, is the first thing a long-running system hits. |
| How many networks per engagement / allowlist? | **One per distinct allowlist**, shared by later runs and engagements (`network_name` hashes the sorted allowlist) `[R][E: E3]`. The scheduler dispatches `network.*` only against a `cidr` scope /29 or wider, using the scope as the allowlist `[R]`, so the count is the number of **distinct cidr scopes ever dispatched against**, not per engagement. A web action with a proxy would use **two** (tool side and target side) `[R]`; the scheduler does not dispatch `web.*`. CI's full suite leaves 6 `[D: CI run]`. |
| What does an orphan proxy do? | Keeps running with its labels; holds the tool-side network (another engagement's run on it → `NetworkInUse`; its owner's runs still work); `remove_network` is silent while it is attached; its **leaf cert + 0600 key stay in `/tmp`** `[E: E4]`. |

**Safe approach (proposal):**

* **Proxies / tool containers:** removable when the DB says the run is finished or absent *or* it is overdue
  (§1.2), identified by labels (`cyberorch.egress_proxy`, `cyberorch.run_id`, `cyberorch.owner`) cross-checked
  against `tool_runs`/`capabilities`. Their secret files go with them (`ProxyEndpoint.secret_files` is lost with
  the process, so files are swept by pattern: below).
* **Networks:** a network is removable when **no container of any state is attached** and it has been idle for a
  retention period (D64-8); removal races a concurrent `ensure_network` (the dispatch finds the network, the
  network is removed, `containers.create` fails with "network not found") — typed `NotStarted`, retryable, so
  safe but noisy. A second trigger: a `NetworkRangeConflict` caused by *our own* idle network should clear it
  (D64-8).
* **Files:** `/tmp/cyberorch-cred-*` and `/tmp/cyberorch-tls-*` older than a bound, not open by any process
  `[N: needs a way to check "open"]`; the *mode* (0644 credential mount) and a per-run `0700` directory are
  D58-17's decision, not this one's (D64-12).

### 1.6 The boundary with D58-6

| | **Reconcile (D58-9, this document)** | **Reopen / failure ladder (D58-6)** |
|---|---|---|
| Question | *What is true now, and is anything still holding resources?* | *Should we try this again, and how?* |
| Acts on | state that crashed or lapsed; Docker/host objects | a proposal that ended without a run, or a voided approval |
| Creates proposals/capabilities/approvals | **never** | yes (a new proposal, a new approval request) |
| Re-runs a tool | **never** (I7) | only by a new, newly authorized proposal |
| Output | a proposal in a terminal, *explained* state; resources freed; an audit record | a new proposal or a human task |

**The interface** is the reason code and one bit derived from it, written by the reconciler and read by D58-6:

| Reconciler outcome (reason code) | Known not-run? | Reopenable by a new proposal? |
|---|---|---|
| `capability_not_live` (R3) | yes | yes |
| `approval_expired`, `approval_revoked` (R4) | yes | yes — needs a **new approval** |
| `engagement_killed` (R5) | yes | **no** (one-way) |
| `abandoned_after_decision` (R6) | yes | yes |
| `unknown_outcome` (R1) | **no** — may have run | **only by a human** (I7) |

The reconciler records the code; it does not decide what to do with it.

## 2. Identity and permissions

The reconciler must (a) read stuck state across **all** engagements, (b) write stage/run state on those rows,
(c) delete Docker objects and host files. Row-level security is by `cyberorch.engagement_id`, and **every** table
is engagement-isolated, `engagements` included `[E]` (`pg_policies`), so "read across engagements" has no
existing path: the scheduler enumerates through its own `scheduler_enrollment` table `[R]`, which lists only
engagements an operator enrolled.

### 2.1 What `cyberorch_app` is, if the reconciler used it

`cyberorch_app` can `SELECT/INSERT/UPDATE/DELETE` `action_proposals`, `tool_runs`, `capabilities`, `approvals`;
`INSERT/SELECT` `audit_log`; `SELECT` `engagements` `[E: grants query]`. It is the runtime role every
`propose_action` runs as, and its isolation is the GUC each caller sets for itself. Using it would give a sweeper
the ability to issue and delete capabilities and delete proposals — far more than "close a stale row".

### 2.2 Options

| | **A. Inside the scheduler** | **B. Separate process, `cyberorch_app` per engagement** | **C. Separate process, own role `reconciler`, one process** | **D. Separate process, own role, split plan / act (like D62)** |
|---|---|---|---|---|
| DB identity | the scheduler's roles (`scheduler_reader`, `scheduler_state_writer`) + the runtime role for dispatch | `cyberorch_app` | a new narrow role | a read-only `reconciler_reader` (stuck rows, cross-engagement) + a write path through narrow functions or `engagement_scope` |
| New privileges | writes on `action_proposals`/`tool_runs` for the scheduler | none | column-level `UPDATE` on stage/dispatch columns, `tool_runs.status`, `INSERT` audit; read policy for stuck stages | the same, split across two roles |
| Docker | the scheduler's (already has the socket) | its own | its own | the **act** side only |
| Lock | shared (`SingletonLock`) | own key | own key | own key |
| For | one deployable; the lock already excludes a second copy; startup reconcile-then-resume (R-A) is a function call | no schema/role change | least privilege; a bug in the sweeper cannot issue a capability | the strongest separation; a decision can be inspected before it is carried out (as `--dry-run`) |
| Against | breaks D62's structural property: the decision side imports only `scheduler_reader` and the execution side only `engagement_scope`, pinned by AST tests `[R]` `test_scheduler_structure.py`; the scheduler would acquire stage-write and Docker-delete powers; a reconciler bug stops dispatch (same process); the serial loop would block on a long removal | the broadest privilege for the least-needed work; cross-engagement enumeration still unsolved | one process holds both "decide" and "delete" | two roles, two connections, more migration; slower to build |

**Can it touch `cyberorch_app`'s connection?** Technically yes (B); the question is whether it should. My
recommendation is **no**: a role that can only do what a reconcile does (C/D). That costs one migration (a role
plus grants, in the shape of 0019) and one more structural test (the reconciler imports no dispatch code).

### 2.3 Reading across engagements

Three ways, none of which exists:

* **(i) the enrollment table only** — free, but misses stuck rows in un-enrolled and withdrawn engagements (the
  very ones the scheduler will never touch);
* **(ii) a read-only policy for the reconciler role** on the stuck stages, no GUC needed
  (`USING (pipeline_stage IN ('dispatching','capability_issued','approved','decided','received'))`), with
  column-level `SELECT` so it sees ids, stage, age and budget but not targets or reasons — the way
  `scheduler_reader` is limited today `[R]`;
* **(iii) a list of engagement ids** the reconciler maintains from `audit_log` global events — circular.

*Recommendation:* (ii).

### 2.4 Deleting Docker objects: what the boundary is, and what forges it

Docker's socket offers **no per-object authorization**: whoever can reach it can delete any container `[N]`. So
the boundary is in the reconciler's code and data, in three layers:

1. **Selection by label, never by name or prune.** Tool containers carry `cyberorch.run_id` and
   `cyberorch.owner`; proxies add `cyberorch.egress_proxy`; networks carry `cyberorch.allowlist` and the name
   prefix `cyberorch-allow-` `[R]`. No `docker prune`, no deletion by name pattern alone.
2. **Cross-check against the database.** A container is removable only if its `run_id` is a run the DB knows to
   be finished, absent, or overdue (§1.2). A label on a container the DB has never heard of is **reported**,
   not removed. Containers with `owner == NO_OWNER` (probes and lab scripts `[R]`) are report-only.
3. **Networks:** only networks whose name and label match *and* with no attached container.

**Who can write the labels?** Whoever creates the container: the sandbox (control plane), or anyone with the
Docker socket. Docker has no API to add a label to an *existing* container `[N]`, so the reconciler can never be
tricked into deleting a victim's container that did not already carry our labels; a party who can create
containers with our labels can already do anything on the host (socket = root `[N]`), so a forged label is not an
escalation — the realistic failure is an accidental lookalike (a lab container someone labelled `cyberorch.*`),
which layer 2 turns into a report. Tool containers have no socket mounted `[R]` (no `docker.sock` anywhere in the
tree). **Optional hardening (D64-9):** a signed label `cyberorch.sig = HMAC(key, run_id|owner|created)` with a
key only the control plane and reconciler hold, so that "ours" is verifiable and not merely asserted; cost: a key
to distribute and rotate.

### 2.5 The host files

The reconciler runs as a host user that can delete files under `/tmp` it can read the names of; the credential
files are 0644 and the TLS leaf files 0600 owned by the control plane's uid `[E: E4]`. A sweeper in another uid
cannot delete the 0600 files — so either it runs as the control plane's user, or the files move to a per-run
`0700` directory the reconciler's group owns (D58-17's decision, D64-12).

## 3. Relation to scheduler v0

* **What the scheduler leaves for it.** `scheduler.started` reports `dispatching` and `capability_issued` per
  enrolled engagement and `approved_waiting`/`approved_redispatch` `[R]`; it acts on none. The reconciler is the
  consumer of those numbers.
* **Start order (ADR D58-9 lean R-A, reconcile-then-resume `[D]`).** A scheduler that starts while R1/R3 rows
  exist dispatches new work on top of unexplained state. Options: (a) the reconciler runs **once, to completion,
  before** the scheduler starts (an operator/`systemd` ordering), then periodically; (b) the scheduler refuses to
  start if the reconciler's last pass is older than its own last stop (a marker row); (c) the scheduler runs the
  reconcile pass itself before its loop (option A of §2.2).
* **One lock or two?** *One shared key* excludes the two at once by construction (no interference to reason
  about) but a long reconcile blocks dispatch and the reverse. *Two keys* let them overlap, which needs the
  argument below.

### 3.1 Can they interfere?

The scheduler only moves `approved → capability_issued → dispatching → recorded/closed`, all inside one
`dispatch_approved` call `[R]`. Row by row:

| Reconciler touches | Scheduler might be doing | Why it is safe |
|---|---|---|
| `capability_issued`, lease lapsed → `closed: capability_not_live` | issuing/dispatching the same row | the update is conditional on the stage and on `lease_expires_at < now()`; a lapsed lease means the dispatch would refuse the same row with the same reason `[E: E6]` — both paths end identically |
| `dispatching`, overdue → `unknown_outcome` | the same dispatch, still recording | overdue = past `max_duration_seconds + G`; a live dispatch is bounded by `container.wait(timeout)` + kill; if the scheduler is stalled *past* that point its later `advance(expected=DISPATCHING)` loses (the stage guard), the result is lost but **flagged unknown** — never silently double |
| `approved`, killed engagement/expired approval → `closed` | about to dispatch it | the scheduler re-reads the engagement right before acting (`servable_now`) and `dispatch_approved` refuses killed/expired itself `[R]`; the reconciler's close is `advance(expected=APPROVED)` — whichever commits first wins, the other matches no row |
| removing a container/proxy/network | a dispatch that has just created it | removal requires "the DB says finished/absent/overdue", and a brand-new run has a `running` row inside its deadline |
| removing an idle network | `ensure_network` has just returned it | a race (§1.5): the create fails as `NotStarted`, retryable; avoided by an idle-retention period long compared with a dispatch |

So two locks are *safe given* the conditional updates and the deadlines; one shared lock is *simpler*. The
decision is D64-10.

## 4. Audit

Same rules as D62 `[D: D62 report]`: a **closed list** of events; payloads of **ids, closed reason codes and
counts only** (no target, CIDR, command or path); each event has a schema and `emit` refuses anything else;
every closed-code column a CHECK that excludes NULL where a code is required (ACCEPTANCE 5.69); and
**edge-triggered**.

**Edge-triggering needs no new state table if only actions taken are audited:** closing a proposal, killing a
container, removing a network all change the thing that would be found next time, so the same fact cannot be
reported twice. The only repeating observations would be "found, not acted on" (inside its deadline, report-only
owner, in use); those are **logged, not audited**, or, if audited, recorded once per object per process
lifetime in memory (a restart reports once more — stated, not hidden). If an operator needs "reported once,
ever", that is a `reconciler_state` table like `scheduler_state` (D64-11).

Proposed vocabulary (names are proposals):

| Event | Scope | Payload | Reason codes (closed) |
|---|---|---|---|
| `reconciler.started` | global | `instance_id`, counts per residue class | — |
| `reconciler.stopped` | global | `instance_id`, `reason_code` | `signal`, `lock_lost`, `db_lost`, `docker_lost`, `audit_failed`, `unexpected_error` |
| `reconciler.start_refused` | global | `instance_id`, `reason_code` | `lock_held` |
| `reconciler.proposal_closed` | engagement | `proposal_id`, `reason_code` | `capability_not_live`, `approval_expired`, `approval_revoked`, `engagement_killed`, `abandoned_after_decision` |
| `reconciler.container_removed` | engagement (owner known) / global | `run_id`, `reason_code` | `overran_deadline`, `run_finished`, `no_run_row_past_grace` |
| `reconciler.proxy_removed` | engagement / global | `run_id`, `reason_code` | `owner_run_ended`, `overran_deadline` |
| `reconciler.network_removed` | global | `network_id` (the hash in the name), `reason_code` | `idle_past_retention`, `blocks_overlapping_range` |
| `reconciler.files_removed` | global | `kind`, `count` | kinds `credential_mount`, `tls_leaf` |
| `reconciler.removal_failed` | global | `kind`, `reason_code` | `in_use`, `daemon_error` |

`dispatch.unknown_outcome` (the existing event, `requires_human_review`) is **kept as the record of an
unresolved run** — the reconciler calls the existing function and does not invent a second event for it.

## 5. Decisions (D58 format; ⚑ = needs your answer)

Recommendation in the third column; "depends on" in the last.

| # | Question | Recommendation and why | Depends on |
|---|---|---|---|
| **D64-1** ⚑ | Process and identity (§2.2): A inside the scheduler / B separate with `cyberorch_app` / C separate, own role / D separate, own role, plan–act split | **D** (C if you want it smaller). Least privilege, and it keeps D62's decide/execute separation (pinned by AST tests) intact. A is cheapest and breaks that property; B grants far more than the work needs (it can issue and delete capabilities). | — |
| **D64-2** ⚑ | How the reconciler reads across engagements (§2.3) | **(ii)** a read-only policy for the new role on the stuck stages with column-level `SELECT` (ids, stage, age, budget). (i) misses un-enrolled engagements. | D64-1 |
| **D64-3** ⚑ | The overdue thresholds | `dispatching`: `stage_updated_at + budget.max_duration_seconds + G`; `capability_issued`: `lease_expires_at + G'`. Proposal **G = 120 s, G' = 30 s** `[N]` — these are numbers to choose, not measured; the budget is read from the capability, never guessed. | D64-1 |
| **D64-4** ⚑ | An overdue **running** container | **Kill it, keep the exited container a retention window (24 h `[N]`), remove after.** I7 forbids silent re-execution, not stopping an overdue process; keeping the corpse preserves the only evidence of what ran. Alternative: remove at once (frees the network now, loses the evidence). | D64-3 |
| **D64-5** ⚑ | Stuck `received` (no decision) can no longer be closed (0021's CHECK) | (a) **leave them**, report their age; or (b) extend the CHECK to allow `closed` without a decision when `stage_detail` starts `abandoned_` — a one-line migration but it re-opens the "closed with no decision" shape 0021 closed. **(a)**: a proposal nobody decided is not a state the database should be asked to bless; D58-6 owns re-driving them. | D58-6 |
| **D64-6** | `capability_issued` with a lapsed lease: close it (`capability_not_live`)? | **Yes** — exactly what a resumed `propose_action` does `[E: E6]`; known not-run. | D64-1 |
| **D64-7** | `approved` rows: which to close | Only those the scheduler **cannot reach**: engagement killed (`engagement_killed`), or not enrolled with an expired/revoked approval. Leave paused. For servable engagements the scheduler already resolves expiry `[E: E7]`. | D64-1 |
| **D64-8** ⚑ | Sandbox networks (§1.5) | Remove a network when it has **no attached container of any state** and has been idle **1 h `[N]`**; also remove one that causes a `NetworkRangeConflict` for a new allowlist if it is idle (self-heal of the overlap case). Alternatives: never remove, alarm on count (overlap still bites, E3); a network per run (a sandbox redesign; out of scope). | D64-1, D64-10 |
| **D64-9** | Label integrity (§2.4) | **DB cross-check mandatory; `NO_OWNER` report-only; no HMAC yet.** Add the signed label when more than one tenant shares the Docker host. | D64-1 |
| **D64-10** ⚑ | Start order and locks (§3) | **One-shot reconcile to completion before the scheduler starts, then periodic; two lock keys** (the safety argument is §3.1). One shared key is simpler but makes a long reconcile and dispatch exclude each other. | D64-1 |
| **D64-11** | A `reconciler_state` table for "reported once, ever"? | **No** for now: audit actions taken only (§4); the observation-only cases are logged. Add the table if an operator needs the deferred-style record D62 has. | — |
| **D64-12** | Host files | The reconciler sweeps `cyberorch-cred-*` and `cyberorch-tls-*` by prefix and age. The *mode* and a per-run `0700` directory are **D58-17's**, to be decided with it; until then the sweeper must run as the control plane's uid to delete the 0600 files. | D58-17 |
| **D64-13** | Excluded from this deliverable | R10 (task claims, X7), the failure ladder / reopen (D58-6), quotas (D58-13), credentialed-dispatch kill (D58-16). | — |

Order of dependence: D64-1 first; D64-2, 3, 6, 7, 9, 10 follow from it; D64-4 from D64-3; D64-8 from D64-1 and
D64-10; D64-5 and D64-12 wait on D58-6 and D58-17.

## 6. Experiments

All run on this machine (Docker 29.3.1, default configuration, PostgreSQL 16), with cleanup afterwards; the
scripts are in the session's scratch area, not in the repository.

| # | What | Result |
|---|---|---|
| **E1** | create networks with **no subnet** until the daemon refuses | 30 created (172.18–172.31 as /16, 192.168.0–240 as /20), then `all predefined address pools have been fully subnetted` (1.6 s) |
| **E2** | create internal networks with an **explicit /29 each** (what `ensure_network` does) up to 1,100 | all 1,100 created; cumulative 1.4 s @50, 3.1 s @100, 6.8 s @200, 16.7 s @400, 43.5 s @800, 61 s @1,000; removal 189 s |
| **E3** | `DockerSandbox.ensure_network` for a /24 then a /29 inside it; then remove the /24 | `NetworkRangeConflict` for the /29; the same allowlist gives the same network name; after the /24 is removed the /29 is created |
| **E4** | start an egress proxy for engagement A in a child process, `kill -9` the child; then try engagement B and A on the tool-side network; `remove_network` | proxy container still `running` with labels `cyberorch.egress_proxy=1`, `cyberorch.owner=ENG-A`, `cyberorch.run_id=…`; **leaf cert and key still in `/tmp` (`cyberorch-tls-*.pem`, 0600)**; B → `NetworkInUse`; A → ran, exit 0; `remove_network` left the network in place |
| **E5** | `DockerSandbox.run(... max_duration_seconds=5)` of a listener in a child, `kill -9` the child at 3 s | the container (random name, label `cyberorch.run_id`) was `running` at +0 s, +10 s and **+25 s** — nothing bounds it once the control plane is gone |
| **E6** | a proposal at `capability_issued` (fault before the run row commits), lease set into the past by the owner; run `reconcile_stale_dispatches`; resume `propose_action` | `reconcile_stale_dispatches` → `[]`; the resume → `closed`, detail `capability_not_live`, 0 container calls |
| **E7** | an `approved` proposal whose approval is shortened into the past (the trigger allows shortening), engagement enrolled; two ticks | the scheduler dispatched it once; the broker refused; `closed: capability_refused:approval_expired`; 0 container calls; the second tick found nothing |
| **E8** | an `approved` proposal in a **killed** engagement; three ticks | `deferred` once, then nothing; stage still `approved` |

Not run: the 2-minute node-delete cost (ACCEPTANCE 5.23) was measured at D63; the stale credential file
(`cyberorch-cred-*`) was not reproduced here (`[D]` ADR E12 recorded it at D58); a Docker restart's effect on
networks (would they survive a daemon restart with their containers?) was not tested `[N]`.

## 7. What this document does not do

It writes no code, no migration and no test. It does not pick values for G, the retention windows or the idle
period (they are labelled `[N]` and listed as decisions). It does not decide D58-6, D58-13, D58-16 or D58-17; it
names where it depends on them. Once you have answered §5 (⚑), the build is: a role and grants (one migration, in
the shape of 0019), a `control_plane/reconciler` package split like `scheduler` (plan / act / emit / lock), one
operator script, and tests that fail every boundary (the way `tests/test_decision_boundaries.py` does for the
decision stage), a structural test that the reconciler imports no dispatch code, and the residue check
(`tests/residue.py`) extended to the objects it manages.
