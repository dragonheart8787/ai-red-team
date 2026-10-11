# D64 — The reconciler (D58-9): design checkpoint (revision 2)

**Status: design only.** No code, migration or test is written or changed by this document. Everything below
the line "Decisions" is a proposal waiting for answers; nothing is built until they are given.

**How claims are tagged.** `[R]` read in the code at this commit; `[E]` executed here, on this machine, with the
experiment named in §6; `[D]` taken from an older document (named); `[N]` not verified — knowledge or reasoning
that I have not checked against this system.

**What revision 2 changes** (each was asked for; the experiments behind them are §6 E9–E16):

1. ACCEPTANCE 5.72 now says what was measured: the address pool is not the limit, range overlap is (§1.5).
2. D64-5 becomes a new terminal stage `abandoned`, with the design of migration 0022 and a grace period (§1.8).
   The experiments found two things the first draft would have got wrong: a CHECK that passes on NULL (the
   5.69 trap), and a caller that loses a race to the reconciler is told `DENY` with no reason (E9, E10).
3. Every overdue threshold is now derived from the capability's budget, and §2.3 says how the reconciler is
   allowed to read a budget at all (E11, E12).
4. §2.4 is rewritten as the Docker permission boundary and the real limits of label-forgery protection (E13).
5. Every deletion is verified afterwards; §1.7 lists the verification for each (E14).
6. The deadline inside the container is listed as a separate deliverable candidate, with the `kill -9`
   experiment (§8, E15–E16).
7. The thirteen decisions of §5 are also given one line each in the reply.

## 0. In one page

The scheduler (D62 v0) **observes** stuck proposals and acts on none of them: `scheduler.started` reports how
many are `dispatching` and `capability_issued`, then goes on `[R]`. Nothing else in the tree repairs a crash:
`reconcile_stale_dispatches` is called by tests only `[R]`, and nothing sweeps a container, a network or a file
`[R][E]`. What the experiments added to what was already written down:

* **A killed control plane leaves a tool container running past its budget.** The run's `max_duration_seconds`
  is enforced by the control plane's own `container.wait(timeout)`; there is no timer inside the container. A
  container started with a 5 s budget was still running 21 s after its parent was `kill -9`'d (25 s in the first
  run) `[E: E16-A, E5]`.
  Docker itself has no maximum-lifetime option `[E: E15]`.
* **An orphaned egress proxy holds its network against every other engagement** (`NetworkInUse`), keeps
  running, and leaves its **TLS leaf certificate and private key** in `/tmp`; `remove_network` quietly does
  nothing while it is attached `[E: E4, E14]`.
* **The sandbox's networks use the allowlist itself as their subnet**, so the daemon's default address pool
  (30 networks) is *not* what limits them; 1,100 `/29` networks were created without a refusal. What does bind
  is **overlap**: a network left behind for a `/24` makes a later `/29` inside it fail with
  `NetworkRangeConflict` until someone removes it `[E: E1–E3]`.
* **Three of the four "stuck" states are not all stuck.** An `approved` proposal whose approval has expired
  *is* resolved by the scheduler `[E: E7]`; an `approved` proposal in a **killed** engagement stays `approved`
  for ever `[E: E8]`; a `capability_issued` proposal whose lease has lapsed is closed only by a *resumed*
  `propose_action` that nothing calls `[E: E6]`.
* **A consequence of migration 0021:** a proposal stuck at `received` can no longer be closed without a
  decision. The answer proposed here is a new terminal stage, `abandoned` (§1.8, migration 0022), not a
  loosening of `closed`.
* **A time bound is not a number to type in.** No ceiling on `max_duration_seconds` exists in the broker `[R]`,
  so a constant would be wrong in both directions. Every bound below is `budget + a term built from client
  timeouts in the code`, and the reconciler reads the budget through one narrow function, not the table (§1.2,
  §2.3).

The proposal, in short (each is argued below and listed as a decision in §5): a **separate process** with its
**own database role** and **its own lock**, split like the scheduler into a read-only *plan* side and an *act*
side, the plan reading through one `SECURITY DEFINER` function; **never** resumes, re-runs, re-issues or
re-proposes anything (I7 and D58-6 stay where they are); acts on Docker **only** on objects whose labels are
confirmed by the database, by full container id, re-inspected immediately before; **verifies every removal
afterwards** and audits only what it verified.

## 1. Scope: what residue, and the safe thing to do with each

### 1.1 The residues, their cause, and what handles them today

| # | Residue | How it arises | Handled today | Evidence |
|---|---|---|---|---|
| R1 | proposal at `dispatching` (run row `running`), control plane gone | crash/kill/DB loss after the run row commits (D60) | `reconcile_stale_dispatches`, **tests only**: marks `dispatch_state`/`tool_runs` `unknown_outcome`, stage → `recorded`/`unknown_outcome`, audit `dispatch.unknown_outcome` (`requires_human_review`) | `[R]` `dispatch.py:1464`; callers `[R]` grep |
| R2 | the tool **container** of R1 still running | the control plane enforces `max_duration_seconds`, not the container | nothing | `[R]` `sandbox.py` `container.wait(timeout)`; `[E: E5, E16-A]` |
| R3 | proposal at `capability_issued`, lease lapsed | crash between issue and dispatch | a **resumed** `propose_action` closes it (`capability_not_live`); nobody resumes; `reconcile_stale_dispatches` returns `[]` | `[E: E6]` |
| R4 | `approved`, approval expired/revoked | a human's yes outlives its validity | **resolved by the scheduler** if the engagement is servable (broker refuses → `closed: capability_refused:approval_expired`); not resolved if unenrolled | `[E: E7]`; `[R]` `approved_dispatch.py` |
| R5 | `approved`, engagement **killed** (one-way) | kill after approval | scheduler records `deferred` once and never closes it | `[E: E8]`; kill is one-way `[R]` `engagement.py:279` |
| R6 | `received` (no decision) / `decided` (ALLOW, no capability), no further stage | crash in the decision stage or before issue | a resumed `propose_action` with the same key; nothing resumes | `[D]` D60 report §3; `[R]` `_drive`; 152 such `received` rows older than an hour sit in this machine's development database `[E: E9]` |
| R7 | orphan **egress proxy** container | control plane dies between `start_egress_proxy` and `stop_egress_proxy` | nothing | `[E: E4]`; `[D]` D59 report |
| R8 | sandbox **networks** | one per allowlist, never removed in production | `remove_network()` — **no caller** in `control_plane`, and it swallows failure | `[R]` grep; `[E: E14]`; `[D]` ADR D58-13 |
| R9 | host **files**: credential mounts (`cyberorch-cred-*`, mode 0644) and proxy TLS leaf files (`cyberorch-tls-*`, 0600) | killed between write and the `finally` | nothing | `[E: E4]` (tls); `[D]` ADR X14/E12 (cred) |
| R10 | task claims with expired leases (X7) | worker dies holding a claim | nothing (`claim_task` never requeues) | `[D]` ADR X7 |

R10 is a different table with no tool run behind it and no I7 risk; it is **left out of this checkpoint** (a
small separate deliverable), and noted so that it is not forgotten.

### 1.2 R1/R2 — a stale dispatch, and where the time bounds come from (I7: never re-run)

**What `reconcile_stale_dispatches` does `[R]`:** for one engagement, rows whose `dispatch_state` is in
`IN_FLIGHT = (dispatching, running)` and `updated_at` older than a threshold become `unknown_outcome`; their
`tool_runs` rows too; the stage advances `dispatching → recorded` with detail `unknown_outcome`; one audit
record per proposal. It never starts anything.

**What is missing:**

1. **It looks at `dispatch_state`, not at Docker.** It cannot tell "the container finished and the control plane
   died before recording" from "the container is still running". For the second it declares an outcome unknown
   while the tool may still be acting, and nothing ends it (R2).
2. **Its threshold is typed in by the caller** (`older_than_seconds`). No fixed number can be right: the budget
   is `capabilities.budget.max_duration_seconds`, default 600, set by the caller of `propose_action`
   (120 there, 120 for the approval path), and **nothing in the broker bounds it** `[R]` (`broker.py`: the only
   use is `lease = min(ttl, max_duration)` and the renewal cap `issued_at + max_duration`). A run may legally be
   given a budget of a day.
3. **It is per engagement and needs that engagement's connection** `[R]`; nothing enumerates engagements.
4. **It is not wired to anything.**

**The bounds, derived.** A dispatch has three phases; each has a bound that comes from a number in the code or
from the capability:

| Phase | What bounds it | Value |
|---|---|---|
| before the container runs | every Docker call made by `DockerSandbox.run` has the docker-py client timeout, `DEFAULT_TIMEOUT_SECONDS = 60` `[E: E15]`; `run` makes at most 7 such calls before `wait` (`images.get`, `networks.get`, `networks.create`, `containers.create`, `containers.list`, `attach_socket` only with stdin, `start`) `[R]`; a proxy run adds the target-side network (2 calls) and `start_egress_proxy` (`images.get`, `create`, `connect`, `start`, `reload`, a 15 s readiness wait whose last poll is one more call) — 8 calls and 15 s `[R]` | `P` ≤ 7 × 60 s = 420 s (proxy run: + 8 × 60 s + 15 s = 915 s) |
| the run | `container.wait(timeout=max_duration_seconds)`, then `kill()` | `B` = the capability's `max_duration_seconds` |
| after the run | `kill`, `logs` × 2, `remove`: 4 calls `[R]` (a proxy run: + 1 call to remove the proxy); then the DB writes | `Q` ≤ 4 × 60 s = 240 s (proxy run: 300 s) |

Two different judgements use them, and they must not share a threshold:

* **Kill the container** (R2). The control plane's own `wait` starts within milliseconds of `start`, so a
  container that is *still running* at `State.StartedAt + B + K` — K = 60 s, the longest the control plane's own
  `kill()` is allowed — has outlived its owner's ability to stop it. The container's own start time comes from
  Docker, not from a guess about the database. `T_kill = StartedAt + B + 60 s`.
* **Declare the proposal's outcome unknown** (R1). This is a database fact about whether a *live* driver can
  still be about to write; it must cover the slowest honest driver: `T_unknown = stage_updated_at + B + P + Q`,
  which is `B + 660 s` for an ordinary run (`B + 1,215 s` with a proxy). **These are upper bounds read from the
  code, not measured worst cases `[N]`**; a typical run starts its container in under a second `[E: E16]`.
  They are computed from `docker.constants.DEFAULT_TIMEOUT_SECONDS` and from the call counts, not copied, so
  a change in either changes the bound. A wrong guess is bounded by the stage guard (§3.1), not safe by luck.

If the budget cannot be read (no capability row for the proposal; a value ≤ 0), the plan **does not guess**: it
reports the row and does nothing to it.

For an overdue dispatch:

1. find the container(s) by the label `cyberorch.run_id` (not by name: tool containers have random names
   `[E: E5]`);
2. if one is running past `T_kill` → **kill it**, keep the exited container for a retention window (D64-4) so a
   human can read its output, then remove it later (§1.7);
3. past `T_unknown`: mark the run and the proposal `unknown_outcome`, stage `recorded` (the existing function's
   job) with `requires_human_review`;
4. **never** call `dispatch_*`, `propose_action`, `dispatch_approved` — the ladder to *try again* is D58-6.

The kill is the one new *destructive* act on a thing the tool may still be doing; I7 forbids a silent
re-execution, not stopping an overdue process, and the kill switch's own gap (it does not stop a running
container, D44-7/D58-16 `[D]`) is the same gap seen from the other side. If the control plane is in fact alive
but slow, the reconciler's kill makes its `wait` return an exit code instead of `timed_out`: the run is
recorded as failed, not as timed out — a cosmetic difference, stated.

### 1.3 R3 — `capability_issued`, lease lapsed

Nothing was started (the stage precedes `dispatching`, so there is no run row `[R]` `stages.py`; the resume in
E6 made 0 container calls `[E]`), the capability can never be used (its lease is the deadline `[R]`
`broker.py`), and a resumed `propose_action` would end by closing it with `capability_not_live` `[E: E6]`.
**Safe action:** close it the same way — `closed`, detail `capability_not_live`, conditional on
`pipeline_stage = 'capability_issued'` and `lease_expires_at < now() - G'` — which is exactly what the resume
would do, so the two cannot disagree. The lease is itself derived from the budget (`min(ttl, max_duration)` at
issue; renewal cannot pass `issued_at + max_duration`) `[R]`. G' = 30 s is **not** a safety parameter: a driver
that is alive and about to dispatch takes the stage with a conditional update, and whoever commits first wins
(§3.1). It is known not-run, so it is retryable by a re-proposal (D58-6).

### 1.4 R4/R5 — `approved`

* **R4 (approval expired/revoked):** the scheduler already resolves it when the engagement is servable
  `[E: E7]`. The gap is only for engagements the scheduler does not serve. A reconciler could close them, but
  it would be doing the dispatcher's job by a different route. *Proposal:* reconcile R4 only for rows the
  scheduler **cannot reach** (engagement not enrolled, or killed), with the broker's own reason
  (`approval_expired`), judged from `approvals.valid_until` — an approval's own validity, not a capability
  budget.
* **R5 (killed engagement):** kill is one-way, so these can never run. *Proposal:* close with
  `engagement_killed` — data hygiene, and it takes them off the scheduler's "waiting" counts. A **paused**
  engagement is *not* touched: pause is reversible.
* `awaiting_approval` is a person's, not a fault; untouched.

R6 (`received`, `decided`) is §1.8.

### 1.5 R7–R9 — orphan resources

**Measured, not estimated (§6):**

| Question | Answer |
|---|---|
| How many networks can the daemon's **default pool** give? | **30** beyond the default bridge (14 × /16 from 172.18.0.0 to 172.31.0.0, then 16 × /20 from 192.168.0.0 to 192.168.240.0), then "all predefined address pools have been fully subnetted" `[E: E1]` |
| Does the sandbox use that pool? | **No.** Every sandbox network is created with an explicit subnet: the allowlist `[R]` `ensure_network`. So the 30 is irrelevant to `network.*` dispatch. The earlier estimate in ACCEPTANCE 5.72 (pool exhaustion as the symptom) was wrong and is corrected there. |
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
  (D64-8) — this is the case that actually occurs. The reconciler must **not** call
  `DockerSandbox.remove_network`: it returns nothing and swallows every error `[E: E14]`; it uses the Docker
  API directly and verifies (§1.7).
* **Files:** `/tmp/cyberorch-cred-*` and `/tmp/cyberorch-tls-*` older than a bound, regular files owned by the
  expected uid, never symlinks (§1.7); the *mode* (0644 credential mount) and a per-run `0700` directory are
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

| Reconciler outcome (stage, reason code) | Known not-run? | Reopenable by a new proposal? |
|---|---|---|
| `closed` / `capability_not_live` (R3) | yes | yes |
| `closed` / `approval_expired`, `approval_revoked` (R4) | yes | yes — needs a **new approval** |
| `closed` / `engagement_killed` (R5) | yes | **no** (one-way) |
| `closed` / `abandoned_after_decision` (R6, `decided`) | yes | yes |
| `abandoned` / `undecided_past_grace` (R6, `received`) | yes — never decided | yes, by a **new key** (the old key answers "abandoned") |
| `recorded` / `unknown_outcome` (R1) | **no** — may have run | **only by a human** (I7) |

The reconciler records the code; it does not decide what to do with it.

### 1.7 Every removal is verified afterwards

A reply of "done" from a Docker call, a `unlink` or an `UPDATE` is not the fact. The design rule is:
**act → verify, independently of the call's own return value → audit only what was verified.** An
`…_removed` / `…_closed` audit event therefore means *the thing was seen to be gone (or changed)*, and a failed
verification is an `action_failed` event and a retry on the next pass, never a silent success. The rule is
testable by fault injection (the way `tests/test_decision_boundaries.py` does for the decision stage): make the
call report success without doing it and require `action_failed`, not `*_removed`.

| Action | How it is done | Verification (a second, independent observation) | If verification fails |
|---|---|---|---|
| close / abandon / mark unknown a **proposal** | one conditional `UPDATE … WHERE pipeline_stage = :expected AND stage_updated_at = :planned RETURNING` — compare-and-set on what the plan observed (E12-C2) | after commit, a **new connection** re-reads `(pipeline_stage, stage_detail)` and requires the expected pair; `RETURNING` alone proves only this transaction | `action_failed` `not_changed_after_update`; nothing else is attempted for the row |
| **kill** a running container | `container.kill()` by full id | `inspect` → `State.Running == false`, polled for ≤ 10 s | `action_failed` `still_running_after_kill` |
| **remove** a container | `remove(force=True)` by full id, after `inspect` shows the labels and id still match (§2.4) | `containers.get(id)` raises `NotFound` **and** `containers.list(all=True, filters={"id": id})` is empty `[E: E14-V2]` (187 ms for a running one) | `action_failed` `not_gone_after_removal` |
| remove an **egress proxy** | as a container, then its TLS leaf files | container verification above; the tool-side network's attached-container list no longer names it; file verification below | as the failing part |
| remove a **network** | Docker API `remove()` (never `DockerSandbox.remove_network`), only when no container of any state is attached | `networks.get(name)` raises `NotFound` `[E: E14-V1]`. The existing helper returned `None` and left the network in place while a container was attached — only this check sees it | `action_failed` `in_use` if Docker refused, else `not_gone_after_removal` |
| remove a **host file** | `lstat` through a directory fd: must be a regular file, not a symlink, owned by the expected uid, name matching the pattern, older than the bound; `unlink(name, dir_fd=…)` | `lstat` again → `FileNotFoundError` `[E: E14-V3]`; a symlink is *skipped and reported*, its target untouched | `action_failed` `not_gone_after_removal` |
| the **pass as a whole** | — | the plan is recomputed after acting and must not contain anything acted on in this pass | `reconciler.stopped` is not affected; the leftover set is counted in the next `reconciler.started` |

A failed action is retried on the next pass; to keep a stuck object from filling the audit log, a given
`(object, reason_code)` is audited once per process lifetime and counted thereafter (a restart reports once
more — stated, not hidden; D64-11).

### 1.8 R6 — the terminal stage `abandoned`, migration 0022, and the grace period

*Why a new stage, not a looser `closed`.* Migration 0021 made `closed` (and every stage past `received`) require
a decision. A proposal stuck at `received` has none, and "closed" would say a decision was made. The first
draft left them alone; this one gives them a terminal stage of their own, so that **"undecided" and "abandoned"
are visible in the stage and the database still refuses `closed` without a decision.** (The revision request said "see above" for the definition of `abandoned`; no earlier message carrying a definition is available to me, so this section is built from the D64-5 question it answers, and the definition below is the one to confirm or correct.)

**Definition.** `abandoned` is terminal. It is reached only from `received`, only by the reconciler, only when no
decision exists, and carries `stage_detail = 'undecided_past_grace'`. Nothing ran, nothing was decided, no
capability exists. It is the *known not-run* shape D58-6 reads.

**Migration 0022 (one transaction, proposed text — not written).**

| Step | Statement | Why |
|---|---|---|
| 1 | replace `action_proposals_pipeline_stage_check` with the list plus `'abandoned'` | the stage must be legal |
| 2 | replace `action_proposals_decision_past_received` with `decision IS NOT NULL OR pipeline_stage IN ('received','abandoned')` | the one legal NULL stage list grows from `{received}` to `{received, abandoned}`; `closed` still cannot be undecided `[E: E9-A4]` |
| 3 | add `action_proposals_abandoned_is_undecided`: `pipeline_stage <> 'abandoned' OR (decision IS NULL AND stage_detail IS NOT NULL AND stage_detail = 'undecided_past_grace')` | an abandoned row has no decision and the one reason code. **The `IS NOT NULL` is not decoration:** written as `… AND stage_detail = '…'` the CHECK passes on a NULL detail, and `abandoned` with no reason was accepted `[E: E9-A11]` — the 5.69 rule, met a second time |
| 4 | rebuild `action_proposals_open_stage` with `NOT IN ('recorded','closed','abandoned')` | otherwise every abandoned row stays in the "open" index for ever `[E: E9-A9]` |
| 5 | `COMMENT ON COLUMN … pipeline_stage` updated | the documentation of the stage list |

*Upgrade* only relaxes constraints, so it needs no pre-check and cannot fail on existing rows.

*Downgrade* must move the rows first: `UPDATE … SET pipeline_stage='received', stage_detail=NULL,
stage_updated_at=now() WHERE pipeline_stage='abandoned'`, then drop the new CHECK, restore the two old ones, and
rebuild the index. A downgrade without the row move **fails**: `check constraint "action_proposals_pipeline_stage_check"
… is violated by some row` `[E: E9-A10]`; with it, every abandoned row (155 in that run) went back to `received` and the
constraint definitions came back identical `[E: E10 setup, with the comment caveat of §6]`. The semantics of the downgrade — an abandoned
proposal becomes resumable again by its key — are stated in the migration docstring; a migration cannot write
the audit record that says so.

*Code the stage implies (listed so they are not forgotten; not written):* `stages.ABANDONED` in `STAGES` and
`TERMINAL`; `_outcome_from_rows` gets an explicit `abandoned` branch (below); the tests that enumerate stages
(`LEGAL_NULL_STAGES`, the pipeline-coherence checks) grow by one.

**What a caller sees.** The experiment (E10) runs the real `propose_action` and abandons the row while its
decision stage is in flight:

* the reconciler's conditional update wins; the caller's `_record_decision` then loses on the stage guard, and
  **writes no `policy.decided` record** (the audit-after-win order, `stages.py`); the only trace is the earlier
  `policy_reviewer.opinion` record, and the reviewer call is wasted;
* **but the caller is returned `DENY` with `deny_reasons=()` and `failure=None`** — the current
  `_outcome_from_rows` treats "no decision" as `DENY` and has no reason to give. A retry with the same key gets
  the same. That is a defect in the first draft of this design, not in the code as it stands (nothing reaches
  it today). **0022's code change must give the `abandoned` stage its own outcome:** `DENY`,
  `deny_reasons=('abandoned_before_decision',)`, `failure='abandoned'`, so that a caller can tell "refused" from
  "never decided" and knows the next step is a new key;
* if the caller wins instead, the abandon matches no row and writes nothing `[E: E10-R2]`.

So the race is **safe in either order at the data level** (one decision at most; never two; no run), and the
grace period is a matter of *not surprising live callers*, not of correctness.

**The grace period, from two parts.**

* *Floor — never abandon a live decision stage.* The longest the stage can honestly take is the reviewer plus
  OPA: the reviewer's client timeout is 30 s for the API and headless reviewers and **120 s** for the local one
  `[R: agents/llm]`, OPA is `timeout=30` `[R: policy/engine.py]`, so **150 s**; the SDK's own retries may add to
  the API reviewer `[N]`. A measured live stage with a fake reviewer and the real OPA took 0.1 s in total
  `[E: E10-R3]`, so the floor is the timeouts, not the machinery. The reconciler **refuses to start** with a
  grace below twice the floor (300 s).
* *Courtesy — let the caller's retry find its proposal.* A caller that failed mid-decision retries with the same
  key; abandonment before it does turns a recoverable retry into "use a new key". How long callers retry is a
  property of the callers, not something the code knows `[N]`. **Proposal: 1 hour** (configurable, ≥ the floor),
  chosen, not derived.

`decided` (an ALLOW, no capability) is closed after the same grace as `closed / abandoned_after_decision` — it
has a decision, so it may be `closed`.

**Tests the stage will need (when built):** the 0022 round trip with abandoned rows present; the CHECK matrix of
E9 including the NULL detail; the race of E10 as a test (loser gets the explicit outcome, one decision at most);
a fault injected at each boundary of the reconciler's own transaction (the way `test_decision_boundaries.py`
does); and a structural test that nothing but the reconciler's module writes the stage.

## 2. Identity and permissions

The reconciler must (a) read stuck state across **all** engagements, (b) write stage/run state on those rows,
(c) delete Docker objects and host files. Row-level security is by `cyberorch.engagement_id`, and **every** table
is engagement-isolated, `engagements` included `[E]` (`pg_policies`), so "read across engagements" has no
existing path: the scheduler enumerates through its own `scheduler_enrollment` table `[R]`, which lists only
engagements an operator enrolled, and then reads one engagement at a time under the GUC.

### 2.1 What `cyberorch_app` is, if the reconciler used it

`cyberorch_app` can `SELECT/INSERT/UPDATE/DELETE` `action_proposals`, `tool_runs`, `capabilities`, `approvals`;
`INSERT/SELECT` `audit_log`; `SELECT` `engagements` `[E: grants query]`. It is the runtime role every
`propose_action` runs as, and its isolation is the GUC each caller sets for itself. Using it would give a sweeper
the ability to issue and delete capabilities and delete proposals — far more than "close a stale row".

### 2.2 Options

| | **A. Inside the scheduler** | **B. Separate process, `cyberorch_app` per engagement** | **C. Separate process, own role `reconciler`, one process** | **D. Separate process, own role, split plan / act (like D62)** |
|---|---|---|---|---|
| DB identity | the scheduler's roles (`scheduler_reader`, `scheduler_state_writer`) + the runtime role for dispatch | `cyberorch_app` | a new narrow role | a read-only `reconciler_reader` (EXECUTE on one function) + a write role with column-level `UPDATE` under `engagement_scope` |
| New privileges | writes on `action_proposals`/`tool_runs` for the scheduler | none | column-level `UPDATE` on stage/dispatch columns, `tool_runs.status`, `INSERT` audit; the read function | the same, split across two roles |
| Docker | the scheduler's (already has the socket) | its own | its own | the **act** side only |
| Lock | shared (`SingletonLock`) | own key | own key | own key |
| For | one deployable; the lock already excludes a second copy; startup reconcile-then-resume (R-A) is a function call | no schema/role change | least privilege; a bug in the sweeper cannot issue a capability | the strongest separation; a decision can be inspected before it is carried out (as `--dry-run`); the actor never needs to read a budget (§2.3) |
| Against | breaks D62's structural property: the decision side imports only `scheduler_reader` and the execution side only `engagement_scope`, pinned by AST tests `[R]` `test_scheduler_structure.py`; the scheduler would acquire stage-write and Docker-delete powers; a reconciler bug stops dispatch (same process); the serial loop would block on a long removal | the broadest privilege for the least-needed work; cross-engagement enumeration still unsolved | one process holds both "decide" and "delete" | two roles, two connections, more migration; slower to build |

**Can it touch `cyberorch_app`'s connection?** Technically yes (B); the question is whether it should. My
recommendation is **no**: a role that can only do what a reconcile does (C/D). That costs one migration (a role
plus grants, in the shape of 0019, after 0022) and one more structural test (the reconciler imports no dispatch
code).

### 2.3 Reading across engagements — and how the reconciler may read a budget

The thresholds of §1.2 need `capabilities.budget`; the other judgements need a few columns of four other tables
(`action_proposals`, `tool_runs`, `approvals`, `engagements`). All five are under FORCE RLS keyed on the GUC.
What a role needs to read them, found by trying it in a transaction that was rolled back (E11):

| Way | Result |
|---|---|
| column-level `SELECT` only, no policy for the role | **0 rows** — FORCE RLS applies, no GUC `[E: E11-B1]` |
| + a read policy `TO reconciler_reader USING (pipeline_stage IN (stuck stages))` | sees the stuck rows of **every** engagement (in this development database: 8,199 rows in 6,903 engagements, no terminal row); columns not granted (`target`, `decision_reasons`) are refused `[E: E11-B2]` |
| + `SELECT (budget)` on `capabilities` and a policy | works, but **the whole `budget` document is readable**, including `budget.tool` (the adapter-specific dimension, `broker.py`) `[E: E11-B3]` — column privileges cannot reach inside a `jsonb` |
| **a `SECURITY DEFINER` function owned by a no-login role that holds the policies and column grants; the reader has `EXECUTE` and nothing else** | the reader gets exactly the function's columns — `max_duration_seconds` as an integer, `lease_expires_at`, run status, approval validity, engagement status/kill — for stuck rows only (a `recorded` proposal is not returned); a direct `SELECT` on each of the five tables is **`permission denied`** `[E: E11-F]` |

**Recommendation (D64-2): the function.** It is the narrowest of the four: no table is readable, the budget
leaves the database as one integer, and the function is the one place that says what the reconciler may know.
The columns it returns are listed in the migration and pinned by a test (the way `scheduler_proposals` is). Its
cost is the usual one of `SECURITY DEFINER`: `search_path` is pinned in the definition, `EXECUTE` is revoked from
`PUBLIC`, and the owner role owns nothing else.

Two things this is *not*, said plainly:

* **It is a new class of privilege.** The reconciler's reader would be the first role in the system that sees
  rows of more than one engagement without setting the GUC. It cannot see a target, a reason, a budget's tool
  document or any other tenant data, but it does see *which engagements have stuck work* (6,903 of 13,338
  engagements in this database) `[E: E11]`. That is inherent in "read across engagements" and is the reason
  D64-2 is a decision for you.
* **The budget is not mutable under the reconciler's feet.** The code never updates `capabilities.budget`
  (the five `UPDATE capabilities` statements touch lease, heartbeat, the request counter and revocation only `[R]`); nothing in the
  database *prevents* it `[N: no trigger found]`.

**The write side.** The act side is an ordinary per-engagement scope with a role that has column-level `UPDATE`
(`pipeline_stage`, `stage_detail`, `stage_updated_at`, `updated_at`) and nothing else: with no GUC it sees and
changes nothing; with the GUC of one engagement a statement aimed at another engagement's row moves 0 rows;
`UPDATE decision` and `DELETE` are `permission denied` `[E: E12]`. It never reads a budget: the plan hands it
`(proposal_id, expected_stage, planned stage_updated_at)` and its statement is a **compare-and-set on exactly
that observation** (`WHERE pipeline_stage = :expected AND stage_updated_at = :planned`), so a row that moved
between plan and act is not touched. This is what lets the plan side be read-only and the act side be small.

### 2.4 Docker: the permission boundary, and what label checks can and cannot prove

**What the reconciler's Docker identity is.** Docker's socket offers **no per-object authorization**: whoever
can reach it can list, kill and delete any container and create new ones `[N: Docker documentation; not tested
as a non-root user — this machine runs as root]`. The reconciler's boundary is therefore *its own code and the
database*, not Docker. Everything below is about making that code hard to fool, and about being clear where it
cannot be.

**What was tried (E13):**

| Question | Result |
|---|---|
| Can a label be changed on an existing container? | **No.** `Container.update` takes resource limits and a restart policy; `labels=` is `TypeError` `[E: E13-D1]`. A label is fixed at creation. |
| Can anyone who reaches the socket make a container the selection will return? | **Yes, trivially.** A container created with a copy of a real container's labels is returned by the same label filter; the labels compare equal. Only Docker's own `Created` timestamp differs `[E: E13-D2]`. |
| Does removing by **name** hold? | **No.** After the labelled container was removed and another, *unlabelled*, container took its name, removal by name deleted the newcomer; removal by the full id raised `NotFound` and left it running `[E: E13-D3]`. |
| Does the **network name prefix** identify ours? | **No.** `cyberorch-allow-lookalike` (no label) matches the prefix; only the label separates them `[E: E13-D4]`. |
| Does Docker protect a network in use? | **Yes** — removing a network with an attached container is refused (`has active endpoints`) `[E: E13-D4]`; the existing `remove_network` hides that refusal (§1.5). |

**Rules that follow:**

1. *Select* by label **and** require the database to know the object: a container's `cyberorch.run_id` must be a
   run the DB knows (finished, absent past a grace, or overdue §1.2); a label on a container the DB has never
   heard of is **reported, not removed**. `NO_OWNER` containers (probes and lab scripts `[R]`) are report-only.
   A network needs the name prefix **and** the `cyberorch.allowlist` label **and** no attached container of any
   state.
2. *Act* only by the **full id** from the listing, and `inspect` it again immediately before: labels and id
   must still be what the plan saw. Never by name, never `prune`.
3. *Verify* afterwards (§1.7).

**The real limits — what this does not protect against:**

* **A party that can reach the Docker socket can forge anything the check looks at.** Labels are chosen by the
  creator (D2); a copy passes the label filter. The database cross-check turns a forged label into one of three
  outcomes: the id names a run the DB knows to be finished (the forger's own container is removed — their loss),
  names a live run (it is left alone — an availability effect, not an integrity one), or names nothing (reported).
  What it cannot do is make the reconciler delete a *victim's* container, because the victim's container is
  reached only through its own labels and id, and a label cannot be added to it afterwards (D1, D3).
* **The reconciler itself is the most powerful thing in the picture.** With the socket it can delete every
  container on the host, not only ours. "Only ours" is a property of its code and its tests, not of Docker. A
  bug in the selection, or a compromise of the process, is a host-wide deletion. This is why the plan/act split,
  the full-id rule and the structural tests matter, and why its blast radius is a decision (D64-9), not a detail.
* **The optional HMAC label (`cyberorch.sig = HMAC(key, run_id|owner|created)`) would add less than it appears
  to.** The key must be readable by the control plane and the reconciler, which a party with the socket (root on
  the host) can read from process memory; a copied label set carries its signature with it (D2). The only
  binding that resists copying is the container's own `Created` time as Docker reports it, compared with the run's
  recorded start — which stops a *later* replay, not one in the same few seconds, and not root. It helps against
  *accident* (a lab container someone labelled `cyberorch.*`) and against parties who can create containers but
  cannot read the key — a population that does not exist in this tree today `[N]`. **Recommendation: do not add
  it yet.**
* **Boundaries that would actually be one** (not built, not tested here `[N]`): a dedicated Docker daemon (or
  host) for the sandbox, so that "every container in this daemon is ours" is true by construction — which would
  also take the overlap problem of §1.5 off the shared host; a Docker authorization plugin or a socket proxy that
  admits only list/inspect/kill/remove to the reconciler's side (it limits verbs, not objects); rootless Docker.
  Each is an operations decision with its own cost, listed in D64-9.
* No `docker.sock` is mounted into any tool container `[R]` (grep), so a *tool* cannot reach the daemon; the
  parties in question are operators and other software on the host.

### 2.5 The host files

The reconciler runs as a host user that can delete files under `/tmp` it can read the names of; the credential
files are 0644 and the TLS leaf files 0600 owned by the control plane's uid `[E: E4]`. A sweeper in another uid
cannot delete the 0600 files — so either it runs as the control plane's user, or the files move to a per-run
`0700` directory the reconciler's group owns (D58-17's decision, D64-12). `/tmp` is world-writable: a name that
matches the pattern may be a symlink someone else made, so the sweeper works through a directory fd, `lstat`s,
skips anything that is not a regular file of the expected owner, and verifies the unlink (§1.7, E14-V3).

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
| `capability_issued`, lease lapsed → `closed: capability_not_live` | issuing/dispatching the same row | the update is conditional on the stage and the observed `stage_updated_at`; a lapsed lease means the dispatch would refuse the same row with the same reason `[E: E6]` — both paths end identically |
| `dispatching`, overdue → `unknown_outcome` | the same dispatch, still recording | overdue = past `B + P + Q` (§1.2), the sum of every bound the code puts on a live dispatch; if the scheduler is stalled *past* that point its later `advance(expected=DISPATCHING)` loses (the stage guard), the result is lost but **flagged unknown** — never silently double |
| `received` → `abandoned` | a caller still in its decision stage | the same stage guard: whoever commits first wins; the loser writes no decision record; the caller then gets the explicit `abandoned` outcome (§1.8, `[E: E10]`) |
| `approved`, killed engagement/expired approval → `closed` | about to dispatch it | the scheduler re-reads the engagement right before acting (`servable_now`) and `dispatch_approved` refuses killed/expired itself `[R]`; the reconciler's close is a compare-and-set on `APPROVED` — whichever commits first wins, the other matches no row |
| removing a container/proxy/network | a dispatch that has just created it | removal requires "the DB says finished/absent/overdue", and a brand-new run has a `running` row inside its deadline |
| removing an idle network | `ensure_network` has just returned it | a race (§1.5): the create fails as `NotStarted`, retryable; avoided by an idle-retention period long compared with a dispatch; Docker itself refuses to remove a network with an attached endpoint `[E: E13-D4]` |

So two locks are *safe given* the conditional updates and the deadlines; one shared lock is *simpler*. The
decision is D64-10.

## 4. Audit

Same rules as D62 `[D: D62 report]`: a **closed list** of events; payloads of **ids, closed reason codes and
counts only** (no target, CIDR, command or path); each event has a schema and `emit` refuses anything else;
every closed-code column a CHECK that excludes NULL where a code is required (ACCEPTANCE 5.69, met again in
§1.8); and **edge-triggered**.

**Edge-triggering needs no new state table if only actions taken are audited:** closing a proposal, killing a
container, removing a network all change the thing that would be found next time, so the same fact cannot be
reported twice. **A removal event is written only after its verification (§1.7)** — the event means *seen
gone*. The only repeating observations are "found, not acted on" (inside its deadline, report-only owner, in use)
and failed actions; those are **logged, not audited**, except that a failed action is audited once per
`(object, reason_code)` per process lifetime (a restart reports once more — stated, not hidden). If an operator
needs "reported once, ever", that is a `reconciler_state` table like `scheduler_state` (D64-11).

Proposed vocabulary (names are proposals):

| Event | Scope | Payload | Reason codes (closed) |
|---|---|---|---|
| `reconciler.started` | global | `instance_id`, counts per residue class | — |
| `reconciler.stopped` | global | `instance_id`, `reason_code` | `signal`, `lock_lost`, `db_lost`, `docker_lost`, `audit_failed`, `unexpected_error` |
| `reconciler.start_refused` | global | `instance_id`, `reason_code` | `lock_held`, `grace_below_floor` |
| `reconciler.proposal_closed` | engagement | `proposal_id`, `reason_code` | `capability_not_live`, `approval_expired`, `approval_revoked`, `engagement_killed`, `abandoned_after_decision` |
| `reconciler.proposal_abandoned` | engagement | `proposal_id`, `reason_code` | `undecided_past_grace` |
| `reconciler.container_killed` | engagement (owner known) | `run_id`, `reason_code` | `overran_deadline` |
| `reconciler.container_removed` | engagement (owner known) / global | `run_id`, `reason_code` | `overran_deadline`, `run_finished`, `no_run_row_past_grace` |
| `reconciler.proxy_removed` | engagement / global | `run_id`, `reason_code` | `owner_run_ended`, `overran_deadline` |
| `reconciler.network_removed` | global | `network_id` (the hash in the name), `reason_code` | `idle_past_retention`, `blocks_overlapping_range` |
| `reconciler.files_removed` | global | `kind`, `count` | kinds `credential_mount`, `tls_leaf` |
| `reconciler.action_failed` | global / engagement | `kind`, `reason_code` | `in_use`, `daemon_error`, `not_gone_after_removal`, `not_changed_after_update`, `still_running_after_kill`, `budget_unreadable` |

`dispatch.unknown_outcome` (the existing event, `requires_human_review`) is **kept as the record of an
unresolved run** — the reconciler calls the existing function and does not invent a second event for it.

## 5. Decisions (D58 format; ⚑ = needs your answer)

Recommendation in the third column; "depends on" in the last.

| # | Question | Recommendation and why | Depends on |
|---|---|---|---|
| **D64-1** ⚑ | Process and identity (§2.2): A inside the scheduler / B separate with `cyberorch_app` / C separate, own role / D separate, own role, plan–act split | **D** (C if you want it smaller). Least privilege, and it keeps D62's decide/execute separation (pinned by AST tests) intact. A is cheapest and breaks that property; B grants far more than the work needs (it can issue and delete capabilities). | — |
| **D64-2** ⚑ | How the reconciler reads across engagements, and the budget (§2.3) | **One `SECURITY DEFINER` function, `EXECUTE` only for the reader; no table readable.** The budget leaves the database as one integer; the first role able to see more than one engagement without the GUC, listing which engagements have stuck work. Alternatives: column grants + policy (exposes `budget.tool`), enrollment table only (misses un-enrolled engagements). | D64-1 |
| **D64-3** ⚑ | The overdue thresholds | **Derived from the capability's budget, never typed in:** kill a container at `StartedAt + B + 60 s`; declare `unknown_outcome` at `stage_updated_at + B + P + Q` (`B + 660 s`, `B + 1,215 s` with a proxy — upper bounds read from the code's client timeouts `[N]`, not measured worst cases); close a lapsed lease at `lease_expires_at + 30 s`; budget unreadable → report, change nothing. | D64-1, D64-2 |
| **D64-4** ⚑ | An overdue **running** container | **Kill it, keep the exited container a retention window (24 h `[N]`), remove after.** I7 forbids silent re-execution, not stopping an overdue process; keeping the corpse preserves the only evidence of what ran. Alternative: remove at once (frees the network now, loses the evidence). The in-container deadline (§8) would make this a backstop. | D64-3 |
| **D64-5** ⚑ | Stuck `received` (no decision), now that 0021 forbids closing it | **A new terminal stage `abandoned`, migration 0022** (stage list + decision CHECK + an `IS NOT NULL` reason CHECK + index; the downgrade moves rows back to `received`), written only by the reconciler after a grace of **1 h `[N]`** (floor 150 s from the reviewer and OPA timeouts `[R]`; refuse to start below twice the floor); a retried key gets an explicit `abandoned` outcome, not today's reasonless `DENY`. Alternative: leave them, report their age. | D58-6 |
| **D64-6** | `capability_issued` with a lapsed lease: close it (`capability_not_live`)? | **Yes** — exactly what a resumed `propose_action` does `[E: E6]`; known not-run. | D64-1 |
| **D64-7** | `approved` rows: which to close | Only those the scheduler **cannot reach**: engagement killed (`engagement_killed`), or not enrolled with an expired/revoked approval. Leave paused. For servable engagements the scheduler already resolves expiry `[E: E7]`. | D64-1 |
| **D64-8** ⚑ | Sandbox networks (§1.5) | Remove a network when it has **no attached container of any state** and has been idle **1 h `[N]`**, **verified gone**; also remove one that causes a `NetworkRangeConflict` for a new allowlist if it is idle (self-heal of the overlap case, the one that occurs). Alternatives: never remove, alarm on count (overlap still bites, E3); a network per run (a sandbox redesign; out of scope). | D64-1, D64-10 |
| **D64-9** | Label integrity and the Docker boundary (§2.4) | **Select by label *and* the DB's knowledge; act by full id after re-inspect; `NO_OWNER` report-only; no HMAC label** (it adds nothing against whoever holds the socket). State that "only ours" is a property of the reconciler's code, not of Docker; the real boundary is a dedicated daemon or a verb-limiting socket proxy — an operations decision, not made here. | D64-1 |
| **D64-10** ⚑ | Start order and locks (§3) | **One-shot reconcile to completion before the scheduler starts, then periodic; two lock keys** (the safety argument is §3.1). One shared key is simpler but makes a long reconcile and dispatch exclude each other. | D64-1 |
| **D64-11** | A `reconciler_state` table for "reported once, ever"? | **No** for now: audit actions taken and verified (§4); observation-only cases are logged; a failed action is audited once per object and reason per process. Add the table if an operator needs the deferred-style record D62 has. | — |
| **D64-12** | Host files | The reconciler sweeps `cyberorch-cred-*` and `cyberorch-tls-*` by prefix and age, through a directory fd, regular files of the expected owner only, verified by `lstat`. The *mode* and a per-run `0700` directory are **D58-17's**; until then the sweeper must run as the control plane's uid to delete the 0600 files. | D58-17 |
| **D64-13** | Excluded from this deliverable | R10 (task claims, X7), the failure ladder / reopen (D58-6), quotas (D58-13), credentialed-dispatch kill (D58-16) — and **the deadline inside the container, which is listed as its own deliverable candidate (§8)**. | — |

Order of dependence: D64-1 first; D64-2, 3, 6, 7, 9, 10 follow from it; D64-4 from D64-3; D64-8 from D64-1 and
D64-10; D64-5 and D64-12 wait on D58-6 and D58-17. Migrations if all recommendations are taken: **0022**
(the `abandoned` stage, with its small code change) and **0023** (the reconciler's roles, grants and read
function), in that order; 0022 can ship alone.

## 6. Experiments

All run on this machine (Docker 29.3.1, default configuration, PostgreSQL 16, docker-py 7.2.0), with cleanup
afterwards; the scripts are in the session's scratch area, not in the repository. Database experiments ran as
the superuser inside a transaction that was **rolled back** (nothing persists: roles, constraints and rows were
counted afterwards), except E10, which applied the 0022 constraint changes to the development database for the
duration of the run and restored them (the four constraint definitions of `action_proposals` compared
identical before and after; zero abandoned rows left). **That comparison covered definitions, not comments:**
the `COMMENT` on `action_proposals_decision_past_received` (set by migration 0021) was missing afterwards, the
next full-suite run caught it (`test_the_constraint_is_validated_and_says_what_it_is_for`, one failure), it was
restored by hand and the test re-run — the same trap as D63-j. A restore of schema state has to compare
comments too.

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
| **E9** | the 0022 draft in a rolled-back transaction, against fixtures and the development database (A1–A11) | **A1** received → abandoned with the one detail: accepted. **A2** abandoned with a decision: refused by `abandoned_is_undecided`. **A3** abandoned with another detail: refused. **A4** `closed` with no decision: refused by `decision_past_received` — the 0021 rule still holds. **A5** an undecided `received` row stays legal. **A6** a stage name outside the list is refused (by `decision_past_received`, which is checked first). **A7** the conditional update `WHERE pipeline_stage='received' AND decision IS NULL AND stage_updated_at < now() - 1 h` moved **155 rows** (the 3 fixtures and 152 leftovers of earlier fault-injection tests); **A8** a second run moved 0. **A9** the partial index definition with `'abandoned'` excluded. **A10** *downgrade*: without moving rows the old stage CHECK fails (`is violated by some row`); with the row move to `received` it succeeds and all rows are `received`. **A11** the first draft of the abandoned CHECK (`… AND stage_detail = '…'`) **accepted `abandoned` with a NULL detail**; the corrected form (`stage_detail IS NOT NULL AND …`) refuses it and still accepts the legal row |
| **E10** | the real `propose_action` with the 0022 constraints applied (the first-draft abandoned CHECK of A11; the code always writes the detail, so the outcome is unaffected): R1 the reconciler's update wins while the caller is inside its decision stage (the reviewer blocked); R2 the caller commits first; R3 timing | **R1:** abandon moved 1 row; the caller returned `ActionOutcome(decision='DENY', deny_reasons=(), failure=None)`; audit for the proposal: `proposal.submitted`, `policy_reviewer.opinion`, **no `policy.decided`**; row `abandoned / undecided_past_grace / decision NULL`; a retry with the same key: the same reasonless `DENY`, still one proposal. **R2:** a committed ALLOW run, then the abandon matched `[]`; row `recorded / ALLOW`. **R3:** a whole `propose_action` with a fake reviewer, fake sandbox and the real OPA subprocess: 0.11–0.13 s |
| **E11** | what a reader role needs (B1–B5) and the function-only reader (F), rolled back | **B1** column grants only: 0 rows. **B2** + stuck-stage policy: 8,199 rows in 6,903 engagements, 0 terminal rows, `target`/`decision_reasons` → `permission denied`. **B3** + `SELECT (budget)`: the full document readable, `{"tool": {"note": …}, "max_duration_seconds": 5}`. **B4** `SECURITY DEFINER` function, no table grant: the reader sees `max_duration_seconds` only, direct `SELECT budget` → denied. **B5** engagement enumeration limited to engagements with a stuck row: 6,903 of 13,338. **F** function-only reader over five tables: for the fixtures returns `approved` (approval expired, engagement killed), `capability_issued` (budget 120, lease lapsed), `dispatching` (budget 5, run `running`) and `received`, **not** the `recorded` one; a direct `SELECT` on each of the five tables is `permission denied` |
| **E12** | the act role: column-level `UPDATE` under the per-engagement scope (C1–C4) | **C1** no GUC: 0 rows visible. **C2** scoped to engagement X: the old `received` row was abandoned (1 row). **C3** the same kind of statement aimed at engagement Y's row: 0 rows. **C4** `UPDATE decision` → `permission denied`; `DELETE` → `permission denied` |
| **E13** | Docker boundary (D1–D4) | **D1** `Container.update(labels=…)` → `TypeError`; labels unchanged. **D2** a container created with copied labels is returned by the label filter beside the real one; the label sets compare equal; `Created` differs (…17.858 vs …18.349). **D3** removal by id after the name was re-used: `NotFound`, newcomer still running; by name: newcomer removed. **D4** prefix match returns the labelled and the unlabelled network, the label filter only the labelled; removal with an attached container refused (`has active endpoints`); after the container is gone, removal succeeded and `networks.get` → `NotFound` |
| **E14** | removal verification (V1–V3) | **V1** `DockerSandbox.remove_network` with a container attached: returned `None`, no exception, **network still present** (`inspect` found it); after the container was removed, a second call made it `NotFound`. **V2** `remove(force=True)` of a running container: 187 ms; `get(id)` → `NotFound`, `list(all=True, id)` → `[]`. **V3** in a directory with a regular `cyberorch-tls-*.pem` (0600) and a symlink of the same pattern to another file: `os.path.exists` follows the link and says True for both; the `lstat`/dir-fd sweep removed the regular file (verified by `FileNotFoundError`), skipped the symlink and left its target intact |
| **E15** | facts for §8: Docker's own lifetime options; which tool images can run a deadline wrapper; whether a static helper can be built | `docker run --help` has `--stop-timeout` (grace on stop) and `--health-timeout`; **no maximum lifetime**. `timeout(1)` present in `semgrep`, `bloodhound`, `browser`; **absent from `nmap`, `gitleaks`, `egress-proxy`** (no such binary / no shell). A 790 KB statically linked C helper built with `gcc -static`; `Config.Entrypoint` and `Cmd` are null for the `nmap` and `gitleaks` images |
| **E16** | a deadline inside the container, with the control plane `kill -9`'d (A–D), through `DockerSandbox.run` with the helper bind-mounted read-only by the existing `source_mounts` | **A** no helper, budget 5 s, parent killed at 3 s: container `running` 20.9 s later when observation stopped. **B** helper deadline 10 s, parent killed at 3 s: container `exited` with code **124** at 10.7 s (start ≈ 0.7 s after launch). **C** control plane alive, budget 5 s, helper 10 s: `run()` returned after 5.3 s, `timed_out=True` — the backstop does not change the normal path. **D** a tool that traps TERM and starts a `setsid` grandchild, helper 4 s, parent killed at 1 s: container exited (124) at 4.7 s; the grandchild existed while it ran (positive control: 2 host processes) and **0** after |

Not run: the 2-minute node-delete cost (ACCEPTANCE 5.23) was measured at D63; the stale credential file
(`cyberorch-cred-*`) was not reproduced here (`[D]` ADR E12 recorded it at D58); a Docker restart's effect on
networks (would they survive a daemon restart with their containers?) was not tested `[N]`; Docker's behaviour
for a non-root member of the `docker` group, a socket proxy and rootless mode were not tested `[N]`; the
worst-case duration of the pre-start and post-run phases (§1.2) is a bound read from the code, not a measured
maximum `[N]`.

## 7. What this document does not do

It writes no code, no migration and no test. It does not pick values for the grace, the retention windows or
the idle period (they are labelled `[N]` and listed as decisions). It does not decide D58-6, D58-13, D58-16 or
D58-17; it names where it depends on them. Once you have answered §5 (⚑), the build is: migration 0022 and the
small code change it implies (§1.8); a role, grants and the read function (migration 0023, in the shape of
0019); a `control_plane/reconciler` package split like `scheduler` (plan / act / verify / emit / lock); one
operator script; tests that fail every boundary (the way `tests/test_decision_boundaries.py` does for the
decision stage) and that make a call report success without effect to prove nothing is audited unverified; a
structural test that the reconciler imports no dispatch code; and the residue check (`tests/residue.py`)
extended to the objects it manages.

## 8. Candidate deliverable (separate): a deadline inside the container

**The problem.** A tool container's duration is enforced from outside, by the control plane's
`container.wait(timeout)` and `kill()`. If the control plane dies, nothing stops the container: a 5 s budget was
still running 21 s after `kill -9` of its parent `[E: E16-A]`, and Docker has no option to give a container a
maximum lifetime `[E: E15]`. Today the only thing that would end it is the reconciler (§1.2), and the reconciler's
bound for *declaring the outcome unknown* is `B + 660 s`. A deadline inside the container is the precise answer:
the container ends itself at the budget, whoever is or is not alive.

**What was tried (E15, E16):**

| Option | Works? | Notes |
|---|---|---|
| `timeout -s KILL N <tool>` as the command | only where `timeout` exists | present in `semgrep`, `bloodhound`, `browser`; **absent from `nmap`, `gitleaks`, `egress-proxy`** `[E: E15]`. Not universal. |
| **a small static helper, bind-mounted read-only as the command's first element** | **yes, in every image tried** | the existing `source_mounts` primitive carries it, so `DockerSandbox.run` needed no change for the experiment. It is PID 1: it starts the tool, sets an alarm, and on expiry kills the tool and exits **124**. Its exit ends the PID namespace, so grandchildren die with it (E16-D, with a positive control). With the control plane alive the budget still wins (E16-C). Deadline precision: the container exited 0.7 s after the nominal time, which is its own start-up (E16-B). |
| a host-side dead-man timer (`sleep N; docker kill ID`, detached) | `[N]` not tested | survives the control plane only if it is not in the same process group / cgroup; adds a host process per run. |
| the reconciler alone (§1.2) | yes, but late | bound `B + 660 s`; kills a container still running at `StartedAt + B + 60 s`. |

**Open points for a deliverable (not decided here):**

* *Which deadline.* `B + slack` (slack ≈ 5–10 s) so that in the normal path the control plane's own kill wins
  and the helper is only the backstop (E16-C).
* *The exit code.* 124 means "deadline" in E16; a tool can return 124 too. Dispatch must decide how it maps
  the code onto `timed_out` `[N]`.
* *The helper is trusted code running as PID 1 beside the tool.* It adds no capability (the container keeps
  `cap_drop ALL`, `no-new-privileges`, read-only root), but it must be built reproducibly, pinned by hash, and
  mounted read-only; per-architecture builds are needed (the experiment's is x86-64). Signal forwarding for
  `docker stop` (the experiment's helper does not forward SIGTERM) must be added.
* *Images with an `ENTRYPOINT`.* The images here have none (`Config.Entrypoint` null for `nmap` and `gitleaks`);
  the others were not checked `[N]`.
* *Tests it needs:* the E16 experiments as real tests (parent killed → container gone at the deadline; tool
  traps TERM; grandchild; normal path unchanged), each mutation-checked.

**Why separate from D64.** It changes how every adapter's command is assembled or how `run` starts a container,
has its own tests and its own review, and is useful with or without the reconciler. With it, the reconciler's
container kill becomes a backstop and the `B + 660 s` bound only concerns *database* state, not running
processes. Listed as the candidate **D65-A** (a name for tracking, not a commitment).
