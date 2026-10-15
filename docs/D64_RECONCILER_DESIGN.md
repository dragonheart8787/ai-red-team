# D64 — The reconciler (D58-9): design checkpoint (revision 3)

**Status: design only.** No code, migration or test is written or changed by this document. Everything below
the line "Decisions" is a proposal waiting for answers; nothing is built until they are given.

**How claims are tagged.** `[R]` read in the code at this commit; `[E]` executed here, on this machine, with the
experiment named in §6; `[D]` taken from an older document (named); `[N]` not verified — knowledge or reasoning
that I have not checked against this system.

**What revision 3 changes** (the ten items asked for; the experiments behind them are E17–E26 in §6, run in
rolled-back transactions, in a template-copied temporary database, or against Docker, with the scripts kept in
the session's scratch area):

1. **§1.8 lists the properties of `abandoned` one by one so they can be checked against your definition. I do
   not have that definition:** the request says "見上" ("see above") twice, and no message in this conversation
   carries one. The comparison is therefore *not done*; the table is built so that it can be, row by row.
2. **D64-1 (§2.2a):** the plan and act sides use separate connections; every state change goes through the
   existing engagement-scoped `cyberorch_app` path, so no cross-engagement write exists or is added; the AST
   tests that pin it are described. The narrow-grant act role of revision 2 (E12) is withdrawn.
3. **D64-2 (§2.3):** how a `SECURITY DEFINER` function reads past row-level security — it does not, it runs
   under its owner's policies — with the six experiments (E20), the checklist (`search_path`, owner, PUBLIC,
   output types) and four defects that the experiments found in the revision-2 sketch of the function.
4. **D64-3 (§1.2, §3.1, §3.2):** the budget is capped, `B = min(budget, B_cap)`, cap proposed 1,800 s; D58-16's
   Rego ceiling is a prerequisite; closing is a conditional UPDATE; nine race tests are planned. **E17 showed
   that a claim in revision 2 (§3.1) was wrong**; it is now ACCEPTANCE 5.74.
5. **D64-5 (§1.8, §1.9):** every place that names a stage, and the structural tests; the reason-code CHECK
   excludes NULL explicitly.
6. **D64-8 (§1.5):** conflict-driven removal first, a 24 h sweep second; a sandbox network that is gone is
   re-created; what a stopped container does to `network rm` was measured (E21).
7. **D64-10 (§3.3):** the start order is a convention, and the document says so; concurrency tests are listed.
8. **D64-12 (§1.5):** a credential or TLS file is removable when no live container mounts it **and** it is older
   than the longest legal run plus the dispatch margin (E22).
9. **§9:** the shared `snapshot_schema()` and the template database. Replaying the COMMENT incident it catches
   it; it also found ACCEPTANCE 5.75 (E18, E19).
10. **D65-A** has its own document, `docs/D65A_CONTAINER_DEADLINE_DESIGN.md`; §8 here is the summary.

**Order of work once the decisions are confirmed:** D65-A first; then migration 0022 together with the two small
dispatch-side fixes it depends on; then the reconciler (migration 0023 and the package).

*Revision 2 (earlier)* corrected ACCEPTANCE 5.72, gave D64-5 the terminal stage `abandoned`, derived the
thresholds from the budget, added the Docker boundary, the verified removals and the in-container deadline
candidate. Its content is folded into the sections below.

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
* **A claim of revision 2 was wrong, and an experiment says how.** §3.1 said that a dispatch that loses the
  stage race to the reconciler "loses its result, which is flagged unknown". With the existing
  `reconcile_stale_dispatches` run while a container is still running, the dispatch's result is **recorded as
  a success beside a `recorded / unknown_outcome` stage** — stage, dispatch state, run status, evidence and
  audit contradict each other — because the dispatch ignores that its own stage transition matched no row
  `[E: E17]`. That is ACCEPTANCE 5.74 and a prerequisite of the reconciler.
* **A downgrade with real rows has never been run, and the first one failed.** `alembic downgrade 0016` on a
  copy of the development database fails at 0017: its data repair runs as the owner under FORCE ROW LEVEL
  SECURITY and moves nothing `[E: E18]` (ACCEPTANCE 5.75). The 0022 draft had the same flaw until the same
  experiment caught it `[E: E19]`.
* **A time bound is not a number to type in.** No ceiling on `max_duration_seconds` exists in the broker `[R]`,
  so a constant would be wrong in both directions. Every bound below is `budget + a term built from client
  timeouts in the code`, and the reconciler reads the budget through one narrow function, not the table (§1.2,
  §2.3).

The proposal, in short (each is argued below and listed as a decision in §5): a **separate process** with
**its own lock**, split like the scheduler into a read-only *plan* side (its own login role, which can only
execute one `SECURITY DEFINER` function) and an *act* side whose every state change goes through the existing
engagement-scoped `cyberorch_app` path — **no cross-engagement write, no new write grant**; **never** resumes, re-runs, re-issues or
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

**The budget is capped: `B = min(budget.max_duration_seconds, B_cap)`.** Nothing in the broker or the policy
bounds `max_duration_seconds` `[R: only `max_targets` is checked in `authz.rego`; ADR D58-16 records it]`, so a
budget of a day is legal and would turn every bound below into a day. Two consequences. First, the reconciler
must not trust the number without limit, so it applies a cap. Second, the system should not *issue* what the cap
would overrule: D58-16's operator-owned per-action ceiling, enforced in Rego, is a **prerequisite** of these
thresholds (it is not built `[D: ADR D58-16]`). Until it exists the cap is the only bound, and a dispatch whose
budget is above it is, from the reconciler's side, judged overdue by the capped time — it can be killed while its
owner still expects it to run. A run longer than the cap is outside what this system was designed for, and the
reconciler says so (a count in `reconciler.started` and a log line per capability) rather than waiting.

**Proposed `B_cap` = 1,800 s `[N]`.** Evidence: the largest budget any code path builds is 600 s (`Budget()`;
the adapters default to the same `budget.get("max_duration_seconds", 600)`); `propose_action` uses 120 s, the
approval path 120 s, the live-run scripts 30–120 s `[R: grep]`. 1,800 s is three times the largest in use —
room to grow without a change, short enough that the worst bound stays under an hour (`B_cap + 660 s` = 2,460 s;
with a proxy `B_cap + 1,215 s` = 3,015 s). The Rego ceiling, when built, must be ≤ the cap, and a test compares
the two so that they cannot drift.

Two different judgements use the bounds, and they must not share a threshold:

* **Kill the container** (R2). The control plane's own `wait` starts within milliseconds of `start`, so a
  container that is *still running* at `State.StartedAt + B + K` — K = 60 s, the longest the control plane's own
  `kill()` is allowed — has outlived its owner's ability to stop it. The container's start time comes from
  Docker, not from a guess about the database. `T_kill = StartedAt + B + 60 s`.
* **Declare the proposal's outcome unknown** (R1). This is a database fact about whether a *live* driver can
  still be about to write; it must cover the slowest honest driver: `T_unknown = stage_updated_at + B + P + Q`,
  which is `B + 660 s` for an ordinary run (`B + 1,215 s` with a proxy). **These are upper bounds read from the
  code, not measured worst cases `[N]`**; a typical run starts its container in under a second `[E: E16]`.
  They are computed from `docker.constants.DEFAULT_TIMEOUT_SECONDS` and from the call counts, not copied, so a
  change in either changes the bound.

If the budget cannot be read (no capability row for the proposal; a value ≤ 0; a value the function's guarded
cast could not read, §2.3), the plan **does not guess**: it reports the row and does nothing to it.

**Implemented (D64 step 6b, ACCEPTANCE 5.81).** The thresholds are *configuration*, not constants: `P_S`/`Q_S` of the
ordinary run are not configured at all (the proxy bound, the longer, is used for every run, because the database does not say
which a run is), and `config.load()` refuses to start with any key missing or below the least the code implies. The kill bound
for a container whose proposal has already left `dispatching` is `StartedAt + B_cap + K`.

**Closing a dispatch is one conditional UPDATE, a compare-and-set on what the plan observed.** The plan hands the
act side `(engagement_id, proposal_id, planned stage_updated_at)`; the act side, in a transaction scoped to that
one engagement, runs

```sql
WITH moved AS (
  UPDATE action_proposals
  SET pipeline_stage = 'recorded', stage_detail = 'unknown_outcome', dispatch_state = 'unknown_outcome',
      stage_updated_at = now(), updated_at = now()
  WHERE proposal_id = :p AND pipeline_stage = 'dispatching' AND stage_updated_at = :planned
  RETURNING proposal_id)
UPDATE tool_runs SET status = 'unknown_outcome'
WHERE proposal_id IN (SELECT proposal_id FROM moved) AND status IN ('dispatching', 'running')
```

Zero rows moved means someone else moved the proposal since the plan looked, and nothing is audited (§4). The
existing `reconcile_stale_dispatches` is **not** used for this and stays a test helper: it sets `dispatch_state`
first, filters on `updated_at` instead of the stage, and ignores the result of its own stage `advance` `[E: E17]`.
The same shape closes the other residues: `capability_issued` with a lapsed lease (the lease predicate evaluated
in the same statement), `approved` in a killed engagement (the engagement's kill flag in the same statement),
`received` past the grace (§1.8).

**The live side has to cooperate, and today it does not.** The race in which the reconciler is wrong about a
dispatch being dead is excluded by the time bound, not by the code: a dispatch whose record transaction finds its
stage already moved must *fail* that transaction instead of recording a success next to it (ACCEPTANCE 5.74:
`stages.take` in place of `stages.advance` at the three record sites of `dispatch.py`). The raw output is already
durable on disk before that transaction and its path is logged, so a lost record loses no evidence. This fix is
part of the same change as 0022 and is tested by RT1 (§3.2).

For an overdue dispatch:

1. find the container(s) by the label `cyberorch.run_id` (not by name: tool containers have random names
   `[E: E5]`);
2. if one is running past `T_kill` → **kill it**, keep the exited container for a retention window (D64-4) so a
   human can read its output, then remove it later (§1.7);
3. past `T_unknown`: the conditional UPDATE above — `unknown_outcome`, `requires_human_review`;
4. **never** call `dispatch_*`, `propose_action`, `dispatch_approved` — the ladder to *try again* is D58-6.

The kill is the one new *destructive* act on a thing the tool may still be doing; I7 forbids a silent
re-execution, not stopping an overdue process, and the kill switch's own gap (it does not stop a running
container, D44-7/D58-16 `[D]`) is the same gap seen from the other side. If the control plane is in fact alive
but slow, the reconciler's kill makes its `wait` return an exit code instead of `timed_out`: the run is
recorded as failed, not as timed out — a cosmetic difference, stated. With the in-container deadline (D65-A) the
kill becomes a backstop that should seldom fire.

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
* **Networks — a conflict first, a sweep second (D64-8).**
  * *Primary trigger: a conflict.* The failure that actually occurs is a dispatch refused with
    `network_range_conflicts_with_another_network` `[E: E3, E21-N4]`. That refusal is recorded
    (`tool_run.refused`, reasons `network_unavailable` and that code; the message names the requested range; the
    `tool_runs` row keeps `network_allowlist`) `[R: dispatch.py _refused_before_start, sandbox.py]`. The
    reconciler finds recent refusals with that code — through the same `SECURITY DEFINER` function (§2.3), which
    would return `(engagement_id, run_id, network_allowlist, at)` and nothing else — computes which of **our**
    labelled networks overlap the requested range (`ipaddress` overlap against the label
    `cyberorch.allowlist`), and removes each such network that is idle, then verifies (§1.7). An overlapping
    network that is *not* ours (a lab's) is reported and left. It does not retry the refused proposal (D58-6).
  * *Secondary: a 24-hour sweep* of idle networks, so that a system that never hits a conflict does not
    accumulate them for ever. Idle = no container of any state attached, and the newest container that used it
    finished (or, with none ever, the network was created) at least 1 h ago. The 24 h period is chosen `[N]`; the
    sweep bounds the *count*, for which no limit was found (1,100 were created, E2), it does not prevent a failure.
  * *Why "no container of any state", not Docker's own refusal.* Docker refuses `network rm` only for **running
    and paused** containers; a **created** (never started) and an **exited** container do **not** block it, and
    `containers.list(all=True, filters={"network": name})` finds all four `[E: E21-N1]`. Removing a network
    under a `created` container is exactly a dispatch between `create` and `start`: its `start` then fails with
    "network … not found", which the sandbox types as `ContainerStartRefused` — a `NotStarted`, safe and
    retryable `[E: E21-N3]`. So the reconciler's rule is stricter than Docker's, and the 1 h idle period (far
    longer than a dispatch's `P`) is what closes the window.
  * *A network that is gone is re-created.* `ensure_network` finds nothing and creates it again with the same
    name and subnet, and the next run on it succeeded `[E: E21-N2]`: removing an idle network costs one network
    creation, not a failed dispatch.
  * The reconciler must **not** call `DockerSandbox.remove_network`: it returns nothing and swallows every
    error `[E: E14]`; it uses the Docker API directly and verifies (§1.7).
* **Files — judged by who mounts them, then by age (D64-12).** A `cyberorch-cred-*` or `cyberorch-tls-*` file
  is removable when **both** hold:
  1. *no container in a live state — `created`, `running`, `paused`, `restarting` — has it as a mount source.*
     Found with `containers.list(all=True, filters={"volume": <host path>})`, or by reading `Mounts[].Source`
     of every container; both find created, running and exited holders, and an exited one no longer needs the
     file `[E: E22]`;
  2. *it is older than `B_cap + P + Q`* (§1.2): the longest legal run plus the dispatch's own margin.

  Neither alone is enough. Age alone would remove the credential of a legal long run. "Not mounted" alone would
  remove a file that was written *before* its container exists (`mount_for_run` and `start_egress_proxy` write
  first and create second `[R]`), i.e. a dispatch that is about to start. Regular files owned by the expected
  uid, never symlinks; opened through a directory fd; verified (§1.7). The *mode* of the credential file and a
  per-run `0700` directory are D58-17's decision, not this one's.

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

**Implemented (D64 step 6c, ACCEPTANCE 5.82).** The table above is `act.py`, `act_docker.py`, `act_files.py`; the waits are
`verify_wait_s`. Deletions (kill, remove, unlink) exist and are tested, and are behind five switches — `kill`, `container`,
`proxy`, `network`, `file` — each off by default, each turned on by `--enable <name>` and a phrase typed at a terminal, and
the last two refused in this version (ACCEPTANCE 5.92; the first three drilled on a real daemon, 5.95).

A failed action is retried after `RETRY_AFTER_FAILURE_S` (any kind, since completion 3: ACCEPTANCE 5.94); to keep a stuck object from filling the audit log, a given
`(object, reason_code)` is audited once per process lifetime and counted thereafter (a restart reports once
more — stated, not hidden; D64-11).

### 1.8 R6 — the terminal stage `abandoned`, migration 0022, and the grace period

**Implemented (D64 implementation step 5, ACCEPTANCE 5.78).** A1–A9 below were confirmed as the definition, with
three additions that are built: **A7** has a coherence check (`assert_coherent` refuses an abandoned proposal that
has a capability, a run, an approval or a `policy.decided` record) and race tests in both orders plus a genuinely
concurrent one; **A5** has a registered vocabulary (`stages.ABANDON_REASONS`, held equal to the database CHECK by a
test); and the planner's side is entered as the **D58-12** mapping in the ADR. `stages.abandon()` is the one writer
(compare-and-set on `received` and on the `stage_updated_at` the reconciler planned from). The text below is the
design as confirmed; where the migration differs from it, the migration's docstring is the record.

*Why a new stage, not a looser `closed`.* Migration 0021 made `closed` (and every stage past `received`) require
a decision. A proposal stuck at `received` has none, and "closed" would say a decision was made. Revision 1 left
them alone; a terminal stage of their own makes **"undecided" and "abandoned" visible in the stage while the
database still refuses `closed` without a decision.**

**The definition, as properties that can be checked one by one.** *I do not have your definition* (the request
says "見上" and nothing above it carries one), so this is the definition I built, laid out so that a row can be
confirmed or corrected; if yours differs on a row — say, abandoning `decided` rows, or a manual path — say which.

| # | Property | Enforced by |
|---|---|---|
| A1 | Terminal: nothing moves a proposal out of `abandoned`. | `ABANDONED ∈ TERMINAL`; no `expected=` in the code names it; structural test (§1.9) |
| A2 | Reachable only from `received`. | the reconciler's compare-and-set, `WHERE pipeline_stage = 'received' AND stage_updated_at = :planned` |
| A3 | Written only by the reconciler. | structural test: one module holds the write; **the database cannot enforce *who*** `[N]` |
| A4 | Only when no decision exists. | CHECK `action_proposals_abandoned_is_undecided` (`decision IS NULL`) |
| A5 | Exactly one reason code, never NULL. | the same CHECK: `stage_detail IS NOT NULL AND stage_detail = 'undecided_past_grace'` |
| A6 | Only after a grace. | the reconciler's predicate `stage_updated_at < now() - grace`; it refuses to start with a grace below twice the floor |
| A7 | No capability, run or approval can exist for it. | follows from A2 (they are created only after `decided`); asserted by the coherence check |
| A8 | Known not run; reopenable only by a **new key**; the old key keeps answering "abandoned". | the explicit outcome below; D58-6 reads it |
| A9 | Not a decision. | no `policy.decided` is ever written for it; its audit event is `reconciler.proposal_abandoned` |

**Migration 0022 (one transaction, proposed text — not written).**

| Step | Statement | Why |
|---|---|---|
| 1 | replace `action_proposals_pipeline_stage_check` with the list plus `'abandoned'` | the stage must be legal |
| 2 | replace `action_proposals_decision_past_received` with `decision IS NOT NULL OR pipeline_stage IN ('received','abandoned')`, **and set its COMMENT again** | the one legal NULL stage list grows from `{received}` to `{received, abandoned}`; `closed` still cannot be undecided `[E: E9-A4]`. A dropped and re-added constraint loses its COMMENT — what broke the suite in revision 2 `[E: E19-T2]` |
| 3 | add `action_proposals_abandoned_is_undecided`: `pipeline_stage <> 'abandoned' OR (decision IS NULL AND stage_detail IS NOT NULL AND stage_detail = 'undecided_past_grace')`, with a COMMENT | an abandoned row has no decision and the one reason. **The `IS NOT NULL` is not decoration:** written as `… AND stage_detail = '…'` the CHECK passes on a NULL detail and `abandoned` with no reason was accepted `[E: E9-A11]` — ACCEPTANCE 5.69, met a second time, and it must be listed in `test_check_constraints_null_rule.py` with its reason |
| 4 | rebuild `action_proposals_open_stage` with `NOT IN ('recorded','closed','abandoned')` | otherwise every abandoned row stays in the "open" index for ever `[E: E9-A9]` |
| 5 | update the COMMENT on `pipeline_stage` | the documented stage list |

*Upgrade* only relaxes constraints, so it needs no pre-check and cannot fail on existing rows. Compared with
`snapshot_schema()` (§9) it changes exactly the three existing constraints/index it names and adds one
constraint, nothing else `[E: E19-T3]`.

*Downgrade* must move the rows first, **and must switch row-level security off around the move**: in one
transaction, `ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY`; `UPDATE … SET pipeline_stage =
'received', stage_detail = NULL, stage_updated_at = now() WHERE pipeline_stage = 'abandoned'`; `ALTER TABLE …
FORCE ROW LEVEL SECURITY`; then drop the new CHECK, restore the two old ones **with the 0021 COMMENT**, rebuild
the index, restore the column comment. Without the row move the old stage CHECK cannot be added (`is violated by
some row`) `[E: E9-A10]`; **without the `NO FORCE` the owner's UPDATE sees no rows under FORCE RLS and moves
nothing, with the same failure** `[E: E19-T3b]` — which the first run of this experiment missed because it ran
as the superuser, who bypasses RLS. 0020 does the same switch for `scheduler_state`; 0017's downgrade does not
(ACCEPTANCE 5.75). With both fixes the round trip leaves **no schema difference** and the moved rows are
`received / NULL` `[E: E19-T5]`; omitting the COMMENT restore is caught by the snapshot `[E: E19-T4]`. The
semantics of the downgrade — an abandoned proposal becomes resumable again by its key — go in the migration
docstring; a migration cannot write the audit record that says so.

**What a caller sees.** The experiment (E10) runs the real `propose_action` and abandons the row while its
decision stage is in flight:

* the reconciler's conditional update wins; the caller's `_record_decision` then loses on the stage guard and
  **writes no `policy.decided` record** (the audit-after-win order, `stages.py`); the only trace is the earlier
  `policy_reviewer.opinion` record, and the reviewer call is wasted;
* **but the caller is returned `DENY` with `deny_reasons=()` and `failure=None`** — the current
  `_outcome_from_rows` treats "no decision" as `DENY` and has no reason to give. A retry with the same key gets
  the same. Nothing reaches this today. **0022's code change must give the stage its own outcome:** `DENY`,
  `deny_reasons=('abandoned_before_decision',)`, `failure='abandoned'`, so that a caller can tell "refused" from
  "never decided" and knows the next step is a new key;
* if the caller wins instead, the abandon matches no row and writes nothing `[E: E10-R2]`.

So the race is **safe in either order at the data level** (one decision at most, never two; no run), and the
grace is a matter of *not surprising live callers*, not of correctness.

**The grace period, from two parts.**

* *Floor — never abandon a live decision stage.* The longest the stage can honestly take is the reviewer plus
  OPA: the reviewer's client timeout is 30 s for the API and headless reviewers and **120 s** for the local one
  `[R: agents/llm]`, OPA is `timeout=30` `[R: policy/engine.py]`, so **150 s**; the SDK's own retries may add to
  the API reviewer `[N]`. A measured live stage with a fake reviewer and the real OPA took 0.1 s in total
  `[E: E10-R3]`, so the floor is the timeouts, not the machinery. The reconciler **refuses to start** with a
  grace below twice the floor (300 s).
* *Courtesy — let the caller's retry find its proposal.* A caller that failed mid-decision retries with the same
  key; abandonment before it does turns a recoverable retry into "use a new key". How long callers retry is a
  property of the callers `[N]`. **Proposal: 1 hour** (configurable, ≥ the floor), chosen, not derived.

`decided` (an ALLOW, no capability) is closed after the same grace as `closed / abandoned_after_decision` — it
has a decision, so it may be `closed`.

### 1.9 Every place that names a stage, and the structural tests that keep the list true

Found by reading the code, not remembered (grep of `stages.`, `pipeline_stage` and the stage literals across
`control_plane`, `scripts`, `agents`, `tool_gateway`, `db/migrations`, `tests`, `policy_tests`). The
`dispatch_state` column also contains `dispatching` — a different vocabulary — which is why the structural test
below keys on the column, not on the word.

| Where | Names | What `abandoned` needs |
|---|---|---|
| `orchestrator/stages.py`: constants, `STAGES`, `TERMINAL`, `BEFORE_DISPATCH`, `WAITING`, the docstring diagram | all | add `ABANDONED` to `STAGES` and `TERMINAL`; **not** to `BEFORE_DISPATCH` or `WAITING`; redraw the diagram |
| DB CHECK `action_proposals_pipeline_stage_check` (0016, 0017) | the list | add (0022) |
| DB CHECK `action_proposals_decision_past_received` (0021) | `received` | add `abandoned` (0022) |
| DB partial index `action_proposals_open_stage` (0016, 0017) | `recorded, closed` | add `abandoned` (0022) |
| `state/models.py` | the column | none |
| `api/function_api.py` `_drive` | `RECEIVED, APPROVED, DECIDED, CAPABILITY_ISSUED`, else-branch | none: an abandoned row falls into the else-branch and returns `_outcome_from_rows` |
| `api/function_api.py` `_outcome_from_rows` | `DISPATCHING, CLOSED, RECORDED, TERMINAL` | **the explicit `abandoned` outcome** (§1.8); decide whether `TERMINAL` membership triggers `_record_provenance` — proposal: no, `provenance/graph.py:190` already returns for any stage but `recorded`/`closed` and an abandoned proposal has no outcome to record |
| `api/function_api.py` `take/advance` at 826, 890, 924, 955; `_record_decision` | their own stages | none; none expects `abandoned` |
| `api/approvals.py` (`AWAITING_APPROVAL → APPROVED/CLOSED`) | | none |
| `api/approved_dispatch.py` SQL `pipeline_stage = :approved`, the stage read at 296 | `APPROVED` | none; test that `dispatch_approved` refuses a row at `abandoned` |
| `orchestrator/dispatch.py`: `BEFORE_DISPATCH` takes, `DISPATCHING`, `RECORDED`, `CLOSED`; `reconcile_stale_dispatches` | | none; a hand-written dispatch of an abandoned row is refused by `take(expected=BEFORE_DISPATCH)` — test; (5.74: the `advance`→`take` change lands here) |
| `scheduler/decide.py` SQL (`'approved'`, `('dispatching','capability_issued')`), `service.py`, the view `scheduler_proposals` | two lists | none; the view exposes every stage and the scheduler reads two lists — test that an abandoned row is invisible to every scheduler count |
| `provenance/graph.py:190` | `("recorded","closed")` | leave; documented above |
| `scripts/mutations_d62_d63.py` | `received`, `recorded` literals | new mutations for 0022 (§1.9 tests) |
| tests: `test_pipeline_stages` (iterates `stages.STAGES`), `test_action_proposals_decision_stage` (`LEGAL_NULL_STAGES`, `set(stages.STAGES) == …`), `test_decision_boundaries`, `test_migrations_roundtrip`, `test_check_constraints_null_rule`, `test_scheduler_e2e`, `test_scheduler_roles`, `test_approved_dispatch`, `test_sandbox_not_started`, `tests/crash_child.py` | | updated where they enumerate stages |
| docs: the `stages.py` docstring, ADR, D60 report, ACCEPTANCE 5.53/5.69 | the list | updated |

**Structural tests (to write with 0022):**

* **ST1 — every stage literal in code is a stage.** Parse `control_plane/` (and `scripts/`) with `ast`; take every
  string constant that sits in a SQL text next to `pipeline_stage` (`=`, `IN`, `<>`, `NOT IN`, `ANY`) and require
  it ⊆ `stages.STAGES`. A typo (`'abandonned'`) or a stage nobody added fails.
* **ST2 — the database and the code agree.** Read `pg_get_constraintdef` of `action_proposals_pipeline_stage_check`
  and require its list == `set(stages.STAGES)`; read the partial index predicate and require the excluded set ==
  `set(stages.TERMINAL)`; read `decision_past_received` and require the stage list == `LEGAL_NULL_STAGES`.
* **ST3 — the file registry.** A dictionary in the test lists every file that mentions a stage name or constant
  and why; a new file that starts naming a stage fails until it is listed — the same device as
  `NULL_IS_A_STATE`.
* **ST4 — one writer.** `ABANDONED` / `'abandoned'` appears as a *write* only in the reconciler's act module;
  `function_api.py` reads it. (A3.)
* **ST5 — every stage is classified once.** A table `STAGE_CLASS = {stage: terminal | waiting | before_dispatch |
  in_flight}` in the test must cover `stages.STAGES` exactly and agree with the constants; a new stage fails
  until classified.
* **ST6 — behaviour, table-driven.** Parametrized over `stages.STAGES` (as `test_action_proposals_decision_stage`
  already is): a proposal placed at each stage gets the right `_outcome_from_rows` (an explicit failure for each
  terminal stage — the case that gave a reasonless `DENY` for `abandoned`), the right scheduler counts, and the
  right refusal from `dispatch_approved` and the `dispatch_*` functions.
* **ST7 — the round trip carries rows.** The 0022 up/down test runs with a row at **every** stage including
  `abandoned` and `awaiting_approval/approved` (the missing coverage that let 5.75 hide), compares
  `snapshot_schema()` (§9) after every step, and asserts the moved rows.

**Reason codes, and the NULL rule.** Every closed-code column this work adds follows ACCEPTANCE 5.69: either
`NOT NULL`, or the CHECK says `IS NOT NULL` explicitly in each branch that needs a code (A5). The three CHECKs 0022
touches or adds are entered in `test_check_constraints_null_rule.py::NULL_IS_A_STATE` with their reasons (the
updated `decision_past_received`: NULL decision legal at two named stages; `abandoned_is_undecided`: NULL
decision is the point, NULL detail is refused explicitly), and a fault test inserts `abandoned` with a NULL
detail and requires the refusal. The reconciler's *audit* reason codes are a closed list in code (`emit` refuses
anything else, §4); with no state table (D64-11) there is no column to CHECK. **A measured option, not in 0022 unless
you say so:** `stage_detail` is free text for `closed` and `recorded` (families such as `decision_*`,
`capability_refused:*`, `dedup_hit:<id>`), not a closed vocabulary; today it is never NULL for those stages — 0 of
1,080 `closed` and 0 of 2,089 `recorded` rows in this database `[E: E19 survey]` — so a CHECK requiring a detail
for them would hold, at the cost of one more constraint to keep in step.

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
| DB identity | the scheduler's roles (`scheduler_reader`, `scheduler_state_writer`) + the runtime role for dispatch | `cyberorch_app` | a new narrow role | a read-only login role `reconciler_reader` that can only `EXECUTE` the read function (§2.3), for the plan side; **the existing engagement-scoped `cyberorch_app` path** (`engagement_scope`) for every state change on the act side |
| New privileges | writes on `action_proposals`/`tool_runs` for the scheduler | none | column-level `UPDATE` on stage/dispatch columns, `tool_runs.status`, `INSERT` audit; the read function | **none for writing** (no new role, grant or policy that writes); for reading: the reader role, the function owner role, the function and SELECT-only policies for the owner (§2.3) |
| Docker | the scheduler's (already has the socket) | its own | its own | the **act** side only |
| Lock | shared (`SingletonLock`) | own key | own key | own key |
| For | one deployable; the lock already excludes a second copy; startup reconcile-then-resume (R-A) is a function call | no schema/role change | least privilege; a bug in the sweeper cannot issue a capability | the strongest separation; a decision can be inspected before it is carried out (as `--dry-run`); the act side never reads a budget; **no cross-engagement write exists** because every write is scoped to one engagement by the same mechanism `propose_action` uses |
| Against | breaks D62's structural property: the decision side imports only `scheduler_reader` and the execution side only `engagement_scope`, pinned by AST tests `[R]` `test_scheduler_structure.py`; the scheduler would acquire stage-write and Docker-delete powers; a reconciler bug stops dispatch (same process); the serial loop would block on a long removal | the broadest privilege for the least-needed work; cross-engagement enumeration still unsolved | one process holds both "decide" and "delete" | two connections, more migration; slower to build; `cyberorch_app` can do more than the reconciler needs, so the restriction is in code and tests (§2.2a), not in a grant |

**Can it use `cyberorch_app`?** For *writes*, yes, and that is now the recommendation (D64-1): a state change
is one conditional UPDATE under `engagement_scope(eid)`, exactly the mechanism every stage uses, so it can touch
only that engagement. For *reading* across engagements it cannot (RLS), hence the reader and the function (§2.3).
Revision 2 proposed a separate write role with column-level `UPDATE` (E12); it would have been narrower in the
database and a second write path to maintain. It is withdrawn in favour of one write path pinned by tests.

### 2.2a Connections, and the tests that pin them (D64-1)

The scheduler's own structure test (`tests/test_scheduler_structure.py`) is the model: it reads the syntax trees
of `control_plane/scheduler/` and pins which module may import which connection. The same, for the reconciler:

| | **Plan side** (`reconciler/plan.py`, `observe.py`) | **Act side** (`act.py`, `act_docker.py`, `act_files.py`) |
|---|---|---|
| Database | `reconciler_reader_scope()` — a new scope in `state/db.py`, login role `reconciler_reader`, which can do one thing: `EXECUTE` the read function | `engagement_scope(engagement_id)` — the existing path: `cyberorch_app` with `cyberorch.engagement_id` set for the **one** engagement of the row being changed |
| Docker | read calls only: `containers.list/get`, `networks.list/get`, `inspect` | `kill`, `remove`, network `remove` |
| Files | `lstat`, `listdir` | `unlink` through a directory fd |
| Hands over / takes | a frozen dataclass `Action` of plain data: `engagement_id`, the object's id, `expected_stage`, `planned_stage_updated_at`, `reason_code` — no connection, no cursor, no Docker object | consumes an `Action`, re-verifies it, acts, verifies the result (§1.7), returns a `Result` |

The plan connection is closed before the act side opens its own; no transaction spans both. **No new write path:**
a statement aimed at another engagement's row moves 0 rows under `engagement_scope` (the policy
`engagement_isolation`, as for every other caller), so a cross-engagement write cannot be expressed by the act side.

The price is that `cyberorch_app` can do more than the reconciler needs (insert and delete capabilities, delete
proposals). So the restriction is pinned in the code's structure, not by a grant:

1. **AST, plan side.** From `control_plane.state.db` it imports only `reconciler_reader_scope`; it imports none of
   `engagement_scope`, `get_engine`, `control_plane.api`, `control_plane.orchestrator`, `control_plane.audit`,
   `control_plane.capability`, `control_plane.policy`, `control_plane.vault`, `tool_gateway`, `agents`. (Same
   shape as the scheduler's `decide.py` test.)
2. **AST, act side.** From `state.db` it imports only `engagement_scope`; not `reconciler_reader_scope`, not the
   plan module, not `control_plane.api` and not `control_plane.orchestrator.dispatch` — the reconciler never
   calls `propose_action`, `dispatch_*` or `dispatch_approved` (I7). It reaches `record_audit` only through
   `reconciler.emit`.
3. **Statement allow-list, act side.** Every string literal in `act*.py` that is SQL must match one of a short
   list of shapes — the conditional `UPDATE action_proposals SET pipeline_stage … WHERE … pipeline_stage =
   :expected AND stage_updated_at = :planned` (§1.2) and `UPDATE tool_runs SET status …` — and none may contain
   `DELETE`, `INSERT` (the audit emitter excepted), `DROP`, `TRUNCATE`, or name `capabilities`, `approvals` or
   `credential_material`. A mutation test adds `DELETE FROM capabilities` to the act side and requires the test
   to go red.
4. **Docker verbs.** `kill` and `remove` appear only in `act_docker.py`; `create`, `run`, `exec_run`, `prune`,
   `put_archive` appear nowhere in `control_plane/reconciler/`.
5. **Runtime separation.** A test gives the plan a recording connection factory and asserts the act side never
   receives it; a type-annotation check requires that no field of `Action` is a `Connection`, cursor or Docker
   object.
6. **One writer.** Nothing outside `control_plane/reconciler/` writes `abandoned` or imports `reconciler` (ST4).

If you prefer the narrow database grant over the code-level pinning, E12 is what it would look like; the two can
be combined (a narrow grant in addition) at the price of the second write path.

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

**Implemented (D64 step 6a, migration 0023, ACCEPTANCE 5.80).** Two functions, `reconciler_stuck_proposals()` and
`reconciler_run_states(text[])`; the checklist below is the test list (`tests/test_reconciler_reader.py`, 48 tests)
and S2–S5 each have a mutation (`D64-6a-a`…`j`). Where the build differs from, or adds to, this section:

* **Role membership leaked the policies (found by running it).** `migration_owner` has to be able to `SET ROLE` to the
  function owner to hand the functions over. With the default `INHERIT TRUE`, the policies written `TO
  reconciler_fn_owner` applied to `migration_owner` — which owns every table and the scheduler's view — and
  `scheduler_reader` saw 8,202 stuck proposals of engagements it never named. The membership is `WITH INHERIT FALSE,
  SET TRUE` (db/roles.sql); the hand-over is the migration's last step because `migration_owner` cannot touch the
  functions afterwards.
* **Indexes.** The first version took 18 s on this database (a sequential scan of `capabilities`, `approvals` and
  `tool_runs` per stuck row); four indexes bring it to 0.15 s `[E21]`.
* **Output.** Time is the database's clock, as epoch microseconds, with `db_now_us` in every row; booleans (kill flag,
  enrolled, revoked, and since migration 0026 `has_decision` -- whether the proposal has a decision, never what it is)
  are two-value enums. The result is capped at 5,000 oldest rows: **a full page means "truncated"** and
  the plan must say so. *(Since migration 0024 the reader pages past the first page with `reconciler_stuck_proposals_after`, up to `RECONCILER_MAX_PAGES`; `docs/D64_PREDELETION_COMPLETION.md` §6, ACCEPTANCE 5.88.)* Whether the budget is a proxy run's is not exposed (the allowlist is an array); the plan uses
  the proxy-run bound for every run, which is the longer one.
* **`reconciler_run_states`** refuses a NULL and more than 2,000 ids with a fixed error text, because an absent id
  means *orphan*.
* **Not built:** the conflict-driven network removal of D64-8 (a CIDR cannot be returned under "ids, enums, integers"). **Designed since, and the read function and plan side built (5.90)** (name hash + last use + conflict count, no range crosses; `docs/D64_PREDELETION_COMPLETION.md` §3, ACCEPTANCE 5.85); D64-N1 decided and built (5.90).

**Recommendation (D64-2): the function.** It is the narrowest of the four: no table is readable, the budget
leaves the database as one integer, and the function is the one place that says what the reconciler may know.

#### How a `SECURITY DEFINER` function reads — it does not bypass row-level security (E20)

A `SECURITY DEFINER` function runs with its **owner's** identity, and the owner's row policies apply like anyone's.
What it changes is *whose* policies; it does not switch policies off. Measured, in a transaction that was rolled
back, with the reader and owner as plain `NOLOGIN` roles:

| # | Experiment | Result |
|---|---|---|
| S1 | the owner has **no** policy for the table | the function returns **0 rows**; the owner's own direct `SELECT` also 0 |
| S1′ | the same function owned by a `BYPASSRLS` role | it sees every row — the configuration to forbid |
| S2 | the owner has a stuck-stage policy; the function has **no** stage filter of its own; the reader sets `cyberorch.engagement_id` | a `recorded` row of that engagement **is returned**: the existing `engagement_isolation` policy is `TO PUBLIC`, so it applies to the owner too and policies are OR-ed. With an explicit stage filter in the function body: 0 |
| S3 | `EXECUTE` | defaults to `PUBLIC`: an unrelated role could call it. After `REVOKE ALL … FROM PUBLIC`, that role is refused and the reader still can |
| S4 | `search_path` | an **unpinned** function resolved `action_proposals` to a `TEMP` table the caller had made (and granted the owner `SELECT` on) and returned `{FORGED-ROW}`; the function with `SET search_path = pg_catalog, public, pg_temp` and schema-qualified names ignored it. The reader has `TEMP` on the database by default; it has no `CREATE` on `public` |
| S5 | a capability whose budget the function cannot cast | `(budget->>'max_duration_seconds')::int` on `"abc"` raises `invalid input syntax for type integer: "abc"` for the **whole call** — one bad row blinds the reconciler — and echoes the value. The guarded form `CASE WHEN … ~ '^[1-9][0-9]{0,8}$' THEN (…)::int END` returns NULL for `"abc"`, `5.5` and `99999999999`, which the plan reports as `budget_unreadable` |
| S6 | owner and output | owner `NOSUPERUSER NOBYPASSRLS NOLOGIN`, owns no table; `RETURNS TABLE(text, integer, …)` only |

**What the revision-2 sketch of the function would have got wrong:** it had no stage filter (S2), no pinned
`search_path` (S4), an unguarded cast (S5), and no `PUBLIC` revoke (S3). All four are in the checklist now.

**The checklist the migration must satisfy, and what pins each item:**

| Item | Requirement | Pinned by |
|---|---|---|
| owner | a dedicated `NOLOGIN` role: `rolsuper = false`, `rolbypassrls = false`, `rolcreaterole = false`; not the table owner; owns no table, schema or other function | catalog test (and `snapshot_schema()` role lines) |
| policies | `SELECT`-only policies `TO <owner>` on the five tables, each restricted (stuck stages / a proposal that is visible) | grant-matrix test + a per-table test: the owner sees no `recorded` row without a GUC |
| column grants | the owner has column-level `SELECT` on exactly the columns the function reads, nothing wider | grant-matrix test, like the scheduler roles' |
| stage filter | an explicit `pipeline_stage IN (…)` in the function body, because a GUC widens the owner's policies (S2) | test: GUC set, a `recorded` row is never returned |
| `search_path` | `SET search_path = pg_catalog, public, pg_temp` in the definition; every relation schema-qualified | catalog test on `proconfig`; a test over the function body |
| `PUBLIC` | `REVOKE ALL ON FUNCTION … FROM PUBLIC`; `GRANT EXECUTE` to `reconciler_reader` only | `proacl` test |
| `TEMP` / `CREATE` | `REVOKE TEMP ON DATABASE … FROM reconciler_reader` (and from `PUBLIC` where no other role needs it); no `CREATE` on `public` | privilege test |
| output type | `RETURNS TABLE(…)` with a **pinned column list** of scalar types — ids, the closed `pipeline_stage` text, integers, timestamps, booleans; no `jsonb`, no array, no free text; `budget.tool` never appears | the pinned list in the test |
| casts | every cast of document content guarded by a pattern → NULL | fault test with `"abc"`, `5.5`, `-1`, `0`, `99999999999`, a missing key |
| volatility | `STABLE`; reads only | catalog test |
| error text | no error the function raises contains document content (S5) | the same fault test |

Two things this is *not*, said plainly:

* **It is a new class of privilege.** The reconciler's reader would be the first role in the system that sees
  rows of more than one engagement without setting the GUC. It cannot see a target, a reason, a budget's tool
  document or any other tenant data, but it does see *which engagements have stuck work* (6,903 of 13,338
  engagements in this database) `[E: E11]`. That is inherent in "read across engagements" and is the reason
  D64-2 is a decision for you.
* **The budget is not mutable under the reconciler's feet.** The code never updates `capabilities.budget` (the
  five `UPDATE capabilities` statements touch lease, heartbeat, the request counter and revocation only `[R]`);
  nothing in the database *prevents* it `[N: no trigger found]`.

**The write side** is §2.2a: the act side never reads a budget. The plan hands it `(engagement_id, proposal_id,
planned stage_updated_at)` and its statement is a **compare-and-set on exactly that observation**, so a row that
moved between plan and act is not touched. (Revision 2's narrow write role, E12, is kept in §6 as the alternative.)

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
  exist dispatches new work on top of unexplained state. The options and the honest answer are §3.3: **nothing
  makes the order true; it is a convention.**
* **One lock or two?** *One shared key* excludes the two at once by construction (no interference to reason
  about) but a long reconcile blocks dispatch and the reverse. *Two keys* let them overlap, which needs the
  argument below and the tests of §3.2–§3.3.

### 3.1 Can they interfere?

The scheduler only moves `approved → capability_issued → dispatching → recorded/closed`, all inside one
`dispatch_approved` call `[R]`. Row by row:

| Reconciler touches | Scheduler might be doing | Why it is safe |
|---|---|---|
| `capability_issued`, lease lapsed → `closed: capability_not_live` | issuing/dispatching the same row | the update is conditional on the stage and the observed `stage_updated_at`; a lapsed lease means the dispatch would refuse the same row with the same reason `[E: E6]` — both paths end identically |
| `dispatching`, overdue → `unknown_outcome` | the same dispatch, still recording | **Corrected after E17.** Revision 2 said that a dispatch which loses the stage race "loses its result, which is flagged unknown". It does not: `advance` returns False and `_record_scan_result` ignores it, so the result *is* recorded as a success beside a `recorded / unknown_outcome` stage (ACCEPTANCE 5.74). What makes the pair safe is (a) the reconciler's close being a compare-and-set that runs only past `B + P + Q`, a time a live dispatch cannot reach, and (b) the dispatch side taking its stage with `take`, so that the case the bound excludes fails loudly instead of contradicting itself. (b) is a prerequisite fix, in the same change as 0022 |
| `received` → `abandoned` | a caller still in its decision stage | the same stage guard: whoever commits first wins; the loser writes no decision record; the caller then gets the explicit `abandoned` outcome (§1.8, `[E: E10]`) |
| `approved`, killed engagement/expired approval → `closed` | about to dispatch it | the scheduler re-reads the engagement right before acting (`servable_now`) and `dispatch_approved` refuses killed/expired itself `[R]`; the reconciler's close is a compare-and-set on `APPROVED` — whichever commits first wins, the other matches no row |
| removing a container/proxy/network | a dispatch that has just created it | removal requires "the DB says finished/absent/overdue", and a brand-new run has a `running` row inside its deadline |
| removing an idle network | `ensure_network` has just returned it | a race (§1.5): the create fails as `NotStarted`, retryable; avoided by an idle-retention period long compared with a dispatch; Docker itself refuses to remove a network with an attached endpoint `[E: E13-D4]` |

So two locks are *safe given* the conditional updates, the deadlines and the two prerequisite fixes; one shared
lock is *simpler*. The decision is D64-10.

### 3.2 Race tests (planned, not written)

The pattern is the one `tests/test_decision_boundaries.py` and the E10/E17 experiments use: a `threading.Barrier`
or a hook inside `FakeSandbox.during` / the reviewer holds one side while the other runs, then both orders are
checked. Each test also states the mutation that must turn it red.

| # | Race | Both orders must end in | Mutation that must break it |
|---|---|---|---|
| RT1 | reconciler closes a `dispatching` row while the (fake) container is still running, then the dispatch finishes (E17 as a test) | exactly one of {dispatch recorded `succeeded`, reconciler `unknown_outcome`} — **never both**; the loser writes no evidence row and no success audit; the raw output is on disk; stage, `dispatch_state`, `tool_runs.status` and audit agree | `stages.take` → `stages.advance` at the record sites |
| RT2 | the dispatch records first; the reconciler's compare-and-set arrives later | 0 rows moved, no audit, the dispatch's result untouched | drop `stage_updated_at = :planned` from the predicate |
| RT3 | `capability_issued`, lease lapsed: the reconciler closes while a heartbeat renews the lease or the dispatch takes the stage | dispatch wins → reconciler moves 0; reconciler wins → the dispatch refuses with `capability_not_live`; the final state is the same `closed` either way | evaluate the lease in Python instead of in the statement |
| RT4 | `received` → `abandoned` while the caller is inside its decision stage (E10 as a test) | at most one `policy.decided`; the loser's outcome is the explicit `abandoned` one or the committed decision, never a reasonless `DENY` | remove the explicit `abandoned` branch of `_outcome_from_rows` |
| RT5 | `approved` in a killed engagement: the reconciler closes while the scheduler tries `dispatch_approved` | one winner; no container call if the reconciler wins; no `closed` after a recorded run | close without the kill predicate |
| RT6 | two reconcile passes act on the same `Action` (the lock bypassed in the test) | the second moves 0 rows; one audit event | audit before checking the row count |
| RT7 | pause or kill switch between plan and act | a paused engagement's rows are not touched (the predicate is re-evaluated in the statement); a killed one is closed | plan-time check only |
| RT8 | container: the reconciler kills/removes while the control plane's own `kill()` / `remove(force=True)` run | whichever order, the object is gone, verification passes, `NotFound` on the second remover counts as gone and raises no `action_failed` | treat `NotFound` as failure |
| RT9 | network: removed between `ensure_network` and `containers.create`/`start` (E21-N3), with a retry | the first dispatch fails typed `NotStarted`, the retry succeeds on the re-created network | remove a network that still has a `created` container |

### 3.3 Start order and locks, said honestly (D64-10)

**Nothing enforces that the reconciler ran before the scheduler.** "Reconcile first" is an operator convention (a
`systemd` `After=`, a runbook line). The two are separate processes with separate lock keys, and nothing in the
database makes one wait for the other. What exists: (a) the stage guards, which make a concurrent action lose
cleanly (§3.1); (b) the time bounds, which keep the reconciler off a live dispatch; (c) each side's lock against a
second copy of *itself*. What does **not** exist is any guarantee that a new dispatch does not start on top of
unreconciled state. If the order matters enough, option (b) of the earlier list — a marker row, with the
scheduler refusing to start while the reconciler's last completed pass is older than the scheduler's last stop —
turns the convention into a check, at the cost of a table and a coupling. **Not recommended now:** the two work on
disjoint states except through the guarded updates, and the harm of the wrong order is bounded to a stale row
being acted on one pass later.

**Implemented (D64 step 6d, ACCEPTANCE 5.83).** `scripts/run_reconciler.py` is the separate process; its lock key is its own
(`0x0D64_5EC0_0000_0001`), the scheduler's is untouched, and a test holds both at once. **Run `--once` before the scheduler
starts: that is the convention, and it is a convention only.** CT1–CT5 and RT1–RT3, RT5, RT6, RT8, RT9 are written (RT4 is `test_stage_vocabulary.py::test_a7_*`; 5.89)
(`tests/test_reconciler_concurrency.py`); RT7 is moot (nothing the plan decides depends on pause), the rest are covered from the
other end by 5.74/5.78.

**Concurrency tests (as planned; see above for what was written):**

| # | Test | Invariant |
|---|---|---|
| CT1 | both processes run against one database for N cycles, with a fixture holding every residue class (R1–R9) and a live stream of fake dispatches | after each cycle (extending `assert_coherent`): no proposal with contradictory stage / `dispatch_state` / run status; no proposal executed twice (the sandbox call count per proposal ≤ 1); every `*_removed` event has its object gone; no event for an action that changed nothing |
| CT2 | the order inverted: the scheduler starts first on a database with stale R1/R3 rows, then the reconciler | the same invariants; the scheduler's `dispatching` / `capability_issued` counts fall to 0 afterwards |
| CT3 | `kill -9` of either process at random points between plan and act (the `crash_child.py` pattern of the D60 tests), then restart | eventually consistent; nothing audited that did not happen |
| CT4 | the two lock keys | both can be held at once (positive control that they do not exclude each other); a second copy of each is excluded |
| CT5 | real Docker: the reconciler runs a pass while a real run (the `nmap` image) is inside its deadline | the live run's container is not touched |

## 4. Audit

> **Revised at the pre-deletion completion (item 4, ACCEPTANCE 5.86; `docs/D64_PREDELETION_COMPLETION.md` §4).** Where this section says an action is audited *after* it was verified, that is now true of the Docker and file result events only. A proposal transition and its event are one database transaction; a kill, a removal or an unlink is preceded by `reconciler.action_intended`, and an intent with no result is listed by `audit.query.unresolved_reconciler_intents`. The event list below gains `reconciler.action_intended`; `reconciler.files_removed` is one event per file (`count` 1) instead of one per pass.

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

> **Revised at completion 5 (ACCEPTANCE 5.101).** The evidence files are `<evidence dir>/<engagement id>/<container id>.inspect.json` and `.logs`, the subdirectory `0700`; they are raw data (not redacted); the service probes the directory when it starts and refuses to start if it cannot write there.

> **Revised at completion 4 (ACCEPTANCE 5.97, 5.98).** A container whose run ended in `unknown_outcome` is removed with reason `run_unknown_outcome`, and only after its inspect output and logs were written to the operator's `--evidence-dir` and their SHA-256 recorded in `reconciler.evidence_saved` (the order is archive, intent, `evidence_saved`, removal, `container_removed`; if the archive fails nothing else happens). `reconciler.failure_summary` also carries `reported`: for each `subject:reason` the plan reported and left alone, the number of distinct objects in the window.

**Implemented (D64 step 6d, ACCEPTANCE 5.83):** `control_plane/reconciler/emit.py` is this table, with two differences:
`reconciler.dispatch_unknown_outcome` stands where the table says the existing `dispatch.unknown_outcome` is kept (its payload
has a boolean and free text; the rule is ids and reason codes, so a query for unresolved runs asks for both), and
`reconciler.failure_summary` is the periodic summary of failures. A dry run writes no audit record at all.

Proposed vocabulary (names are proposals):

| Event | Scope | Payload | Reason codes (closed) |
|---|---|---|---|
| `reconciler.started` | global | `instance_id`, counts per residue class | — |
| `reconciler.stopped` | global | `instance_id`, `reason_code` | `signal`, `lock_lost`, `db_lost`, `docker_lost`, `audit_failed`, `unexpected_error` |
| `reconciler.start_refused` | global | `instance_id`, `reason_code` | `lock_held`, `grace_below_floor` |
| `reconciler.proposal_closed` | engagement | `proposal_id`, `reason_code` | `capability_not_live`, `approval_expired`, `approval_revoked`, `engagement_killed`, `abandoned_after_decision` |
| `reconciler.proposal_abandoned` | engagement | `proposal_id`, `reason_code` | `undecided_past_grace` |
| `reconciler.container_killed` | engagement (owner known) | `run_id`, `reason_code` | `overran_deadline` |
| `reconciler.container_removed` | engagement (owner known) / global | `run_id`, `reason_code` | `overran_deadline`, `run_finished`, `run_unknown_outcome`, `no_run_row_past_grace` |
| `reconciler.evidence_saved` | engagement (owner known) | `run_id`, `container_id`, `inspect_sha256`, `logs_sha256` | — (written after the intent and before the removal of a container whose run is `unknown_outcome`; ids and hashes only, never a path; ACCEPTANCE 5.97) |
| `reconciler.proxy_removed` | engagement / global | `run_id`, `reason_code` | `owner_run_ended`, `overran_deadline` |
| `reconciler.network_removed` | global | `network_id` (the hash in the name), `reason_code` | `range_conflict`, `idle_sweep` |
| `reconciler.files_removed` | global | `kind`, `count` | kinds `credential_mount`, `tls_leaf` (removed only when no live container mounts them and they are older than `B_cap + P + Q`) |
| `reconciler.action_failed` | global / engagement | `kind`, `reason_code` | `in_use`, `daemon_error`, `not_gone_after_removal`, `not_changed_after_update`, `still_running_after_kill`, `budget_unreadable` |

`dispatch.unknown_outcome` (the existing event, `requires_human_review`) is **kept as the record of an
unresolved run** — the reconciler calls the existing function and does not invent a second event for it.

## 5. Decisions (D58 format; ⚑ = needs your answer)

Recommendation in the third column; "depends on" in the last.

| # | Question | Recommendation and why | Depends on |
|---|---|---|---|
| **D64-1** ⚑ | Process and identity (§2.2, §2.2a): A inside the scheduler / B separate with `cyberorch_app` / C separate, own role / D separate, plan–act split | **D, with every write through the existing engagement-scoped `cyberorch_app` path.** Separate process; plan side = a new login role that can only `EXECUTE` the read function; act side = `engagement_scope(eid)` per proposal, so **no cross-engagement write exists and no write grant is added** (the narrow-grant act role of revision 2, E12, is withdrawn). The restriction lives in code and is pinned by two AST tests, a statement allow-list, a Docker-verb test and a runtime-separation test (§2.2a). A breaks D62's structure (pinned by AST tests); B/`cyberorch_app` as the *read* identity cannot read across engagements. | — |
| **D64-2** ⚑ | How the reconciler reads across engagements, and the budget (§2.3) | **One `SECURITY DEFINER` function owned by a dedicated, non-bypass `NOLOGIN` role; `EXECUTE` only for the reader; no table readable.** It does not bypass RLS — it runs under the owner's policies — so it filters the stage itself (a GUC would otherwise widen it), pins `search_path`, revokes `PUBLIC` and `TEMP`, returns scalar types only and guards every cast (E20: one uncastable budget would otherwise blind the whole pass). The first role able to see more than one engagement without the GUC — it can list which engagements have stuck work. Alternatives: column grants + policy (exposes `budget.tool`); enrollment table only (misses un-enrolled engagements). | D64-1 |
| **D64-3** ⚑ | The overdue thresholds | **Derived from the budget, capped, never typed in:** `B = min(budget.max_duration_seconds, B_cap)`, **`B_cap` = 1,800 s `[N]`**; kill a container at `StartedAt + B + 60 s`; `unknown_outcome` at `stage_updated_at + B + P + Q` (`B + 660 s`, `B + 1,215 s` with a proxy — upper bounds read from the code's client timeouts `[N]`); a lapsed lease at `lease_expires_at + 30 s`; **closing is one conditional UPDATE** (compare-and-set on the stage and the observed `stage_updated_at`); budget unreadable → report, change nothing. **Prerequisites:** D58-16's operator-owned Rego ceiling (≤ `B_cap`, compared by a test) — *the global ceiling is built (implementation step 3, ACCEPTANCE 5.76), `B_cap` = `control_plane/policy/ceiling.py`* and the dispatch-side fix of ACCEPTANCE 5.74 (a lost stage must fail the record, not contradict it). Race tests RT1–RT9 (§3.2). | D64-1, D64-2, D58-16 |
| **D64-4** ⚑ | An overdue **running** container | **Kill it, keep the exited container a retention window (24 h `[N]`), remove after.** I7 forbids silent re-execution, not stopping an overdue process; keeping the corpse preserves the only evidence of what ran. Alternative: remove at once (frees the network now, loses the evidence). The in-container deadline (§8) would make this a backstop. | D64-3 |
| **D64-5** ⚑ | Stuck `received` (no decision), now that 0021 forbids closing it | **A new terminal stage `abandoned`, migration 0022.** Defined as nine checkable properties (§1.8 — *compare with yours; I do not have it*); CHECKs written NULL-exact (E9-A11); index rebuilt; the downgrade moves rows with `NO FORCE / FORCE ROW LEVEL SECURITY` around the UPDATE and restores the COMMENT (E19); every place that names a stage inventoried, with seven structural tests (§1.9); an explicit `abandoned` outcome for a retried key instead of today's reasonless `DENY`. Grace **1 h `[N]`**, floor 150 s, refuse to start below twice the floor. Option: also require `stage_detail IS NOT NULL` for `closed`/`recorded` (0 NULL in 1,080 / 2,089 rows here) — not in 0022 unless you say so. Alternative: leave them, report their age. | D58-6 |
| **D64-6** | `capability_issued` with a lapsed lease: close it (`capability_not_live`)? | **Yes** — exactly what a resumed `propose_action` does `[E: E6]`; known not-run. | D64-1 |
| **D64-7** | `approved` rows: which to close | Only those the scheduler **cannot reach**: engagement killed (`engagement_killed`), or not enrolled with an expired/revoked approval. Leave paused. For servable engagements the scheduler already resolves expiry `[E: E7]`. | D64-1 |
| **D64-8** ⚑ | Sandbox networks (§1.5) | **Conflict-driven first, a 24 h sweep second.** On a recorded `network_range_conflicts…` refusal, remove our idle networks that overlap the requested range (others are reported); a 24 h sweep removes idle ones. Idle = no container of **any** state attached (Docker itself refuses only for running/paused, E21) and the last container finished ≥ 1 h ago `[N]`; verified gone. A removed network is re-created by the next dispatch (E21-N2); a race with `create`→`start` is a typed `NotStarted` (E21-N3). Alternatives: never remove, alarm on count (overlap still bites, E3); a network per run (a sandbox redesign; out of scope). | D64-1, D64-10 |
| **D64-9** | Label integrity and the Docker boundary (§2.4) | **Select by label *and* the DB's knowledge; act by full id after re-inspect; `NO_OWNER` report-only; no HMAC label** (it adds nothing against whoever holds the socket). State that "only ours" is a property of the reconciler's code, not of Docker; the real boundary is a dedicated daemon or a verb-limiting socket proxy — an operations decision, not made here. | D64-1 |
| **D64-10** ⚑ | Start order and locks (§3, §3.3) | **Two lock keys. Reconcile-before-schedule is an operator convention, and the document says so** — nothing makes one process wait for the other. Safety rests on the guarded updates, the time bounds and the two prerequisite fixes (§3.1), not on order. Concurrency tests CT1–CT5 (§3.3) include the inverted order. A marker row that turns the order into a check exists and is not recommended now. One shared key is simpler but makes a long reconcile and dispatch exclude each other. | D64-1 |
| **D64-11** | A `reconciler_state` table for "reported once, ever"? | **No** for now: audit actions taken and verified (§4); observation-only cases are logged; a failed action is audited once per object and reason per process. Add the table if an operator needs the deferred-style record D62 has. | — |
| **D64-12** | Host files (§1.5) | Remove `cyberorch-cred-*` and `cyberorch-tls-*` when **no container in a live state (`created`, `running`, `paused`, `restarting`) mounts the file *and* it is older than `B_cap + P + Q`** — neither condition alone (E22); regular files of the expected owner through a directory fd, verified by `lstat`. The mode and a per-run `0700` directory remain **D58-17's**; until then the sweeper runs as the control plane's uid to delete the 0600 files. | D58-17 |
| **D64-13** | Excluded from this deliverable | R10 (task claims, X7), the failure ladder / reopen (D58-6), quotas (D58-13), credentialed-dispatch kill (D58-16, except its Rego ceiling, which D64-3 needs) — and **the deadline inside the container, which has its own design document (`docs/D65A_CONTAINER_DEADLINE_DESIGN.md`) and goes first.** | — |

Order of dependence: D64-1 first; D64-2, 3, 6, 7, 9, 10 follow from it; D64-4 from D64-3; D64-8 from D64-1 and
D64-10; D64-5 and D64-12 wait on D58-6 and D58-17; D64-3 waits on D58-16's ceiling. **Order of work if you confirm:**
D65-A (its own document); then **0022** with the two dispatch-side fixes (ACCEPTANCE 5.74, and the explicit
`abandoned` outcome) and the 0017 downgrade fix (5.75); then **0023** (the reconciler's roles, grants and read
function) and the reconciler package. 0022 can ship alone.

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

**Revision 3, E17–E26.** E17 used the test fixtures (the engagement and rows it creates are removed by them; the
session-end residue check passed). E18–E20 ran in a **template-copied temporary database** (`cyberorch_d64tmp`,
dropped afterwards) or in transactions that were rolled back, and each ends with a `snapshot_schema()` comparison
or a count of what is left. E21–E26 used Docker and removed what they made; afterwards no container, sandbox
network, `/tmp/cyberorch-*` file, temporary database or `d64*`/`s_*` role was left, and the two containers that
were there before (`web-target-d40`, `d11-target`) were untouched. The lesson of revision 2 is applied: nothing
modified the development database.

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
| **E17** | the existing `reconcile_stale_dispatches` (threshold 0) run from inside a `FakeSandbox.during` hook, i.e. while the dispatch's container is "running"; then the dispatch finishes | the function marked the proposal; the state right then: `recorded / unknown_outcome`, run `unknown_outcome`. The live caller was returned `ALLOW` with a run. **Final row: stage `recorded`, detail `unknown_outcome`, `dispatch_state` `succeeded`, `tool_runs` `succeeded` exit 0, 1 evidence row, audit `dispatch.unknown_outcome` ×1, `tool_run.started` ×1, `tool_run.succeeded` ×1** — self-contradictory (ACCEPTANCE 5.74) |
| **E18** | `alembic downgrade` step by step on a template copy of the development database (6,387 `approved`, 200 `awaiting_approval` rows), then `upgrade head`; `snapshot_schema()` before and after | downgrades to 0020, 0019, 0018, 0017 succeed; **to 0016 fails: `check constraint "action_proposals_pipeline_stage_check" … is violated by some row`** (0017's UPDATE runs as the owner under FORCE RLS and moves nothing; ACCEPTANCE 5.75). `upgrade head` from 0017 succeeds; schema differences: 0 |
| **E19** | `snapshot_schema()` (§9) in a template copy: T1 two snapshots of an untouched database; T2 replay of the COMMENT incident; T3 the 0022 upgrade; T3b the downgrade as first drafted; T4 the downgrade without restoring the COMMENT; T5 with it. Plus a survey of `stage_detail` | **T1** 431 keys (232 columns, 83 constraints, 40 indexes, 26 policies, 28 relations, 11 roles, 5 functions, 4 triggers, 1 view, 1 alembic), no difference. **T2** the snapshot reports `constraint:action_proposals.action_proposals_decision_past_received` changed — its COMMENT gone; after restoring it, no difference. **T3** the upgrade changes exactly: `decision_past_received`, `pipeline_stage_check`, the index `open_stage`, and adds `abandoned_is_undecided`. **T3b** the downgrade without `NO FORCE / FORCE` **fails** (`is violated by some row`: the owner's UPDATE moved nothing under FORCE RLS; the superuser run of revision 2 bypassed RLS and hid this). **T4** with the RLS switch but no COMMENT restore: the snapshot reports the lost COMMENT; the moved row is `received / NULL`. **T5** complete: no schema difference. Survey: `closed` 1,080 rows, 0 with a NULL `stage_detail`; `recorded` 2,089, 0; `received` 3,091 undecided rows exist in this development database |
| **E20** | `SECURITY DEFINER` (S1–S6), in a rolled-back transaction | see §2.3: S1 owner without a policy → 0 rows; S1′ `BYPASSRLS` owner sees all; S2 a GUC widens what the owner sees (a `recorded` row returned) until the function filters the stage; S3 `EXECUTE` defaults to `PUBLIC`; S4 an unpinned function read the caller's TEMP table (`{FORGED-ROW}`), the pinned one did not, the reader has `TEMP` by default and no `CREATE` on `public`; S5 `"abc"` aborts the whole call and is echoed, the guarded cast gives NULL for `"abc"`, `5.5`, `99999999999`; S6 owner `NOSUPERUSER NOBYPASSRLS NOLOGIN` owns nothing, output `TABLE(text, integer)` |
| **E21** | networks (N1–N4) | **N1** `network rm` with a container attached: `running` **refused** (`has active endpoints`); `paused` **refused**; `created` (never started) **removed**; `exited` **removed**; `containers.list(all=True, filters={"network": …})` finds all four. **N2** an idle network removed, then `ensure_network`: re-created with the same name; a run on it exited 0. **N3** the network removed between `ensure_network` and the container's `start`: `ContainerStartRefused` (a `NotStarted`, reason `container_start_refused`), message `network … not found`. **N4** a `/24` exists and a `/29` inside it is asked for: `NetworkRangeConflict`, reason `network_range_conflicts_with_another_network`, message naming the range |
| **E22** | files mounted into containers | a bind-mounted file is listed in `Mounts[].Source` of a `created`, a `running` **and** an `exited` container; `containers.list(volume=<host path>)` finds all three; reading every container's mounts and keeping the live states (`created`, `running`, `paused`, `restarting`) finds the first two, and none once they are removed |
| **E23** | `CREATE DATABASE … TEMPLATE cyberorch` | first copy of the 139 MB database 8.9 s, the next 0.5 s; **refused while any other session is connected to the source** (`source database "cyberorch" is being accessed by other users`); `migration_owner` and `cyberorch_app` lack `CREATEDB` — a superuser (or a dedicated role) is needed |
| **E24** | the deadline helper, build (D65-A) | a 60-line C helper, `gcc -O2 -static -s -fno-ident -Wl,--build-id=none`: 714,680 bytes, the same sha256 when rebuilt from another directory, under another file name, a second later; a Go version, `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid="`: 1,757,332 bytes, the same sha256 from another directory and a second later, and an `arm64` build produced without a cross toolchain |
| **E25** | the deadline helper, behaviour (D65-A), both builds | stdin passthrough; exit codes (3 → 3, killed -9 → 137, the tool's own 124 → 124 after 0.2 s, missing binary → 127 with a message); deadline 3 s → 124 after 3.2 s; `docker stop` of a tool that traps TERM took 0.2 s (SIGTERM forwarded) and exited 0; uid 65534 + `cap_drop ALL` + read-only root + `no-new-privileges` works; the parent `kill -9`'d at 2 s with a 6 s deadline → exit 124 after 6.1 s by Docker's own timestamps and no leftover grandchild |
| **E26** | the helper on a `noexec` host filesystem | the container's `start` is refused (`failed to create task for container …`), before anything of the tool runs — fail-closed |

Not run: the 2-minute node-delete cost (ACCEPTANCE 5.23) was measured at D63; the stale credential file
(`cyberorch-cred-*`) was not reproduced here (`[D]` ADR E12 recorded it at D58); a Docker restart's effect on
networks (would they survive a daemon restart with their containers?) was not tested `[N]`; Docker's behaviour
for a non-root member of the `docker` group, a socket proxy and rootless mode were not tested `[N]`; the
worst-case duration of the pre-start and post-run phases (§1.2) is a bound read from the code, not a measured
maximum `[N]`; the helper's reproducibility across *machines* and toolchain versions (E24 covers one machine) `[N]`.

## 7. What this document does not do

It writes no code, no migration and no test; the prototypes of `snapshot_schema()` and of the deadline helper live
in the session's scratch area. It does not pick values for the grace, `B_cap`, the retention windows or the idle
period (they are labelled `[N]` and listed as decisions). It does not decide D58-6, D58-13, D58-16 or D58-17; it
names where it depends on them. Once you have answered §5 (⚑), the build is, in this order: **D65-A** (its own
document); **0022** with the dispatch-side fixes (5.74, the explicit `abandoned` outcome) and the 0017 downgrade
fix (5.75), and `snapshot_schema()`; then **0023** (roles, grants, the read function) and a
`control_plane/reconciler` package split like `scheduler` (plan / act / verify / emit / lock); one operator
script; the tests of §1.9, §2.2a, §3.2 and §3.3 (each failing a boundary, the way
`tests/test_decision_boundaries.py` does for the decision stage), including the one that makes a call report
success without effect to prove nothing is audited unverified; and the residue check (`tests/residue.py`)
extended to the objects it manages.

## 8. The deadline inside the container (summary; the design is `docs/D65A_CONTAINER_DEADLINE_DESIGN.md`)

**Implemented (D64 implementation step 4, ACCEPTANCE 5.77).** The helper exists, in Rust: `tool_gateway/deadline/`,
mounted at `/cyberorch-deadline` as the container's *entrypoint* (two of the five images have one of their own, which
follows it), checked against the committed `SHA256SUMS` before every run, with the label `cyberorch.deadline=<D>` (or
`none` for an explicit opt-out) on every container `DockerSandbox.run` creates. For the reconciler this means: the
**label** says what deadline a container was started with and is absent only on containers the sandbox did not create
for a tool run (the egress proxy has none: D65A-7); an **exited container with code 124 that ran at least `D − 2 s`**
by Docker's own timestamps is a run whose control plane died and whose helper ended it (§7 of the D65-A document); and
the container-kill threshold `T_kill` is a backstop, as §8 says below. Nothing in the reconciler reads the label yet —
that is step 6.

**The problem.** A tool container's duration is enforced from outside, by the control plane's
`container.wait(timeout)` and `kill()`. If the control plane dies nothing stops the container: a 5 s budget was
still running 21 s after `kill -9` of its parent `[E: E16-A]`, and Docker has no option for a maximum lifetime
`[E: E15]`. **The experiment answer:** a small static PID-1 helper, bind-mounted read-only through the existing
`source_mounts` primitive, starts the tool and ends the container at `B + slack`, exit 124; with the parent
`kill -9`'d the container exited after 6.1 s on a 6 s deadline, grandchildren included `[E: E16, E25]`. With the
control plane alive the budget still wins `[E: E16-C]`. It is a separate deliverable because it changes how every
run is started and has its own tests; with it, the reconciler's container kill becomes a backstop and the
`B + 660 s` bound concerns database state only. It goes **first**, because the reconciler's thresholds (§1.2)
are written for the world in which it exists.

## 9. Shared test utilities: `snapshot_schema()` and the template database

**Implemented (step 5):** `control_plane/state/schema_snapshot.py` (`snapshot_schema(conn, schema)`, `diff()`); the
round-trip tests in `test_migrations_roundtrip.py` compare it after every step, and `tests/test_schema_snapshot.py`
shows with 18 positive controls that each kind of change (a COMMENT, an ACL, a FORCE flag, a function's
`SECURITY DEFINER` or `search_path`, a trigger's state, …) is seen. The template-database helper is not built yet.

**The problem, from two incidents.** A restore that compared constraint *definitions* but not their COMMENTs lost
a COMMENT (D63-j, and again in revision 2 of this document, caught by the next full-suite run). The existing
`Scratch.fingerprint()` in `tests/test_migrations_roundtrip.py` covers columns, constraints (definition only),
policies, indexes, trigger names, function bodies and table/column grants; it does **not** cover COMMENTs, the
owner, `relrowsecurity`/`relforcerowsecurity`, `convalidated`, function attributes (`SECURITY DEFINER`,
`search_path`, ACL), view definitions or options, relation ACLs, default ACLs or role attributes — the things this
design depends on.

**The tool (proposed; prototype in the scratch area).** `tests/schema_snapshot.py`:

* `snapshot_schema(conn, schema="public") -> dict[str, str]` — one entry per schema object, key `kind:name`, value a
  normalised text of everything about it: for columns the type, nullability, default, identity, generated flag,
  ACL and COMMENT; for relations the kind, owner, both RLS flags, ACL, options and COMMENT; for constraints the
  definition, `convalidated`, deferrability and COMMENT; for indexes the definition, validity and COMMENT; for
  triggers the definition, enabled state and COMMENT; for policies the command, roles, `USING` and `WITH CHECK`;
  for functions the full definition, owner, `SECURITY DEFINER`, `proconfig`, ACL and COMMENT; for views the
  definition; for roles `rolsuper`, `rolcreaterole`, `rolcreatedb`, `rolcanlogin`, `rolbypassrls`; default ACLs;
  the Alembic version. No OIDs and no timestamps, so two snapshots of equal schemas are equal. **431 entries on the
  current database.**
* `diff_snapshots(a, b) -> list[str]` — `missing after`, `new after`, `changed` with the first differing
  characters shown.
* `assert_schema_unchanged(before, after, allow=())` — for tests; `allow` names the keys a step is *meant* to change.

**Proof it earns its place** `[E: E19]`: two snapshots of an untouched database are equal; the revision-2 incident
replayed (drop and re-add the CHECK without its COMMENT) is reported as one changed key, and no difference remains
once the COMMENT is restored; the 0022 upgrade is reported as exactly four changed keys and one new one; the
downgrade is shown to need `NO FORCE / FORCE` (the snapshot alone would not have shown that — the *data* did; see
ST7); `alembic downgrade`/`upgrade` over the real data left 0 differences (E18).

**Where it is used (all part of the implementation, none written now):**

1. replaces `Scratch.fingerprint()`; the round-trip tests compare snapshots after **every** step up and down, not
   only the first and the last;
2. `scripts/mutation_check.py`: after the restore of each mutation, compare a snapshot taken before — it would have
   caught D63-j;
3. destructive experiments and tests: every one ends with a snapshot comparison against the source ("no
   difference"), or is run in a transaction that is rolled back.

**The temporary database.** `CREATE DATABASE … TEMPLATE cyberorch` copies 139 MB in 0.5 s (8.9 s cold), but it is
**refused while any other session is connected to the source**, and the application roles cannot create databases
`[E: E23]`. So it cannot be done from a pytest session that already holds pooled connections. Options:

| | How | For | Against |
|---|---|---|---|
| (a) | a never-connected `cyberorch_template` kept at head by `scripts/init_db.sh`, copied by a role with `CREATEDB` | real data shape, fast | a new database and a new privilege; must be refreshed after every migration |
| **(b) recommended for tests** | the existing scratch-**schema** harness (migrations run into a `migtest_*` schema, ~4–6 s per test), plus rows seeded at every stage | no new privilege; already in CI; no source-session problem | no production-sized data |
| (c) | terminate other sessions, then copy | works | kills the session's own connections; unsuitable inside a test run |

**Recommendation:** (b) for CI tests, **with representative rows at every stage** (the missing coverage that hid
ACCEPTANCE 5.75); the template copy only for manual and destructive experiments, run by a superuser with no other
sessions on the source, as the experiments of this revision (E18, E19, E20) were. Revision 2's E10 changed the
development database directly — which is how the COMMENT was lost.
