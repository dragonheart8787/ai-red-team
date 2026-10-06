# D60 — `propose_action` as stages that each commit (D58-5)

D58 showed, with eleven experiments, that `propose_action` was one database transaction from the
first canonicalization to the last provenance edge, and what that cost: a `kill -9`, a Postgres
restart and a kill switch in the middle of a dispatch each rolled every state row back and left only
the audit trail to say anything had begun. `reconcile_stale_dispatches` could not find an
interrupted dispatch because the row it looks for never existed; a revocation could not find the
capability it was meant to revoke; one cheap, late provenance insert could take a finished tool run
down with it. D59 had already paid for the same assumption once (a network conflict recorded as
`unknown_outcome` because the design knew only "succeeded" and "failed completely").

This deliverable is that decision, D58-5 Option B, made real, and nothing else: no failure ladder
(D58-6), no reconciler (D58-9), no scheduler, nothing about credentials.

**Headline.**

* `propose_action` and the three `dispatch_*` functions **no longer take a connection.** A caller's
  transaction is exactly what cannot be allowed to contain the stages, because it would commit them
  all at once, at its own exit. They open their own short transactions, the way `record_audit`
  always has.
* **Seven short transactions replace one long one**, each committing before the next begins (§1).
  The container runs with **no transaction open anywhere**.
* **A stage runs once.** Every transition is a conditional `UPDATE … WHERE pipeline_stage = <expected>`
  taken first in the transaction that does the stage's work; a proposal's stage is always the last
  one whose work is fully committed, and is queryable (`action_proposals.pipeline_stage`).
* **Retrying is safe.** `idempotency_key` makes a retry resume from the committed stage and repeat
  nothing. Mutation-verified six ways (§5).
* The three D58 crash experiments, reproduced (§3): the decision, the capability and the run row now
  survive; a kill switch reaches the capability; a restart during a run costs nothing.

---

## 1. Where the boundaries are

```
 txn 0   INSERT action_proposals (stage received)  + audit proposal.submitted          ── commit
         (ON CONFLICT (engagement, idempotency key) DO NOTHING: a retry finds the first, and resumes)

 STAGE 1  DECIDE
 txn 1a   resolve authorization, metadata, scope objects            (reads only)       ── commit
          reviewer.review()   — a model call;   opa eval — a subprocess:  NO transaction held
 txn 1b   take received → decided | closed;  decision, reasons, the scope object and
          asset the resolvers found;  audit policy.decided                              ── commit
          DENY / HUMAN_APPROVAL: closed here, provenance, return

 STAGE 2  ISSUE
 txn 2    take decided → capability_issued;  issue_capability() — status, kill switch,
          credential, scope object, approval checked NOW;  INSERT capabilities;
          audit capability.issued    (refused: closed, "capability_refused:<reasons>")  ── commit

 STAGE 3  DISPATCH                                   (dispatch_scan / _collection / _code_scan)
 txn 3a   re-read the capability AND the engagement (kill switch, pause, revocation, lease);
          build the plan; dedup; claim; spend the request budget; INSERT tool_runs 'running';
          take → dispatching;  audit tool_run.started;  [credential file / git fetch]   ── commit
 3b       the container — NO transaction held, no pooled connection pinned
 txn 3c   (raw output already durable on disk) INSERT evidence, finish the run, set
          dispatch_state, audit tool_run.<status>, take dispatching → recorded           ── commit
 txn 3d   ad.collect only: the Security Graph batch — after the result, never with it   ── commit

 STEP 4   PROVENANCE
 txn P    derive every edge from the committed rows; only what is missing;
          set provenance_complete                                                        ── commit
```

**What each stage commits does not depend on a later stage succeeding.** The decision is visible the
moment it is made; the capability is visible to a revocation before the container exists; the run
row is committed `running` before the container starts, so a process that dies from then on leaves a
row for the reconciler; the result is committed as soon as the container is gone.

The stage vocabulary (`orchestrator/stages.py`, migration `0016`, CHECK-constrained):

| `pipeline_stage` | Meaning | Left behind by |
|---|---|---|
| `received` | proposal row committed, nothing decided | a failure before the decision commit |
| `decided` | decision (ALLOW) committed | a failure in the broker's stage |
| `capability_issued` | capability committed | a failure before the run row commits |
| `dispatching` | run row `running` committed; container about to start or running | a crash, a lost connection, an exception from the sandbox |
| `recorded` | the run's outcome — `succeeded`, `failed` or `unknown_outcome` — committed | (normal end) |
| `closed` | finished without a run: DENY / HUMAN_APPROVAL, capability refused, dispatch refused before a run row existed, dedup hit; `stage_detail` says which | (normal end) |

`stage_updated_at` is what a reconciler will age by; `provenance_complete` says whether step 4 has
run. `authorized_scope_object_id` / `classified_asset_id` keep the two facts the resolvers
established so provenance can be derived from rows instead of written alongside them.

### 1.1 Decisions made on the way (each had an alternative)

* **No `conn` parameter, rather than "accept one and ignore it".** The signature is the only thing
  that cannot be misused. It cost 35 modified test and script files, mechanical, listed in §6.
* **The reviewer and OPA run with no transaction open.** Before, a 30–120 s model call pinned a pooled
  connection and a snapshot. Side effect, not a goal: the capability's lease is now anchored to the
  *issue stage's* start, not the pipeline's (§4, X3).
* **The `dispatching` guard takes "any stage before dispatch"**, not "exactly `capability_issued`".
  Hand-built proposals (nine test files insert rows directly) are `received`; `claim_for_dispatch`
  already makes the dispatch exclusive, and the stage guard adds ordering without breaking them.
* **Audit stays *inside* the stage's transaction, after the transition is won.** A stage that loses
  the race has written nothing. The cost, stated in `audit/logger.py` since D8 and true here: if a
  stage's transaction fails *after* its audit write, the record outlives the state and a retry
  writes it again (§5, "just after the capability insert").
* **The result is not discarded if the stage transition is somehow wrong.** Stage 3c uses the
  non-raising `advance`; losing a result to a bookkeeping mismatch is the wrong trade.
* **Dedup hits and refusals before a run row** end the pipeline at `closed`; a dedup hit keeps the
  cached run's id in `stage_detail` so its provenance edge can still be derived.
* **The Security Graph batch moves out of the result's transaction** (3d). It is unbounded and
  re-derivable from the raw artifact; a parse or write failure is audited
  (`security_graph.record_failed`) and cannot touch the evidence. One consequence: it is now audited
  *after* `tool_run.succeeded` rather than before.
* **`reconcile_stale_dispatches` moves the stage with the state** (`dispatching → recorded`,
  `unknown_outcome`). That is existing code keeping two columns coherent, not the reconciler.

## 2. How a proposal's stage is observed

`SELECT pipeline_stage, stage_detail, stage_updated_at FROM action_proposals WHERE …` — committed,
so visible from any connection (verified from a second connection *while the container runs*, in
`test_a_proposal_walks_the_stages_and_each_is_visible_from_another_connection`, which also reads
`pg_stat_activity` from inside the container: **0 open transactions**). The partial index
`action_proposals_open_stage` covers exactly the rows a reconciler looks for.

`ui_reader` was **not** granted the new columns (not needed for this; the console shows decisions).

## 3. The three D58 crash experiments, reproduced

Same scenarios as the D58 report's Appendix A (E1, E2, E3), re-run against the new pipeline — E1 and
E3 with the original method; E2 by hand, with the real server restart.

| | D58 (before) | D60 (after) |
|---|---|---|
| **E1** `kill -9` mid-dispatch | `action_proposals []`, `tool_runs []`, `capabilities []`; audit ended at `tool_run.started`. `reconcile_stale_dispatches` → `[]` | `action_proposals [('running', 'dispatching', 'ALLOW')]`, `tool_runs [('running')]`, one live capability; audit identical. **`reconcile_stale_dispatches` finds it** and moves it to `unknown_outcome` / `recorded` / detail `unknown_outcome`. A restarted caller retrying the request **does not run it again** (sandbox call count 0). Permanent test: a real subprocess, a real SIGKILL |
| **E2** Postgres `-m immediate` restart while the tool "ran" | raw `OperationalError`; no state rows; audit to `tool_run.started` | `returned ALLOW`; `succeeded / recorded / ALLOW`, evidence written, full audit trail. No transaction was open, so the restart killed only idle connections and `pool_pre_ping` replaced them. *Run by hand; CI cannot stop its database.* The harsher timing — the database gone **at the instant the result is to be recorded** — is the permanent test below |
| **E2′** database unreachable at recording | (same as E2: everything lost) | the run row is `running` (committed in 3a); the raw output is on disk and **the CRITICAL log names its path**; stage `dispatching`, ready for the reconciler. The window in which "the result exists nowhere" is closed |
| **E3** kill switch mid-run | `revoked: []`; run proceeded; capability `revoked: false` | `revoked: ['CAP-…']`; run still completes and is recorded; capability `revoked, kill_switch_engaged`; **the result's audit record says `capability_revoked_during_run`** |
| **E3′** kill switch *between* stages | (impossible to observe) | engaged after the capability commits and before dispatch: the capability is revoked, dispatch's first act is to look again, **the container is never started**, stage `closed`, detail `capability_not_live` |

**What E3 does and does not establish.** The kill switch now *reaches* the run: the capability is
committed, visible, revoked, and the revocation is recorded against the result. It does **not** stop a
container that is already running. That is D44-7 / D58-16 (an active `docker kill`), as the brief said;
the minimum asked for — re-check at the stage boundary — is what E3′ shows.

**No partly-correct state.** `assert_coherent` (in `tests/test_pipeline_stages.py`) is run after every
failure injected in the suite: a proposal past `received` has a decision; past `decided` it is ALLOW;
a capability implies an ALLOW decision whose decision stage committed; a run implies a capability;
`dispatching` implies a `running` row and `dispatch_state = running`; evidence implies a run. Five
fault points, each injected one at a time (the reviewer; the decision commit; just after the broker's
INSERT; before the run row commits; inside the container), plus a stress run (§4, X6) whose 9 failed
proposals all left the same coherent rows.

## 4. Side effects on D58's defect list

| D58 | Was | Now |
|---|---|---|
| X1 interrupted dispatch invisible to the reconciler | `[]` | **closed** (E1) |
| X2 kill switch / pause do not reach an in-flight run | `revoked: []` | **reaches the capability; does not stop the container** (E3, E3′) |
| X3 lease anchored to transaction start; `ALLOW` + never dispatched | `ttl=3 s`, reviewer 4 s → `ALLOW`, `run_id None`, `capability_not_live` | **same input → `ALLOW`, `run_id` set**. By construction: the reviewer runs before the issue stage's transaction opens. Measured |
| X11 provenance can destroy a recorded result | edge failure rolled back the run | **closed** (§5) |
| X5, X4 (daemon-unreachable part), X7, X8, X9, X10, X12–X16 | | untouched |
| **X6 pool deadlock** | 15 concurrent in-flight steps: *every* audit write timed out after 30 s | **reduced, not removed.** Re-measured: **12 concurrent proposals** (reviewer 1 s + container 2 s each) all complete; **25 started at the same instant**: 16 complete, 9 fail — with `AuditWriteError` / pool timeout — and **every failure leaves a coherent, resumable row** (7 `received`, 2 `decided`; 0 runs without a capability, 0 `dispatching` without a running row). The hold-and-wait is now inside a *stage's* transaction (a connection held while `record_audit` takes a second one), so the window is milliseconds, not the whole pipeline. The remedy is D58-13's: a dedicated audit pool or a concurrency cap below the ceiling — a few lines, deliberately not taken here |

## 5. Idempotency, re-verified (D4.1 across stages)

Before D60, "retry the whole proposal" was safe only because a failed pipeline left nothing: every
call minted `PROP-<random>` and the key was `idem-<that id>`, so the idempotency index could never fire.
With stages that commit, a naive retry would run stage 1 a second time. So the key is real now:
`propose_action(..., idempotency_key=...)`. A second call with the same key **finds the first proposal,
reads its committed stage, and carries on from the next one** — it does not decide again, issue again
or dispatch again. A key reused for a *different* action or target is refused (and audited), not
resumed. With no key, each call is a new proposal, as before.

A proposal found at `dispatching` is **not** re-dispatched: its container may be running or may have
run, which is `unknown_outcome` (§8.8, I7) and the reconciler's to settle. The retry returns
`failure="dispatch_in_progress_or_unknown_outcome"` and touches nothing.

`tests/test_pipeline_stages.py` (21 tests; full suite 1468 passed). Verdicts are taken from committed rows read through
another connection and from audit counts, never from the call's own return value.

| Property | Test |
|---|---|
| the same request twice = one proposal, one decision, one capability, one run, one container; every audit event exactly once; same ids returned | `test_the_same_request_twice_…` |
| stage 1 committed, stage 2 failed: the retry does not call the reviewer again and does not write a second `policy.decided` | `test_a_retry_after_the_decision_…` |
| a fault at each of five boundaries leaves coherent state, and a retry completes it with **exactly one** capability, run and container | `test_a_fault_at_any_boundary_…` ×5 |
| a fault inside the container: the retry does **not** run it again | same, the `dispatching` case |
| a killed process: the retry does not run it again, and no second proposal appears | `test_a_killed_process_…` |
| two callers, one key, racing: one proposal, one `policy.decided`, one capability, one run | `test_two_callers_with_one_key_…` |
| a reused key for a different request is refused | `test_a_key_reused_…` |
| provenance failure leaves the result whole; repairing it adds only what is missing, any number of times; not written for an unfinished proposal | `test_a_provenance_failure_…`, `…_not_written_for…` |

**Mutation tests.** Each guard put back the old way, observed red, restored (`diff` against the saved
copy checked clean after):

| Mutation | Red |
|---|---|
| the stage transition always "wins" (`advance` → `True`) | `test_two_callers_with_one_key_…` (two deciders) |
| …and the driver also ignores the committed stage (the pre-D60 "retry = run everything") | **7 tests**: the same-request-twice, retry-after-decision, three boundary-retries, the killed-process retry, the two-callers race |
| `ON CONFLICT … DO NOTHING` removed (a retry inserts a second proposal) | **10 tests** |
| dispatch does not take the `dispatching` stage | the stage walk, and the killed-process test |
| provenance failure not isolated (propagates) | `test_a_provenance_failure_cannot_take_a_recorded_result_with_it` |
| dispatch trusts the capability it was handed instead of re-reading it | `test_a_kill_switch_between_the_capability_and_the_dispatch_…` |

One mutation is *not* separately red and that is a design fact worth recording: with only the guard
disabled, the retry tests stay green, because the driver reads the stage first — two independent
layers hold the same line. Only the concurrency test reaches the guard alone.

## 6. What changed

Code: `control_plane/orchestrator/stages.py` (new); `function_api.propose_action` (stages; takes no
connection; `idempotency_key`; derived outcomes on resume); `dispatch.py` (each `dispatch_*` split into
start / run / record, shared `_begin` / `_execute` / `_record_scan_result`; fresh capability + engagement
read at the boundary; typed network refusals now `closed`); `provenance/graph.py`
(`record_provenance`, `record_edge_once`); migration `0016`; `state/models.py`;
`reconcile_stale_dispatches` keeps the stage with the state.

Tests and scripts (mechanical, to the new signatures): 35 modified files. Two kinds of edit, both honest about
what changed: the call sites lose their `conn`; and tests that **built their fixture inside one open
transaction and then dispatched** — a state no running system can be in — now use
`tests/helpers.committing_scope`, which commits as it goes, so that what a test sets up is committed
before the next stage reads it, exactly as in production. `tests/adapter_kit.probe_dispatch` stands in
for the transactions it never had; the D56 contract tests follow the function split. Two live-run
scripts (`live_run.py`, `d13_worker.py`) created a task and proposed an action in one transaction and
now commit the task first. No test lost an assertion.

## 7. What this does not do — and what it did not verify

* **No failure ladder, reconciler, scheduler, credential change** (D58-6…17). Everything here is a
  precondition for them. A `dispatching` proposal waits for the reconciler; nothing resolves it
  automatically.
* **The kill switch does not stop a running container** (D44-7 / D58-16).
* **X6 is reduced, not removed** (§4). The cheapest fix is the first thing D58-13 should do.
* **`grant_approval` is unchanged.** A human-approved proposal sits at `closed` with a capability and
  nothing dispatches it (D58-8); its stage is not advanced by the grant.
* **A resumed call needs the arguments it was first given** (reviewer, policy, sandbox, budget, …).
  The stages persist the *facts*; the orchestrator that retries must pass the same *inputs*.
* **The idempotency key is the caller's to supply.** The orchestrator must always pass one, derived
  from the task and the attempt; the default (no key) keeps every call an independent proposal.
* **Audit-before-commit duplicates** exist for a stage whose transaction fails after its audit write.
  One instance is pinned by a test; none is a state change.
* **A git fetch (`code.scan`) still runs inside the start stage's transaction**, holding a connection
  for a shallow clone. It reads, writes nothing, and a crash during it leaves `capability_issued`.
* **The real Postgres restart (E2) is not in CI**; its deterministic equivalent is.
* **Not verified:** behaviour of the real `claude` backends under the new call shape (the D40 harness
  was edited, not run); `scripts/live_run/d45_ad_collection_e2e.py`, whose claim that a mid-flight
  revoke is a no-op against the run (D45 §6, ACCEPTANCE 5.24) is **no longer true of the capability**
  — the revoke now finds and revokes it — while the exposure of a credential file inside a running
  container is exactly as before.

## 8. Reproducing

```
.venv/bin/python -m pytest tests/test_pipeline_stages.py -v        # 21 tests, ~5 s
```

The crash experiments of §3 are the D58 Appendix A scripts with the new call signature (not committed;
the method is in that appendix). To see the old behaviour, make `stages.advance` return `True` and the
driver ignore the stage (mutation 2 above).
