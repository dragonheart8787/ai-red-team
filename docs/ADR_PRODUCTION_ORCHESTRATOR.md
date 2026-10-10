# ADR: Production Orchestrator — Phase 1 investigation (D58)

Status: **partly built — read the index below before anything else.** This document began as an investigation
(`ad2c8d5`: nothing decided, eighteen decision points in §8). Since then eight of the decision points were
decided and built, in the deliverables named below; **the document as a whole is not implemented**, and the
body of it is still the text written at `ad2c8d5` (the addenda say what changed). Final state, as of the D63
merge audit:

| Decision point | State | Where |
|---|---|---|
| D58-1 discovery / read model | **built** (D62): explicit enrolment (Option A) plus a narrow database role for the read side | `D62_SCHEDULER_V0_DESIGN.md`, ACCEPTANCE 5.59 |
| D58-2 topology | **built** (D62): one resident process, singleton advisory lock (Option A) | same |
| D58-3 metadata/content line | **built** (D62): the reader sees the columns tabled in the design note, `action` only as a closed class | same |
| D58-4 audit of scheduler decisions | **built** (D62): Option B, edge-triggered, closed vocabulary | same |
| D58-5 transaction shape | **built** (D60): Option B, stages that each commit | `D60_PIPELINE_STAGES_REPORT.md`, 5.53 |
| D58-6 failure containment (the ladder) | **NOT built.** v0 stops the whole service on any fault it cannot account for (a temporary simplification) | — |
| D58-6b what an L2 hold is | **NOT built** | — |
| D58-7 `UNKNOWN_OUTCOME` | **built, option B** (the mislabel fixed; "never auto-retry" kept; the retry half is not taken) | `D58_7_SANDBOX_NOT_STARTED_REPORT.md`, 5.58 |
| D58-8 lease / approved-proposal dispatch | **built** (D61, H-A) with the approval re-derivation | `D61_JIT_CAPABILITY_REPORT.md`, 5.56 |
| D58-9 recovery / reconciler | **NOT built** (the singleton lock of its scope is built, under D58-2) | — |
| D58-10 recording the defects X1–X16 | **partly**: recorded as they were closed (5.52, 5.53, 5.56–5.58); X6 (residual), X7, X9, X10, X13, X14, X15, X16 are *not* separate ACCEPTANCE rows | — |
| D58-11 priority basis | not needed yet (serial scheduler) | — |
| D58-12 planning / closed-directions ledger | **NOT built** | — |
| D58-13 resource quotas | **NOT built** (the scheduler is serial: concurrency 1) | — |
| D58-14 network isolation | **built** (D59) | `D59_NETWORK_ISOLATION_REPORT.md`, 5.52 |
| D58-15 who selects `credential_id` | **NOT built**; an approved `ad.collect` still cannot run | 5.57 |
| D58-16 unattended credentialed dispatch / kill | **NOT built** (the kill switch does not stop a running container) | — |
| D58-17 secret residency / orphans | **NOT built** | — |

Built: D58-1, -2, -3, -4, -5, -7, -8, -14. Not built: -6, -6b, -9, -12, -13, -15, -16, -17 (and -10 in part).
Labels: commit `adc4632` is titled "D62" but is D58-7; the scheduler is D62 (the D58-7 report was relabelled).

**Addendum (D59).** X12 / D58-14 (cross-engagement network reachability) was taken out of this document and
fixed on its own, in `docs/D59_NETWORK_ISOLATION_REPORT.md` (ACCEPTANCE 5.52). Two corrections to what is
written below: (1) the reachability was wider than E9 showed — TCP and HTTP-through-the-proxy as well as ICMP,
the last being an authorization bypass; (2) the direction is decided: **two engagements are never live on one
network** (a private bridge per engagement is impossible, Docker refuses an identical subnet), so same-range
engagements serialize and the orchestrator must treat `NetworkInUse` as "retry later". The "Option (A)
in-process semaphores" of D58-13 should account for that, and the 15-container pool ceiling (X6) is unchanged.
Everything below is otherwise as written at `ad2c8d5`.

**Addendum (D60).** D58-5 is decided and built: **Option B**, `propose_action` split into stages that each
commit — see `docs/D60_PIPELINE_STAGES_REPORT.md` (ACCEPTANCE 5.53). Effects on this document, read with
that report: premise 5 of §0.2 is now false (a crash leaves a committed `dispatching` row and
`reconcile_stale_dispatches` finds it); X1, X3 and X11 are closed, X2 is half-closed (the kill switch
reaches the committed capability and is checked at every stage boundary; it still does not stop a running
container); X6 is reduced to a stage's transaction, not removed (re-measured: 12 concurrent fine, 25
started together fail 9, cleanly) — a dedicated audit pool or a concurrency cap is the first item of
D58-13. D58-6, -7, -8, -9, -16 are now unblocked and none of them is done. Two facts the orchestrator must
honour: it must pass an `idempotency_key` (derived from task and attempt) on every `propose_action`, and
a proposal found at `dispatching` is the reconciler's, not the retry's. Everything else below is as
written at `ad2c8d5`.

**Addendum (D61).** D58-8 is decided and built: **H-A for approved proposals** — `grant_approval` records the
approval and issues nothing; `approved_dispatch.dispatch_approved` issues the capability at dispatch, re-running the
broker's checks plus "policy unchanged since the decision" — see `docs/D61_JIT_CAPABILITY_REPORT.md` (ACCEPTANCE 5.56).
Effects on this document: X8 is half closed (an approved proposal is now dispatched; the missing `credential_id` is 5.57), and W1 for approved proposals is
~0 (measured < 1 s); `approved` is a queryable stage, the interface the reconciler (D58-9) reads. Still open and
unchanged: the ad.collect credential incompatibility of §5 (ACCEPTANCE 5.57 → D58-15); `dispatch_approved` had no production
caller until the scheduler (D62, D58-1..4) became its first; and the multi-dispatch renewal question of §3.3 is not
touched — an approved capability is single-dispatch, as H-A proposes. **Same round (also D58-8):** the approval-to-dispatch link — `dispatch_approved` re-derives the decision chain against the approval's recorded snapshot and refuses on any change the approver did not see (D61 report §2b). Everything else below is as written at `ad2c8d5`.

**Addendum (D58-7).** D58-7 option (B) is built: the mislabel is fixed — a sandbox that provably did not start
(Docker unreachable, image absent, network unobtainable, container not created) is `failed`/retryable, and the cached-client
raw `ConnectionError` (X5) is typed — see `docs/D58_7_SANDBOX_NOT_STARTED_REPORT.md` (ACCEPTANCE 5.58). X4 and X5 are
closed for the dispatch path. `unknown_outcome` keeps its meaning and its "never auto-retry"; the policy half of D58-7
(retrying genuinely unknown side-effect-free actions) is not taken.

Investigation and design only. No schema, migration, code, Rego, harness or service skeleton was
written or changed for this document. Every claim below about the current system was checked against
the tree at the time of writing (`d64b335`, post-D57 merge), and each is tagged with *how* it was
checked, because on this question the difference matters more than usual:

| Tag | Meaning |
|---|---|
| **[E]** | **Executed.** I ran it against the live database / Docker daemon in this environment and observed the result. The throwaway scripts lived in the session scratchpad and are **not** committed (instruction: no code); Appendix A states each experiment precisely enough to redo it. |
| **[R]** | **Read.** Established by reading the code or the migration at the commit above. |
| **[D]** | **Documented.** Taken from an earlier ADR / ACCEPTANCE row / report, and *not* re-derived. Where a document and the code disagree, the code wins and §0.2 says so. |
| **[N]** | **Not verified.** Reasoned, not observed. §9 collects all of these in one place. |

The brief asked that no existing mechanism be assumed to carry over unchanged to a service that runs
continuously and decides its own next step. That instruction paid for itself: of the nine
premises I would otherwise have carried in from earlier deliverables, **six turned out to be wrong or
only partly right** (§0.2). Two of the six are structural — they change what the orchestrator has to be.

---

## 0. Why this is a different trust boundary than every prior caller of `propose_action`

### 0.1 Who has called this pipeline so far, and who decided what

Every prior path into `propose_action` had a *person or a script author* making the decisions a
resident service will now make for itself:

| Caller | Who chose the engagement | Who chose the timing | Who handled errors |
|---|---|---|---|
| `tests/` (e.g. `test_gitleaks_e2e.py`) | the fixture | the test | pytest — an exception is a red test |
| `scripts/live_run/d40_three_role.py` (the closest thing to a loop that exists) | one engagement per process, created by the script | strictly sequential rounds | the author reading the output [R] |
| `scripts/approvals.py` / `web/app.py` | the operator | the operator | the operator |

The D40 harness is the only multi-step loop, and it is **single-engagement, single-threaded, synchronous,
and re-loads the effective policy in a separate transaction before each task** [R:
`scripts/live_run/d40_three_role.py:330-440`]. It is a demonstration that the roles compose, not a
scheduler. `docs/ACCEPTANCE_MVP1_AGENTS.md` 5.51 already records that no production caller of
`load_effective_policy` exists; I add that *nothing* in `control_plane/` or `agents/` calls
`renew_capability`, `reconcile_stale_dispatches`, or any sweeper either [R, grep over all non-test
sources].

D44 §0 contrasted D35 and D44 and found the *mechanism* transferred while the *trust conclusion* did
not. The same shape recurs here: the **mechanisms** (RLS scoping, the capability broker, the dispatch
state machine, the fail-closed audit) all exist and are individually well tested; the **assumptions
those mechanisms were built under** — a caller that commits at known points, that does not crash
mid-call, that reads the result, that picks one engagement — are the part that does not transfer.

### 0.2 Premise corrections — what the brief (and earlier deliverables) assumed vs. what is true

| # | Premise | What is actually true | How |
|---|---|---|---|
| 1 | "The Tool Gateway has concurrency limits" | **No concurrency limit is enforced anywhere.** `Budget.max_concurrency` is carried and recorded but read by nothing; `docs/LIVE_RUN_REPORT.md` records it as deliberately unenforced because "a proposal produces one capability, one dispatch and one container, so there is nothing in a request to compare it against" — counting in-flight runs was left as "a question about system state". The orchestrator is what creates that state. | [R][D] |
| 2 | "Earlier renewals were externally triggered" | **Nothing ever called `renew_capability` outside tests.** It has zero production callers. The capability lease (60 s default) has therefore only ever *expired*, never been renewed, in any non-test run. | [R] |
| 3 | "D44 §2.1 gives credentials a lease-tied lifetime" | §2.1 says credentials **need** a lease/heartbeat tie-in; what was built (§2.3 → D44-5) is a **per-dispatch file with `finally` cleanup**. The vault has no lease, no heartbeat and no revocation check of its own; `credential_revoked` is consulted only by `check_preconditions` at *issue* time (and at renewal, which never happens). | [R] |
| 4 | "`cyberorch_app` is a connection pool with one connection per engagement" | There is **one** shared pool (`pool_size=5, max_overflow=10`); the engagement is a *transaction-local* GUC set per `engine.begin()`. Any pooled connection serves any engagement, one transaction at a time. | [R][E] |
| 5 | "`reconcile_stale_dispatches` catches a dispatch interrupted by a crash" (§8.8) | **It cannot, under the current transaction shape.** `propose_action`'s pipeline is one open transaction; a `kill -9` mid-dispatch rolls back the `action_proposals`, `tool_runs` and `capabilities` rows, so the reconciler's `WHERE dispatch_state IN ('dispatching','running')` matches nothing. Only the (separately committed) audit trail records that the run started. | [E] |
| 6 | "A worker that dies does not strand a task" (`claim_task` docstring; ARCHITECTURE §6 promises a sweeper) | `claim_task` selects only `status='queued'`. **No code reads `tasks.lease_expires_at` for requeue** — its only reader is `query_state`'s display `SELECT`. The §6 background job was specified and never built. | [R] |

Three further premises were *confirmed*, and are listed because the confirmation is itself a finding:
`kill_switch`/`pause`/credential revocation do **not** reach an in-flight run (extends D45/5.24 from
credentials to every revocation path, §3.1 experiment 3); the audit logger **is** fail-closed on a lost
write (§3.2 link 6); and RLS **does** fail closed with no GUC (§2.1).

### 0.3 What the architecture already promised a background process would do

ARCHITECTURE v0.3 names five jobs that need something resident. None exists. This is the orchestrator's
minimum job list, before any new idea:

| Promised job | Where | State today |
|---|---|---|
| Requeue `claimed` tasks whose lease expired | §6 | not built [R] |
| Reconcile `unknown_outcome` dispatches; alert when unqueryable | §8.8 | `reconcile_stale_dispatches` exists, called by tests only [R] |
| Renew capabilities; treat a missing heartbeat as an anomaly | §1.2(a), §4.6 | `renew_capability` exists, no caller; sweeper = ACCEPTANCE 5.4 [R] |
| Stop in-flight work on kill/pause/revoke ("namespace teardown") | §1.2(e), D44-7 | not built; the kill-switch audit payload *claims* it (`engagement.py:305-306`) [R] |
| **Dispatch an approved proposal** (not in the architecture list; found here) | §4.7, D24 | **nothing does** — see §3.3 |

---

## 1. What a resident cycle would actually call — the verified transaction shape

The single fact that organizes most of this document: **`propose_action` runs the whole pipeline on one
caller-supplied connection, so it is one database transaction, from canonicalization through the Docker
run to the provenance edges.** The caller's `with engagement_scope(...)` commits it at exit [R:
`function_api.py:428-700`; `db.py:_scoped` uses `engine.begin()`]. Audit is the exception: `record_audit`
opens its **own** connection and commits immediately [R: `audit/logger.py`].

```
txn T (caller's conn, one engagement GUC)                        separate connections
─────────────────────────────────────────                        ─────────────────────
 INSERT action_proposals                                          audit: proposal.submitted   ✔ committed now
 resolve authorization / metadata   (reads)
 reviewer.review()  ── headless LLM, 30–120 s ──                  audit: policy_reviewer.opinion ✔
 opa eval (subprocess)                                            audit: policy.decided       ✔
 INSERT capabilities  (lease = now()+ttl  ← T's START time)       audit: capability.issued    ✔
 UPDATE action_proposals → dispatching/running
 INSERT tool_runs
 sandbox.run()  ── container, up to max_duration ──               audit: tool_run.started     ✔
 write raw artifact to disk  → INSERT evidence                    audit: evidence.recorded    ✔
 UPDATE tool_runs / action_proposals → succeeded                  audit: tool_run.succeeded   ✔
 INSERT provenance_edges ×N
COMMIT  ◄── only here do the state rows become visible to anyone else
```

Consequences, each verified in §3: (i) audit says "happened" strictly before state says anything;
(ii) every state row a *concurrent* actor would need to see (the capability to revoke, the run to
reconcile, the proposal to dedup against) is invisible until the container has already finished;
(iii) an LLM call and a container run both hold a pooled DB connection **and** a Postgres snapshot the
whole time; (iv) `now()` inside T is T's start time, which makes the capability lease start *before* the
reviewer ran (§3.3).

This is not a bug in the usual sense — D45 found the credential variant, accepted the window (D44-7
Option A), and the design was always one-shot. It becomes the central design question the moment the
caller is a service that must *survive* these windows rather than a person who retries.

---

## 2. Part 一 — The orchestrator's identity and cross-engagement authorization

### 2.1 What RLS is, and what it is not, when the caller is a service

**Verified facts.**

* `cyberorch_app` is `NOSUPERUSER NOBYPASSRLS`, owns no table; so is every other role (`migration_owner`,
  `registry_admin`, `global_auditor`, `ui_reader`, `credential_admin`, `global_policy_admin`) — **no role
  in the database has `BYPASSRLS` or superuser** [E: `pg_roles`]. Every table is `FORCE ROW LEVEL
  SECURITY`, owner included [E: `relforcerowsecurity`].
* `engagement_isolation` (`engagement_id = cyberorch_current_engagement()`, which is
  `NULLIF(current_setting('cyberorch.engagement_id', true), '')`) is on **every** table — **including
  `engagements` itself** [E: `pg_policy`]. With no GUC set, `cyberorch_app` sees **zero** engagements.
  **No existing role can enumerate engagements.** There is no scheduler-shaped read in the system at all.
* The GUC is set with `set_config(..., true)` — transaction-local — so a pooled connection never leaks an
  engagement into the next checkout [R: `db.py:_scoped`]. Separate *roles* use separate engines (not
  `SET ROLE`), so the role boundary is not SQL-crossable [R: `db.py` docstring].
* `audit_log` has two extra permissive policies: `audit_global_insert` (`scope='global' AND
  engagement_id IS NULL`, **insert**) and `audit_global_read` (`scope='global' AND CURRENT_USER =
  'global_auditor'`, **select**) [E: `pg_policy`]. A global-scope audit record can therefore already be
  written by `cyberorch_app` with no engagement bound, and read only by `global_auditor` — **with no new
  grant** [R: `db.py:global_audit_scope`].

**What this means for a resident service — stated plainly because it is easy to over-read RLS.**
The GUC is a **self-declared selector, not a credential.** Whoever holds the `cyberorch_app` connection
string can call `engagement_scope('ENG-ANY')` for any engagement they can name; the database cannot tell
a legitimate scoped call from a wrong one. §8.6's RLS exists to make *code that forgets a filter* fail
closed, and it does that well [E]. It was never a defence against *the process holding the role choosing
the wrong engagement id* — because until now nothing long-lived chose engagement ids at all.

For a resident multi-engagement service this moves the real boundary from "the database" to **"which
code path computes the `engagement_id` handed to `engagement_scope`"**. That has two corollaries:

1. A **process-per-engagement** layout does *not* strengthen the database boundary: each process would
   still hold the same role and could name any engagement. It strengthens only OS-level blast radius
   (memory, key residency). This is the key to evaluating Option 2-B below.
2. Agents themselves are **not** in this threat path today: `agents/` never imports `state.db` or opens a
   connection [R: grep] — Worker/Reviewer/Supervisor return plain objects, and the control plane acts on
   them. The attacker-influenced values that *reach* the scheduler are `tasks.priority` (0–9, bounded
   integer from the Supervisor [R: `supervisor_base.py:554-562`]), `tasks.goal` (free text), and the
   volume of tasks a Supervisor chooses to create.

**The SECURITY DEFINER shortcut does not work as one might expect.** An obvious way to give the
`cyberorch_app` role a cross-engagement metadata read is a `SECURITY DEFINER` function. I tested the
obvious form: a `SECURITY DEFINER` function counting `engagements`, run as the table owner
(`migration_owner`) with no GUC, returns **0** [E] — because `FORCE ROW LEVEL SECURITY` applies to the
owner and nothing grants it a bypass. `SECURITY DEFINER` changes `CURRENT_USER`, not whether RLS applies.
It *could* work with a policy keyed to the function owner's name (the `audit_global_read` pattern), but
that is then just Option 2-B with an extra indirection. [N: the owner-keyed-policy variant was not
executed.]

### 2.2 Decision D58-1 — How the scheduler learns which engagements exist, and what it may read

The brief's framing — "a pool with one connection per engagement, or a new role" — has a hidden
false dichotomy (premise 4). There are really **two separable questions**:

* **(i) Discovery:** how does the service learn *which engagements to serve* and read cross-engagement
  scheduling metadata?
* **(ii) Action:** once it has chosen an engagement, as what identity does it do the work?

(ii) is answered the same way in every option — `engagement_scope(eid)` on the shared `cyberorch_app`
pool, because `claim_task`, `propose_action`, `complete_task`, the broker and the vault all already run
there. So the real choice is (i).

**Option A — explicit enrollment; no new database capability.** The operator tells the service which
engagement ids it serves (a configuration the operator owns). The service iterates the enrolled list,
opens `engagement_scope(eid)` for each, and reads that engagement's own state with the queries it
already has. Cross-engagement ordering (§4) is computed in the service from what each per-engagement
read returned.

* *For*: **adds no privilege to any role.** A scheduler that can only touch what an operator enrolled is
  a **positive allowlist**, which is a stronger property than "can enumerate everything and chooses not
  to" — an engagement created by registry_admin and never enrolled is never touched, by construction.
  Matches the codebase's strongest habit (fail-closed absence: a missing classification is "unknown",
  never "none", D43/D50-B).
* *For*: engagement creation is already an operator act (`create_engagement`, `registry_admin`), so
  "and then enrol it" is one more explicit step, not a new class of act. The service never *needs* to
  discover — the set is small and slow-changing.
* *For*: enrolled-but-nonexistent is detectable and loud (RLS returns zero rows → the service treats an
  enrolled engagement with no `engagements` row as an error, not an empty queue).
* *Against*: **the metadata/content line (§2.3) is then enforced by code, not by the database.**
  `cyberorch_app` has `SELECT` on *every* column of `tasks`, `capabilities`, `action_proposals` within
  an engagement [E: `information_schema`]. A scheduler module that "only reads metadata" is a convention
  — pinned by a structural test (the repo has the precedent: `test_broker_reads_scope_only_as_a_liveness_
  check`), but a convention. A bug or a future edit can widen it silently.
* *Against*: a cross-engagement overview ("which capability leases expire soonest across all
  engagements") costs N scoped round-trips per tick. At the engagement counts in view (tens) that is
  trivial; at hundreds it is not.
* *Against*: the enrolment list lives outside the database, so "which engagements is the production
  service serving right now" is not answerable *from the audit trail* unless the service audits its own
  enrolment (§2.4 does).

**Option B — a new, dedicated read role (`scheduler`) with column-narrowed cross-engagement SELECT.**
A new role gets `SELECT` on a **column list** (not the table) of `engagements`, `tasks`, `capabilities`,
plus a permissive RLS policy `TO scheduler USING (true)` on those tables. Postgres enforces column
privileges below RLS, so the role *cannot* read `tasks.goal` / `capabilities.constraints` even by
accident.

* *For*: **the metadata line becomes database-enforced** — the same move D44 §1.3 made for credentials
  ("a new category of sensitive access arrives → a new role, not a widened one"). The precedents are
  exact: `audit_global_read` is a policy keyed to one role, and migration 0013 already uses
  column-level `UPDATE` grants on `engagements`/`policy_layers`.
* *For*: cross-engagement overview becomes one query; no list to maintain; new engagements are seen
  immediately.
* *Against*: **it creates the first role that can enumerate engagements** — a capability that does not
  exist today and that the original isolation design (§8.6) deliberately avoided. A leak of this role's
  credential reveals *which customers exist and what they are doing in aggregate*, even without content.
  For an offensive-security platform whose customer list is itself sensitive, that is a real cost.
* *Against*: it is a *read* role; the service still needs `cyberorch_app` to act, so it holds **both**
  credentials. The role split buys DB-enforced narrowness for the *discovery reads only*; it does not
  reduce what the process can do.
* *Against*: one more role to provision (`scripts/init_db.sh`, migration, `assert_*` guard, test that no
  agent module imports it — the `global_policy_admin` pattern). [N: column-grant + RLS-policy interaction
  was not executed here; it is standard Postgres behaviour but is the first thing a phase-2 migration
  test should pin.]

**Option C — `SECURITY DEFINER` functions returning narrow metadata.** Rejected on the evidence above
unless paired with an owner-keyed policy, at which point it is Option B with more moving parts
(function + owner role + policy) and a weaker audit story (calls are not role-attributable in
`pg_stat_activity` the way a dedicated login is).

**Option D — a denormalized scheduling ledger** (a new table, maintained by `create_engagement` and the
lifecycle functions, without per-engagement RLS). *Against, decisively*: a second copy of
`status`/`kill_switch_engaged` is exactly the "two places deciding the same thing" the broker docstring
warns about (a stale `active` row is a fail-**open** scheduler for a killed engagement). Listed to be
rejected explicitly.

**Lean: Option A for the first implementation, with Option B recorded as the correct move on a named
trigger** — *a cross-engagement query the scheduler genuinely needs that N scoped reads cannot serve
(a measured tick-latency problem, or an overview feature)*. Reasoning, in the D42-5 / D44-1 spirit of
"don't add infrastructure ahead of a measured need": the *positive allowlist* property of A is better
than anything B offers on the one question that matters for a resident service holding a vault key, and
the cost A pays (convention instead of DB enforcement of the metadata line) is the cost the broker has
already paid and tested its way around once. **⚑ This is the highest-priority decision in the document.**

### 2.3 Decision D58-2 — Acting identity and process topology

Independent of D58-1, the service **holds** `cyberorch_app`, which can: `INSERT/UPDATE/DELETE` on
`tasks`, `capabilities`, `action_proposals`, `tool_runs`, `findings`, `approvals`; `INSERT/UPDATE/DELETE`
on `credentials`; **`SELECT` on `credential_material`**; column-level `UPDATE` on `engagements.status /
kill_switch_engaged` [E: `information_schema`]. And it must hold `VAULT_MASTER_KEY` in its environment to
decrypt that material (`vault.py:_fernet`, no fallback) [R]. A harness holds all of this for one
engagement and a few minutes. A resident service holds it for **every enrolled engagement, indefinitely.**
The blast radius of "this process is compromised" is the union of all enrolled engagements' credentials
and state. That is a real change and the document should not let it pass as a deployment detail.

**Option A — one resident process serves all enrolled engagements.**
* *For*: simplest; one connection pool, one place for the global quota (§4.3), one audit identity;
  matches ARCHITECTURE §2's "same process, internal function calls, no network hops until scaling
  demands it".
* *Against*: maximal concentration (above). One bug in engagement selection exposes all.

**Option B — a scheduler process plus one worker process per engagement.** Each worker process is
launched for exactly one engagement id and never given another.
* *For*: bounds *OS-level* blast radius — a compromised or crashed worker process holds one engagement's
  decrypted material in memory, not all; a crash is contained to one engagement; per-process resource
  limits are available (cgroups, `ulimit`).
* *Against*: **does not strengthen the database boundary** (§2.1 corollary 1) — each worker still holds
  `cyberorch_app` and can name any engagement. It also needs the vault key per worker (or a key broker),
  an IPC channel, a supervisor-of-supervisors, and multiplies the pool-sizing problem (§3.2, link 1).
  A security gain that is real but smaller than it looks, at the largest complexity cost of the three.

**Option C — per-engagement database identities** (a role or credential per engagement, so the database
itself can refuse a wrong engagement).
* *For*: the only option that makes the DB boundary real against a mis-selecting process.
* *Against*: collides with the one-role-one-job ladder (N roles per job), the `engagement_isolation`
  policy would need to become role-keyed, migrations per engagement, and the vault key problem remains.
  **Not recommended**; named so it is a considered rejection, not an omission.

**Lean: Option A**, **provided** (a) the engagement-selection path is the single, small, structurally
tested module of D58-1/Option A, (b) a singleton guard stops two scheduler instances from running at once
(§3.5), and (c) the vault-key residency question is answered separately (D58-17). Option B is the
escalation if D58-17 concludes the key must not live in the scheduling process. **⚑**

### 2.4 Decision D58-3 — What the scheduler may see and may not (the line)

Two components must be kept apart, because they have different needs and conflating them is how the line
gets erased:

* the **scheduling decision** — *which engagement and which task next, whether to pause, when to retry*;
* the **execution step** — claim, propose, dispatch, record — which unavoidably touches content, but only
  *inside one engagement scope* and only through the existing functions.

The line applies to the first. Classified against the verified schema:

| Datum | Where | Scheduling decision may read? | Why |
|---|---|---|---|
| engagement id, `status`, `kill_switch_engaged`, `created_at` | `engagements` | **yes** | pure lifecycle state; needed before every dispatch |
| `baseline_frozen_through`, `policy_snapshot_version` | `engagements` | no (not needed) | policy is loaded *at decision time* by the step, not cached by the scheduler (§3.2 link 2) |
| task `status`, `owner_agent_id`, `lease_expires_at`, `created_at`, `updated_at`, `parent_task_id` | `tasks` | **yes** | queue state |
| task `priority` | `tasks` | **read, never trusted for cross-engagement ordering** | Supervisor-assigned (0–9); within an engagement it is the existing order, across engagements it would let a Supervisor win a fairness contest (§4.2) |
| task `action` | `tasks` | **yes, as an enum** (resource class for quota) | the *kind* of tool, needed to count browser vs scan slots; not the target |
| `canonical_target`, `identity_key`, `scope_object_id` | `tasks` | **no** | content: *what* is being tested |
| `goal`, `result_summary` | `tasks` | **no** | free text; `goal` is attacker-influenced via the planner (`ADR_GOAL_LAUNDERING.md`) and must never steer scheduler logic or appear in a scheduler audit payload |
| capability `revoked`, `lease_expires_at`, `last_heartbeat_at`, `renewal_count`, `issued_at`, `agent_id` | `capabilities` | **yes** | lease/renewal bookkeeping |
| capability `budget.max_duration_seconds` | `capabilities.budget` | **yes (that one key)** | needed to bound a run; a JSON column, so *not* column-narrowable under D58-1/B either — see below |
| capability `constraints`, `credential_id` presence | `capabilities` | `credential_id IS NOT NULL` only | whether a credential is involved matters to gating (§5); *which* credential and every constraint value do not |
| `tool_runs.status`, `started_at`, `finished_at` | `tool_runs` | **yes** | in-flight counting |
| `tool_runs.normalized_target / normalized_params / execution_context` | `tool_runs` | **no** | content |
| `action_proposals.decision`, `decision_reasons`, `dispatch_state` | `action_proposals` | **yes (the reason vocabulary, not free text)** | what §4.1's history-reading needs |
| `action_proposals.target / authorization / discovery / reason` | `action_proposals` | **no** | content |
| evidence `derived_view`, raw artifacts | `evidence` | **no** | §4.4: never reaches a model; here, also never reaches the scheduling logic |
| `credential_material`, `VAULT_MASTER_KEY` | `credential_material` | **never** (the execution step's `vault` module only) | §1.2 of D44 |

**Does the existing schema let the scheduler see only the left-hand column without a new query
capability?** No, on two counts, and the document should say so rather than imply otherwise:

1. **Under the existing roles, no.** `cyberorch_app` is table-wide `SELECT` inside an engagement; no role
   offers a column-narrowed or cross-engagement view. The line can be *drawn* but under D58-1/A it is held
   by code and a structural test, not by the database. Under D58-1/B it is database-enforced for every
   column listed "no".
2. **One datum straddles the line even under B.** `capabilities.budget` is a `jsonb` blob; `max_duration_
   seconds` (needed) and `tool` (tool-specific sub-budgets: `budget.tool.http` etc., not sensitive but
   not needed) live in one column, and Postgres column privileges cannot split a JSON column. Under B this
   means either granting the whole `budget` column (it holds no content — budgets are numbers and limits,
   D34–D36 [R]) or promoting `max_duration_seconds` to its own column (a schema change). Not a blocker;
   it is the kind of thing a phase-2 migration review should catch rather than discover.

**⚑ Decision to confirm:** the table above as the line — especially that `tasks.action` (the kind of
tool) is metadata but `canonical_target` is not, and that `goal` is excluded outright.

### 2.5 Decision D58-4 — Auditing the scheduler's own decisions (D8 / D24)

**Verified.** `record_audit` takes an engagement-scoped record on `audit_scope(eid)` or a `scope='global'`
record on the no-engagement connection; the global path needs no new grant and is readable only by
`global_auditor` [E/R, §2.1]. D24's `consume_request` states the governing principle in a comment
(`broker.py:718-722`): *"Refusals are audited; successful consumption is not. A refusal is a decision —
the budget stopped something — while a successful request is bookkeeping already visible in
`capabilities.requests_used` and in the tool_run record. Auditing every one would bury the decisions among
them, and an audit log nobody can search is one nobody reads."* The D8 spec (`reconstruct_decision`)
reconstructs *why a proposal was allowed or refused* by walking proposal → decision → capability → run.

The question is whether scheduler acts are "decisions" (audit them) or "bookkeeping" (state tables are
enough). **The answer is not uniform, and the useful line is the one D24 already drew: a scheduler act is
a decision exactly when it causes, prevents or delays an action, or changes who is allowed to act.**

| Scheduler act | Decision or bookkeeping | Why |
|---|---|---|
| Tick started / finished; engagement polled, nothing to do | bookkeeping | visible in no state, matters to no one; auditing it is the log nobody reads |
| Task claimed | already audited (`task.claimed`) | existing |
| **Dispatched task X for engagement E** | decision | it caused an action; but `proposal.submitted`…`tool_run.started` already record it from the pipeline's side — the scheduler adds only the *selection reason* |
| **Engagement E deferred / skipped this tick: reason** (quota full, hold, paused, backoff) | decision **when it persists** | prevents an action; one record per *transition into and out of* the deferred state, **not per tick** |
| **Task re-queued** after claim-lease expiry | decision | changes who may act on a task; and, given §3.1, can cause a duplicate run |
| **Engagement placed on / released from scheduler hold** (failure containment, §3.2) | decision | the system stopped itself; the operator must be able to see why |
| **Service started / stopped / lost DB / lost Docker / reconciled N orphans / resumed** | decision (global scope) | belongs to no engagement |
| **Enrolment list read at start** | decision (global scope) | answers "which engagements was production serving at 14:02" — which the DB alone cannot (D58-1/A) |
| Capability renewed OK | bookkeeping (`capability.renewed` already audits; keep as is) | existing |
| Renewal refused / capability revoked on renewal | already audited | existing |

**Edge-triggered, not level-triggered.** The failure mode of auditing a scheduler is volume: N engagements
× ticks/minute. The design that keeps the log searchable and still reconstructable is to audit
**transitions of the scheduler's per-engagement and per-task disposition** (`served → deferred(reason) →
served`; `ok → held(reason) → ok`), carrying `since` and a count of ticks coalesced. That also makes
**starvation visible**: "task T was ready for 3 h and was deferred for `quota_full`" is one record opened
at the start of the deferral and closed at its end — whereas pure per-act auditing would show only the
picks and never the passed-over.

**Options.**
* *(A) Audit every scheduling decision per tick.* Complete; defeats §24's own reasoning at N×rate.
* *(B) Audit only state-changing or action-denying decisions, edge-triggered; bookkeeping not audited.*
  **Lean.** Consistent with D24; adds a small closed event vocabulary (`scheduler.*`), engagement-scoped
  for engagement acts and `scope='global'` for service acts; payloads carry reason codes and ids, **never
  `goal`/target/evidence text** (§2.4 line).
* *(C) Not audited; the scheduler's behaviour is "derivable from state".* *Against*: **false for the
  cases that matter** — a deferral leaves no state at all, and (§3.1) a decision to re-queue can
  contradict state that was rolled back. D8's promise ("why did this happen / not happen") needs the
  scheduler's reasons recorded.

**Audit failure.** The logger is fail-closed by design (`AuditWriteError`; the caller must not catch to
continue) [R]. For the scheduler that is the correct semantic and gives the answer to "audit down?":
**a scheduler that cannot record a decision it just made must not act on it.** Since `audit_log` and the
state tables are the same Postgres, "audit down" and "database down" are almost always the same event
(§3.4); the case where they differ (audit role/permission/tablespace fault) is rare and handled the same
way — halt (D58-6, link 6).

**⚑ Decision to confirm:** option (B), the event vocabulary being small and closed, and the
edge-triggered rule.

---

## 3. Part 二 — Continuity risks of long-running operation

### 3.1 The foundation experiments: what survives, and what cannot be stopped

Three experiments on the real pipeline (Appendix A has the exact setup). Each used the genuine
`propose_action` against the live database; only the sandbox was replaced where the point was timing
rather than Docker.

**Experiment 1 — `kill -9` of the process during `sandbox.run()`.** The child process ran `propose_action`
with a sandbox that blocks; the parent confirmed it had entered the sandbox, `SIGKILL`ed it, and queried
the engagement. **[E]**

```
action_proposals  []
tool_runs         []
capabilities      []
audit             [..., proposal.submitted, policy_reviewer.opinion, policy.decided,
                        capability.issued, tool_run.started]      ← and nothing after
```

Every state row rolled back. The audit trail alone remembers a capability and a run that, to the state
tables, never existed. **`reconcile_stale_dispatches` would return `[]`** — it selects
`action_proposals WHERE dispatch_state IN ('dispatching','running')` and there is no such row. The §8.8
promise ("a crashed dispatch becomes `UNKNOWN_OUTCOME`") holds only for a crash *between committed
transactions*, which this pipeline never has.

**Experiment 2 — Postgres restarted (`-m immediate`) while the tool "ran".** **[E]** The sandbox stand-in
stopped the cluster for 3 s mid-run, then returned a successful result. Outcome:

```
RAISED: sqlalchemy.exc.OperationalError (psycopg.OperationalError) consuming input failed: SSL error: unexpected eof...
action_proposals []   tool_runs []   evidence []
audit [... capability.issued, tool_run.started]
```

Same end state as the crash: the tool finished (so any side effect happened), the result is gone, and
**the exception is a raw `OperationalError`, not `AuditWriteError` and not a pipeline outcome** — a loop
that catches only the typed outcomes dies here. Good news in the same run: the **pool recovered** — the
very next scoped queries after the restart succeeded (`pool_pre_ping=True`).

**Experiment 3 — `engage_kill_switch` while a run is in flight.** **[E]** A thread ran `propose_action`
with a sandbox blocked on an event; another connection engaged the kill switch; then the sandbox was
released.

```
kill switch engaged mid-run; capabilities revoked: []
run still completed after kill switch: decision ALLOW  run True  evidence True
capability row: [(False, None)]            ← not revoked
tool_runs:      [('succeeded',)]
```

`revoke_all_for_engagement` is an `UPDATE … WHERE revoked IS FALSE` on **committed** rows; the in-flight
capability is uncommitted and invisible to it. The kill switch **reported success, revoked nothing, and
the run proceeded to produce evidence.** D45 found this for `revoke_credential`; it is true of **every**
revocation path (kill switch, pause, completion, scope retirement, credential revocation), and the
kill-switch audit payload's note — "with a container sandbox, revocation plus namespace teardown stops
in-flight work" (`engagement.py:305-306`) — describes behaviour that does not exist. Labels
(`cyberorch.run_id`) are set on containers but **nothing queries them** [R: grep] — no sweeper, no
`docker kill`-by-run, no orphan cleanup on restart.

#### Decision D58-5 — The transaction shape of `propose_action` (a prerequisite for almost everything below)

These three experiments are one fact seen three ways, and they decide whether Part 二's remaining
questions have answers at all. For a resident service the options are:

**Option A — keep the single transaction; the orchestrator compensates around it.**
Treat the *audit trail* as the intent log: `tool_run.started` is committed before the container runs and
has no terminal event if the process dies. A startup reconciler reads
`tool_run.started` without a matching `tool_run.{succeeded,failed,unknown_outcome}` for the same
`subject_id`, and **writes the blocking state itself** (a `tool_runs` row and `action_proposals`
`unknown_outcome`).
* *For*: no change to `propose_action`; every closed finding (D45, D47–D57) keeps its tests untouched.
* *Against*: **in-flight revocation remains impossible** (experiment 3 is unchanged) — so kill/pause/
  credential-revoke stay advisory until the run ends, which for a *service* means "the operator hits the
  kill switch and the system keeps working for up to `max_duration_seconds`". Also the reconciler would be
  *synthesizing state from audit rows* — the audit log is documented as "a decision the control plane made,
  not state that exists" (`logger.py`); promoting it to a source of state inverts that contract.
* *Against*: leaves the window in which a re-proposal of the same work **is not deduplicated** (no
  committed `tool_runs` row → `find_cached_run` misses → a second dispatch of a possibly-side-effecting
  action) until the reconciler runs. I7 is violated in that window.

**Option B — split `propose_action` into committed phases.**
(1) decide + issue capability + insert `action_proposals`/`tool_runs` as `running` → **commit**;
(2) execute (container, no DB connection held); (3) new transaction: evidence, final state, provenance.
* *For*: **everything composes**: a crash leaves a committed `running` row, so the §8.8 reconciler works as
  designed; revocation/kill/pause see the committed capability; an LLM reviewer call and a container run
  stop pinning a pooled connection and a snapshot (also fixes §3.2 link 1's pool-ceiling finding);
  dedup sees in-flight runs.
* *Against*: it changes the single most-tested function in the repo and reopens D45's closed finding in
  the *good* direction — every test that asserts on the one-transaction shape, and the D47/D51/D57-class
  e2e tests, are in scope. It also introduces a new failure that does not exist today: **phase (1) committed,
  phase (3) failed** (the tool ran and its result was not recorded) — which is exactly `UNKNOWN_OUTCOME`
  and is *correctly* modelled, but must now be handled rather than being unreachable.
* *Against*: kill/pause still need the *container* stopped, not just the row flipped — Option B makes the
  revoke visible; stopping the container is the separate D44-7 Option B (`docker kill` by label), which
  this unlocks but does not itself do.

**Option C — accept the shape; run with "crash ⇒ human".**
No reconciler beyond what exists; an orchestrator crash or DB outage mid-dispatch holds the *whole
service* for a human to read the audit trail and decide.
* *For*: smallest change; honest about the limit.
* *Against*: for a service intended to run unattended, "any restart is a human page" is the product not
  working; and it still has the dedup-miss window of Option A.

**Lean: Option B**, as an explicit **phase-0 prerequisite**, before any scheduler logic. Reasoning: every
other containment promise in this document (kill switch, pause, credential revocation, the reconciler,
dedup of in-flight work, the connection-pool ceiling) is conditional on the capability and the run being
*committed before the container starts*. Building a scheduler first and fixing the shape later means
building the scheduler's failure handling twice. Option A is the fallback if reopening `propose_action` is
judged too large — and then the document's claims about kill/pause for a resident service must be
rewritten as "advisory until the run ends". **⚑ This decision gates D58-6 through D58-9.**

### 3.2 Decision D58-6 — Failure semantics for each of the seven links, as policy

The ladder of containment, from least to most disruptive:

* **L1 — skip the task.** The task is marked failed/deferred with a reason code; the engagement continues.
* **L2 — hold the engagement.** The scheduler stops *new* dispatch for that engagement, leaves in-flight
  work alone, audits the hold, and waits for an operator release. (A sub-decision follows the table: whether
  the hold is a distinct scheduler state or the existing operator `pause_engagement`.)
* **L3 — halt the service.** All scheduling stops; a human is paged.

The recommendations below are policy, so each carries its reasoning and what is verified. The unit of the
rule is *what the failure says about blast radius*: a fault specific to one task → L1; to one engagement's
trust assumptions → L2; to shared infrastructure the security properties depend on → L3.

| Link | Verified current behaviour | Failure modes in continuous operation | **Recommended** | Why |
|---|---|---|---|---|
| **1. `propose_action` pipeline** (canonicalize → resolve → persist) | One transaction (§1) holding a pooled connection; **`record_audit` needs a *second* pooled connection while the first is held.** Default pool 5+10=15. **[E]** 8 concurrent in-flight steps: fine; **15 concurrent: every audit write waited the full 30 s `pool_timeout` and failed (`AuditWriteError` ×15)** — a self-inflicted deadlock. Effective safe ceiling ≈ `pool_size + max_overflow − 1` = **14 in-flight steps** per engine, and the LLM reviewer (30–120 s) and container run both count against it. | DB error (transient) / bug (poison task) / pool exhaustion | DB error: **L1 + bounded retry with backoff**; **K consecutive DB errors across engagements ⇒ L3** (it is infrastructure, §3.4). Unexpected exception *after* `tool_run.started`: **never auto-retry** (§3.2 link 4). Same task failing K times: **L1→L2** (poison task). In-flight concurrency **must be capped below the pool ceiling by the scheduler itself** (D58-13). | A repeated failure of the *same* task is a task fault; a failure of *every* task is not. |
| **2. OPA decision** (`opa eval` subprocess per decision) | `evaluate()` returns `DENY` with `engine_error` + reason `engine_unavailable` if the binary is missing / the call fails — **fail-closed, correctly** [R]. **But**: the Supervisor's `recent_decisions` and any history-based dedup read `DENY` as a *closed direction* [R: `query_state`, D40 §2.3]. A **transient** OPA failure is therefore remembered as a **permanent-looking refusal**. | binary missing / timeout / crash | **L1 for the task, with the `engine_unavailable` DENY excluded from "closed directions"** (`reasons` carry a distinct string, so it is distinguishable [R]); **K consecutive ⇒ L3** (OPA is shared and security-critical: no decisions means no safe action for anyone). | Fail-closed must not turn into fail-*permanent*. |
| **3. Capability broker** | `issue_capability` refuses on paused/killed/revoked-credential/stale-scope/approval-expired and **audits the refusal then returns** (not raises) [R]. | These are **decisions**, not faults. | Treat as **L1** (task → `failed(reason)`); engagement `paused`/`killed`/`completed` ⇒ the scheduler **stops serving that engagement** (it must re-read `engagements.status` before *each* dispatch, not once per tick — §3.1 shows a revoke does not reach in-flight work). | A refusal is the broker working. Don't escalate it. |
| **3b. Lease / heartbeat** | no caller of `renew_capability`; **lease anchored to transaction start** (§3.3) | `ALLOW` but capability already expired at dispatch | see §3.3, D58-8 | |
| **4. Dispatch** (`dispatch_scan` / `_collection` / `_code_scan`) | `SandboxUnavailable` → committed `UNKNOWN_OUTCOME` (never retried). **[E]** Two defects the resident service inherits: (i) **daemon unreachable *before anything started* is recorded as `unknown_outcome`** — the tool *provably did not run* — so a Docker outage turns every dispatch in the outage window into a permanently-stuck proposal; (ii) with a **cached** client and the daemon *dead*, `sandbox.run` raises a raw `requests.exceptions.ConnectionError`, **not** `SandboxUnavailable` — it escapes `propose_action` entirely (and, being inside the one transaction, rolls everything back, §3.1 experiment 2). Also **[E]** two engagements with *overlapping* (non-identical) allowlists: the second's `networks.create` is refused by Docker ("Pool overlaps with other one") → `SandboxUnavailable` → **`unknown_outcome` for a run that never started**. | daemon down / network create refused / tool timeout (→ `FAILED`, killed) / crash | `unknown_outcome` **for a side-effecting action**: **L2** (the next steps may depend on a state we cannot read). **For a side-effect-free action** (scan, collection; `registry.side_effect_floor` is known per action [R]): **L1 + alert, the (action,target) blocked from auto-retry, engagement continues** — *if* D58-7 is accepted. Daemon-down: **L3** after K tasks across engagements (shared infra), with in-flight work left to its own `max_duration` kill. | The brief's own question. Side-effect knowledge is the discriminator, and it already exists per action. |
| **5. Evidence write** | Raw artifact **written to disk first**, then `INSERT evidence`, both inside T; the container is **already `remove(force=True)`d in `run`'s `finally`** [R]. Disk-full / `EVIDENCE_STORE` unwritable raises `OSError` (uncaught) → T rolls back. | tool ran; output exists nowhere else | Output of a **side-effect-free** run is **lost but re-obtainable** → L1, retry allowed (only if no committed run row says otherwise). Disk-full / store unwritable is **shared infrastructure** ⇒ **L3** (it will fail for every engagement; the root is one directory). | The data-loss is real; the *fix* is Option B of D58-5 (record the result in its own short transaction right after the container exits). |
| **6. Audit** | **Fail-closed** [R]: `AuditWriteError` propagates; the lost record is written to the application log at CRITICAL (`AUDIT WRITE FAILED — record not persisted`) as the independent channel. Opens its own connection per call. | DB down; role/permission/tablespace fault; **pool starvation (link 1)** | **L3, always.** No security-relevant act without a record, and the shared cause makes per-engagement containment pointless. | This is the one place there is no policy question — the logger's contract is already "the operation fails with it". **But**: the CRITICAL log is the *only* record during an audit outage, so it **must go to a sink independent of the DB host** (D58-9 sub-point). |
| **7. Provenance** (`graph.record_edge`, ≤ 7 edges per run) | Inside T, **after** the tool ran. A failed edge insert raises and **rolls back the run record that already contained a real result** [R: `function_api.py:662-695`]. Edges are derivable from ids already present in state rows (`PROPOSED/AUTHORIZED/CLASSIFIED/ISSUED/EXECUTED/PRODUCED`) [R]. | DB error | Provenance is **derived** data: it must **not** be able to destroy a recorded result. Under D58-5/B, record edges in phase (3) *after* the result commit (or in a separate retried step, reconstructable from state); a missing edge is an **alert + backfill**, not an L-anything. Until then: L1 and accept the result loss. | Today a late, cheap write holds the whole run hostage. |
| **(added) Reviewer / Worker / Supervisor backends** (`claude` headless: reviewer 30 s, worker/supervisor 120 s) | Reviewer failure is **fail-closed into `HUMAN_APPROVAL`** (`_escalate`: `risk_hint="high"`) [R]; Supervisor failure returns `None` [R]; D17 lost 46/62 calls to a bare `cli exited 1` [D]. The reviewer opinion's *audit payload* does **not** carry a structured `failed` flag — only the free-text hint "policy reviewer unavailable: …" [R: `ReviewerOpinion.as_dict`]. | rate limit / CLI outage / timeouts | **A reviewer outage must not manufacture a human queue.** Circuit-breaker: when the reviewer-unavailable rate in a window crosses a threshold, **hold LLM-dependent steps (global)** rather than let each become a `HUMAN_APPROVAL` row an operator then bulk-approves out of fatigue. Distinguishing "worried" from "unreachable" needs a structured field, not a substring match. | An approval queue full of "reviewer was down" is a social-engineering surface made by the platform itself. |

**Sub-decision D58-6b — what an "L2 hold" is.** Two shapes:
* *(i)* the existing `pause_engagement` — operator-visible, audited, revokes capabilities, `resume` re-checks
  the kill switch and does **not** restore revoked capabilities (I9). Using it for machine-triggered
  containment means automatic and manual pauses are the same state (distinguished only by `actor`/reason),
  and an automatic pause **cannot be undone by the same automation without re-using an operator act**.
* *(ii)* a separate **scheduler hold** that the orchestrator sets and an operator releases, persisted so a
  restart doesn't forget it — but that needs somewhere to live (a column or table; a schema change, and an
  *engagement-scoped* write by the scheduler).
* Lean: **(i)** — one control, one audit trail, no new state to keep consistent; accept that releasing is
  always a human act. It is the conservative reading of "the system stopped itself." **⚑**

#### Decision D58-7 — `UNKNOWN_OUTCOME`: never auto-retry, or retry only what is provably harmless?

§8.8 and I7 say *never*. With a service, "never" has a cost: Docker flaps (this environment demonstrates
it on a regular basis), so a policy of *permanent* `unknown_outcome` for every dispatch in an outage window
means the queue fills with items only a human can clear. Two separate things are tangled here:

1. **Mislabelling** (a bug, not a policy): "the daemon was unreachable before any container existed" and
   "the connection dropped after `container.start()`" are different facts. The first is *provably not
   executed*; recording it as `unknown_outcome` is wrong, not cautious. A pre-start failure should be a
   distinct, retry-safe state (e.g. `not_started`), with `UNKNOWN_OUTCOME` reserved for failures at or
   after `start()`. This applies to the network-overlap case too. **[E]**
2. **Policy:** for a genuinely unknown outcome of a **side-effect-free** action (`writes_data=False and
   changes_state=False` after the D34 floor), may a reconciler re-run it? Re-running a read-only scan cannot
   duplicate a side effect.

* *Option A — never auto-retry anything unknown (status quo; I7 literal).* *For*: simplest, uncontroversial.
  *Against*: a flapping daemon becomes a human-clearance queue.
* *Option B — fix the mislabel only; keep "never" for everything that was genuinely at/after start.*
  **Lean.** Removes the outage-induced noise without relaxing I7 at all.
* *Option C — B plus auto-retry of genuinely-unknown *side-effect-free* runs after a reconciler check.*
  *For*: further reduces human load. *Against*: relaxes an invariant the architecture put in a box; the
  floor "is this action side-effect-free" is a classification the project has already been burned by
  trusting (D34's writes_data floor). Recorded as the next step, not recommended now. **⚑**

### 3.3 Re-examining the lease / heartbeat model when the orchestrator owns the clock

Verified inputs: default lease **60 s** (`DEFAULT_LEASE_SECONDS`; `ProposedAction.requested_capability_ttl_seconds=60`);
`lease = min(ttl, budget.max_duration_seconds)`; renewal extends to at most `issued_at + max_duration_seconds`
(so the *whole-life* budget is the hard bound, not the lease); `heartbeat_required` unread (5.4); **no
production caller of `renew_capability`**; and — new — **a capability's `lease_expires_at` is anchored to the
start of the surrounding transaction, not to the moment of issue**, because `now()` in Postgres is the
transaction start (`INSERT … now() + make_interval(…)`) [R].

**New finding — `ALLOW` can silently mean "never ran". [E]** With `capability_ttl_seconds=3` and a reviewer
that takes 4 s (standing in for a slow LLM reviewer):

```
ttl=3s, reviewer took 4s -> decision ALLOW | run_id None | failure capability_not_live
capability lease: 3.0 s   dispatch_state: queued
```

The capability was born already expired, `dispatch_scan` refused it (`capability_not_live`), and the
proposal is left `ALLOW` / `queued` — **not** in `reconcile_stale_dispatches`'s in-flight set, so nothing
will ever look at it again. With the production defaults the margin is 60 s − reviewer time: the headless
reviewer's own timeout is 30 s (fine), the **local reviewer's is 120 s (a slow call alone can exceed the lease)**, and OPA, the
resolvers, `list_scope_objects` and DB latency all spend the same 60 s. For a harness this was an
unobserved corner; for a service it is a class of silently-lost work that needs a defined owner (§3.2
link 3b, and the "never ran" classification of D58-7).

**Exposure windows the orchestrator's clock creates or changes** (the D44-7 analysis, restated for the
new caller). Let `L` = lease, `I` = renewal interval the orchestrator chooses, `M` = `max_duration_seconds`,
`R` = time for a revocation to *reach* a running container.

| Window | Definition | Bounded by | Under the old callers | Under a self-scheduling orchestrator |
|---|---|---|---|---|
| W1 issue → dispatch | capability exists, not yet used | `L` (and now-anchored-to-T-start, above) | harness dispatches immediately in the same call | **approved proposals**: `grant_approval` issues a 60 s capability at grant time and **nothing dispatches it** (§3.3b) |
| W2 in-flight vs revocation | run executing, revocation arrives | **`M`** (the sandbox kill), *not* `L` — lease is never re-checked after start; `R=∞` today (§3.1 exp. 3) | accepted (D44-7 A) | same, but now unattended — nobody is watching at 03:00 |
| W3 *detection* latency of a state change the broker only learns about by re-checking | a policy publish (**no eager revoke on publish exists**; layers.py: outstanding capabilities "are still revoked on their next heartbeat"), a scope deactivation without cascade, an approval expiry | **`I`** — now an *orchestrator-chosen* number | `I = ∞` (nobody renewed, the lease just lapsed in ≤ 60 s) | **a dial.** A long `I` is a long policy-tightening latency; a short `I` is load |
| W4 liveness lie | renewal says "alive" | — | n/a | renewal-on-a-timer proves the **orchestrator** is alive, not the tool. §1.2(a) of ARCHITECTURE intended the *tool* heartbeat; no third-party tool (nmap, bloodhound-python, semgrep, gitleaks) can send one. |
| W5 renewal outlives its premises | `renew_capability` re-checks policy version, approval validity, credential, scope, engagement; **it does not re-check the *target's* current state or the reviewer's opinion** | — | n/a | acceptable by I9 as written; stated so nobody assumes more |

**Does renewal timing create new exposure?** Yes, in exactly one way and it is easy to mis-state: **it turns
the default from fail-safe into fail-depends.** Today, no heartbeat ⇒ the capability *lapses* (safe by
default, `broker.py` docstring). If the orchestrator renews on a timer, a capability lives as long as the
orchestrator keeps renewing it, bounded only by `issued_at + M`; the *only* thing standing between "an
orchestrator bug that keeps renewing" and "a capability alive for M" is that `M` bound and the re-checks
inside `renew_capability`. Both are real and tested — so the hard bound survives — but the *default
direction* is reversed, and that should be a chosen property, not a side effect.

**Options.**
* **H-A — no renewal; single-dispatch capabilities; issue just-in-time.** A capability is issued
  immediately before its one dispatch (same statement-time, after the reviewer and OPA, with `now()`
  replaced by a statement-time clock) and is never renewed. Approved proposals get their capability
  *issued by the orchestrator at dispatch time* (re-running the broker's checks), **not** at `grant_approval`
  time. `heartbeat_required` stays inert and 5.4 is closed as "no multi-dispatch capability exists, so there
  is nothing to heartbeat".
  * *For*: the fail-safe default survives (everything lapses); W1 shrinks to ~0; W3 collapses to "at the
    next issue" — which for single-dispatch capabilities is *every* dispatch; fewest moving parts.
  * *Against*: W2 is unchanged (needs D58-5/B + D44-7-B to improve); a *multi-minute* tool run gets no
    mid-run re-authorization — but none was ever delivered, and none can be without killing the container.
* **H-B — orchestrator-timed renewal at `I ≈ L/3`, renewal failure ⇒ kill the container.**
  * *For*: bounds W3 to `I` and makes revocation *effective* (a failed renewal stops the run, if the kill
    exists). The only option that closes W2 for runs longer than `I`.
  * *Against*: **requires D58-5/B and D44-7-B (active `docker kill` by `cyberorch.run_id`)** or renewal
    failure changes nothing. Creates the W4 liveness lie unless tied to an *observed* signal. Reverses the
    default direction (above). Adds a per-capability timer for every in-flight run — load on exactly the
    connection pool §3.2 link 1 shows is the scarce resource.
* **H-C — observed-liveness renewal.** Renew only while the orchestrator can see the container running (a
  Docker `inspect` by run label), so the signal is the tool's, not the orchestrator's.
  * *For*: closes W4. *Against*: it is H-B plus a polling dependency on the Docker daemon — meaning a Docker
    outage (§3.4) now *revokes everything in flight*, which may or may not be the intended failure mode.
* **Lean: H-A now; H-B named as the escalation when a tool needs a run longer than the policy-detection
  latency the operator will accept, and only with D58-5/B and D44-7-B.** Reasoning: today's real flaw is
  not "renewal is missing", it is "the lease is anchored to the wrong instant and nobody dispatches the
  approved capability". H-A fixes both without introducing a timer that reverses the safe default.
  **⚑** (Also decides whether ACCEPTANCE 5.4 closes as won't-do or stays open for H-B.)

#### 3.3b The approved capability that nobody dispatches (found while tracing renewal)

`grant_approval` writes the `approvals` row and issues a capability "through the existing broker", and
**returns** — [R: `approvals.py:256-340`]; its two callers are `web/app.py` and `scripts/approvals.py`;
**no code in `control_plane/` or `agents/` dispatches an approved proposal.** The capability it issues has
a 60 s lease (`ttl_seconds=row[…] or 60`) and `dispatch_scan` refuses a non-live capability. So today an
approval **cannot result in a run** unless something dispatches within a minute of the click — and the
brief's own subject (human-approval-stuck work) therefore has no completion path. In addition,
`grant_approval` has no `credential_id` parameter, so an approved `ad.collect` produces a credential-less
capability that `dispatch_collection` refuses (D50-F1) — **the HUMAN_APPROVAL path and the credential path
do not compose** (§5).

This makes an **approved-proposal dispatcher** a required orchestrator component that earlier designs did
not list, and it is the strongest argument for H-A's "issue at dispatch, not at grant": a long-lived
grant-time capability is exactly the W1 window with the longest tail. **⚑** (decided together with D58-8.)

### 3.4 Underlying services disconnecting and recovering

This environment kills Postgres and Docker routinely — the brief called for treating it head-on, and the
experiments above are that. Four facts first, then the design.

**What recovers by itself.** SQLAlchemy's `pool_pre_ping=True` revalidates a connection at checkout, and
**[E]** after a `-m immediate` restart the next scoped query succeeded without any reconstruction of the
engine. The *connection pool* is not the problem; **in-flight transactions** are.

**What does not.** (a) The in-flight transaction (all of §3.1). (b) A **cached Docker client**: after the
daemon dies, `DockerSandbox._client` stays set and `run()` raises a raw `requests.exceptions.ConnectionError`
rather than `SandboxUnavailable` [E] — typed outcomes the pipeline expects are bypassed. After the daemon
restarts, a cached client reconnects on its own (the SDK re-opens the unix socket per request) [R/N: I
restarted `dockerd` after this experiment and confirmed `docker info`; I did not run a second
`DockerSandbox` call to prove the cached client reconnects — see §9]. (c) **Orphan resources**: containers
(labelled, never swept), per-allowlist networks (shared and never removed except by `remove_network()` in
tests), the raw evidence file written before the failed insert, and — see §5 — **mounted credential files**
(`finally` does not run on `SIGKILL`; **[E]** `/tmp/cyberorch-cred-odpdmcpv`, mode `0644`, dated Sep 29, is
already sitting on this machine from an earlier killed run — I did not read its content).

**Scheduling decisions that should have happened during the outage.** The question has a clean structural
answer, and it is the design principle I would hold onto:

> **The scheduler must be level-triggered and stateless between ticks.** Every decision is re-derived from
> database state each tick; the scheduler keeps in memory *only* caches that can be discarded (and never
> caches policy — §3.2 link 2). Then a missed tick is not a missed decision: the next tick sees the same
> state. There is no event queue to replay.

What *can* go wrong under that principle — the things that are edge-triggered *in the existing system*,
and so would genuinely be lost across an outage:

| Edge-triggered thing | What an outage does to it | Recovery |
|---|---|---|
| Expired task claims (needs a sweep that does not exist) | stay `claimed` forever (premise 6) | the sweep, with the **duplicate-run hazard** below |
| Interrupted dispatches | invisible under the one-transaction shape (§3.1) | D58-5 |
| Policy tightened during the outage | no heartbeats ⇒ no re-check; but capabilities lapse in ≤ 60 s anyway, and a *new* decision calls `load_effective_policy` | none needed **if policy is read at decision time**; a scheduler that cached the effective policy would be silently stale — and note `load_effective_policy` and `propose_action` currently run in **separate transactions** [R: d40 harness], so a layer published between them is judged on the old policy but the capability records the *new* version [N: by reading; not executed] |
| Kill switch / pause | DB flags: level-triggered, fine | — |
| Approvals / `valid_until` | passive expiry, fine | — |

**A hazard worth stating precisely: the §6 requeue sweeper plus the one-transaction shape is dangerous.**
`claim_task`'s lease is 5 minutes. A single Worker step is Worker LLM (≤ 120 s) + Reviewer (≤ 30–120 s) +
container (`max_duration` up to 600 s by `Budget` default). A step can legitimately run past 5 minutes.
A sweeper that requeues expired `claimed` tasks would requeue a task *still being executed*, whose
in-flight run is invisible (§3.1) — so the second execution is neither blocked by `claim_for_dispatch`
(new proposal id) nor by `find_cached_run` (no committed run). **Implementing the architecture's promised
sweeper first would create duplicate executions.** [R/N: derived from verified parts, not executed.] Another
reason D58-5 precedes the scheduler; and a claim lease must be *renewed by the step* (or exceed the maximum
step time) regardless.

**Recovery protocol options.**
* **R-A — reconcile-then-resume.** On start, and after any detected loss of Postgres or Docker, run the
  reconciler (orphaned `started`s per D58-5, stale dispatches, stale claims, orphan containers by label,
  orphan credential/CA/proxy files) **before** any new dispatch; hold dispatch until it completes and
  audit the outcome (`scheduler.reconciled N`).
* **R-B — resume immediately; reconcile in the background.**
* **Lean: R-A.** B reintroduces the dedup-miss window of D58-5/A for exactly as long as the reconciler
  takes. The cost of A is a short, bounded startup latency. Add: a **singleton guard** — a Postgres session
  advisory lock held for the process's life — so a restart overlapping a not-yet-dead predecessor cannot
  run two schedulers. (`FOR UPDATE SKIP LOCKED` and `claim_for_dispatch` protect tasks and proposals from
  double *claiming*; nothing protects two Supervisors from double *planning*.) **⚑**
* Sub-point: the CRITICAL `AUDIT WRITE FAILED` log line is the only record while audit is down, so the
  service's log **must** be shipped somewhere other than the database host (or the loss of one machine
  loses both).

---

## 4. Part 三 — Multi-engagement scheduling logic

### 4.1 Extending the D40 behaviour (Supervisor avoids repeating stuck or denied work) to concurrency

**What D40 verified, exactly.** The Supervisor reads `policy_decisions_so_far` (the `decision_limit`=20
newest rows of `action_proposals`, newest-first, from `query_state`) on the *trusted* side of its prompt and,
in the one engagement over four rounds, treated `HUMAN_APPROVAL`-pending and `DENY` as closed directions
and planned nothing duplicative [D: D40 §2.3]. D40 also recorded that `status_assessment` is **not stable
under a frozen state** (Finding #4) and that the headless prompt has no bound on cumulative evidence
(Finding #2, argv limit).

**What changes with a resident loop.** Four things, each of which D40's one-engagement, four-round window
could not exhibit:

1. **A recency window is not a memory.** The "closed directions" the Supervisor sees are *the last 20
   decisions*. In a long-lived engagement older `DENY`s scroll out; the Supervisor then re-proposes the
   denied work, OPA denies again, the reviewer is paid again, the audit log grows — an unbounded
   propose-deny loop at the cost of one Supervisor + one Reviewer call per cycle. A resident loop needs a
   **durable closed-directions set** — distinct `(action, canonical target)` with a terminal-for-now
   decision — derived deterministically from `action_proposals` (the `identity_key` machinery of
   `ADR_TASK_IDENTITY.md` already defines "the same work").
2. **Transient infrastructure errors must not enter that set** (§3.2 link 2): `engine_unavailable` and
   `capability_refused`-for-lease reasons are *not* directions the engagement has closed.
3. **Planning must be change-triggered.** In D40's rounds 3 and 4 the Supervisor spent a real model call to
   conclude "nothing left to do" — fine once; with N engagements × a tick every 30 s it is a standing
   cost and, per Finding #4, a categorical assessment that flips under a frozen state cannot serve as the
   scheduler's convergence signal. Call `Supervisor.plan` only when the engagement's state has changed
   (counts + newest `updated_at` over tasks / decisions / findings / approvals) since the last plan.
4. **Where does the avoidance live — in the LLM, or in software?** D40 showed the LLM *did* the right
   thing; it is not a guarantee. The project's ethos is that software leads and AI proposes (ARCHITECTURE
   §1.1, row on LangGraph). So a **deterministic pre-filter** — drop a Supervisor-proposed task whose
   identity key matches a closed direction or a pending `HUMAN_APPROVAL` — is the consistent shape, with
   the LLM's reading of history remaining an *efficiency*, not the enforcement.

**Concurrency-specific consequences.** Per-engagement history reading is already isolated by RLS
(`query_state` has "no cross-engagement variant and no parameter that could ask for one"); a cross-
engagement scheduler **must not** use closed directions from engagement A to inform engagement B — that
would be an isolation violation by information flow even though no row crosses the boundary. The scheduler
therefore plans each engagement from that engagement's history only, and any cross-engagement logic (§4.2)
operates on **counts and states**, never on content.

**Priority basis across engagements** (no decision needed now, per the brief; options listed with what each
costs and what it forces on the §2 decision):

| Basis | Behaviour | Starves | Trustworthy against the LLM? | What it needs |
|---|---|---|---|---|
| **FIFO over all ready tasks** (global `created_at`) | arrival order | an engagement behind a burst from another | yes (timestamps) | cross-engagement ordering ⇒ N scoped reads (A) or role B |
| **Engagement creation time** (oldest engagement first) | seniority | newer engagements indefinitely | yes | only `engagements.created_at` |
| **Queue length — shortest-first** | throughput | large backlogs | **no** — the Supervisor controls how many tasks it creates | task counts |
| **Queue length — longest-first** | drain backlog | small engagements | **no** (same) — and a Supervisor can *inflate* its own priority | task counts |
| **Round-robin with a per-engagement in-flight cap** (fair share) | bounded service to each | nothing (by construction) | yes (counts only) | in-flight counts per engagement — the same state §4.3 needs |
| **Operator-weighted fair share** (round-robin + a weight in the enrolment) | as above, with operator priority | nothing | yes — the weight is operator-owned | an enrolment record with a weight |

`tasks.priority` (0–9) is Supervisor-chosen; keeping it as the *within-engagement* order (existing
`claim_task`) is fine, but it must not feed any *cross*-engagement basis. **Not a decision now**, but note
the constraint: **queue length is LLM-influenced and therefore not a safe fairness basis**, and fair-share
needs only what D58-1/A already provides. **⚑ (low priority; recorded because it constrains the enrolment
format.)**

### 4.2 Decision D58-13 — Resource allocation across engagements

**What exists, verified.**

| Mechanism | Scope | Aggregates across capabilities? |
|---|---|---|
| `Budget.max_duration_seconds` | one capability; enforced by killing the container | no |
| `Budget.max_targets` | one proposal; OPA `canonical.target.address_count` | no |
| `Budget.max_concurrency` | **carried, recorded, enforced by nothing** (premise 1) | n/a |
| `consume_request` / `budget.max_requests` | one capability's request count (atomic UPDATE) | no |
| D35/D36 sub-schemas `budget.tool.http` / `budget.tool.browser` | per-capability per-request bounds, validated in the adapter's `build_plan` | no |
| `DockerSandbox`: `mem_limit="512m"`, `pids_limit=256`, `cap_drop=ALL`, read-only root, per-run container labels | **per container** | no |
| Postgres pool 5+10, one engine per role | process-wide | — (§3.2 link 1: 14 in-flight) |

**Nothing counts anything across runs.** Not per engagement, not globally. In particular, and **[R]** from
`DockerSandbox.run`'s `containers.create(...)` arguments: **no CPU limit at all** (no `cpu_quota`,
`nano_cpus`, or `cpuset`), no cap on the number of containers, no disk quota on the evidence store, and no
rate limit on the shared LLM backend (the headless `claude` subscription, shared by every engagement's
Supervisor, Worker *and* Reviewer — D17's 46/62 failures were this).

**Contention that is real and verified:**

* **Pool ceiling.** 15 concurrent in-flight steps deadlocked on audit (§3.2 link 1, **[E]**). With the
  one-transaction shape, concurrency is capped by the pool, not by any intended limit.
* **Network sharing across engagements.** `network_name` is `cyberorch-allow-<hash of the sorted
  allowlist>` — **keyed by the allowlist, not the engagement** [R]. Two engagements with the *same*
  allowlist share one Docker bridge, and **[E]** a container of engagement B **can reach** a container of
  engagement A on it (ping across, `REACHABLE`). Overlapping-but-different allowlists instead fail with the
  Docker pool-overlap error (and become `unknown_outcome`, §3.2 link 4). Overlapping private ranges across
  *customers* are ordinary. So concurrent multi-engagement operation turns a harmless naming choice into
  **a cross-engagement reachability finding** — "tool container of customer B can reach tool container of
  customer A", inside the isolation boundary §8.6 exists to defend.
* **Cross-engagement quota cannot live in OPA.** `max_concurrency` was *in the OPA input* by design. A
  cross-engagement quota there would mean putting *another engagement's* in-flight counts into one
  engagement's policy input — an information flow across the RLS boundary, even if it never writes a row.
  So the cross-engagement quota **is an orchestrator-local operator-owned configuration** (a *resource*
  policy, not an authorization policy), and it needs only counts.

**Options.**
* **(A) In-process semaphores in the orchestrator** — a global container cap, a per-engagement cap, per-
  tool-class caps (browser is heavier than nmap); the pool ceiling folded in as `cap < pool − 1`.
  *For*: simple, no schema, enforces exactly the limit the operator sets; consistent with D58-2/A (one
  process). *Against*: lost on crash (re-derived from `tool_runs status='running'` at startup per R-A);
  invisible to a second process (D58-2/B would need shared state).
* **(B) DB-backed counting** (`SELECT count(*) FROM tool_runs WHERE status='running'` per engagement,
  inside the engagement scope) enforced at dispatch via an atomic conditional insert (the `consume_request`
  pattern). *For*: survives restarts and works across processes; **gives `max_concurrency` the meaning
  it never had** (per-engagement). *Against*: only per-engagement without cross-engagement reads (§2.2 A) —
  a global cap still needs the process-local counter or role B; and under the one-transaction shape the
  `running` row is uncommitted and *invisible to the count* (§3.1) — so it is sound **only after D58-5/B**.
* **(C) cgroup / Docker-level quotas** (a per-engagement cgroup parent; `--cpus`; a bounded user-defined
  network pool). *For*: limits real resources, not counts. *Against*: a platform-level mechanism well
  beyond this scope; no CPU limit exists today, so this is where "per-container CPU" would first appear.
* **Lean: A for the global/per-class caps now, B for per-engagement `max_concurrency` once D58-5/B lands**
  (and either the capability-level field is wired or **explicitly removed** — a carried-but-unread budget
  dimension is exactly the "a number in a database" the sandbox docstring warns about). **Per-engagement
  network naming** (include the engagement id in `network_name`, accept that overlapping allowlists across
  engagements then collide at Docker — which has to be solved by allocating non-overlapping *internal*
  subnets or by a different isolation mechanism) is a **separate decision, D58-14, and is a security
  finding rather than a tuning one.** **⚑**

---

## 5. Part 四 — The Credential Vault when the service decides when to dispatch

### 5.1 Does the D44 trust model need re-examination? Yes — in three specific places

D44 §0 contrasted a container this system *owns* (D35's proxy) with a container running *the actual tool*,
and §2.2 stated the blast radius of a compromised **tool container** holding a credential: authenticate as
that principal against hosts inside the capability's `network_allowlist` for at most `max_duration_seconds`.
**That conclusion stands**; none of it depended on who triggered the dispatch. What D44 did **not** model —
because every caller was a person or a script that *named* the credential — is the *decider*:

**(i) Who chooses `credential_id`?** `propose_action`'s docstring is explicit: `credential_id` is "the
caller's job to supply … this function does not choose one on its own initiative" [R]. Every prior caller
hard-coded it. A resident orchestrator is the first caller that must *derive* it. The candidates:

* **V1 — operator-bound mapping.** The operator declares, per engagement, which credential serves which
  scope object / action (a binding that lives in operator-owned data; the orchestrator only looks it up).
  *For*: the decision is a human's and is auditable at binding time; the orchestrator stays a lookup.
  *Against*: needs a place to hold the binding — `credentials` has only `credential_id, engagement_id,
  label, revoked, revoked_at, created_at` (no scope/action linkage) [E] — i.e. a schema change in the
  registry/vault family, with the role consequences of D44 §1.3.
* **V2 — human-approved first use.** Credentialed dispatch always goes through `HUMAN_APPROVAL`, the
  approval naming the credential. *For*: a person gates every credentialed run. *Against*: **does not work
  today** — `grant_approval` has no `credential_id` parameter (§3.3b), so the approved capability carries
  none and `dispatch_collection` refuses it. It would be new work in the approval path, and defeats
  unattended operation for AD collection.
* **V3 — the LLM (Worker/Supervisor) selects the credential.** **Rejected outright** — the credential
  decides *whose identity the tool binds as* (D50-B made that the credential's property, not the
  proposal's, precisely so a proposal cannot steer it).
* **Lean: V1**, with V2 as an optional per-engagement policy on top for sensitive credentials. **⚑ D58-15.**

**(ii) "Lease-tied lifetime" — who decides heartbeat timing, and does it compound with §3.3?**
Premise 3: D44 §2.1 *states a need*; §2.3 resolved it as **per-dispatch file + `finally` cleanup**, with
**no lease, no heartbeat, no revocation check in the vault** [R: `vault.py`, `dispatch.py` `finally` blocks].
So the literal answer to the brief — *"who decides heartbeat timing"* — is: **nobody, today, and under H-A
nobody ever needs to.** The credential's on-disk life is `[mount_for_run … cleanup_mount]`, i.e. one
dispatch.

It does compound with §3.3 W2/W3, and the compounding has a clean statement. For a credentialed capability
the **exposure window** is

> `min( M , t_detect + R )`

where `M` = `max_duration_seconds`, `t_detect` = how long until the orchestrator *notices* the credential was
revoked, and `R` = how long until that notice *stops the container*. Today `R = ∞` (§3.1 exp. 3, and D45), so
the window is `M` and **`t_detect` is irrelevant**. Under H-B, `t_detect ≈ I` (the orchestrator-chosen renewal
interval) and `R` = kill latency *if and only if* D58-5/B and D44-7-B are built. Hence: **the renewal interval
only starts to matter for credentials after the container kill exists; before that, a short `I` buys
nothing for credentials, and `M` — an orchestrator-chosen number — is the entire dial.** And `M` is chosen by
whoever builds the `Budget`: `propose_action`'s default is 120 s, `Budget()`'s is 600 s, and **no Rego rule
bounds `max_duration_seconds`** [R: only `max_targets` is checked, `authz.rego:230-235`]. In a resident
service the orchestrator, not a person, fixes `M` for credentialed actions → **a per-action `M` ceiling is
an operator-owned configuration the orchestrator must obey for credentialed capabilities** (⚑ D58-16).

**(iii) What changes about *when* a credentialed run happens.** D44 accepted the exposure window (D44-7 A)
in a world where a human or a supervised harness started the run. A resident service starts them at 03:00
with no one watching. The window is the same length; the *supervision* of it is not. Options:
* **G-A — credentialed dispatch is unattended like any other.** *For*: that is the point of a resident
  service. *Against*: D44-7's acceptance silently assumed attendance.
* **G-B — a credentialed action requires, at least on first use per credential, a human acknowledgment**
  (e.g. via V2, or an operator "arm" of the credential for a time window). *For*: restores a human in the
  loop exactly where D44 said the stakes rise. *Against*: friction; needs the §3.3b approval path fixed.
* **G-C — unattended allowed only if D44-7-B (active kill) exists.** *For*: ties the acceptance of the
  window to the existence of the mitigation. *Against*: sequences a large piece of work ahead of any
  credentialed unattended run.
* **Lean: G-C if the active kill is built in the same effort as D58-5/B (they share the label-and-kill
  machinery); G-B in the meantime.** **⚑ D58-16.**

### 5.2 New exposure created by *concurrency and residency*, independent of timing

1. **Orphaned secret files.** `mount_for_run` writes the secret with `mkstemp(prefix="cyberorch-cred-")`
   and `chmod 0644` [R: `vault.py:_MOUNT_FILE_MODE`]; removal is in a `finally`, which does not run on
   `SIGKILL`/OOM-kill/power loss. **[E]** One such file from an earlier killed run is on this machine now
   (`/tmp/cyberorch-cred-odpdmcpv`, `-rw-r--r--`, 31 bytes, 2026-09-29). It is world-readable, in the shared
   `/tmp`, with **no sweeper** [R: grep]. A harness leaves one orphan per crash and a human notices; a
   service that restarts on every Postgres blip leaves them *systematically*, for the lifetime of the host.
   The same applies to the control-plane fetch checkouts (`cleanup_repo`) and the CA/proxy-key temp files.
2. **N simultaneous plaintext files.** Concurrency multiplies the number of `0644` secret files existing at
   once on the host, each for up to `M`.
3. **Key and role residency** (§2.3): `VAULT_MASTER_KEY` and `SELECT` on all engagements' `credential_material`
   in one long-lived process. Not a new capability — a new *duration* and *breadth*.
* **Options for D58-17.** *(A)* a startup + periodic sweeper for temp artefacts by prefix and age, plus
  `0600`-with-owner-matched-uid if the container's user can be made to match (D43/D44 chose `0644` because
  the tool's non-root user could not read `0600`; that is a constraint, not an oversight) — cheap, narrow.
  *(B)* a **per-run `0700` directory under a dedicated tmpfs** owned by the control-plane user, so that the
  world-readable file is not world-*reachable* — fixes the exposure without changing the file mode the
  container needs. *(C)* a **vault sidecar process** that alone holds the master key and the
  `credential_material` grant and exposes `mount_for_run` over a unix socket — real separation, and the
  right answer if D58-2 lands on A and key residency is judged unacceptable; large. **Lean: A + B now,
  C recorded as the escalation.** **⚑**

---

## 6. Defects the orchestrator inherits (found while verifying, not decided here)

These are not design alternatives — each is a verified gap whose fix is on the critical path of some
decision above. Listed so they can be recorded in ACCEPTANCE in the project's usual form once you choose
what to do; **I have not recorded them**.

| # | Defect | Evidence | Needed by |
|---|---|---|---|
| X1 | Interrupted dispatch invisible to `reconcile_stale_dispatches` | [E] exp. 1 | D58-5 |
| X2 | Kill switch / pause / completion do not reach an in-flight run; success is reported with `revoked: []` | [E] exp. 3 | D58-5, D44-7 |
| X3 | Capability lease anchored to transaction start; `ALLOW` + `queued` + never dispatched, no sweeper | [E] | D58-8 |
| X4 | Pre-start failure and overlapping-network failure recorded as `unknown_outcome` | [E] | D58-7 |
| X5 | Cached Docker client + dead daemon raises raw `ConnectionError`, escapes the typed path | [E] | D58-6 |
| X6 | Pool deadlock at ≥ 15 concurrent in-flight steps (audit needs a second connection) | [E] | D58-13 |
| X7 | `claim_task` expired leases never requeued (premise 6) | [R] | D58-9 |
| X8 | `grant_approval` issues a 60 s capability and nothing dispatches it; no `credential_id` on the approval path | [R] | D58-8 / D58-15 |
| X9 | Transient `engine_unavailable` DENY is indistinguishable (to history readers) from a real refusal | [R] | D58-6 / §4.1 |
| X10 | Reviewer-unavailable is a free-text hint, not a structured field | [R] | D58-6 |
| X11 | Provenance edge failure can destroy an already-recorded run result | [R] | D58-5 / D58-6 |
| X12 | Allowlist-keyed shared network ⇒ cross-engagement container reachability | [E] | D58-14 |
| X13 | No CPU limit, no container-count cap, no evidence-store quota | [R] | D58-13 |
| X14 | Orphaned credential temp files, mode `0644`, no sweeper | [E] | D58-17 |
| X15 | `load_effective_policy` and `propose_action` in separate transactions (policy TOCTOU for a caching caller) | [R/N] | D58-9 |
| X16 | `max_concurrency` carried but unread | [R][D] | D58-13 |

---

## 7. Validating the shape against the real loop

A sanity check that nothing above is invented: map the one loop that exists (D40) onto the pieces and see
what a resident version has to add.

| D40 harness does | Resident equivalent | New here |
|---|---|---|
| `uid("ENG-D40-…")`, `setup_engagement` | operator creates + **enrols** (D58-1/A) | enrolment record; audited at start |
| `build_state(...)` → `supervisor.plan(...)` each round | per-engagement, **change-triggered** (§4.1) | change detector; durable closed-directions pre-filter |
| `create_task` per planned task | same, behind the pre-filter | — |
| `claim_task` (once, immediately) | claim with **renewable** lease ≥ max step time | claim renewal; sweeper (after D58-5) |
| `worker.propose` | same, bounded by a Worker circuit-breaker | LLM backend breaker |
| `load_effective_policy` → `propose_action` | policy **loaded in the same decision** (or version-checked) | no policy cache |
| `propose_action` (one transaction) | **phased** (D58-5/B) | — |
| (nothing) | **approved-proposal dispatcher** | §3.3b |
| (nothing) | **reconciler**, startup + after outage (R-A) | orphan sweep (containers, networks, temp files) |
| (nothing) | **quota gate** (D58-13) | cross-engagement counts, operator-owned |
| (nothing) | **containment ladder** (D58-6) | L1/L2/L3 + audit of holds |
| prints | **scheduler audit** (D58-4) | edge-triggered, closed vocabulary |

---

## 8. Decisions needing your sign-off

⚑ = needs your decision. "Gate" = another decision cannot be settled until this one is.

| # | Decision | Options | This document's lean | Gate |
|---|---|---|---|---|
| **D58-1** ⚑ | How the scheduler learns which engagements exist, and the cross-engagement read model | (A) explicit operator enrolment, no new DB capability; (B) new `scheduler` role, column-narrowed SELECT + permissive policy; (C) `SECURITY DEFINER` (shown not to work as-is); (D) denormalized ledger (rejected) | **(A)**, with (B) on the named trigger "a cross-engagement query N scoped reads cannot serve" | gates D58-3, §4.1 priority basis, D58-13 |
| **D58-2** ⚑ | Acting identity / process topology | (A) one resident process, all engagements; (B) scheduler + per-engagement worker processes; (C) per-engagement DB identities (not recommended) | **(A)**, with a singleton lock and the D58-1/A structural fence; (B) if key residency (D58-17) is judged unacceptable | gates D58-17 |
| **D58-3** ⚑ | The metadata/content line | the table in §2.4 | as tabled; confirm `tasks.action` = metadata, `canonical_target`/`goal` = excluded | — |
| **D58-4** ⚑ | Audit of scheduler decisions | (A) every decision per tick; (B) state-changing/denying only, edge-triggered, closed vocabulary; (C) none | **(B)**; engagement-scoped for engagement acts, `scope='global'` for service acts | — |
| **D58-5** ⚑ | **Transaction shape of `propose_action`** | (A) keep one txn, reconcile from audit; (B) split into committed phases; (C) accept, "crash ⇒ human" | **(B), as a phase-0 prerequisite**; (A) as fallback with kill/pause documented as advisory | **gates D58-6, 7, 8, 9, 13** |
| **D58-6** ⚑ | Failure containment per link (L1 skip / L2 hold / L3 halt) | the table in §3.2 | as tabled — in particular **audit and shared-infrastructure faults ⇒ L3**, `engine_unavailable` ≠ a closed direction | after D58-5 |
| **D58-6b** ⚑ | What an L2 hold *is* | (i) existing `pause_engagement`; (ii) a separate persisted scheduler hold | **(i)** | — |
| **D58-7** ⚑ | `UNKNOWN_OUTCOME` policy | (A) never retry; (B) fix mislabel, keep "never"; (C) B + retry side-effect-free | **(B)** | — |
| **D58-8** ⚑ | Lease / heartbeat model; approved-proposal dispatch | (H-A) JIT issue, no renewal; (H-B) timed renewal + kill; (H-C) observed-liveness | **(H-A)**; issue an approved proposal's capability **at dispatch**, not at grant; closes 5.4 as "no multi-dispatch capability" | after D58-5 |
| **D58-9** ⚑ | Recovery protocol | (R-A) reconcile-then-resume; (R-B) resume then reconcile; plus singleton lock; plus an off-host log sink | **(R-A)** + lock + off-host sink | after D58-5 |
| **D58-10** ⚑ | Recording the §6 defects (X1–X16) | (A) record all in ACCEPTANCE now, in the project's usual form; (B) hold until you choose directions, then record only those that survive; (C) fix the independent ones first (X4, X5, X9, X10, X12, X14 do not depend on D58-5) | **(B)** — recording before the direction is chosen risks recording defects whose fix is superseded by D58-5/B; but X4/X5/X9/X10 are small, independent and worth doing regardless | — |
| **D58-11** | Cross-engagement priority basis (*not needed now*) | FIFO; creation time; queue-length (short/long); round-robin w/ cap; operator-weighted | round-robin with a per-engagement cap, optionally operator-weighted; **never** queue length or `tasks.priority` | — |
| **D58-12** | Durable closed-directions pre-filter; change-triggered planning | recency window as today vs. deterministic ledger + change detector | the ledger + detector | — |
| **D58-13** ⚑ | Cross-engagement resource quota | (A) in-process semaphores; (B) DB-backed counting; (C) cgroup quotas; and what `max_concurrency` becomes (enforce per-engagement, or delete) | **(A)** global/per-class now, **(B)** per-engagement after D58-5/B; the cross-engagement quota is operator config, **not OPA** | after D58-1, D58-5 |
| **D58-14** ⚑ | Per-engagement network isolation | keep allowlist-keyed; key by engagement + solve overlap; other isolation | **security finding**: cross-engagement reachability is verified; direction needs your call — I do not have a lean without a decision on how real customer ranges are reached | — |
| **D58-15** ⚑ | Who selects `credential_id` | (V1) operator-bound mapping; (V2) human-approved first use; (V3) the LLM (rejected) | **(V1)**, optionally (V2) on top; requires fixing the approval path to carry `credential_id` | — |
| **D58-16** ⚑ | Gating unattended credentialed dispatch; `M` ceiling | (G-A) unattended; (G-B) human acknowledgment; (G-C) unattended only after active kill exists; + operator-owned per-action `max_duration_seconds` ceiling | **(G-C)** if the kill is built with D58-5/B, **(G-B)** until then; ceiling mandatory | after D58-5 |
| **D58-17** ⚑ | Secret residency and orphan handling | (A) sweeper + mode review; (B) `0700` per-run dir on a dedicated tmpfs; (C) vault sidecar holding the key | **A + B** now; **C** if D58-2 = A and residency is unacceptable | after D58-2 |

### 8.1 What I would settle first, and why

If you decide only three things, decide **D58-5, D58-1 and D58-2**. D58-5 determines whether kill/pause/
revoke/dedup/reconcile mean anything; D58-1 and D58-2 determine the entire identity model, which the vault
and quota decisions then inherit. Most other rows are conditional on one of the three.

### 8.2 Dependency order among the decisions (not phasing — you asked for direction before phasing)

```
D58-5 (txn shape) ──┬─► D58-6 failure containment ──► D58-6b, D58-7
                    ├─► D58-8 lease/heartbeat + approved-dispatch ──► D58-16
                    ├─► D58-9 recovery + singleton
                    └─► D58-13 quotas (per-engagement part)
D58-1 (discovery) ──► D58-3 line ──► D58-13 (global part) ──► D58-11 priority
D58-2 (topology)  ──► D58-17 residency
D58-4 (audit)       independent (but its vocabulary is fed by D58-6/9)
D58-14, D58-15      independent of the above (both touch existing, non-orchestrator code)
```

---

## 9. What this document does not do — and what it did not verify

No code, schema, migration, Rego, harness, or service skeleton was written. The experiments' throwaway
scripts are not in the repository (Appendix A has the method). The experiment engagements
(`ENG-D58-*`) and their audit rows remain in this environment's development database, like the `ENG-TEST-*`
engagements every test run leaves; nothing in a shared system was touched. I restarted this
environment's `dockerd` and Postgres as the experiments required.

**Not verified [N] — listed so no one reads these as findings:**

1. A `SECURITY DEFINER` function **with an owner-keyed permissive policy** (§2.1) — only the *negative*
   result (owner under `FORCE RLS` sees 0 rows) was executed.
2. A **column-narrowed `SELECT` grant combined with a role-scoped permissive policy** (D58-1/B) — standard
   Postgres semantics, not executed here; the first thing a phase-2 migration test should pin.
3. That a **cached Docker client reconnects after the daemon returns** (§3.4) — I confirmed the daemon came
   back (`docker info`) but did not issue a second `DockerSandbox.run` to observe the client.
4. The **policy TOCTOU** between `load_effective_policy` and `propose_action` (X15) — read, not executed.
5. The **duplicate-execution hazard of a naive requeue sweeper** (§3.4) — derived from verified parts
   (the claim lease, the invisibility of in-flight runs), not reproduced end-to-end.
6. **Two scheduler instances** running at once, and the advisory-lock remedy — not executed.
7. **cgroup / Docker-level quotas** (D58-13 option C) — not evaluated.
8. **How a real customer network is reached** from an "internal" Docker bridge whose subnet *is* the
   allowlist — relevant to D58-14, outside what these experiments touch; the verified part is only that two
   containers on the same bridge reach each other.
9. The behaviour of the **real LLM reviewer/Supervisor under rate limiting** at scale — D17's figures are
   cited, not reproduced.
10. **Performance under load** of any option — nothing in this document was benchmarked (compare ACCEPTANCE
    5.23, which is the same kind of gap for the Graph).

Nothing about `propose_action`, the broker, the dispatch functions, the vault, the roles or the policy was
changed.

---

## Appendix A — Experiments (exact method)

All against the development database as `cyberorch_app` (the runtime role, so RLS applied exactly as in
production), real `propose_action`, real `create_engagement` (which requires a global baseline, supplied by
`tests/helpers.ensure_test_baseline`), a real scope object, `HonestFakeReviewer`, and `network.scan`. Scripts
lived in the session scratchpad.

| # | Question | Method | Result |
|---|---|---|---|
| E1 | What survives a `kill -9` mid-dispatch? | Child process runs `propose_action` with a sandbox whose `run()` prints a marker and sleeps; parent reads the marker, `SIGKILL`s the child, then queries `action_proposals`, `tool_runs`, `capabilities`, `audit_log` for the engagement. | State tables empty; audit ends at `tool_run.started` (§3.1) |
| E2 | What does a Postgres outage mid-run leave? | Sandbox stand-in runs `pg_ctlcluster 16 main stop -m immediate`, sleeps 3 s, starts it, waits until reachable, returns a successful `SandboxResult`. | Raw `OperationalError`; state tables empty; audit retains `started`; pool usable afterwards (§3.1) |
| E3 | Does the kill switch stop an in-flight run? | Thread runs `propose_action` with a sandbox blocked on a `threading.Event`; main thread calls `engage_kill_switch` (via `engagement_scope`, the only role with the column grant) then releases the event. | `revoked_capabilities=[]`; run `succeeded`; capability `revoked=False` (§3.1) |
| E4 | Is a daemon-unreachable dispatch recorded as `unknown_outcome`? | Real `DockerSandbox` with `DOCKER_HOST=unix:///nonexistent.sock`. | `unknown_outcome` for proposal and run (§3.2 link 4) |
| E5 | Overlapping allowlists across engagements | Real sandbox, engagement A `10.84.0.0/16` (succeeds), engagement B `10.84.1.0/24`. | B: Docker "Pool overlaps with other one" → `unknown_outcome` |
| E6 | Cached client + dead daemon | `DockerSandbox.client()` connected; `pkill -9 dockerd containerd`; `run(...)`. | `requests.exceptions.ConnectionError`, **not** `SandboxUnavailable`. `dockerd` then restarted. |
| E7 | Capability lease vs. a slow reviewer | `capability_ttl_seconds=3`, reviewer sleeps 4 s before delegating. | `ALLOW`, `run_id=None`, `failure=capability_not_live`, `dispatch_state=queued` (§3.3) |
| E8 | Pool ceiling | N threads each hold an `engagement_scope` connection, barrier, then `record_audit`. | N=8: all succeed in 0.1 s. **N=15: all 15 `AuditWriteError` after 30.0 s** (§3.2 link 1) |
| E9 | Cross-engagement container reachability | `ensure_network(["10.87.0.0/24"])`; container "A" `sleep 60`; container "B" `ping` A's IP on the same network. Network and containers removed after. | Same network name for identical allowlist; **ping succeeded** (§4.2) |
| E10 | `SECURITY DEFINER` and RLS | In a rolled-back transaction as `migration_owner` (table owner, `FORCE RLS`), a `pg_temp` `SECURITY DEFINER` function `SELECT count(*) FROM engagements`, called with no GUC and with a nonexistent engagement GUC. | `0` and `0` (§2.1) |
| E11 | Roles / grants / policies | `pg_roles`, `pg_policy`, `pg_class.relforcerowsecurity`, `information_schema.{column_privileges,role_table_grants}`. | §2.1, §2.3 |
| E12 | Orphaned credential file | `ls -l /tmp \| grep cyberorch` (content deliberately not read). | `-rw-r--r-- 31 B Sep 29` `cyberorch-cred-*` (§5.2) |

## Addendum (D62) — what was decided and built

Option A (enrollment record) and the narrow read role were built as scheduler v0; see
`docs/D62_SCHEDULER_V0_DESIGN.md` (decisions D-0…D-9) and `docs/D62_SCHEDULER_V0_REPORT.md`. Not built: the
failure ladder (D58-6), reconciler (D58-9), planning (D58-12), credential selection, quotas.

