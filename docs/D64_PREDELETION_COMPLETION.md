# D64 — the completion round before any deletion is switched on

Written after step 6 (migration 0023, commits ac3c48b..ae258ae). **The deletion flag is still off and nothing in this
round turns it on.** The round has seven items; each has its own section, its own commit and, where it changes behaviour,
its own ACCEPTANCE row. Evidence tags: **[R]** read in code or catalog, **[E]** measured, **[D]** decided here, **[N]** a
number chosen without a measurement. Experiments are numbered from E22 (E1–E21 are in `D64_RECONCILER_DESIGN.md` §6).

| item | what | where |
|---|---|---|
| 1 | every role membership and every definer object, audited as a whole; PostgreSQL 16 stated | ACCEPTANCE 5.84, `tests/test_database_authority.py` |
| 2 | the development-database cleanup of 2026-10-12 reported as it really is; test data accumulates | §2 here, ACCEPTANCE 5.23 |
| 3 | the network-conflict trigger, designed (name hash + last use + conflict count) | §3 here, ACCEPTANCE 5.85 |
| 4 | change and record in one transaction; intent before an irreversible act | §4 here, ACCEPTANCE 5.86 |
| 5 | the two "unknown outcome" event names: consumers, and where the free text came from | §5 here, ACCEPTANCE 5.87 |
| 6 | more than 5,000 stuck rows: paging, a bound on a pass, back-off | §6 here, ACCEPTANCE 5.88 |
| 7 | four open questions answered (verb allow-list, negative experiments, `ABANDON_CALLERS`, concurrency); one defect found and fixed | §7 here, ACCEPTANCE 5.89 |
| round 2 | D64-N1 built (`tool_runs.refusal_code`, the conflict read, the plan side); the 18,123 corrected; the session cleans up its own rows; races x40; the first dry run | §8 here, ACCEPTANCE 5.90–5.91, `D64_DRY_RUN_2026-10-13.md` |

---

## 2. The development-database cleanup of 2026-10-12 (item 2)

**What was done.** At 2026-10-12 07:43:46 UTC, in the previous container of this session, the development database (not
CI, not any other environment) was cleaned of stuck `action_proposals` rows left by older test runs, because the
reconciler's read function returns the *oldest* 5,000 stuck rows and thousands of junk rows from earlier runs were hiding
the fixture rows of the new tests. One `psql` session as **`migration_owner`** (the table owner; not a superuser,
NOBYPASSRLS), one transaction **[R: the recorded command]**:

```
BEGIN;
SELECT ... count(*) ... GROUP BY pipeline_stage;                          -- "before"
ALTER TABLE action_proposals NO FORCE ROW LEVEL SECURITY;
UPDATE action_proposals
   SET pipeline_stage = CASE WHEN decision IS NULL THEN 'abandoned' ELSE 'closed' END,
       stage_detail   = CASE WHEN decision IS NULL THEN 'undecided_past_grace' ELSE 'dev_db_cleanup' END,
       stage_updated_at = now()
 WHERE pipeline_stage IN ('received','decided','approved','capability_issued','dispatching')
   AND stage_updated_at < now() - interval '1 hour';                       -- UPDATE 18123
ALTER TABLE action_proposals FORCE ROW LEVEL SECURITY;
SELECT ... count(*) ... ;                                                  -- "after"
SELECT relforcerowsecurity FROM pg_class WHERE relname = 'action_proposals';   -- t
COMMIT;
```

**FORCE state.** `NO FORCE` and `FORCE` were in the same transaction as the `UPDATE` (the pattern migration 0020 uses and
`tests/test_migrations_roundtrip.py` pins): had the `UPDATE` failed, the `NO FORCE` would have rolled back with it. The
statement returned `t` for `relforcerowsecurity` before `COMMIT` **[R]**. Today (superuser read of `pg_class`): all **20**
tables that have row security also have `FORCE` on **[E]**. Only `action_proposals` was altered.

**The snapshot diff does not exist, and the reason is the finding.** The two `SELECT count(*)` statements ran as
`migration_owner` *under* `FORCE ROW LEVEL SECURITY` with no engagement bound — exactly the isolation this project built:
the owner sees **0 rows**. They printed nothing (the recorded output is `BEGIN / ALTER TABLE / UPDATE 18123 / ALTER TABLE
/ t / COMMIT`; no `before` or `after` rows). The "before" check was blind and the "after" check was blind; I did not
notice at the time and the earlier report did not say so. The only evidence of the size of the change is the `UPDATE`
count, **18,123**. What can be reconstructed now, read-only, as the superuser **[E]**:

| what | rows | how known |
|---|---|---|
| closed, `stage_detail = 'dev_db_cleanup'` | **17,716** | counted directly: the tag is unique to this statement |
| abandoned by the same statement | **407** | **observed (2026-10-13)**, not by subtraction: every row the statement changed carries the same `stage_updated_at` (the transaction's `now()`, 2026-10-12 07:43:47.361263+00), and exactly 18,123 rows carry it: 17,716 `closed / dev_db_cleanup` + 407 `abandoned / undecided_past_grace` (§2.2). The other 1,270 rows with that abandoned reason are the reconciler's own tests |
| original stage of each row | **unrecoverable** as a stage; its class is not | the `UPDATE` overwrote `pipeline_stage` and `stage_updated_at`. The untouched `decision` column still says: 407 were undecided (so `received`), 9,572 `ALLOW` and 8,144 `HUMAN_APPROVAL` (so one of `decided`, `approved`, `capability_issued`, `dispatching`) |
| `audit_log` events for these transitions | **none** | the statement bypassed `stages.*` and the audit path |
| the rows' `tool_runs` | **left as they were** | 601 `tool_runs` are `running`/`dispatching` while their proposal is `closed`, `abandoned` or `recorded`; some of those predate the cleanup, and which ones cannot be told. The reconciler's own path (`mark_unknown_outcome`) closes proposal and runs together; this statement did not |

**Consequences, stated.**

1. The state of the development database before 2026-10-12 07:43 UTC is not reconstructible. No number that depends on it
   can be re-derived exactly — the 18 s figure for the read function (25k proposals, 22k capabilities) is one.
2. It does not bear on CI or on any test: CI starts from an empty database and the tests that need rows create and close
   their own (`tests/conftest.py` close-out).
3. It was a one-off by hand and is **not a procedure**. The supported way to close such rows is the reconciler's
   `state-only` mode, which writes the audit event and closes the runs with the proposal (and, after item 4, in one
   transaction).
4. **Rule from now on** **[D]**: a manual change to a state table first takes its own "before" snapshot *as a role that
   can see the rows* (a superuser read, or inside the same `NO FORCE` window) and writes it to a file; a count taken by the
   table owner under `FORCE` is not a snapshot.

### 2.1 Test data accumulates (item 2, second half; the ACCEPTANCE 5.23 addendum)

5.23 is about measurement, and every measurement on the development database is a measurement of whatever the tests
left in it. Nothing the suite creates is removed: the tables are under `FORCE ROW LEVEL SECURITY` and the runtime role
has no `DELETE`, so rows only ever accumulate -- apart from the closings of §2 and §2.2 (a state change, not a deletion).

**Measured** (a snapshot of row counts before and after each of two complete runs of the suite, 2,650 tests, 13 min
each, the second 12:08–12:21 UTC and the third 12:24–12:37 UTC on 2026-10-12 `[E]`):

| table | run A | run B | | table | run A | run B |
|---|---:|---:|---|---|---:|---:|
| `action_proposals` | +1,491 | +1,324 | | `scope_registry` | +1,172 | +1,176 |
| `capabilities` | +1,297 | +1,258 | | `policy_layers` | +2,341 | +2,232 |
| `approvals` | +604 | +592 | | `evidence` | +185 | +167 |
| `tool_runs` | +256 | +230 | | `tasks` | +94 | +94 |
| `audit_log` | +13,209 | +13,240 | | `security_graph_nodes` / `_edges` | +43 / +28 | +43 / +28 |
| `engagements` | +1,504 | +1,492 | | **database size** | **+10.2 MB** | **+9.7 MB** |
| **proposals left in a stuck stage** | **+605** | **+632** | | | | |

After run B: `audit_log` 382,312 rows (about 177 MB), `action_proposals` 38,816, `capabilities` 32,980, `policy_layers`
58,107, `engagements` 45,505; the database is 356 MB. (The non-suite work between the two — mutation runs — adds rows
too: about 1,470 proposals between the 11:48 snapshot and the start of run A.)

**What it costs, as observed.**

1. *The reconciler's read page.* `reconciler_stuck_proposals()` returns the oldest 5,000 stuck rows. A full run leaves
   about 600 proposals in a stuck stage (mostly `received` and `approved`, from tests that stop a proposal part-way), so
   about eight runs fill the page and rows beyond it are invisible until the older ones are closed. That is why
   item 6 pages through them instead of assuming the first 5,000 are the whole of it. (An earlier version of this paragraph
   said this was *how* the development database came to hold 18,123 of them; that was an inference, corrected in §2.2.)
2. *Plans that depend on table size.* The first version of that function took 18 s here and 0.15 s with four indexes
   (5.80); the figure is a property of this database's size on that day, and so is every other timing taken on it.
3. *Run time.* A full run took 11 min at about 1,800 tests and 13 min at 2,650; the growth in the database is not
   separable from the growth in tests, and it is not claimed to be.
4. *CI is unaffected*: it starts from an empty database. A number is only comparable if the table sizes it was taken at are
   stated.

**A binding constraint for whoever measures 5.23 (added to the row):** record the row counts of the tables the query
touches at the time of measurement (a snapshot like the one above), and quote a figure only with them; or measure on a
database loaded to a stated size, not on whatever the development database holds that day. **A candidate, not built:** a
documented reset of the development database (drop and re-create through `scripts/init_db.sh`) in place of by-hand
`UPDATE`s; the day one is needed it should be a script that takes its own snapshot first (rule 4 above).


---


### 2.2 Correction (2026-10-13): where the 18,123 came from

§2 and §2.1 said, or implied, three things about the 18,123 rows that were closed by hand. Each is checked now, read-only,
as the superuser **[E]**, and two were wrong.

| claim | verdict | what the database says |
|---|---|---|
| "407 abandoned, by subtraction" | **now observed** | one statement leaves one timestamp: 18,123 rows carry `stage_updated_at = 2026-10-12 07:43:47.361263+00`; `closed / dev_db_cleanup` 17,716 + `abandoned / undecided_past_grace` 407 = 18,123 |
| "that is how the database had come to hold 18,123" (about 600 stuck rows per full run, 8 runs to fill the page) | **an inference, and not the whole story** | see below |
| "the one-off in §2 is the only time anything was cleared" | **false** | `make_room_in_the_page()` (a test helper) closes every stuck row older than an hour in the whole database, in one statement; its footprints are on 2026-10-12: 07:51:24 (565 rows), 08:00:30 (383), 11:43:26 (2,156), 12:34:04 (88), 12:50:45 (527), each with one timestamp and `test_cleanup` |

**What the 18,123 are.** Every one belongs to a test agent: `worker-1` 8,110 rows (8,052 engagements), `fake-worker` 7,786
(2,803), `agent` 1,714, `worker` 465, `a` 34, `w` 10, `crash-child` 4. None belongs to a real agent or a real engagement.
By decision: `ALLOW` 9,572, `HUMAN_APPROVAL` 8,144, none 407. By engagement family: **`ENG-SM-*` 7,650 rows in 2,667 engagements — the Hypothesis state machine
`tests/stateful/test_capability_lifecycle.py`, one engagement per generated example** — and `ENG-TEST-*` 10,473 rows in 9,497
engagements (the ordinary tests). They were created between 2026-10-11 02:00 and 2026-10-12
07:4x UTC — 14,870 on the 11th, 3,253 on the 12th — and the busiest hour alone (the 11th, 03:00) made 6,042.

**What that does and does not show.**

* ~600 stuck proposals per **full** run is measured (605 and 632, §2.1) and so is the arithmetic that eight of them fill the
  reconciler's 5,000-row page. That part stands.
* It does **not** show that the 18,123 were ~29 full runs. A full run takes 11–13 minutes, so at most ~5 an hour and ~3,000
  rows an hour; 6,042 in one hour is about twice that. The bulk therefore came from something that leaves more rows per
  minute than a full run: **repeated runs of narrower test sets** — the mutation campaigns of that day re-run the target test
  files once per mutation, the scheduler and approval tests (`worker-1`, one stuck proposal per test) are among them, and the
  state machine is the other: it makes hundreds of engagements per run (the dry run of 2026-10-13 found 326 of its
  engagements still holding stuck rows).
  That is "consistent with", not established **[N]**; how many runs of what there were is not recoverable, and §2's own
  point stands: the state before 07:43 on the 12th cannot be reconstructed.
* The two cleanups were not the same kind of act. §2 was a manual statement outside any procedure; `make_room_in_the_page()` is
  committed test code that does the same thing (row security off for one statement) every time a test needs a fresh row within
  the first page. §8 replaces the habit with something narrower: each session closes **its own** rows.

## 3. The network-conflict trigger (item 3) — designed, **not built**

### 3.1 The problem, with what is known

A dispatch is refused with `network_range_conflicts_with_another_network` when the allowlist it needs overlaps a network
that already exists `[E: E3, E21-N4]`. The usual blocker is an **idle network of our own**, made for an earlier
allowlist and never removed (5.72). The refusal is recorded as `tool_run.refused` with the code in `reasons` and the
run's `network_allowlist` kept on its `tool_runs` row `[R: dispatch.py:_refused_before_start]`; the development database
holds 37 of them, 2026-10-11 02:59 to 2026-10-12 08:00 `[E]` (all from tests, one allowlist).

`D64_RECONCILER_DESIGN.md` §1.5 (D64-8) made this the *primary* trigger for removing a network, with the 24-hour idle
sweep second. Step 6a could not build it as written: the plan side may read **ids, closed enums and integers, never a
target**, and the sketch returned the requested range. A CIDR is a target-derived value; two integers (the network
address and the prefix length) would be the same value in disguise. So the CIDR may not leave the database function, in
any encoding.

### 3.2 The design: three signals, none of them a range

| signal | where it comes from | what crosses to the plan side |
|---|---|---|
| **name hash** — *which of our networks blocks the refused request* | The database computes it. Our networks are named `cyberorch-allow-<h>`, `h` = first 12 hex of `sha256("\|".join(sorted(allowlist)))` `[R: sandbox.py:network_name]`. For each distinct allowlist in `tool_runs` history (other than the refused one) that **overlaps** the refused allowlist, the function returns `h`. | the 12-hex strings only |
| **last use** — *is it safe to remove now* | The database: `max(tool_runs.created_at)` over runs on that allowlist, and the number of runs on it that are not terminal. Docker adds the other half: any container of any state attached to the network (`containers.list(all=True, filters={"network": name})`). Unlike the idle sweep, it **survives a restart**, because it is not this process's memory. | an epoch-microsecond integer and a count |
| **conflict count** — *how much it matters, and when to stop* | The database: refusals attributed to that blocking hash inside a configured window, and the time of the latest. | two integers |

Experiments, all on this machine, all read-only against the database and with real Docker networks (E22):

| # | what | result `[E]` |
|---|---|---|
| E22-1 | the hash of an allowlist computed in SQL (`sha256`, `string_agg` in `COLLATE "C"` order, `substr(…,1,12)`) against Python's `network_name` | **identical** (`df0ec60922bb` for `{10.0.1.0/29, 10.0.0.0/24}`) |
| E22-2 | the overlap test in SQL (`inet && inet`) | `10.0.0.0/24 && 10.0.0.8/29` = true; `10.0.0.0/24 && 10.0.1.0/29` = false |
| E22-3 | the whole path with real Docker: create network A (`10.231.0.0/24`) → request B (`10.231.0.8/29`) → `NetworkRangeConflict` with the expected code → SQL names the blocking hash from the history of A and B **without returning a range** (`5e48cdc36d55`, equal to A's name suffix) → it matches exactly one Docker network of ours → with a `created` (never started) container attached, `list(all=True, filters={"network": …})` finds it, so the network is **not** idle by our rule → after the container is removed it is idle → removed, verified gone → B is created on the retry | as described; no network left behind |
| E22-4 | a foreign network (no `cyberorch.allowlist` label, not named `cyberorch-allow-*`) overlaps the request | the same `NetworkRangeConflict`. In this experiment no allowlist of ours overlaps (by construction), so the history query returns no hash; independently, the foreign network could never match, because only `cyberorch-allow-<12 hex>` names are looked up. Nothing is removed; the conflict is only reported |
| E22-5 | cost of the "distinct allowlists with last use and live-run count" aggregate on 2,000,000 synthetic `tool_runs` rows (50 distinct allowlists) | 0.76 s without an index, 0.85 s with a btree on `(network_allowlist, created_at)` — an index does not help a full group-by. Hence the gate below |

### 3.3 The function and the rule (for the build)

* **`reconciler_network_conflicts(p_window_s integer)`**, migration 0024, `SECURITY DEFINER`, the same owner, the same
  pinned `search_path`, `REVOKE ALL … FROM PUBLIC`, `EXECUTE` for `reconciler_reader` alone — all of item 1's audit
  applies, and `EXPECTED_DEFINERS` gets a fifth entry. It returns one row per blocking hash:
  `(blocking_hash text, conflicts_n integer, last_conflict_us bigint, last_used_us bigint, live_runs_n integer)`.
  Its aggregate over `tool_runs` runs **only if the window holds at least one conflict refusal** (a gating `EXISTS`), so
  the steady-state cost is the refusal lookup and not the 0.8 s scan.
* **What the function's owner has to read, and the decision it forces (D64-N1).** The refusal fact lives in two places:
  (A) `audit_log` (`event_type = 'tool_run.refused'` and the code in `reasons`) — the definer's owner would need column
  `SELECT` on the most sensitive table in the schema; (B) a **new closed-vocabulary column `tool_runs.refusal_code`**, set
  by `_refused_before_start` in the same statement that already marks the run failed — one line in `dispatch.py`, one
  CHECK, and the owner reads only `tool_runs`. **Recommendation: (B).** The audit table stays unreadable by every
  function; a fact the reconciler depends on becomes state, not a log line it has to parse. (A) needs no change to the
  dispatcher and is the smaller diff; the cost is that a log becomes an input. *This is the one choice I am asking for.*
* **The plan rule** (pure, thresholds from configuration, refuse to start if missing — as everywhere in 6b): a network is
  removed for a conflict iff *all* hold:
  1. its name suffix is a returned `blocking_hash` and it carries our label and prefix (it is ours);
  2. `conflicts_n ≥ 1` inside `NETWORK_CONFLICT_WINDOW_S` and the latest conflict is **after** the network's last use;
  3. `live_runs_n = 0` and `now − last_used_us ≥ NETWORK_CONFLICT_MIN_IDLE_S` (a floor at `B_cap + P + Q`, so no dispatch
     between `ensure_network` and `start` can be reached — the window of E21-N3);
  4. Docker shows **no container of any state** attached (the act half re-checks this on the spot, as for the idle sweep);
  5. fewer than `NETWORK_CONFLICT_DAILY_CAP` removals of this hash by this process in the last 24 h, so two allowlists
     that overlap each other cannot make the reconciler remove and re-create networks for ever. The count is the
     process's memory and starts again at a restart: across restarts the bound is the cap per restart, which an operator
     controls; reading it back from the audit trail would give the definer's owner a grant on `audit_log` (D64-N1).
  At most **one** network per blocking hash per pass. The action is the existing `remove_network` with a new reason
  code `range_conflict` (the §4 table already names it), acted on by the existing `act_docker` path: by full id, fresh
  inspect, verification by a second observation, the event written after verification — and, after item 4, an intent
  event before the call.
* **What is reported and left alone** (new report reasons): `network_conflict_foreign` — conflicts are being recorded and
  no allowlist of ours in history overlaps (a lab's network, or another deployment sharing the daemon); and
  `network_conflict_unresolved` — the daily cap was reached, or the blocker is not idle, and conflicts continue.
* **What it does not do**: it does not retry the refused proposal (D58-6, I7); it removes no network that is not an
  overlap of a recorded refusal; it never removes a foreign network; it does not use `DockerSandbox.remove_network`
  (E14).

### 3.4 Failure and negative cases the build must show (each a test and a mutation)

| case | expected |
|---|---|
| a `created` container is attached to the blocking network | `in_use`; nothing removed (E22-3) |
| a run on the blocking allowlist is `running`/`dispatching` | not idle; reported `network_conflict_unresolved` |
| the conflict is with a foreign network | no hash; `network_conflict_foreign`; nothing removed (E22-4) |
| the blocker's name hash is not in our Docker networks (already gone) | nothing to do |
| the same pair keeps conflicting | one removal per hash per pass, stops at the daily cap, then reports |
| the reconciler restarts | acts on the next pass: last use comes from the database, not from memory |
| the conflict count is 0 in the window | nothing removed by this rule (the idle sweep is separate) |
| the function is called by any role but the reader | refused (item 1's audit pins it) |

### 3.5 Honest limits

* The blocking set is derived from **history in `tool_runs`**. A network of ours whose allowlist never reached a
  `tool_runs` row of this database (another deployment on the same daemon) is invisible to the rule and is treated as
  foreign. That errs on the safe side.
* The rule removes the *recorded blocker*, not "the network that would have to go for this request to succeed" in the
  general sense: two blockers need two passes.
* Cost at scale is measured above (E22-5) and gated; at 20M rows the gated aggregate would still be seconds, once per
  conflict window. If that matters at build time the alternative is a small `sandbox_networks` registry maintained by the
  dispatcher; not needed at the sizes measured here.

---

## 4. The order of change and record (item 4) — **built**

### 4.1 The gap, as 6d left it

For a proposal transition the sequence was: commit the conditional `UPDATE` → read it back in a new transaction → write
the audit record on its own connection. A `kill -9` between the first commit and the third left a state change with
no record. 6d could only bound it ("at most the number of kills", CT3). That is *under-recording*, the direction
`control_plane/audit/logger.py` calls the dangerous one. For a Docker object or a file the same gap was wider and less
visible: the object was gone and nothing said it had been about to be.

### 4.2 Proposal transitions: change and record are one transaction

```
engagement_scope(engagement)  ──  BEGIN
  UPDATE action_proposals ... WHERE stage = :expected AND stage_updated_at = :planned     (compare-and-set)
  [UPDATE tool_runs ...                                              only for mark_unknown_outcome]
  INSERT INTO audit_log (...)   reconciler.proposal_abandoned | _closed | dispatch_unknown_outcome
COMMIT                                                                                   -- both rows, or neither
```

* **One new writer**, `record_audit_in_transaction(conn, ...)` in `control_plane/audit/logger.py`: the same validation, the
  same CRITICAL log line as `record_audit`, but on the caller's connection. `record_audit` still takes no `conn`. The
  reason it takes none — a *refusal* has to be recorded even if the caller then rolls back — is the opposite of this case:
  the record says "this transition committed", so it has to roll back with it. The logger's docstring now says so.
* **Pinned callers.** `record_audit_in_transaction` is imported by `reconciler/emit.py` and nothing else in the product
  (an AST scan of `control_plane`, `tool_gateway`, `agents`, `scripts`); `emit.emit_in_transaction` is called by the service
  alone; `emit.emit` now **refuses** the three proposal events, so a future code path cannot write them on the audit path's
  own connection by accident. The act half still imports no audit module: the service hands it a `record(conn, action)`
  hook, called once, inside the `with engagement_scope` block that contains the `UPDATE` (a structural test pins both).
* **If the insert fails** the transaction rolls back, the result is `failed / audit_failed`, nothing was changed, and the
  service stops with `audit_failed` at the end of the pass as before. A record the *database* refuses (row-level security on
  another engagement's id) takes the same road; a writer that swallowed that error would leave the transaction aborted,
  PostgreSQL would answer `COMMIT` with a rollback without an error, and the act half would believe it had moved the row —
  mutation `D64-P4-c` shows the tests catch it.
* **The read-back stays**, as detection: a transition that is no longer visible afterwards is `failed /
  not_changed_after_update`. It does not retract the record, which says the transition committed — true.
* **What a record now means for these three events: if and only if.** The caveat in the logger's docstring ("an entry can
  outlive the transaction it describes") does not apply to them. Shown with a real `kill -9` of a child process at three
  points (`tests/test_reconciler_order.py`): before the record is written, after it is written and before the commit, and
  after the commit — the first two leave neither row, the third both.

### 4.3 Docker objects and host files: intent, then act, then verify

A kill, a removal or an unlink cannot join a database transaction, and a removed container cannot be un-removed. What can
be done is to make *the intention* durable before the irreversible call:

```
fresh inspect (full id, labels, state, mounts, age)        changed_since_plan / already_gone  →  no event at all
  ↓ still ours, still removable
INSERT audit  reconciler.action_intended {kind, subject_id, reason_code}     -- own connection, COMMITTED
  ↓ if this write fails: no call is made, result failed / audit_failed
the irreversible call (kill / remove / unlink)
  ↓
verification by a second observation (as in 6c)
  ↓ verified                                       ↓ not verified
reconciler.container_removed | _killed | …         reconciler.action_failed
```

* The intent is written **after** the last check that can decline and **immediately before** the call, in the same function
  (a structural test checks that every `CHANGED`/`already_gone` exit comes before `declared(...)` and `declared(...)` before
  the call). A declined action leaves no intent, so *an intent always means "the call was about to be made"*.
* Every attempt that reaches the call ends in exactly one of: a result event, `action_failed`, or — if the process died
  between the call and its verification — **nothing**. The third case was invisible before; it is now an intent with no
  later result or failure for the same kind and subject, and `control_plane/audit/query.py::unresolved_reconciler_intents`
  lists it. Shown with a real container: a child process removes it for real and is `SIGKILL`ed the instant the removal
  returns; the container is gone, the trail holds exactly one event (the intent), and the query returns it with kind,
  subject and reason. **Not self-healing and not made to look so**: the next pass plans from what exists (an object still
  there gets a new intent; one that is gone needs nothing), and a person reads the list.
* **Files: one result event per file** (`reconciler.files_removed {kind, count: 1}`, the file name as the row's `subject_id`)
  instead of one count per pass, so an unlink intent has a result to be paired with. A random temporary file name is an id
  under the payload whitelist; it is not a path.
* **Bounded volume.** The plan re-plans a failing action every pass; with an intent per attempt that would be an event per
  minute per object for ever. So after a *failed* attempt the same `(kind, subject)` is not attempted again by this
  process for `RECONCILER_RETRY_AFTER_FAILURE_S` (new, required, no default; `.env.example` says 1,800 s `[N]`). A pass that
  holds an action back says so (`PassReport.held_back`). The failure is still reported once per object and reason. *Revised at completion 3 (§9.1): any failed action is held back, not only an irreversible one.*
* **Not done:** a two-phase protocol between Docker and PostgreSQL. There is none to be had; the intent record is the
  honest alternative, and the flag that would let any of this run is still off.

### 4.4 Tests and mutations

`tests/test_reconciler_order.py` (31 tests), new cases in `test_reconciler_emit.py`, `test_reconciler_service.py` and
`test_reconciler_structure.py`; 13 mutations `D64-P4-a`…`m` (the record after the commit in a second transaction; a failing
record ignored; the writer returning instead of raising; a kill without its intent; the intent before the check that can
decline; an unwritable intent ignored; a file unlinked without its intent; the unresolved-intents query accepting any later
event; the hold-back off; a proposal event written twice; `emit` taking a proposal event again; `emit_in_transaction` taking
any event; another module importing the in-transaction writer), all valid.

---

## 5. The two "unknown outcome" events, and where the older one's text comes from (item 5) — **built**

The step-6 report said the older event, `dispatch.unknown_outcome`, "has booleans and free text" and that this is why the
reconciler writes its own, `reconciler.dispatch_unknown_outcome`. That was imprecise, and the sentence deserved checking.

### 5.1 Where the text comes from

`control_plane/orchestrator/dispatch.py:reconcile_stale_dispatches` writes, for a proposal it takes over:

```
event_type  dispatch.unknown_outcome        reasons  ("interrupted_before_result",)
payload     {"requires_human_review": True,
             "note": "not retried: the action may already have executed"}
```

* `note` is **one string literal in the source**. Nothing is interpolated into it, and nothing from outside can reach it:
  two proposals with nothing in common (a different target, a run with a 400-character note, a different error) get
  byte-identical payloads — a test runs the sweeper on both and compares them, and a second test reads the call's syntax
  tree and requires every payload value to be a constant.
* So the older event is **not free text in the sense that matters** (text taken from an exception, a document or a
  person). What it is: a boolean and a sentence, neither of which is an id, a closed code or a count — which is all the
  reconciler's whitelist admits. A test shows the older payload is refused by `emit.validate`. That, and nothing about
  the text's origin, is the reason the reconciler's event has its own name.
* The events that **do** carry what an exception said are different ones, and a census test names them:
  `tool_run.unknown_outcome` (the sandbox itself was unreachable, `{"error": str(exc)}`) and `tool_run.refused`
  (`{"error": str(exc)}`, the sandbox's message, which names the requested range). Those are run-level events, not the
  proposal-level pair, and they are not touched here.

### 5.2 The readers

Searching the product code and the scripts for a reader of either name finds exactly one place, `audit/query.py`, and it
already mapped both to the `execution` stage of a proposal's chain. There was no reader that asked for one name only; the
risk the step-6 report named was a future one. What is now in place:

* `UNKNOWN_OUTCOME_EVENTS` — the pair, in one tuple — and `unknown_outcome_events(conn, proposal_id=None)`, which asks
  for both, oldest first. (`tool_run.unknown_outcome` is deliberately not in it: a different fact about a different
  subject.)
* A structural test: no module of `control_plane`, `tool_gateway`, `agents` or `scripts` names either event by its string
  literal except the two writers and `audit/query.py`. A reader that hard-coded one name would fail it.
* Consumer tests, for **each** name: a proposal ended unknown by the older writer (the sweeper) and by the newer (the
  reconciler's act half, with its in-transaction record) appears in `reconstruct_decision` in the execution stage with
  the right event, and in `unknown_outcome_events`; both together come back oldest first; every proposal event the
  reconciler writes is mapped to a stage (none falls into `other`).

### 5.3 Mutations

`D64-P5-a`…`d`, all valid: the query asking for the older name only; the reconciler's event unmapped; the older
sentence built from the proposal's id; another module hard-coding the older name.

---

## 6. More than 5,000 stuck proposals (item 6) — **built**

### 6.1 The problem, reproduced (E23)

`reconciler_stuck_proposals()` returns the **oldest** 5,000 stuck rows (5.80). The reconciler leaves some stuck rows alone
on purpose: an `approved` proposal with no approval row is *reported* (`approval_missing`), not closed. So if the oldest
5,000 are all of that kind, a proposal behind them that does need closing is never seen, pass after pass. The step-6 report
said only that a full page "reports `result_truncated`"; it did not say that the truncation could hide work for ever.

`tests/test_reconciler_paging.py::test_e23_…` builds exactly that on the real database: 5,100 `approved` proposals with no
approval, the oldest rows in the table, and one `decided` proposal behind them. Read as before (one page) the result is full,
every row in it is one of the 5,100, and the `decided` proposal is **absent** — the starvation. Read with two pages it is
found, nothing is repeated, and the plan asks for `close / abandoned_after_decision` for it and for none of the 5,100.
(The development database makes this a live risk, not a thought experiment: a full run of the suite leaves about 600
proposals in a stuck stage, §2.1.)

### 6.2 What was built

* **Migration 0024: `reconciler_stuck_proposals_after(p_after_us bigint, p_after_id text)`** — the next page: the same
  rows, columns, order and limit, strictly after a keyset cursor (the `stage_updated_us` and `proposal_id` of the last row
  of the page before). A keyset, not an `OFFSET`: the partial index on `(stage_updated_at, proposal_id)` serves it as a range
  scan, and rows that leave the stuck set between two pages cannot make the next one skip. `SECURITY DEFINER`, the same
  owner, `search_path`, stage filter, `REVOKE ALL FROM PUBLIC`, `EXECUTE` for the reader alone — item 1's audit covers it and
  `EXPECTED_DEFINERS` has a fifth entry. The zero-argument function is untouched: it is the first page.
* **A bug found by calling it:** with the cursor `(5, NULL)` the function returned **every** stuck row. SQL compares rows
  left to right, so `ROW(a, b) > ROW(x, NULL)` is true whenever `a > x` and the missing half is never looked at. A cursor
  with a `NULL` half now returns nothing, stated in the `WHERE` and tested for each of the three shapes (mutation `D64-P6-a`).
* **`observe.read_stuck(conn, max_pages)`** reads page after page. It stops at the first page that is not full — or after
  `max_pages`, and then says **truncated**. A page that does not move past the cursor is an `ObservationError`, not a loop. A
  proposal whose timestamp moved while the pages were being read can appear twice (it moved later); it counts once and the
  later reading wins — the act half's compare-and-set is on whatever it saw.
* **A bound on a pass.** `max_pages` (20 → 100,000 rows) and `max_actions_per_pass` (500): a backlog after an outage is
  worked off in passes of bounded size that can be stopped between, not in one long one; what is left is planned again by
  the next pass (level-triggered, as everywhere). `PassReport` says how many actions it did not carry out (`limited`) and
  whether its read was truncated; a backlog is also logged at WARNING by count (no ids).
* **A wait that backs off.** After a pass that was truncated or limited **and got nothing done**, the wait before the next
  doubles, up to `backoff_max_s` (900 s), never below the interval; any pass that did something, or had no backlog, resets
  it. A pass that is making progress never slows down; a pass that sees a backlog it cannot touch (the 5,100 above) stops
  re-reading it every minute. The three new settings are required and have no default, like every other
  (`RECONCILER_MAX_PAGES`, `RECONCILER_MAX_ACTIONS_PER_PASS`, `RECONCILER_BACKOFF_MAX_S`).

### 6.3 Tests and mutations

15 tests in `test_reconciler_paging.py`, 10 in `test_reconciler_reader.py` (the new function's columns, filter, order, limit,
strictness at the cursor, ties on the timestamp, a missing half, an injection-shaped cursor, the caller's GUC, who may call
it), structure and config tests; 11 mutations `D64-P6-a`…`k`, all valid (a missing cursor half accepted; the cursor row
repeated; no stage filter on the new page; a non-moving page accepted; duplicates counted; truncation never reported; one page
whatever `max_pages` says; the action cap ignored; no ceiling on the back-off; a busy pass slowed; the configured page count
not passed on).

### 6.4 Not done

* A page is read with plain `READ COMMITTED`; a snapshot across pages would remove the duplicates rather than tolerate
  them, at the price of holding a transaction open across Docker calls. Left as it is.
* Truncation is a report in the plan and a log line, not an audit event of its own: the audit vocabulary is closed and a
  persistent backlog is already visible as `report:result_truncated` in `reconciler.started` and as the pass's cadence.

---

## 7. Four open questions, answered (item 7)

The four were left open by the step-6 reports: *does the Docker deny-list cover a verb nobody listed?*, *what has the
reconciler been shown **not** to do, all at once?*, *is "only `act.py` reaches `stages.abandon`" a fact or a spelling?*, and
*which of the race tests the design promised (RT1–RT9) exist?* (The original wording of the four was not in the files I could
read; these are the four the item's own title names, and I say so rather than pretend I had the text.)

### 7.1 The Docker verb allow-list **[R][E]**

The deny-list tests of step 6 name verbs that must not appear (`exec_run`, `run`, `create`, `stop`, `prune` …). That cannot
notice a verb nobody thought of and is walked round by an alias. `test_every_method_called_on_a_docker_handle_is_on_the_modules_allow_list`
starts from the other end: every method called on anything that came from the Docker client — directly, or through any
variable assigned from it, a loop over it or a comprehension — must be on the list for its module, and each module must use
**all** it is allowed (no padding):

| module | verbs it may call on Docker, in full |
|---|---|
| `observe` | `containers.list`, `networks.list`, `reload`, `attrs.get`, `name.startswith` |
| `act_docker` | `containers.get`, `containers.list`, `networks.get`, `reload`, `kill`, `remove`, `attrs.get`, `name.startswith` |

The walker has a positive control (it must flag an aliased `exec_run`, a `prune` on a loop variable, a `stop` inside a
comprehension). Mutations: `D64-P7-a` (a `container.logs()` added to `observe`) and `D64-P7-b` (`alias = container;
alias.pause()` in `act_docker`) are both caught by that test and by nothing else. **What it does not see, stated:** a handle
passed to a function whose parameter has another name, a handle stored in a dict and called through the dict, and
`getattr(handle, name)` with a computed name. None of these exists; a person adding one would have to do it on purpose, and
the structure tests also forbid the modules from importing anything that would hand them such a helper.

### 7.2 Negative experiments, all at once **[E]**

Every act test shows one refusal. `tests/test_reconciler_negative.py::test_e24_…` puts them on a real Docker daemon together,
with the deletion flag on (tests only) and the plan made from the **real observation** of the host:

| object | what it is | what happened |
|---|---|---|
| victim | running, no labels at all | not in the observation, not touched |
| lab script | running, only `cyberorch.owner` | not in the observation, not touched |
| forged live | running, the labels of a run the database says is **live** | in the observation, no action (the run is live) |
| forged unknown | exited, labels naming a run the database has never heard of, older than the retention window | **removed**, verified gone, one `action_intended` event — the forger's own container, the worst a forgery can do (D64 §2.4) |
| lookalike network | the name prefix, no label | not selected |

Afterwards: one container gone, every other object as it was. Two corrections the experiment made to what I expected:
(a) I had written that the lab script's container would be *reported* (`no_run_id_label`); it is not even *seen* — the
observation lists containers by run label or proxy label — which is the stronger result; (b) my first version moved the
host clock three days forward to make the forged container old, and the plan then **killed the live run** as overdue —
correct for that clock, wrong for the test; the fix was a one-second retention window, not a clock jump. Mutation `D64-P7-i`
(the observation also lists owner-labelled containers) turns the test red. The single-refusal negatives are in
`test_reconciler_act.py` (changed labels, short id/name/upper-case handle, a container that took over a removed one's name, a
running container not removed, a network with a `created` container kept, a symlink left with its target).

### 7.3 `ABANDON_CALLERS` is now a fact about routes, not about a spelling **[R][E]**

The earlier scan looked for the text `stages.abandon(` — an alias or `from … import abandon as a` walked round it. The check now
resolves imports: the module under its name or an alias, the function imported by name or under another name, `import *`,
`getattr(stages, "abandon")`, and naming it without calling it. It has a positive-control test (eight routes flagged, four
namesakes not). Separately, `stages.advance` (and so `take`) **raises `ValueError`** if `new` is `abandoned`, whatever the
caller computed — the scan reads spellings, this refuses at run time (`D64-P7-c` removes the refusal; `D64-P7-d` adds an aliased
import to `dispatch.py` and is caught by the scan). The set is still `{control_plane/reconciler/act.py}` and the test fails both
when a module is added and when `act.py` stops being a caller.

### 7.4 Concurrency: RT1–RT9 **[E]**

| # | race | where | status |
|---|---|---|---|
| RT1 | reconciler marks a dispatch unknown while it runs, result late | `test_reconciler_concurrency.py` | built in step 6d |
| RT2 | result first, planned action matches no row | same | built in step 6d |
| **RT3** | `capability_issued`, lease lapsed: dispatch takes the stage / reconciler first / genuinely concurrent / late heartbeat | same | **built now** (4 tests) |
| **RT4** | `received → abandoned` while the caller is in its decision stage | `test_stage_vocabulary.py::test_a7_*` (both orders and a real row-lock wait) | built at step 5a; cited, not duplicated |
| RT5 | killed engagement, either order | same | built in step 6d |
| RT6 | two passes, one action | same | built in step 6d |
| RT7 | pause between plan and act | — | **moot, argued**: nothing the plan decides depends on pause or on the kill switch being off; the compare-and-set on stage and timestamp is the only guard that matters, and RT2/RT3/RT5 exercise it |
| **RT8** | reconciler and control plane remove/kill the same container | same | **built now; found a bug** (below) |
| **RT9** | network removed between `ensure_network` and `containers.create` | same | **built now** |

* **RT3.** The design asked about a heartbeat renewing the lease between plan and act. It cannot: `renew_capability` treats a
  heartbeat after the lease lapsed as evidence of a fault, revokes (`lease_expired`) and extends nothing (tested). So the real
  race is the dispatch taking the stage: dispatch first → the reconciler moves 0 rows (`lost_race`), no event; reconciler first →
  the dispatch's claim fails (`not_claimable`), no run; and with the dispatch's transaction **open**, the reconciler waits on the
  row lock and then loses. `D64-P7-e` (the close compares neither stage nor timestamp) turns the first and third red.
* **RT8 found a real defect.** Forty rounds of `remove_proxy` against a control-plane `remove(force=True)` started on a barrier:
  **26 ended `failed / daemon_error`** — the loser of a Docker removal gets a 409 ("removal already in progress"), `reload()`
  then raises `NotFound`, and `NotFound` is an `APIError`, so it fell into the outer handler. A failure would have produced an
  `action_failed` event and a hold-back for something that was simply gone. Fixed in `act_docker`: after a refused remove or
  kill, a `reload()` that finds nothing is `gone`; a 409 on a removal waits (the verification wait) and, if the container is
  gone, is `gone` — never `done`, because it was not ours. After the fix: 0 failures in 40 rounds (28 `gone`, 12 `done`), and
  the test repeats 12 rounds for `remove_proxy` and for `kill_container`. `D64-P7-f` and `D64-P7-g` undo the two halves; the
  race is probabilistic, so each half also has a scripted, deterministic test (a fake container whose removal Docker refuses with
  a 409 and which is then gone / is still there / vanishes within the wait): my first `D64-P7-f` was **not** caught by the real
  race in 12 rounds, which is why.
* **RT9.** The reconciler sweeps the (empty, ours) network between `ensure_network` and `containers.create`. What Docker does is
  not what the design guessed: `create` against a network that is gone **succeeds**, and the refusal comes at `start` ("failed to
  set up container networking: network … not found"). The sandbox types that from Docker's own record of the container (still
  `created`, no PID, `StartedAt` zero) as **`ContainerStartRefused`, a `NotStarted`** — nothing of the run executed, so a
  retry is safe — and the teardown removes the container. The retry re-creates the network and succeeds. (I had first
  assumed the error came from `create` and `DaemonUnreachable`; the experiment said otherwise, and the first mutation I wrote
  for it, aimed at `create`, was not caught — which is how I found out.) `D64-P7-h` stops `_start_container` typing the
  refusal. The design's own mutation for RT9 ("remove a network that still has a `created` container") is
  `test_real_a_network_with_a_container_of_any_state_is_kept`'s, where it already was.

### 7.5 Numbers

New tests: 13 concurrency (RT3 ×4, RT8 ×8 — two real-Docker orders, two parametrised races, four scripted — and RT9 ×1), 1 whole-host negative, the verb allow-list (2),
the `abandon` walker (2) and the run-time refusal (2). Mutations `D64-P7-a`…`i`: nine.


---

## 8. Completion round 2 (the flags are still off)

### 8.0 What round 1 (items 1–5) found, in a few lines

The role audit found one membership (`migration_owner` in `reconciler_fn_owner`, `INHERIT FALSE`) and four definer functions,
and now pins them as a whole (5.84). The dev-DB cleanup had **no usable before/after snapshot** (the table owner's counts under
`FORCE` are blind) and test data accumulates at ~600 stuck rows per full run (5.23; corrected below). A proposal transition and its
audit record are now one transaction, and an irreversible Docker or file action is announced by an intent record before the call
(5.86). The "free text" in the legacy unknown-outcome event is one string literal and the two event names have one reader (5.87).
More than 5,000 stuck rows are paged, bounded per pass and backed off (5.88) -- the paging bug being a cursor with a NULL half
that returned every row.

### 8.1 D64-N1 decided and built (option B) -- the plan side of the network-conflict trigger

`tool_runs.refusal_code` (migration 0025): the refusal is **state**, written in the statement that fails the run and the
transaction of the stage take; the audit trail stays unreadable by every function. Two CHECKs (vocabulary, and "a code means the
run never ran"), a closed list kept equal in the migration, `dispatch` and the sandbox by a test. `reconciler_network_conflicts`
returns **integers only**; the blocking network is named by the number its name suffix spells. The plan removes a blocking network
only when five conditions hold and reports the rest; the cap on removals is the service's own memory. Details, tests and the four
bugs the tests found: ACCEPTANCE 5.90. Not built, said before: the flag; and the act half has no conflict-specific end-to-end run
because nothing may delete yet.

### 8.2 The 18,123, corrected; and the session cleans up after itself

§2.2 above. `tests/residue.py` (the 5.71 check) now closes the session's own stuck proposals and in-flight runs at the end and
fails on stuck rows in an engagement it did not register. Rows are closed, never deleted.

### 8.3 What the reconciler does not see

An owner-only labelled container is not observed (5.91): by design, with the reason.

### 8.4 Someone else moved first -- forty times each

Proxy, file, network: removed by the other party first, then by the reconciler; and both at once. Real rounds were clean; scripted
branches found a file `FileNotFoundError` and a network refusal that were both classified as failures. Fixed; both pinned.

### 8.5 The first dry run

`D64_DRY_RUN_2026-10-13.md`: 1,403 planned proposal transitions, 12 reports, no Docker or file action; all of the data is the
test suite's, because that is the only data this container has. It also showed the command line hiding 903 of the 1,403 actions;
fixed.

### 8.6 Next, and not started

The classification flag and phase 1 wait for a person to read the plan.
