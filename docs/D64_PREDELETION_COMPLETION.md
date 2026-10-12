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
| 7 | four open questions answered (verb allow-list, negative experiments, `ABANDON_CALLERS`, concurrency) | §7 here, ACCEPTANCE 5.89 |

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
| abandoned by the same statement | **407** | by subtraction (18,123 − 17,716), **not observed**: 1,677 rows now carry `abandoned / undecided_past_grace`, but that is also the reconciler's own reason code and the reconciler tests produce it |
| original stage of each row | **unrecoverable** | the `UPDATE` overwrote `pipeline_stage` and `stage_updated_at` (set to `now()`); nothing else recorded them |
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
has no `DELETE`, so rows only ever accumulate, and the one-off in §2 above is the only time anything was cleared.

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
   about eight runs fill the page and rows beyond it are invisible until the older ones are closed. That is how the
   development database had come to hold 18,123 of them (§2) — and why item 6 pages through them instead of assuming the
   first 5,000 are the whole of it.
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
  holds an action back says so (`PassReport.held_back`). The failure is still reported once per object and reason.
* **Not done:** a two-phase protocol between Docker and PostgreSQL. There is none to be had; the intent record is the
  honest alternative, and the flag that would let any of this run is still off.

### 4.4 Tests and mutations

`tests/test_reconciler_order.py` (31 tests), new cases in `test_reconciler_emit.py`, `test_reconciler_service.py` and
`test_reconciler_structure.py`; 13 mutations `D64-P4-a`…`m` (the record after the commit in a second transaction; a failing
record ignored; the writer returning instead of raising; a kill without its intent; the intent before the check that can
decline; an unwritable intent ignored; a file unlinked without its intent; the unresolved-intents query accepting any later
event; the hold-back off; a proposal event written twice; `emit` taking a proposal event again; `emit_in_transaction` taking
any event; another module importing the in-transaction writer), all valid.
