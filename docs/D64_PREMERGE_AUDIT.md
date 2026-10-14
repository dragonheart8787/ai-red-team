# D64 — pre-merge audit (2026-10-14)

Requested before merging this branch into `main`, with the scope to be taken **from git, not from step or row numbers**, and six
things to check: where the deadline helper's binary comes from (README), whether `scripts/init_db.sh` and CI provision the new roles
and migrations, whether a default deployment has any switch on, whether the ACCEPTANCE numbers and statuses agree with each
other, the stage and vocabulary tests, and the scale numbers. Each is *checked*, below, and what was found is in §3.

**Headline.** One missing instruction (the helper binary is not in git and the README said nothing about it), one stale status
(5.72), and three properties that were true but pinned by nothing a reader could run (the ACCEPTANCE numbering, what ships carrying
no switch, and — found by the change that came first — a mutation that had been valid only because the development database was
dirty). All fixed in this audit's own commits, with tests; nothing else was found wrong. The audit's verdict and the merge are at
the end (§6).

## 1. The real range, from git

`origin/main` is `3bb5b15` ("Merge D63: closeouts 1-4"). The merge base of this branch with it is **`3bb5b15`**, the same commit:
`main` has not moved since the branch left it, so the merge is of exactly the commits listed below (`3bb5b15..`, the tip being the repair that follows the audit) and a fast-forward
is possible; it will be made with `--no-ff` so that the range stays one named thing.

**40 commits, 596 files, +164,091 / -98 lines** (as of the audit's own commit, before the one that repairs the skip CI found in it), of which the vendored `libc` crate of the deadline
helper (`tool_gateway/deadline/vendor/`) is 452 files and +135,782 lines. Without it: **144 files, +28,309 lines**
(`git diff --numstat origin/main...HEAD`):

| area | files | added | removed |
|---|---:|---:|---:|
| tool_gateway/deadline/vendor (the vendored libc) | 452 | +135,782 | -0 |
| tests | 44 | +13,958 | -45 |
| docs | 11 | +4,310 | -6 |
| scripts | 8 | +3,721 | -3 |
| control_plane | 25 | +3,606 | -42 |
| db | 7 | +1,042 | -0 |
| docs (artifacts of the drills) | 30 | +734 | -0 |
| tool_gateway | 14 | +702 | -1 |
| .env.example | 1 | +87 | -0 |
| policy_tests | 2 | +64 | -1 |
| .github | 1 | +51 | -0 |
| README.md | 1 | +34 | -0 |

By what the subjects say (not by their numbers):

| stage | commits | first..last |
|---|---:|---|
| D64 design (checkpoint and revisions 2-3) | 3 | `c2eb800`..`1616fe0` |
| D64 implementation steps 1-6d, with the follow-ups | 9 | `01cbc9b`..`ae258ae` |
| D65-A, the deadline helper in every tool container | 5 | `5a0262c`..`50708cf` |
| CI image guard | 1 | `c19e2a0`..`c19e2a0` |
| Pre-deletion completion, items 1-7 | 7 | `ca7c58e`..`bf91c90` |
| Completion round 2 | 4 | `e5bfc36`..`36bd917` |
| Completion 3 | 5 | `7ad0068`..`b89c180` |
| Completion 4 (this round) | 6 | `e3b6497`..`404037b` |

So the branch is **the whole of D64 (the reconciler, from its design checkpoint to the completion rounds) with D65-A (the deadline helper
in every tool container) and the two changes that came with them (the CI image guard, the late-result transition)**. It is not "the
last few steps": reading the range off a step number would have missed the helper and the migrations 0022–0026, which are in it.

## 2. The six checks

### 2.1 Where the helper's binary comes from (README)

`tool_gateway/deadline/bin/` is git-ignored (`tool_gateway/deadline/.gitignore`: `bin/`), so **a fresh checkout has no helper binary**,
and the sandbox refuses every run without one (`deadline_helper_missing`, `tests/test_deadline_sandbox.py`). The repository's README
did not say so; only `tool_gateway/deadline/README.md` and the CI workflow knew. **Added to the README** (the section after *Setup*): it is
built, not committed; `./tool_gateway/deadline/build.sh --check` (offline, pinned toolchain verified by sha256, compared with the committed
`SHA256SUMS`); which tests need it; that CI builds it in its own job and passes it on as an artifact. CI already did this (job
`deadline-helper`, then `actions/download-artifact`, then `chmod`): read from `.github/workflows/test.yml` and seen green on the previous tip.

### 2.2 `init_db.sh` and CI provision the new roles and migrations

* `db/roles.sql` creates `reconciler_reader` (LOGIN) and `reconciler_fn_owner` (NOLOGIN) and makes `migration_owner` a member of the second
  `WITH INHERIT FALSE, SET TRUE`; `scripts/init_db.sh` generates `RECONCILER_READER_PASSWORD`, passes it to `roles.sql`, writes
  `RECONCILER_READER_DATABASE_URL` to `.env`, and ends with `alembic upgrade head`. CI runs this same script (the test job's
  "Create the database" step), not an equivalent.
* **Run, not read [E]:** the script was run on an *empty* database (`DB_NAME=cyberorch_audit`, from a copy of the working tree, the role
  passwords of the development cluster passed through so that they were not reset): `alembic current` = **0026 (head)**, the four
  `reconciler_*` functions exist, `reconciler_fn_owner` can read `action_proposals.decision` and the reader's call returns `has_decision`;
  232 tests of the database, reader, observe, paging, evidence, round-trip, authority and negative files passed against it. The database
  was dropped afterwards.
* The migration chain is linear, 0001–0026, one head; `tests/test_migrations_roundtrip.py` takes it down to 0015 and to base and back and
  compares schema snapshots at every step it covers; 0026 has its own round trip (5.98).
* Each commit of the branch that adds a migration was also run against a database built by the script at *its* head (0025 for the two
  before 0026): see §5.

### 2.3 A default deployment has no switch on

* In the code: `Settings.enabled` is empty unless `act.settings_for` is given words, and the one caller is the command line's `--enable`,
  which needs a person at a terminal (5.92); no environment variable, configuration key or default reads as one (tests in
  `tests/test_reconciler_flags.py`, 77).
* In what ships: **nothing in the repository starts the reconciler at all** — not the CI workflow, the Makefile, `.env.example`, the shell
  scripts, nor any service definition (there is none). A deployment is therefore whatever a person types; the default of that is
  `--mode state-only` (proposals only) or `--mode dry-run`. This was true but was not a property any test held; it is now
  (`test_nothing_that_ships_starts_the_reconciler_with_a_switch`, and a mutation that adds `--enable kill` to the Makefile turns it red).
* `network` and `file` cannot be turned on in this version whatever is typed (exit 7 before the configuration is read).

### 2.4 ACCEPTANCE numbers and statuses

`tests/test_acceptance_numbering.py` (new, 47 tests) states what a program can know about the document: the numbered table runs
**5.20 to 5.100 without a gap or a repeat, in order**; every row from 5.58 on starts its status with Closed, Open, Designed or Stated; every
`ACCEPTANCE 5.N` in a tracked file of the repository (code, tests, documents) names an item the document has; every "Revised by 5.N" names a
row that exists and comes after the revised one. Six mutations (a number used twice, a row lost, a status in no known word, a pointer to a
row that does not exist, a revision by a row that does not exist, a switch in the Makefile) turn it red.

What it found when first run was only that two rows (5.96, 5.97) were pointed at by code before the document had them — the order of the
work, not an error. What reading found: **5.72** ("Sandbox networks are never removed in production") still said *Open, Class B — an input to
D58-9 (the reconciler)*. D58-9 exists now, its two network removals are built and tested, and they cannot be turned on; the status
line now says exactly that. **5.29** appears twice in the document, once in the closed table and once in the "still open" list, and the
second says in its own text that it is kept as the record of the decision it needed; left as it is. The early rows (5.20–5.57) use other
status words ("Decided", "Recorded decision"); the status check starts at 5.58 and says so.

The table now has **83 numbered rows** in the document (all tables).

### 2.5 The stage and vocabulary tests

`tests/test_stage_vocabulary.py` (the stage names equal the database CHECKs, every module that names a stage is registered with its reason, the
transitions equal `vocab.PROPOSAL_TRANSITIONS`) and the reconciler's structure and emit tests (every reason code of an action is in the audit
validators and the intent list; the closed list of events equals the design's; the package is exactly the files the steps made; the Docker
verbs each module may call; the places that may unlink or remove) passed in the full run (§2.6) **and** at each commit. Three of them changed
with this branch's last commits and are the evidence that they bite: the structure test caught the evidence archive's file writes
(`write`, `link`, `unlink`) and its `container.logs` call, which had to be allowed by name and pinned (`unlink` only of `temporary`, `link` only
`temporary -> final`); the emit test caught the new event; the stage-vocabulary registry caught the new drill scripts naming a stage.

### 2.6 Scale

| what | number | how |
|---|---:|---|
| tests passed in the last full run on the tip | **3,230** passed, 0 skipped, 0:25:44 | `pytest -q -rs` on 404037b plus the files of this audit's own commits (README, the numbering test, the mutation catalogue, the workflow's checkout, the documents); CI fails a run with any skip, and this run has 0 |
| OPA tests | 58/58 | `opa test control_plane/policy/rego policy_tests -v` |
| test files | 122 | `git ls-files` |
| stuck rows closed at the end of the tests that made them / left for the session end | 615 in 16 files / **none** | the session report of the same run (5.96) |
| migrations | 26 (`0001`–`0026`), one head | `db/migrations/versions` |
| reconciler package / its tests | 2977 / 8743 lines | `wc -l` of the tracked files |
| D64 mutation catalogue | 279 (and 54 in D62/D63, 36 in D65-A) | `--list` |
| D64 mutations run on this tip | **279 valid, 0 not** | `scripts/mutations_d64.py` in full, in four runs (the first 28; the other 250; the 10 repaired entries again; the one added after the first CI run), each mutation judged by the rule of 5.70 -- red on an assertion, none broken, every named target among the failures |
| ACCEPTANCE rows | 83 | rows of the form `| **5.N** |` |

Every number above that a document of this branch also states was compared with the tracked text; the older reports (D51, D60, D62) state
the counts of their own day and are records of it, not claims about this tip.

## 3. What was found, and what was done

| # | finding | action |
|---|---|---|
| 1 | the README did not say the helper binary is not in git, how it is built, or what fails without it | README section; §2.1 |
| 2 | 5.72's status was stale | status line; §2.4 |
| 3 | the ACCEPTANCE numbering, statuses and pointers were held by nothing | `tests/test_acceptance_numbering.py` + 5 mutations |
| 4 | "a default deployment has no switch" was true but only the flags' own tests held it | `test_nothing_that_ships_starts_the_reconciler_with_a_switch` + 1 mutation |
| 5 | a mutation (`D64-P6-a`) had been valid only because the development database held leftover stuck rows; with none it passed on a broken function | the test makes its own row; the whole catalogue was run again (§2.6) |
| 6 | the full sweep found **10 catalogue entries that no longer applied** -- the text they change had moved (7 since earlier rounds: `D64-6b-zb`, `6c-u`, `6d-s`, `P4-i`, `P6-k`, `C2-zc` by a changed line or a renamed test, `6d-g` by a test that pre-deletion item 4 had removed; 3 by this round's own edits: `6c-x`, `6c-za`, `P4-e`) -- so nothing was being tested by them | each repaired against the present text or test and run again: all valid. The entries had been valid when written; no sweep had been run after the edits that moved them |
| 7 | the mutation runner, interrupted, leaves a scratch schema and the database's `TEMPORARY` privilege granted when the test it killed was a migration round trip; the next full run restored the privilege and the schema had to be dropped by hand | **not fixed**; stated: do not interrupt a sweep that includes the round-trip mutations |
| 8 | **CI's first run of the audit's commit failed its "nothing was skipped" step**: the new test that compares the residue ceiling with `origin/main`'s skipped where `main` has no ceiling yet (and where the checkout is shallow) -- a skip I had counted as acceptable and the job does not | the test never skips: it fails where `origin/main` is missing, holds where main has no ceiling, its comparison is a function with its own tests and a mutation (`D64-C4-aq`); the test job now checks out the whole history; the full suite was run again (§2.6) |
| 9 | a mistake of the commit splitting (the first version of the residue commit carried the wrong slice of the mutation catalogue) | found by reading the diffstat of the next commit; the four commits were remade before anything was pushed |

## 4. Not checked, and why

* **No production database and no second host exist here.** Everything above ran on this machine's PostgreSQL and Docker.
* **The final CI run** is checked after the push and before the merge (§5).
* The live drills (5.95, 5.99) are not part of CI and were run by hand on this machine.
* `network` and `file` have act-half code and tests and no door; they were not drilled and cannot be.

## 5. Git and CI

Commits since the tip the previous round pushed (`b89c180`, CI green: jobs `deadline-helper` and `test`), each built from the working tree
with only its own hunks and checked on its own before the next (`git worktree` at that commit; ruff; the files it touches and the
reconciler, database, residue and stage tests around them; the two commits before 0026 against a database that `init_db.sh` built at 0025):

* `e3b6497` D64 completion 4 (item 3, ACCEPTANCE 5.96): each test closes what it made when it ends; the sources of the per-file counts found and fixed in one fixture; the allowance is empty and can only go down
* `f8e9c5e` D64 completion 4 (item 2, ACCEPTANCE 5.97): a container whose run's outcome is unknown is removed only after its inspect output and logs are in files and their SHA-256 are in the audit trail; the retention binds it; --enable container needs --evidence-dir
* `01dddaa` D64 completion 4 (item 4, ACCEPTANCE 5.98): migration 0026 -- the stuck-proposals functions say whether a proposal has a decision; the plan reports a received one that has it as unexpected_state; the periodic summary counts what was reported
* `2c62c66` D64 completion 4 (item 1, ACCEPTANCE 5.99): the reconciler beside live control planes -- passes through [B, B + margin + 10 s] leave a healthy or late owner's container, the owner kills first, a frozen owner's container is killed at the first pass after the bound; the corpse's evidence on a real daemon
* `968e732` D64 completion 4 (items 1-5): the report (section 10 of the completion document) and the correction of the first dry-run document's guess about the ENG-SM- rows, pointing at section 9.1
* `404037b` D64 completion 4 (item 6, ACCEPTANCE 5.100): the pre-merge audit -- the range from git, the six checks, what they found (the helper binary's origin, a stale status, the ACCEPTANCE numbering and what ships as tests, ten mutation entries that no longer applied), the full sweep again

The last two commits are this audit's: the audit, and the repair of the skip that CI found in it (finding 8). Before the push of each: the full suite (§2.6), ruff and OPA on the tip. After it: the CI run of the pushed tip is
read with `gh api repos/dragonheart8787/ai-red-team/commits/<sha>/check-runs` and has to be green before the merge; the merge commit
records the tip and that result, and `main`'s own run after the merge is read the same way.

## 6. Verdict

Clean once §3 was done: no finding is open except 7, which is a limit of a tool and is stated. The branch is **40 commits** (plus the
repair of the skip) **ahead of an unchanged `main`**, every migration has its round trip, every irreversible action is off in everything that ships, and
the suite and every mutation of D64 (279) were run again on this code, and the new drill (5.99) ran on it; the older drill (5.95) was not repeated -- its script was changed only to pass `--evidence-dir` -- and its record stands as printed. The merge is `--no-ff`, the branch is kept, and
`main` is pushed only if the CI of the tip is green.
