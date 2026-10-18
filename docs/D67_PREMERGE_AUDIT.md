# D67 -- pre-merge audit (2026-10-18)

Requested before merging this branch into `main`, continuing the specification of D47, D51, D57, D63 (and D64's audit), with the scope
**taken from git and not from row or step numbers**. Four parts: the state of git, the consistency of the documents, whether three
named properties were verified end to end, and the scale numbers. Each is *checked* below; what was found is in section 5.

**Headline.** The range is what the request expected, and `origin/main` is where it was expected (`2f4dca4`). The checks found
**five things to correct, all corrected in this audit's own commits**: two ACCEPTANCE rows that still said something the four-hour run had made
untrue (5.106 "Open: the four-hour run is not made", and the "no four-hour result" of 5.111); five mutation-catalogue entries that no longer applied because
this branch's own changes moved the code they edit (found by a check, repaired, and shown valid); a baseline number in the request (3,332 tests)
that appears nowhere in the repository; and a premise that is **not true as asked**: of the three properties the request wants "triggered for
real at least once among the soak's 16 faults", only one (5.109) was -- the late-result path (5.74) was not, and the migration downgrade
(5.75) cannot be -- and the documents now say so and say where each was verified instead (section 3). Nothing else was found wrong.

## 1. The state of git

### 1.1 Where `main` is

`git fetch origin` (2026-10-18 00:15 UTC): **`origin/main` = `2f4dca4`** ("Merge D64: the reconciler ... with D65-A, the deadline helper"), as
expected. The merge base of this branch with it is **`2f4dca4`**, the same commit: `main` has not moved since the branch left it, so the merge is of exactly
the commits below and a fast-forward would be possible; it is made with `--no-ff` so that the range stays one named thing.

### 1.2 The real range

**30 commits, 156 files, +18,899 / -171 lines** (`git diff --numstat origin/main...HEAD` at the commit before this report's; no vendored code this time, unlike D64):

| area | files | added | removed |
|---|---:|---:|---:|
| docs (artifacts of runs, drills and the audit) | 81 | +10,484 | -0 |
| scripts/soak (the harness) | 14 | +3,180 | -0 |
| tests | 25 | +2,398 | -67 |
| scripts | 10 | +1,605 | -50 |
| docs | 10 | +716 | -9 |
| .github | 4 | +278 | -0 |
| control_plane | 9 | +220 | -39 |
| README.md | 1 | +12 | -5 |
| tool_gateway | 1 | +5 | -1 |
| .gitignore | 1 | +1 | -0 |

By what the subjects say (not by their numbers):

| part | commits | what |
|---|---:|---|
| D64 completion 5 | 6 | the evidence of an unexplained run per engagement (5.101); an interrupted mutation sweep puts back what it changed (5.102); the whole chain on a real daemon (5.103); the late result on a real container (5.104); "off" is a default, not a state (5.105) |
| D66 soak: harness, pilots, F1/F2, F3 pilot | 3 | the harness and three pilots (5.106-5.108); F1 (a vanished object is gone, a lost daemon is lost) and F2 (a typed `NotStarted` for the network race); pilot 4 and the diagnosis of F3 |
| F3, enrollments, CLI, log scan | 3 | one Docker reachability classification for the scheduler and the reconciler, ten real daemon restarts under a dispatch (5.109); tests withdraw their own enrollments, 5.71 covers them, the CLI refuses odd names; post-hoc classification of every log and a report section for what no check covers |
| the interruptions and the heartbeat | 9 | a 30-second heartbeat file; the first attempt interrupted by a host event, 5.110; the two re-runs and their recoveries; progress snapshots; the move to a runner (5.111) |
| the soak on a runner | 5 | measured caps, unprivileged conductor, counted checks, schema check, smoke mode (5.112); `init_db.sh` permission; printing the report to the log; **OPA installed**; the smoke run passed and the four-hour run requested (5.113) |
| reading the result | 2 | `soak-report.yml`; the four-hour result and 5.114 |
| this audit | 3 | a read of the second failed run's report; the audit and its repairs |

So the branch is **the soak (D66) from its harness to its four-hour result, with the three product findings the soak made (F1, F2, F3) and their fixes, the
shared Docker classification, the rule at the operator CLI's door, the enrollment cleanup of the tests, and D64's completion 5 that came before it**. It is not "the
four-hour run": reading the range off the last row would have missed F1-F3 and the reconciler's observe/act changes, which are in it.

### 1.3 Every commit and its CI

CI runs on the head of each push, so a commit pushed together with others has the result of that run ("pushed with"). Jobs: `test` (the suite, with
`Assert nothing was skipped` and lint) and `deadline-helper` on every push; `soak` and `soak-report` only on pushes that touch the request files.

| commit | subject | CI | result |
|---|---|---|---|
| `0feefea` | D66 completion 5 (item 1, ACCEPTANCE 5.101): the evidence of an unexplained run in one 0 | pushed with 2f7e4cf | test success |
| `8bcf538` | Completion 5: the CT5 test gives the service an evidence directory (found by the mutatio | pushed with 2f7e4cf | test success |
| `60d781c` | Completion 5, item 2 (ACCEPTANCE 5.102): an interrupted mutation sweep puts back what it | pushed with 2f7e4cf | test success |
| `e225d76` | Completion 5, item 3 (ACCEPTANCE 5.103): the whole chain on a real daemon with nobody ed | pushed with 2f7e4cf | test success |
| `ac875c2` | Completion 5, item 4 (ACCEPTANCE 5.104): the late result of 5.74 on a real container, 70 | pushed with 2f7e4cf | test success |
| `b5c44a4` | Completion 5, item 5 (ACCEPTANCE 5.105): "off" is a default, not a state of the world; D | pushed with 2f7e4cf | test success |
| `2f7e4cf` | D66 (ACCEPTANCE 5.106-5.108): the soak harness, three pilots, and two product findings;  | own run | test success |
| `15f3a31` | F1 + F2 (ACCEPTANCE 5.107, 5.108): a vanished object is gone, a lost daemon is lost; the | own run | test success |
| `6248bd4` | D66 (ACCEPTANCE 5.109): after the F1 fix, pilot 4 and a docker-restart diagnostic run; F | own run | test success |
| `7dd0655` | F3: one Docker reachability classification for the scheduler and the reconciler (5.109) | pushed with 99ad336 | test success |
| `161694c` | Tests withdraw their own enrollments; 5.71 covers enrollments; the CLI refuses odd names | pushed with 99ad336 | test success |
| `99ad336` | Soak: post-hoc classification of every log, and a section for what no check covers | own run | test success |
| `19817af` | Soak: a 30-second heartbeat file, and the verdict of a run that stopped | pushed with b3073dc | test success |
| `b3073dc` | Soak attempt 1 recorded as interrupted by a host event; 5.110 pins the denial's provenan | own run | test success |
| `51c87f8` | D66_SOAK: two re-runs after the interrupted first attempt, not two attempts in all | own run | test success |
| `cfc0fe3` | Soak progress snapshot (04:15Z): heartbeat, hourly points, key events, host | own run | test success |
| `df1fa8b` | Soak re-run 1: interrupted by a host restart at 04:20-04:33 UTC (evidence read first, no | own run | test success |
| `eed3db6` | Soak re-run 1 interrupted by a second host restart; its state recovered through the prod | own run | test success |
| `8c080de` | Soak progress snapshot (04:52Z): heartbeat, hourly points, key events, host | own run | test success |
| `db3a836` | Soak re-run 2: interrupted by a host restart at ~04:58 UTC (evidence read first, not cou | own run | test success |
| `6d69c7b` | Soak moved to a scheduled workflow after both re-runs were interrupted by host restarts  | own run | test success |
| `38648b1` | Soak on a runner: measured caps, unprivileged conductor, counted checks, schema check, s | own run | soak failure, test success |
| `9df63bd` | soak.yml: let the postgres user read db/roles.sql (init_db failed with Permission denied | own run | soak failure, test success |
| `a3162ab` | soak.yml: print findings, exits, faults and the report head to the log (the artifact can | own run | soak failure, test success |
| `2a9f0eb` | Soak: install OPA on the runner (without it every request was denied: 476 of 476 DENY, 0 | own run | soak success, test success |
| `ffc87db` | Soak: the smoke run on a runner passed; the four-hour run is requested (5.113) | own run | soak success, test success |
| `0d364c8` | soak-report.yml: print the report of a finished soak run into a job log (the artifact ca | own run | soak-report success, test success |
| `87ae3d1` | The four-hour soak on a runner passed with no finding; what it showed and what no check  | own run | test success |
| `552e6ec` | D67: read the report of the second failed soak run (39013653006) to confirm its cause | own run | soak-report success, test success |
| `35a7cdd` | D67 repairs: stale ACCEPTANCE statuses, five stale mutation entries, 5.113/5.114 made ex | own run | test success |

### 1.4 Every red light, and its green

Everything the CI of this branch ever failed (211 runs listed by `gh api .../actions/runs?branch=...`) is below. **Since `main` moved to `2f4dca4` the
`test` workflow has not failed once** (21 runs on the commits of this range: 21 success). Before it, the failures belong to ranges already merged and audited
(D64's audit records 404037b -> 77143b0); they are not repeated here. In this range the red lights are all of the new `soak` workflow, and all are followed by
green:

| run | commit | what failed | cause | followed by |
|---|---|---|---|---|
| 39013500844 | `38648b1` | `init_db.sh` in the "install" step | `psql: /home/runner/work/.../db/roles.sql: Permission denied` -- `init_db.sh` reads the file as the `postgres` user, who cannot enter the runner's home directory | `9df63bd` fixed it (`chmod a+x "$HOME"`) |
| 39013653006 | `9df63bd` | the conductor exited 3 | **OPA was not installed on the runner**: every request was denied. Read for this audit (`soak-report.yml` on that run's artifact): 450 proposals, **0 capabilities, 0 runs, 0 approvals**, the same signature as the next run | `2a9f0eb` installed OPA 1.9.0 |
| 39014549345 | `a3162ab` | the conductor exited 3 | the same cause: 476 of 476 proposals `decision_DENY`, 0 runs, so `pause_container` found nothing to pause (`fault_kind_never_effective`) | `2a9f0eb`: **soak success** (run 39015455542), then `ffc87db`: **soak success** (run 39017478408, the four hours) |

So the two failures the request names are three runs: one for `init_db.sh`'s permission and **two, not one, for the missing OPA** -- the second was
not diagnosed at the time (its log held only the exit code; the report was in an artifact that could not be fetched), and is confirmed here. The lesson of the
second is in the product of the audit: a run in which no request is ever allowed passes every other check, so the conductor now fails it
(`workload_not_exercised`, 5.113). No red light is open.

## 2. The consistency of the documents

### 2.1 ACCEPTANCE 5.96 to 5.114, row against report

Nineteen rows. Each was checked three ways: every file, test, mutation and drill directory it names exists (a script over the rows: **0 unresolved**; seven names that
look like test functions are test modules, which exist); the numbers it states are in the report it cites (rows 5.101-5.109: all found, the one exception, "128", is the
operator CLI's length limit, which is in the code); and the status word is the one the report supports.

| row | status | against its report |
|---|---|---|
| 5.96-5.100 | Closed | on `main` already; unchanged by this branch except by reference |
| 5.101-5.105 | Closed | consistent with their drill documents and `docs/D64_*_2026-10-15.md` |
| 5.106 | **was Open** | **stale**: said the four-hour run was not made. Now Closed, revised, pointing at 5.113 |
| 5.107, 5.108 | Closed | consistent with `D66_F1_VANISHING_OBJECTS.md` |
| 5.109 | Closed | consistent with `D66_F3_DOCKER_LOST_UNDER_DISPATCH.md` and the drill's `rounds.json` |
| 5.110 | Stated and pinned | now also records the 251 of 251 on the runner and points at 5.112/5.113 |
| 5.111 | Stated | **stale**: said "there is no four-hour result" and "it has not been run"; now says what happened on the machine and what happened afterwards |
| 5.112 | Stated | points at 5.110 (the `SAVEPOINT` errors are not tied to the interruptions) and 5.113 |
| 5.113 | Closed | read against the four-hour report; now also says what the run did not exercise, the memory requirement, the schedule |
| 5.114 | Open | rewritten: the trigger, how it would look, what is not done (section 3.3) |

The status words are the four the numbering test accepts (`Closed`, `Open`, `Designed`, `Stated`); the test, which runs in CI, passed on the tip.

### 2.2 The D64 index and section 10

* The ADR index (`docs/ADR_PRODUCTION_ORCHESTRATOR.md`, row D58-9) said "built" and listed the rows up to 5.95. It now also says what was run for real (5.103, 5.104, and four hours of the soak with the
  three switches on for the soak's own engagements: 8 `unknown_outcome` marks, 8 removals, 755 passes), and that after a whole-machine restart the reconciler may do nothing (section 10, 5.111).
* `D64_RECONCILER_DESIGN.md` section 10 was compared with what was actually done on 2026-10-17 (re-run 1 and re-run 2). The order -- Postgres and Docker up; `assert_coherent` and a dry-run before any change; the scheduler dispatches what was
  `approved`; the people's `awaiting_approval` decided with `scripts/approvals.py`; enrollments withdrawn with the CLI; the same checks after; **never a row edited** -- is the order that was followed, and its numbers
  (0 actions in 600 s and 901 s) are the measured ones. Its two commands were **run for this audit** against the development database, so the procedure is not only described:
  `check_reconciler_run.py before` recorded **452 schema facts and the counters of 21 tables**, and `after` reported `schema_differences: 0`. One honest difference: on 2026-10-17 the schema snapshot of step 2 was not taken before the
  reconciler ran, and ACCEPTANCE 5.111 says so; section 10 is the correction, not a record of what happened.
* The facts count differs between machines (452 here and in the local smoke runs, 453 on the runner in both runner runs). Every comparison the soak makes is within one database, so none is affected; the
  runner's extra fact was not identified (the monitoring role's grants are the likely one) and is not claimed.

### 2.3 5.110 and 5.112

They point at each other and do not contradict. 5.110: a denial on an autocommit connection is recorded without its provenance, and only a log line says so; the soak's approver is such a connection; 251 of 251 on the runner,
8 of 8 in a pilot on the development machine. 5.112: the development machine cannot run a long test; three interruptions. The link that was missing -- is the `SAVEPOINT` error environment-dependent, or related to the
interruptions? -- is now written in both: it is the same on every machine and in the runner that was never interrupted, so it is neither.

### 2.4 Does the schedule take effect when this is merged?

**Yes, at once.** GitHub runs `schedule` triggers only from the default branch, and from the moment the file is there. `soak.yml` has `cron: '17 2 * * 0'`: **every Sunday at 02:17 UTC, four hours, unattended**.
The first run is the first Sunday 02:17 UTC after the merge -- **2026-10-25 02:17 UTC** (today, 2026-10-18, 02:17 UTC has passed). It uses Actions minutes (about 4 hours 15 minutes a week) and, if it finds something, shows as a red `soak` run on `main`. The `push` trigger of
`soak.yml` and all of `soak-report.yml` name the development branch and **do nothing on `main`**; `workflow_dispatch` (hours) works from the day the file is on `main` (before that the API answered 404). The file
`.github/soak-request.json` (4 hours) merges as an ordinary file and only matters on the branch. This is stated in the merge message, in `D66_SOAK.md` section 7 and in 5.113.

## 3. End to end

### 3.1 5.74, 5.75, 5.109 among the sixteen faults

| | what it is | triggered by the soak's 16 faults? | where it was verified for real |
|---|---|---|---|
| **5.109** | a daemon that dies is `docker_lost` (exit 5) in the scheduler as well as in the reconciler | **Yes.** After the three `docker_restart` faults the scheduler stopped with exit 5 three times and the reconciler twice; **no exit 1** ("unexpected") among 19 service exits | also ten restarts under a dispatch (`D66_F3_DOCKER_RESTART_DRILL_2026-10-16/`) |
| **5.74** | a dispatch whose stage the reconciler took (`unknown_outcome`) still records its result as `run.late_result` | **No.** The run's audit event types (`D66_SOAK_RUNNER_4H_2026-10-17/README.md`) have no `run.late_result`. It needs a *live* dispatch slower than B+P+Q (about 21 minutes); no fault of the six makes one, and the killed workers never return | the drill of 5.104: a real control-plane process, a real container, a real daemon, the result 70 s after the reconciler's mark |
| **5.75** | the downgrade of migration 0017 repairs its data under row-level security | **Cannot be**: no migration runs in a soak | experiment E18 on a copy of the development database (6,387 `approved` rows), plus the round-trip tests |

The request's premise -- each one "triggered at least once among the 16 injections" -- holds for one of three. The two others are verified at a real level (a real container and daemon; a real database copy),
not only in unit tests, but not by the soak, and 5.113 now says so. A seventh fault that stops the control plane (`SIGSTOP`) past B+P+Q and lets it continue would trigger 5.74 inside a soak; it is **not built** and is written down
as the way (5.113).

### 3.2 The conductor's memory

The wording in 5.113 and `D66_SOAK.md` section 7 now says it in the form asked for: **required before any soak longer than four hours: set a memory cap for the harness from this trend, and find the cause of the growth.** The
numbers: the conductor 74.6 -> 109.2 MB in 251 minutes (hourly 75, 87, 94, 101, 110; 7.5 MB/h), the three services flat. Its present cap, 1,024 MB, is a default and would be reached after about 120 hours: it would not have caught
the growth earlier. The cause was not examined (candidates named, not claimed). Until then it is a candidate defect of the harness, not a known property.

### 3.3 5.114, the `no-new-privileges` spelling

Rewritten with status and trigger: **Open**, found by the log classification, not changed. Trigger: a Docker release that stops accepting `no-new-privileges:true`. Measured for this audit on a real daemon (29.8.2): both
`no-new-privileges:true` and `no-new-privileges=true` create a container today, and an **invalid `--security-opt` is answered with HTTP 500**, not 4xx. `docker_health.py` calls a 5xx *lost*, so the failure would
present as "Docker unreachable" (exit 5, restarted by the supervisor, over and over) and not as what it is, a configuration the daemon refused. That second consequence is new in this audit and is in the row. The one-token fix is
deliberately not made here: it alters the container-creation call that 5.108 and the boundary tests pin, and the four-hour result was made without it.

## 4. Scale

| what | number | how |
|---|---:|---|
| tests collected | **3,451** | `pytest --collect-only -q` on the tip. The recorded baseline is **3,230** (main's merge message and `D64_PREMERGE_AUDIT.md`), so **+221**. The request's baseline, **3,332, appears nowhere** in the repository or in `main`'s history; it is not used |
| tests passed in the last full local run | **3,422** passed, **0 skipped**, 0:17:25; 29 not runnable on this machine | `pytest -q -rs`. The 29 (27 errors, 2 failures) are the tests that need three tool images this machine cannot build (`bloodhound`, `browser`, `semgrep`: the build's `pip` meets the sandbox's TLS interception); every one names one of those images. CI builds them: **CI is green on the tip with the whole suite and `Assert nothing was skipped`**. The `semgrep` image was afterwards built here with the proxy's CA added and the two tests that need it passed (58 of 58 in their files) |
| OPA tests | **58/58** | `opa test control_plane/policy/rego policy_tests` |
| migrations | **26** (`0001`-`0026`), one head, `0026` | `alembic heads` / `alembic current` on a database built by `init_db.sh`; `db/` is not in the diff, so unchanged since `main` |
| database roles | **12** (11 `LOGIN`, `reconciler_fn_owner` `NOLOGIN`) | `pg_roles` of that database; `db/roles.sql` unchanged since `main` |
| test files | 130 | `git ls-files 'tests/test_*.py'` (D64: 122) |
| ACCEPTANCE rows | 98 | rows of the form `| **5.N** |` (`main`: 83) |
| stuck rows closed at the end of the tests that made them / left for the session end | 616 in 17 files / **none** | the session report of the full run (5.96); enrollments: 1 withdrawn at the end of its test, **none** left (5.109) |
| mutation catalogues | 54 (D62/D63), **316** (D64; 279 at its audit), 36 (D65-A), **28** (D66, new) | `--list` |
| mutations run on this tip | **all 183 entries that edit a file this branch changed: 183 valid, 0 not** (15 + 154 + 14), and the 28 of D66 (valid when written, run again after the last code change) | `docs/D67_MUTATIONS/`. Of the 183, 19 first came out INVALID *on this machine* because the baseline was red for the missing `semgrep` image (`test_scheduler_actions`, `test_deadline_sandbox`); after the image was built they were run again and are valid. The entries that edit files this branch did not change were **not** re-run (D64's audit ran all of its own); for them the check of all **392** edits (the old text present the stated number of times) found **0 stale** |
| the sweep's recovery | 1 | a fifth host restart killed the sweep with a mutation applied; the runner put the file back at the next start ("RECOVERED control_plane/reconciler/evidence.py"), which is 5.102 working on a real kill |
| lint | clean | `ruff check .` |
| reconciler package / the soak harness | 3,064 / 3,180 lines | `wc -l` of the tracked files (D64: 2,977 for the reconciler) |

## 5. What was found, and what was done

| # | finding | action |
|---|---|---|
| 1 | ACCEPTANCE 5.106 still said the four-hour run was not made; 5.111 said "no four-hour result", "not been run" | rewritten (revised in place, with what it said) |
| 2 | five mutation entries (`D63-n`, `D64-C5-l`, `D64-F1-h`, `-i`, `-j`) no longer applied: this branch moved the code they edit (`tests/residue.py`; the classification moved to `docker_health.py`) -- found by a check of **all 392 edits** (`old` text present `count` times) | repaired; the five **run and valid**; the catalogue check: 0 stale |
| 3 | the baseline "3,332 tests" of the request appears nowhere; the recorded baseline (main's merge message, D64 audit) is **3,230** | stated in section 4 |
| 4 | the request's premise for 5.74 and 5.75 | documented, not a defect (section 3.1) |
| 5 | the second OPA failure (run 39013653006) had never been read | read; same cause (section 1.4) |
| 6 | 5.114 said only "observed" | trigger, failure mode (HTTP 500 read as a lost daemon), and what is not done |
| 7 | the memory growth was "known" | the requirement before a longer soak, in 5.113 and `D66_SOAK.md` |
| 8 | the schedule would start without anyone being told | section 2.4, the merge message, `D66_SOAK.md` |
| 9 | `D66_SOAK.md` header pointed at a report file that does not exist | pointed at the directories that do |

## 6. Verdict and the merge

**Clean.** The range is as expected; every red light has its green and none is open; the documents agree with each other and with their reports after the repairs of section 5; the
three properties are documented as what they are (one triggered in the soak, two verified elsewhere at a real level); the numbers are measured. Nothing found stands in the way of the merge.

What the merge carries, so that nobody is surprised by it: **`soak.yml` will run every Sunday at 02:17 UTC, four hours, on `main`, unattended** (section 2.4); the first run is the first Sunday
02:17 UTC after the merge (**2026-10-25 02:17 UTC** if it lands before it). Nothing that ships starts the reconciler or turns a switch on. The branch is kept.

Merge: `--no-ff` of the tip into `main` (`2f4dca4`); the merge commit cites this report, the verified range and the schedule; `main`'s CI is read afterwards.

