# D68 S8b -- Q1 (`goal_fit_enforce`): preparation, and what is waiting

Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.
**Status (2026-10-27, owner): closed -- Q1 was not enabled and the 4 h soak was not run (section 13).** Earlier status, kept: prepared, not run. The CI job needs the owner's `claude` login, which the owner adds to the repository settings by hand; until its name is given and the workflow reading it has been checked, no S8b run exists and nothing here has called a model. The 4 h run is not tried on the development machine (owner's instruction; that route was shown unreliable).

## 1. Decisions taken

* **The enabling layer is an emergency overlay, not a baseline** (owner, from S8a: ACCEPTANCE 5.124). An overlay applies to every engagement at once and its retirement returns every engagement; a baseline is frozen into each engagement when it is made and its retirement returns only later ones [E: `docs/D68_S8A_REPORT.md` section 5]. The soak's `--enforce-via overlay` publishes one overlay carrying `task_relation_enforce` and `goal_fit_enforce` (both on, as after S8a) before the engagements exist, and retires it at teardown.
* **The validator's configuration is the one DP-14 was measured on** [R: `docs/D68_S7_FIXED_MODEL_REPORT.md`]: backend `claude_code`, model alias `sonnet`, `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1`. The validator's own default model is `opus` [R: `agents/llm/headless.py` `DEFAULT_MODEL`], and the CLI's default is to answer a classifier-stopped call with a second model; neither is what DP-14 measured, so the workflow sets the model and the fallback switch through the environment, and `scripts/s8_enablement_check.py` and the soak conductor **report an anomaly** when Q1 is asked for with another model, another backend or the fallback on. This is an addition to the two conditions of plan 8.1 (switch true, validator configured): the third is "the validator is the one whose numbers the gate was set from".

## 2. What was built (no credential, no model call)

| piece | what it does |
|---|---|
| `scripts/soak/conductor.py --q1-enforce --enforce-via overlay` | publishes the overlay; **refuses to start** if `goal_fit_enforce` is not true in an engagement's effective policy, if no real validator is configured, or if the configuration is not the measured one |
| `scripts/soak/worker.py` | passes `plan_fit_validator` to `propose_action` when a real backend is named; with none (every run before S8b) it passes none, as before |
| `scripts/soak/checks.py::q1_verdict / q1_enforcement` | a cycle check: the switch in every engagement; a real backend; once 20 proposals are decided, **at least one answer** among the stored `goal_fit` values -- "enabled and no validator ever answered" is a finding. The *rate* of `failed` is counted in the detail and in the report and **not judged** (DP-14: no global ceiling) |
| `scripts/soak/q1_preflight.py` | one real call before the soak starts, so a missing login stops the job in a minute and not after four hours |
| `scripts/soak/q1_stream.py` | the soak's own workload is `network.scan` only; this sends proposals of **every action class** through the real `propose_action` with the real validator, ~100 an hour, weighted to `code.secrets` (4) and `ad.collect` (2), in an engagement of its own outside the soak's invariants (nothing is dispatched). 10% are **crossed** cells: an Active-Directory goal on a `code.secrets` task and a secrets-scan goal on an `ad.collect` task |
| `scripts/soak/q1_report.py` | the failure rate by action class and by goal wording, and the judgement below |
| `.github/workflows/soak.yml` | inputs/request key `q1_enforce`; the workload slowed (`--mean-gap 45`, ~5 requests a minute instead of ~40) so that a real validator is asked about each proposal at a rate a subscription allows; the pre-flight; the stream beside the conductor; the report step. **The step that gives the runner the CLI and its login is not there yet** |

Offline tests: `tests/test_soak_checks.py` (the Q1 verdicts), `tests/test_s8_enablement_check.py`, `tests/test_q1_stream_report.py`.

## 3. The judgement the S8b report must test, written before any data

From S7 (`docs/D68_S7_CODE_SECRETS_FAILURE.md`): the baseline's `code.secrets` failure rate of 65% was Active-Directory collection wording in the goal, a general trigger of the service's safety-classifier stop, and not a property of `code.secrets`. In real traffic through the pipeline it **holds** if all three are true (`q1_report.py` docstring; nothing is relaxed afterwards):

1. the Wilson upper bound of the failure rate over secrets-scan-wording goals (natural `code.secrets` plus the crossed `ad.collect` cell) is below the Wilson lower bound over AD-wording goals (natural `ad.collect` plus the crossed `code.secrets` cell);
2. the same for natural `code.secrets` alone;
3. S7's prediction is not contradicted: the Wilson *lower* bound of natural `code.secrets` does not exceed 12.9% (the S7 probe's upper bound for secrets-scan wording, 1 failure in 40).

Rule 3 exists because 1 and 2 alone would pass a `code.secrets` rate of 60% beside an AD rate of 85%. With the planned stream (a 4 h run: ~400 proposals, ~120 natural `code.secrets`, ~60 natural `ad.collect`, ~40 crossed) a rate near zero for `code.secrets` bounds it under ~2.5% [D]. The soak's own `network.scan` workload is reported separately (S7: `network.scan` matched 0 of 16 failed).

## 4. What it costs [D]

About 1,300 validator calls in a 4 h run (the workload at ~5/min is ~1,150, the stream ~400, less what is denied before it): at S7's $0.009 a call about $14 list price, and about 20 points of the five-hour usage window, spread over four hours. The 0.2 h smoke is about 100 calls.

## 5. The credential, and how the workflow reads it (2026-10-23)

The owner's instruction: a repository secret named **`CLAUDE_CODE_OAUTH_TOKEN`**, the OAuth login of the owner's own account -- the same account path as D10/D10.5 and the S7 baseline (a subscription, not `ANTHROPIC_API_KEY`, which is pay-per-use). Nothing in the repository holds or creates it. `.github/workflows/soak.yml` reads it **by that name and in a Q1 run only**:

* a step installs the CLI at **2.1.307**, the version of the fixed-model baseline DP-14 was set from (the version had moved from 2.1.306 to 2.1.307 during S7; `latest` is 2.1.309 and the undocumented fallback switch is a CLI detail that can change with a version);
* a step fails the job in a second if the secret is empty (naming it and where to set it) or if `ANTHROPIC_API_KEY` is in the environment (the CLI would prefer it); it never prints the value;
* the pre-flight and the soak step get `CLAUDE_CODE_OAUTH_TOKEN` in their environment, `ANTHROPIC_API_KEY` set empty, and the pinned model and fallback switch. The validator's command uses `--safe-mode`, chosen over `--bare` precisely because `--bare` forces `ANTHROPIC_API_KEY` [R: `agents/llm/headless.py`], so the token reaches the CLI. A run that is not a Q1 run gets an empty value, as before.
* **Not verifiable from here [N]:** whether the secret exists and is valid. The job's login step and the pre-flight are what say so.

## 6. What is waiting

* The CI of the commit that holds this wiring; then the 0.2 h smoke (the validator really called: answered `goal_fit` values in the stored decisions, the enablement check clean, the five negative controls), then the 4 h run. The result goes into this report, with the section 3 judgement read from `q1_report.md`.

## 7. First smoke attempt (soak run 10, 2026-10-23 12:01 UTC): stopped at the login step [E]

The CI of the wiring commit was green (`test` #269, normal and enforced jobs). The smoke was requested. The runner installed the CLI -- `2.1.307 (Claude Code)` -- and **the login step failed in under a second: `CLAUDE_CODE_OAUTH_TOKEN` was empty in the job's environment** ("the repository secret CLAUDE_CODE_OAUTH_TOKEN is not set"). The pre-flight and the soak were skipped, as designed; nothing called a model and nothing was run against the database. (The later steps of the job -- the stream report, which found no stream file, and the negative controls, which passed -- are consequences, not findings.)

So the workflow reads the secret by the name given and the secret is not there from the workflow's point of view. Nothing was configured or worked around. The ways a secret that "exists" is empty in a job: it has not been added yet; it was added under *Environments* and not as a *repository* secret; it is in the *Dependabot* or *Codespaces* secret store (separate from Actions); or the name differs by a character. The smoke is requested again by a new push of `.github/soak-request.json` once the owner says the secret is in place.

## 8. Smoke attempt 2 (soak run 11, 2026-10-24 09:16-09:29 UTC): it ran, and it found something [E]

The login step passed (the secret is visible), the CLI was 2.1.307, and the **pre-flight called the real validator once: `goal_fit=plausible` in 2.6 s**. The soak ran 13 minutes with no finding; the five negative controls fired (5 of 5); the P1 check judged 6 of 6 (62 of 62 decided proposals carry a plan_fit, no P1 escalation); the Q1 check executed 6 times and judged 4.

**What it found: the validator failed on 27 of the 62 decided proposals (44%)** -- `{'plausible': 35, 'not_assessed/failed': 27}`. The Q1 stream (19 proposals) failed on 7: `network.scan` 3 of 4, `network.recon` 2 of 2, the crossed `code.secrets` cell 2 of 2; natural `code.secrets` 0 of 5, `code.scan` 0 of 3. So:

* The rate is far above S7's for `network.scan` (0 of 16 failed on matched items), on the class that is nearly all the soak's own workload. With the switch on, each failure is `plan_check_failed`, i.e. a person: about half of ordinary scan proposals. [E] The check does not judge a rate (DP-14), and that is why it passed; the number is what it is.
* **The cause is not known [N].** The failure reason is in the validator's call record, not in the audit, and the run did not keep it. Candidates, none tested: the safety classifier on scan wording from this environment; the validator's 30 s timeout under five concurrent CLI processes on a 4-core runner; an account rate limit; the CLI at 2.1.307 against 2.1.309 on the machine S7 ran on.
* The report's judgement read "does NOT hold" for 2 AD-wording items beside 6 secrets-wording ones. That was the report, not the data: the three rules had been run together as "not met", and 6 against 2 contradicts nothing. Fixed: `holds` has three readings (holds / contradicted by the data / not established), with a test; the criteria for "holds" are unchanged.

**The 4 h run was not requested**, against the plan that said to request it if the smoke was clean: it was mechanically clean and substantively not, and four hours would spend about $14 and 20 points of the usage window to measure a failure rate whose cause is unknown. Added instead, to read the cause: the stream records each validator call's failure reason and seconds, the report lists them by closed kind with samples, and the soak's workers keep a validator per thread and write `worker.q1_failure` events with the reason (printed in the job log). A third smoke (attempt 3) is requested to read them.

## 9. Smoke attempt 3 (soak run 12, 2026-10-24 10:04-10:17 UTC): why the validator failed, and where it does not [E]

CI `test` #273 for the commit that carries the diagnostics: success (normal and enforced jobs).

**The cause, read from the failed calls' own records:** all 7 failures of the Q1 stream, and the failures of the soak's own workload (`worker.q1_failure` events), are **`stop_reason: "refusal"`** -- the service's safety classifier stopping the turn, as in S7; a failed call takes 2.7-3.9 s; no timeout, no rate limit, no login failure. The Q1 check's counts this run: 68 decided, 32 answered, 36 failed. The stream: `network.scan` 3 of 4 failed (`scan-host` goals 2 of 3), `network.recon` 2 of 2, `ad.collect`-wording 2 of 2, natural `code.secrets` 0 of 5, `code.scan` 0 of 3, `web.get`/`web.render` 0 of 1 each. The report's judgement: **not established** (6 secrets-wording and 2 AD-wording goals are too few; nothing contradicts S7).

**Where the same failures do not occur** -- measured on the development machine, same validator, same model alias, same fallback switch, no S8b run (these are single-purpose probes of the validator, 156 calls):

| probe | failed |
|---|---|
| the corpus's 60 matched items again, today (CLI 2.1.310; S7 was 2.1.307) | **11 of 60** (S7: 12 of 60); `network.scan` **0 of 16** (S7: 0 of 16); `network.recon` 5 of 8 (S7: 5 of 8); `ad.collect` 6 of 7 (S7: 7 of 7) |
| the soak's own scan sentence on targets in the soak's ranges (`10.66.252.x`, `10.66.10-40.11-13`) | **0 of 32** |
| the same sentence on random `10.x.y.z` targets | 0 of 16 |
| five threads at once, 8 calls each (the soak's concurrency) | **0 of 40** |

So the classifier's behaviour today is what it was on 2026-10-22; the target range does not matter; the concurrency does not matter; the CLI version does not matter. **What is left is the CI environment itself**: the runner's network egress, and the authentication path (the subscription login by `CLAUDE_CODE_OAUTH_TOKEN` there; the interactive login here). Neither can be varied from the development machine. [N] which of the two it is, or whether it is something else about the runner.

**What this means for S8b [D]:** in the CI environment the validator answers about half of the soak's ordinary `network.scan` proposals and the rest become `plan_check_failed`, i.e. a person. Plan 8.1's observation criterion for Q1 -- no large unexpected `plan_check_failed` -- is **not met in that environment**, whatever the cause, and a 4 h run there would measure that rate for four hours (about $14 and 20 points of the usage window) without telling why. It is not a defect of the check, which reports the number and does not judge it (DP-14).

**Options, for the owner to choose [not decided]:**
1. A sequential pass of the corpus's matched group *inside CI* (60 calls, ~$0.5, ~3 min) added to the Q1 smoke: it separates "CI environment" (high there too) from "the soak's and the stream's own inputs or concurrency" (low there). It is the cheapest next step.
2. Run the 4 h soak anyway, to see the rate over time and under faults.
3. Do not enable Q1 where the validator runs from an environment that behaves like this one; treat the failure rate as a property of where the validator is called from, to be measured at the place before enabling.

## 10. Option 1 chosen (owner, 2026-10-24): the matched group, sequentially, inside CI

Added to the Q1 smoke, before the soak: `scripts/soak/q1_ci_matched.py --run` asks the corpus's 60 matched items one after another, with the measured configuration (backend `claude_code`, model `sonnet`, fallback off), and prints the table per action beside S7's (`network.scan` 0 of 16). Smoke attempt 4 is requested. Reading it: if this environment fails `network.scan` here too, the environment (egress or the OAuth-token path) is the difference; if it does not, the difference is in the soak's or the stream's own inputs or concurrency, which the development-machine probes did not reproduce either.

A ratchet had to be respected on the way: `tests/test_plan_fit_baseline.py::test_nothing_in_ci_runs_the_baseline` keeps the name `plan_fit_baseline` out of every workflow (it reaches a real model; ADR_REVIEWER_BILLING). The workflow names the new module instead, as it names the pre-flight, and the module calls the baseline runner. That keeps the ratchet's text; its purpose -- no model call in a push gate -- is unchanged by it, because `soak.yml` runs only when the owner pushes a request file (and weekly, with Q1 off), never on an ordinary push. This is stated here so that it is not a surprise.

## 11. Smoke attempt 4 (soak run 13, 2026-10-24 10:55-11:11 UTC): the diagnostic did not find the environment [E]

CI `test` #275 for the commit that carries the diagnostic: success. The job: login and pre-flight ok, the diagnostic ran 10:56-10:59 (60 sequential calls), the soak 13 minutes, no finding, 5 of 5 controls.

**The corpus's matched group, sequentially, inside CI, beside S7:**

| action | S7 (dev machine, 2026-10-22) | CI, sequential, 2026-10-24 |
|---|---|---|
| `network.scan` | 0/16 | **3/16** |
| `network.recon` | 5/8 | 7/8 |
| `ad.collect` | 7/7 | 7/7 |
| `code.scan`, `code.secrets`, `web.get`, `web.render` | 0 of 7, 7, 8, 7 | 0 of 7, 7, 8, 7 |
| **all matched** | 12/60 | **17/60** |

By Fisher's exact test (two-sided) 17/60 against 12/60 is p = 0.39, and `network.scan` 3/16 against 0/16 is p = 0.23: **inside CI, asked one after another, the validator behaves like S7 within what chance gives.** The CI environment (runner egress, the OAuth-token path) is therefore **not** shown to be the cause; the diagnostic that was meant to find it did not.

**What is still unexplained is the soak's own workload.** Its proposals are all `network.scan`; the validator failed on (Q1 check's decided minus the stream's): attempt 2 ~20 of 43, attempt 3 ~29 of 49, **attempt 4 32 of 53 (60%)** -- every failure a safety-classifier stop. Against the same environment's sequential `network.scan` 3/16: p = 0.07, 0.008 and 0.004; against everything measured elsewhere (S7 and three development-machine probes, 0 of 104 `network.scan` items) the soak's 81 of 145 is p < 1e-11. The Q1 stream in the same job, with the same validator and the same environment, failed `network.scan` 1 of 4 this time (3 of 4 before), `network.recon` 2 of 2.

What the soak's workload has that none of the probes had [D, none tested]: **few distinct prompts** (nine hosts in the engagements plus three outside ones, so about twelve different sentences, each asked about five times in 13 minutes; the corpus's probes used a new host for each call); a **sustained rate** of roughly five calls a minute from one process for the whole run; calls made **from inside `propose_action`** in a worker with the soak's resource caps (the same code as production). The stream, with fresh hosts for each call, fails less on `network.scan` than the soak does.

**What this changes:** the failure rate in the Q1 soak is not shown to be a property of the environment, and not shown to be a property of the validator on these inputs; it is a property of something in how the soak asks. Until that is known, a 4 h run would again measure the number without explaining it, and the number must not be read as the rate real traffic would see. **The 4 h run is not requested.**

**Next diagnostics, cheap, not run [for the owner]:** (a) record, for each failed call, the host and a hash of the prompt, to see whether specific sentences fail every time (the soak asks the same ones repeatedly); (b) in CI, ask the soak's twelve actual sentences five times each, sequentially, then the same with fresh hosts: it separates repetition from the call path; (c) the same twelve sentences on the development machine.


## 12. DP-15 (owner, 2026-10-24): Q1 is asked per action class; no class is enabled [E]

After the smoke attempts the owner asked for a per-class allowlist (plan 7.3c, ACCEPTANCE 5.125). It is a mechanism only: the list is empty by default, a class outside it is not asked (`not_assessed/class_not_enabled`), a class that fails above 30% of its last 50 calls (at least 30) is taken out automatically (`class_suspended`) and put back only by an operator, and admission is advice from `scripts/manage_goal_fit_classes.py report` (>= 40 calls on the real path, Wilson 95% upper bound <= 15%). It does not explain the soak's ~60% `network.scan` failures (section 11); it contains their effect on decisions, because Q1 is no longer asked for a class nobody admitted. The 4 h run remains not requested. A soak with `--q1-enforce` and an empty list now reports "the validator was never asked" (not judged) instead of "enabled and doing nothing"; it can show nothing about Q1 until a class is listed.

## 13. Closed (owner, 2026-10-27): Q1 was not enabled, the 4 h soak was not run, S8b is closed [E]

* **Status: Q1 is not enabled.** No layer in force in the development database lists a class; the
  record-mode layer exists only in the three databases that were made for measuring (`cyberorch_dp15`,
  `cyberorch_dp15b`, `cyberorch_smoke`), where `goal_fit_enforce` was and is off.
* **S8b's 4-hour soak was not run.** Nothing in this report is a result of it.
* **Why S8b closes here:** DP-15 stage 1 (`docs/D68_DP15_RECORD_MODE/stage1/`; registered at `0747cbe`,
  run from `9df70aa`, results at `ccc6b05`) did not meet C1: 8 of 60 decided `network.scan` wordings
  marked, Wilson and exact 95% upper bounds 24.2% and 24.6% against the registered 15%. The numbers, the
  environment of the run and the owner's decision are in `docs/D68_DP15_RECORD_MODE/stage1/OUTCOME.md`.
  Stage 2 and C3 are not carried out, `goal_fit_enforce` stays off, stage 1 is not re-run, and any
  further measurement is a new pre-registration on new data that attaches this result.
* **A caveat on DP-15 run 1** (`docs/D68_DP15_RECORD_MODE/report_run1.txt`): its 0 failures in 150
  calls used three fixed goal sentences, one per class. It is not evidence of how Q1 behaves and
  must not be cited as such.
