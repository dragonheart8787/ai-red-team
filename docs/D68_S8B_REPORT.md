# D68 S8b -- Q1 (`goal_fit_enforce`): preparation, and what is waiting

Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.
**Status: prepared, not run.** The CI job needs the owner's `claude` login, which the owner adds to the repository settings by hand; until its name is given and the workflow reading it has been checked, no S8b run exists and nothing here has called a model. The 4 h run is not tried on the development machine (owner's instruction; that route was shown unreliable).

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

