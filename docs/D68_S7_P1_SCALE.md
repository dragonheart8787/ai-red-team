# D68 S7 -- P1 in shadow at scale: DP-13 with a sample ten times larger, and what the larger sample showed

Raw records: `docs/D68_S7_BASELINE/p1_scale/` (`opus/`, `sonnet/`: one record per run; `summary.json`), `p1_shadow/` (the first 45), `d40_comparison/` (the 5.50/5.54 check).
Tooling: `scripts/live_run/d40_three_role.py` (new options below), `scripts/live_run/d40_scale_worker.sh`, `scripts/live_run/start_d40_hosts.sh`, `scripts/live_run/summarise_p1_scale.py`, `scripts/live_run/verify_d40_rerun.py`.
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.
**P1 was recorded, not enforced.** `task_relation_enforce` is off everywhere; nothing was switched on. **No DP-13 threshold is proposed here.**

## 1. The headline, and why it is not one number

The first sample (45 proposals, one /24 and one host) gave DP-13 as **1 of 16 (6%; upper bound 28%)**. The bound was wide because the sample was small. The larger sample is **478 proposals** (10.6x) and the bound is narrow -- and **the answer is a different one**, because the first scenario was easy:

| network-task proposals | n | narrowed to one host inside the network | |
|---|---|---|---|
| original scenario (a /24 and one host) | 16 | 1 | 6% (<= 28%) |
| larger scenario, both planner models pooled | 186 | **35** | **18.8% (<= 25.0%)** |
| larger scenario, only tasks whose network was written with its prefix | 128 | 35 | **27.3% (<= 35.6%)** |
| ... planner model `opus` | 31 (27 with a prefix) | 10 | 32% (37%) |
| ... planner model `sonnet` | 155 (101 with a prefix) | 25 | 16% (25%) |

What moved the number is not sampling error: **the rate depends on the scenario and on the planner's model**, by more than the intervals. With a handful of hosts listed beside a network the Worker narrows a network task to a host in one case in five to one in three; with one host and one network it did in one case in sixteen. A threshold for DP-13 set from the pooled 18.8% would describe neither.

## 2. What was run

* **The harness:** `d40_three_role.py`, a **real Supervisor, Worker and (here) a scripted honest Reviewer**, against real containers (`nmap` in the sandbox, real `redis`/`smtp`/`http` daemons), each run a fresh engagement through `create_engagement`. The Reviewer is scripted (`--fake-reviewer`) because the relation to the task does not depend on it and it is a third of the model calls; decisions in these runs are therefore *more often `ALLOW`* than with the real one and **decision-mix figures are not comparable with D40's**.
* **New harness options (all default to the old behaviour):** `--extra-containers` (more authorized hosts), `--subnets` (sub-networks registered as ranges), `--no-parent-range` (the /24 is not itself a scope object), `--web-actions get`, `--fake-reviewer`, `--max-evidence-shown`, `--max-observation-chars`, `--allow-missing-browser`. The last two are not about the question: a /24 scan's evidence is 660 KB and, shown to the next prompt, exceeds the operating system's limit on one argument (`Argument list too long`); the first scaled run lost its Supervisor to it. Both caps are recorded as harness bounds, as the D40 report's own evidence cap was.
* **The larger scenario:** nine authorized hosts (the original target and eight more, spread over four /26 sub-networks) and the **four /26 networks as scope objects, with no /24 object**: the planner has four networks to survey and hosts inside each. Plus the web host, offered for `web.get` only. 3 rounds per run (the earlier rounds-4-and-5 only confirmed "objective met").
* **Strata:** `opus` (the harness default, the model of the first 45): 4 runs, 63 proposals. `sonnet`: 27 runs, 415 proposals. The `sonnet` stratum exists because **the account's usage allowance, not the machine, set the pace**: `opus` runs cost about 5 points of the five-hour window each, `sonnet` about 1 to 1.5; at `opus` prices 450 proposals was most of three windows. Both are shown separately and pooled; they are different populations.
* Runs were serial (two engagements cannot share the allowlisted network: `NetworkInUse`, the D59 property), and the machine restarted twice mid-session; an interrupted run left a partial engagement that is not in any count.
* **Not done:** `web.render` (the browser image cannot be built here: its `pip install` inside the build fails TLS verification against the proxy; not worked around because that would change the image under review), a Reviewer that is real, more than two models, any estate bigger than nine hosts.

## 3. What the 478 proposals look like [E]

| | opus | sonnet | together |
|---|---|---|---|
| runs | 4 | 27 | 31 |
| proposals | 63 | 415 | 478 |
| `matches_task` | 42 | 328 | 370 |
| `differs_from_task` | 21 | 87 | 108 (22.6%) |

Of the 108 that differ, by what happened (classified from the two canonical identities; `summarise_p1_scale.py::classify`, tested as a table):

| why the proposal differs from its task | n | |
|---|---|---|
| **the task's network lost its prefix** -- the Supervisor wrote the range as `10.79.0.64`, the task became `10.79.0.64/32`, the Worker proposed the `/26` it meant | **58** | 31% of network tasks |
| **a network task narrowed to one host inside it** (the DP-13 case) | **35** | 19% (27% of the rest) |
| web: the task names the host as an `ip`, the proposal as a `url` (`http://10.85.0.5/`) | 12 | 12 of 38 `web.get` proposals |
| a network task proposed as a different network | 3 | |

* **The prefix loss is the biggest class and is not the Worker's.** In 58 of the 187 network tasks the Supervisor's own task target carries no prefix (sonnet 54 of 156, opus 4 of 31; 186 of the 187 were proposed); the task canonicalizer reads a `cidr` without a prefix as a `/32`; the Worker, shown the candidates, proposes the network. P1 is right that the task and the proposal differ, and the difference is a wrong *task*. [E]
* **The web class is an identity-form mismatch**, the same shape as the one D40's own report recorded as `web.get` -> `DENY target_out_of_scope`: the scope object, the task and the proposal name one host in two forms (`ip`, `ip`/`url`, `url`). [E]
* What P1 would add if it were enforced, over these decisions: of **400 `ALLOW`** decisions, **94 (23.5%)** would have gone to a human, all as `proposal_outside_task`; 2 already-asked proposals would have gained that reason. Of the 108 differing proposals, 93 are the prefix loss and the narrowing (58 + 35), so **most of the volume P1 would add is those two, not unrelated drift**.
* No `no_task`, no `task_not_live`. Every task got a proposal.

## 4. The 5.50 and 5.54 checks [E]

Made on a re-run of the original configuration (5 main rounds, 3 injection rounds, web with both actions, the real Reviewer, one host, no extra networks), as the two rows ask, before reading anything else (`d40_comparison/`, `scripts/live_run/verify_d40_rerun.py`). The browser image is absent, so the run used `--allow-missing-browser`: a `web.render` proposal is decided, and its dispatch could not have run.

**5.54 (the harness was edited for D59/D60 and not run since):**
* the same decision for the same proposal, round by round: **yes**. Round 1: `network.recon` /24 `ALLOW`, `network.scan` .2 `ALLOW`, `web.get` of the web host `DENY target_out_of_scope`; round 2: `network.scan` .1 and .3 `HUMAN_APPROVAL`; rounds 3-5: no tasks, status `blocked`. One difference in the *reasons*: the pre-D60 report had `sensitive_data_hint` beside `non_authoritative_sensitivity` on the two round-2 approvals and this run did not (that hint is the real Reviewer's opinion, which varies from run to run). The decisions did not change.
* **the web leg reaching the proxy: not observable.** The proxy was started for the engagement (D59: no `NetworkInUse`); but the only web proposal is denied at policy before any dispatch, in the old report and in this run alike, so nothing reached it. This part of the row cannot be confirmed by this harness as configured.
* the injection engagement is unaffected: its three round-1 proposals `ALLOW` and run.
* every proposal's `pipeline_stage`: main engagement: 2 `recorded/succeeded` (provenance complete), 1 `closed/decision_DENY` (complete), **2 `awaiting_approval`** (the two `HUMAN_APPROVAL`; they cannot end at `recorded` or `closed` until a person acts -- the row's wording assumed none); injection: 3 `recorded/succeeded`.

**5.50 (`web.render` requires a known classification):**
* after `setup_engagement`, the web host resolves as **known and `AUTHORITATIVE` for the `ip` identity**: yes.
* a `web.render` proposal for it is **not** escalated with `unknown_classification_for_action_class` **in the `ip` form** (decision `ALLOW`; the dispatch then failed `egress_proxy_required`, as a proposal without a proxy should). **In the `url` form the Worker actually proposes (`http://10.85.0.5/`), it is:** `DENY target_out_of_scope` with `unknown_classification_for_action_class` -- the identity `url:http://10.85.0.5/` has no classification and no scope object. So the row's derivation holds for the form it was derived for and fails for the form the harness's Worker uses. This is "a finding about the rule", which the row said it would be; it is the same identity-form mismatch as the web class in section 3 and the D40 report's own `web.get` result, and it is not fixed here.

## 5. What this does not settle

* One lab; nmap actions, a web host that is always denied; the planner models are two; the Reviewer is scripted. The estate is nine hosts. A real customer's networks, host counts and tasks are not these.
* The two strata differ by planner model **and** by cost-forced run counts; the difference between them (32% vs 16% narrowing) is itself from 31 and 155 network-task proposals.
* The classification into "why" is mine, by canonical identity; the 58 prefix-lost tasks were not each read by a person.
* Two pilot runs (one with the /24 as well as the hosts, lost to the argument limit after round 1; one sub-network pilot before the worker script) are in `p1_scale_pilot_b/` and are in no count. Three concurrent workers were also tried and abandoned: engagements cannot share the allowlisted network, so all but one failed at start and left no record.

## 6. What it means for the decisions you have to take (stated, not decided)

* DP-13: the narrowing rate is **scenario- and model-dependent (6% to 37% in this lab)**; a bound of 25% on the pooled larger sample is narrow, but it is a bound on a mixture. If a threshold is set it needs to say which scenario and planner it is about.
* Two other classes dominate the volume P1 would add and are **not** the DP-13 question: the prefix loss (a task canonicalization issue: `cidr` without a prefix read as `/32`) and the ip/url identity form. Both are candidates in ACCEPTANCE (5.122, 5.123). Whether P1's identity key should change for them, or the producers of tasks should, is yours.

## 7. After the Supervisor schema fix (ACCEPTANCE 5.122) -- the numbers without the prefix loss [E]

**Cause, read from the code [R]:** the plan schema's `target_value` description (`agents/llm/supervisor_base.py`) said a network is given "in CIDR form written as its network address". That wording does not require a prefix, and read literally asks for the bare address. The planner's own `goal` text said "10.79.0.64/26" while its `target_value` was `10.79.0.64` (run 1, round 1). So this is the case "the prompt did not require it", not "the model ignored a requirement": the description was changed to "the network address and its prefix length, e.g. 10.79.0.64/26: a bare address such as 10.79.0.64 names that one host, not the network", and a test pins the wording (`tests/test_supervisor_boundary.py`). Nothing else was changed (not the canonicalizer, not the task-creation path).

**Re-run:** the same scenario and worker as the `sonnet` stratum (nine hosts, four /26 networks, 3 rounds, scripted Reviewer), 10 runs, 149 proposals (`p1_scale/sonnet_prefix_fixed/`, `p1_scale/summary_prefix_fixed.json`).

| | before (sonnet, 27 runs) | after the fix (10 runs) |
|---|---|---|
| network (`cidr`) tasks written without a prefix | 54 of 156 (35%) | **0 of 52** |
| `differs_from_task` over all proposals | 87 of 415 (21%) | 12 of 149 (8%) |
| P1 would send ALLOW decisions to a person | 94 of 400 over both strata | 8 of 120 (6.7%, <= 12.6%) |

The prefix loss does not occur in this run (upper 95% bound for 0 of 52: 5.8%). **Limits:** one planner model (`sonnet`), one scenario, 10 runs; `opus` was not re-run (it lost the prefix in 4 of 31 before). The fix is to the producer's instructions; the canonicalizer still reads a bare `cidr` as a `/32`, so a planner that ignores the new description would produce the same task again.

**The clean DP-13 number (narrowing to one host inside the network):**

| sample | network-task proposals | narrowed to a host inside | rate (95% upper) |
|---|---|---|---|
| after the fix, `sonnet`, 10 runs | 52 | 9 | **17.3% (<= 29.7%)** |
| before the fix, tasks with a prefix, `sonnet` | 101 | 25 | 24.8% (<= 34.0%) |
| before the fix, tasks with a prefix, both models | 128 | 35 | 27.3% (<= 35.6%) |
| original scenario (one /24, one host) | 16 | 1 | 6% (<= 28%) |

* The 58 prefix-lost tasks no longer sit in the denominator, so 17.3% is the first figure for the Worker's own narrowing that the task canonicalization cannot have produced. It is a figure for one planner model in one scenario; its interval (to 29.7%) overlaps the pre-fix `sonnet` rate, so the data do not show that the narrowing rate changed.
* The other class still present: 3 `web.get` proposals whose task names the host as an `ip` and whose proposal is the `url` (ACCEPTANCE 5.123), unchanged.
* **No DP-13 threshold is set or proposed here.**
