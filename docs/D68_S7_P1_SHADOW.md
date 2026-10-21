# D68 S7 addendum -- P1 in shadow on the live roles: the first DP-13 numbers

Raw rows: `docs/D68_S7_BASELINE/p1_shadow/` (`report.json`: the shadow report over the nine engagements; `task_proposal_rows.json`: every task with its proposal and stored relation; `run1..8.json`: the runs' own records).
Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.
**P1 was recorded, not enforced:** `task_relation_enforce` stays off everywhere (that is what shadow mode is; nothing was switched on). No threshold is proposed.

## What was run, and why not the soak

* **The soak's worker cannot answer DP-13.** It creates one task *from each request* (`tests/task_support.py::task_for`, S1), so every proposal equals its task by construction: the relation is `matches_task` every time and a count of "network tasks split into single hosts" is zero by design. Running it would have shown that shadow mode works under load, and nothing about DP-13. I did not run it for this. [D]
* **What can answer it is a planner that chooses its own tasks:** `scripts/live_run/d40_three_role.py`, the existing live-run script, with a **real Supervisor, Worker and Reviewer** (the `claude_code` backend, the script's default model `opus` for all three roles -- not the `sonnet` of the baseline). It builds its engagement through `create_engagement`, registers a /24 scope and a host, and runs rounds of Supervisor -> tasks -> Worker -> `propose_action` -> OPA -> a real `nmap` in the sandbox. Every proposal therefore goes through the shadow code of S2 and stores its `plan_fit`.
* **Run:** nine engagements (one 3-round pilot, then eight 4-round runs), `--skip-web --skip-injection` (the browser image this machine lacks is only needed by `web.render`). The target is the script's own `cyberorch/live-target:local` (built here with `build_target_image.sh`: real Redis, SMTP and HTTP daemons) on the allowlisted 10.79.0.0/24. Between runs the CLI's reported usage was read: five-hour 27% -> 41%, seven-day 41% -> 43%; the guard would have stopped at 70%.
* The script's header says it had not been executed since two later edits (ACCEPTANCE 5.54, 5.50) and lists comparisons to make on its next run. **Those comparisons were not made**; the runs completed without error, which is all that is claimed here.

## The numbers [E]

45 tasks, 45 proposals (every task got one; no Worker declined), 45 decisions, all with a stored `plan_fit`: 26 `ALLOW`, 19 `HUMAN_APPROVAL`.

| the Supervisor's tasks | n |
|---|---|
| `network.scan` on a single host | 28 |
| `network.recon` on the /24 | 9 |
| `network.scan` on the /24 | 7 |
| `network.recon` on a single host | 1 |

| relation of proposal to its task | n |
|---|---|
| `matches_task` | **44** (97.8%) |
| `differs_from_task` / `same_action_target_inside_task_target` | **1** |
| `no_task`, `task_not_live`, other differs | 0 |

* **DP-13, as it was asked** -- of the proposals made for a task whose target is a network, how many were for one host inside it: **1 of 16 (6.3%; upper 95% bound 28.3%)**. The 15 others proposed the task's own network. The one case: a `network.scan` task on `10.79.0.0/24`, proposed as a `network.scan` of the one live host `10.79.0.2` (it was allowed).
* **What P1 enforcement would have added over these decisions:** of the 26 `ALLOW`, **1 (3.8%; upper 95% 18.9%)** would have gone to a human, with `proposal_outside_task`; the 19 already-asked proposals would have gained no reason. `goal_fit` is `not_assessed/disabled` for all 45 (no validator was configured).
* Not one task was created without being proposed, and no proposal named another task or none: the Supervisor-to-Worker path hands the task through intact, as designed.

## What this does and does not show

* It is a **better reference than none, and that is all it is.** Nine engagements of one planner in one lab: one /24 and one host, `nmap` actions only, four rounds each, the same three prompts. The one split in 16 was not a Worker habit I can characterise; the interval is wide (0 to 28%).
* The design worried that a Worker would turn a network task into many host proposals (DP-13). In this lab it **mostly did not**: it ran the network scan as the network scan. It is not evidence about a larger estate, a Worker that gets a long candidate list, or tasks that are more naturally decomposed (the Supervisor here chose host tasks itself for most hosts: 29 of 45 tasks were already single-host).
* Therefore **no change to P1's `identity_key` granularity is indicated by this sample** (the note DP-13 asked to be recorded if the rate were high); the sample is also too small to rule one out.
* 16 of the 29 single-host proposals went to `HUMAN_APPROVAL` already; that is the existing policy on hosts without an authoritative classification, unrelated to P1.
* Nothing here used a Q1 validator; this says nothing about the cost of Q1.

## Tooling change for this

`scripts/plan_fit_report.py` now reports DP-13 in the form it was asked in (proposals for a task on a network, and how many were for one host inside it), by joining each proposal to its task. Three offline tests, one against the real database.
