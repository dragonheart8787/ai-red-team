# Soak report (D66)

* run: `/tmp/claude-0/-home-user-ai-red-team/3cc8933a-877a-5b9a-bf4e-a849e674060c/scratchpad/soak_pilot3`
* started 2026-10-15T08:32:03Z, ended 2026-10-15T08:44:56Z (0.21 h; the traffic and the faults ran 0.6 h, then the drain)
* seed `d66`, engagements 2, worker threads 4, mean gap 15.0 s, run budget 60 s
* outcome: **FINDING - stopped**

## Findings

* `unexplained_exit` -- reconciler exited with 5 and no injected fault explains it

## Faults injected

| fault | times | recovered (s): min / median / max | not recovered | action (s) |
|---|---|---|---|---|
| postgres_restart | 1 | 21 / 21 / 21 | 0 | 2 / 2 / 2 |
| docker_restart | 0 | - | 0 | - |
| kill9_scheduler | 1 | 21 / 21 / 21 | 0 | - |
| kill9_reconciler | 1 | 15 / 15 / 15 | 0 | - |
| kill9_control_plane | 1 | 16 / 16 / 16 | 0 | - |
| pause_container | 1 | 45 / 45 / 45 | 0 | - |

Each injection (recovery = the slowest of: all three services alive with the database and Docker reachable; a reconciler pass after the fault; an ALLOW proposal created after the fault recorded as succeeded; a HUMAN_APPROVAL proposal dispatched by the scheduler and recorded after the fault):

| at | fault | detail | services up | reconciler pass | ALLOW recorded | scheduler dispatched | recovered |
|---|---|---|---|---|---|---|---|
| 2026-10-15T08:33:45Z | pause_container | {"container": "fe5c147534e4", "hold_s": 28.2, "unpause": {"unpaused": true}} | 39.3 | 45.4 | 39.3 | 39.3 | 45.4 |
| 2026-10-15T08:36:55Z | kill9_control_plane | {"pid": 11760} | 6.2 | 15.5 | 9.4 | 9.4 | 15.5 |
| 2026-10-15T08:39:30Z | kill9_scheduler | {"pid": 11747} | 6.2 | 21.4 | 9.4 | 9.4 | 21.4 |
| 2026-10-15T08:41:33Z | postgres_restart | {"detail": "* Restarting PostgreSQL 16 database server\n   ...done."} | 5.5 | 20.8 | 11.7 | 8.6 | 20.8 |
| 2026-10-15T08:44:07Z | kill9_reconciler | {"pid": 23804} | 6.2 | 12.4 | 15.4 | 3.1 | 15.4 |

## Services

| service | starts | exits (cause: count) |
|---|---|---|
| scheduler | 3 | {'injected_kill9': 1, 'explained_by_postgres_restart': 1} |
| reconciler | 3 | {'explained_by_postgres_restart': 1, 'injected_kill9': 1, 'unexplained': 1} |
| worker | 2 | {'injected_kill9': 1, 'conductor_stop': 1} |

`explained_by_*` is a service that stopped itself with its documented exit code after the fault named, and was started again by this program: **neither service reconnects**, a supervisor is part of the design.

## Invariants

| check | runs | failed | last detail |
|---|---|---|---|
| coherence | 3 | 0 | 179 proposals in 2 engagements |
| no capability on an abandoned proposal | 3 | 0 | 0 abandoned proposals |
| I7 database: no proposal and no capability with two runs | 3 | 0 | 149 runs |
| I7 docker: no run, no proposal, with two containers created | 3 | 0 | 147 tool containers created |
| audit events match state transitions | 3 | 0 | state/audit subjects: proposal.submitted 179/179, policy.decided 179/179, capability.issued 150/150, tool_run.started 150/150, tool_run.refused 2/2, tool_run.succeeded 146/146, tool_run.failed 0/0, ev |
| residue (containers, networks, proxies, files) does not grow | 3 | 0 | floors per window: {"containers": [0.0, 1.0, 2.0], "exited_tool_containers": [0.0, 1.0, 2.0], "proxies": [0.0, 0.0, 0.0], "networks": [1.0, 2.0, 2.0], "temp_files": [0.0, 0.0, 0.0]} |
| no connection leak | 3 | 0 | 9 process incarnations; longest idle-in-transaction 0 s |
| unresolved reconciler intents (listed, not judged) | 3 | 0 | 0: [] |

## Traffic

proposals by `stage / detail`: recorded / succeeded 146, closed / decision_DENY 22, closed / approval_denied 7, closed / network_unavailable 2, closed / test_cleanup 2

runs by status: succeeded 146, failed 2, unknown_outcome 2

audit events: approval.denied 7, approval.granted 46, capability.issued 150, engagement.created 2, evidence.recorded 146, policy.decided 179, policy_layer.published 2, policy_reviewer.opinion 179, proposal.submitted 179, scheduler.dispatched 46, scope_object.registered 2, tool_run.refused 2, tool_run.started 150, tool_run.succeeded 146

worker: {'worker.started': 2, 'worker.stopped': 1}

reconciler actions (kind, outcome): 

reconciler passes seen: 32

## Memory and connections (per process incarnation)

| process | pid | minutes | RSS first / last / max (MB) | RSS slope (MB/h) | fds min-max | pg connections min-max | threads min-max |
|---|---|---|---|---|---|---|---|
| scheduler | 11747 | 7.0 | 69.8 / 71.5 / 71.5 | 6.94 | [6, 18] | [3, 5] | [2, 2] |
| reconciler | 11725 | 9.4 | 63.1 / 63.4 / 63.4 | 2.04 | [14, 31] | [0, 3] | [1, 2] |
| worker | 11760 | 4.4 | 73.2 / 74.6 / 74.6 | 17.1 | [11, 22] | [8, 8] | [5, 5] |
| conductor | 11699 | 12.4 | 71.5 / 79.5 / 79.6 | 48.87 | [12, 14] | [2, 5] | [7, 8] |
| worker | 17172 | 7.4 | 73.9 / 75.2 / 75.2 | 9.59 | [11, 21] | [3, 8] | [5, 5] |
| scheduler | 20553 | 1.7 | 70.7 / 71.3 / 71.3 | 25.63 | [8, 18] | [5, 5] | [2, 2] |
| scheduler | 23268 | 3.0 | 28.8 / 71.4 / 71.4 | 417.89 | [3, 8] | [0, 5] | [1, 2] |
| reconciler | 23804 | 2.0 | 63.2 / 63.3 / 63.3 | 2.37 | [26, 29] | [3, 3] | [2, 2] |
| reconciler | 26978 | 0.3 | 63.1 / 63.1 / 63.1 | None | [23, 23] | [3, 3] | [2, 2] |

database backends (all roles): min 7, median 21, max 21, last 15; longest idle-in-transaction 0 s

## Host residue over time (window floors, 15 min windows)

* containers: floors [0.0, 1.0, 2.0], max 3, last 3.0
* exited tool containers: floors [0.0, 1.0, 2.0], max 2, last 2.0
* proxies: floors [0.0, 0.0, 0.0], max 0, last 0.0
* sandbox networks: floors [1.0, 2.0, 2.0], max 2, last 2.0
* temp credential/TLS files: floors [0.0, 0.0, 0.0], max 0, last 0.0
* evidence files: floors [0.0, 0.0, 0.0], max 0, last 0.0

## What needed a person

* `unexplained_exit`: reconciler exited with 5 and no injected fault explains it

teardown: {"withdrawn": ["ENG-SOAK-1015083204-0", "ENG-SOAK-1015083204-1"], "closed_proposals": {"dispatching": 2}, "closed_runs": 2, "baseline_retired": false}
