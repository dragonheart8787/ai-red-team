# The smoke run on a GitHub runner, 2026-10-17

`soak.yml`, run 39015455542, commit after 38648b1 (OPA installed), `hours` = 0.2 requested by a push of
`.github/soak-request.json`. **Outcome: no finding.** The numbers below are transcribed from the job log
(`mcp__github__get_job_logs`, job 117346631509); the artifact `soak-run` (Artifact ID 12095282848, 30
days) holds the full report, journal and logs, and cannot be fetched from the development machine (the
blob host is not reachable from it).

* Runner: 4 cores, 15,989 MB, 147,718 MB disk (87,158 free), `max_connections` 100, soft `nofile` 65,536,
  kernel `6.17.0-1022-azure`. Caps derived from it: containers 100, backends 77, per-process connections
  20, descriptors 1,024, RSS 512/512/1024/1024 MB, run directory 2,048 MB (defaults where smaller).
* Traffic: 352 proposals (287 recorded/succeeded, 40 closed/decision_DENY, 11 closed/approval_denied, 8
  closed/docker_unreachable, 5 recorded/unknown_outcome, 1 recorded/failed); 301 runs; 85 scheduler
  dispatches; 293 tool containers created, none twice.
* Faults: 14 in 12 minutes -- postgres_restart 2, docker_restart 2, kill9_scheduler 3, kill9_reconciler 2,
  kill9_control_plane 3, pause_container 2 -- every kind at least twice and effective; recovery
  (seconds, min/median/max): postgres 15/18/21, docker 18/23/28, kill9_scheduler 18/21/24,
  kill9_reconciler 9/11/12, kill9_control_plane 9/9/21, pause 44/61/78; none unrecovered.
* Checks, executions / judged: coherence, capability-on-abandoned, I7 database, I7 docker, audit
  pairing, schema identity -- 6 / 6 each; residue 6 / 3; connection leak 6 / 3; unresolved intents 6 /
  listed; the drain check 1 / 1. None with zero executions.
* **Recorded and not enforced (smoke only): residue.** One result failed ("containers: floor [1, 3, 5, 6]").
  Exited tool containers peaked at 5-8 and went to **0** after the drain; the reconciler made 5
  `mark_unknown_outcome` and 5 `remove_container` (all `done`), the last at about 26 minutes after the
  faults -- B + P + Q plus the retention, as designed. After the drain: 0 containers, 0 files; 3 sandbox
  networks remain (kept by design).
* Reconciler passes 89; all actions `done`. Processes: 64-85 MB RSS each, at most 45 descriptors, at
  most 21 backends, nothing idle in a transaction.
* The first CI attempts found, and the workflow/harness now guards: `init_db.sh` could not read
  `db/roles.sql` as the postgres user (Permission denied) -- fixed in the workflow; OPA was not installed
  and every one of 476 requests was `DENY` with 0 runs -- fixed in the workflow, and the conductor now
  fails a run in which no ALLOW and no HUMAN_APPROVAL proposal was ever recorded
  (`workload_not_exercised`, mutation `D66-S-j`).
