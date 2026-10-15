# D66 -- the soak: method, definitions, limits

*Written before the first run. Nothing here was changed after seeing a result; the results are in
`docs/D66_SOAK_REPORT_<date>.md`.*

A soak is a long run of the real parts together, under faults, with questions asked of the state
at fixed times. It adds no feature: every process is the product's own command line, except the
**control-plane worker**, which is a test harness that calls the product's own `propose_action`.

```
python -m scripts.soak.conductor --run-dir DIR --hours 4        # exit 0 clean, 3 on a finding
```

## 1. What runs

| process | what | restarted by |
|---|---|---|
| scheduler | `scripts/run_scheduler.py --interval 5` (singleton lock, real `DockerSandbox`) | the conductor |
| reconciler | `scripts/run_reconciler.py --mode state-only --interval 20 --enable kill --enable container --enable proxy --evidence-dir DIR/evidence --engagement ...`, the phrase typed on a pseudo-terminal | the conductor |
| control-plane worker | `scripts/soak/worker.py`: 4 threads, each proposing through `propose_action` | the conductor |
| approver | thread of the conductor: grants (90 %) or denies (10 %) a `HUMAN_APPROVAL` proposal 2-20 s after seeing it, through `grant_approval` / `deny_approval` | -- |
| witness | `docker events` for containers with the sandbox's labels, kept in `docker_events.jsonl` | the conductor |
| sampler | once a minute: `/proc` of every process (RSS, descriptors, threads, TCP connections to Postgres), `pg_stat_activity`, Docker's containers/networks, the temp directory, the evidence directory | -- |

**The reconciler's switches are on** in a soak, for the three that can be (`kill`, `container`,
`proxy`) and only for the soak's own engagements (`--engagement`): the soak exists to see what they do
under faults. `network` and `file` cannot be turned on in this version and were not.

**Neither service restarts or reconnects itself** (their own documentation says so and they exit with a
code). The conductor is what a service manager would be. Every exit is written down with its cause.

### Requests

60 % `allow` (in scope, decided ALLOW, dispatched in the worker's own process to a real container --
the path a `kill -9` of the control plane interrupts), 30 % `human` (HUMAN_APPROVAL; dispatched by the
scheduler after the approver grants), 10 % `deny` (outside the scope object). Each request has an
idempotency key and is written to `requests.jsonl` before the call and again when it returns. A worker
that is killed and started again **retries half of the requests that never returned** (by the hash of
the key), with the same key, and drops the other half: a retry must resume, never repeat.

The workload is `network.scan` (nmap in the sandbox). It starts **no egress proxy** and writes **no
credential or TLS file**, so those two counts are measured and are expected to be zero throughout;
they are not exercised.

### Thresholds

Those of `.env.example`, except five, shortened so that what four hours can reach is reached:
`RECONCILER_STAGE_GRACE_S` 300 (a proposal received and never decided is abandoned after five
minutes), `RECONCILER_RETENTION_S` 300, `RECONCILER_RETRY_AFTER_FAILURE_S` 120,
`RECONCILER_BACKOFF_MAX_S` 60, `RECONCILER_SUMMARY_PERIOD_S` 600. `B + P + Q` (budget + 915 + 300 s)
is **not** shortened: a run left behind by a killed worker is declared `unknown_outcome` about 21
minutes after it began.

## 2. Faults

Every 10 to 20 minutes (uniformly), one of six, drawn from a shuffled bag (every kind once before any
twice):

| fault | how |
|---|---|
| `postgres_restart` | `service postgresql restart` |
| `docker_restart` | SIGTERM to `dockerd`, wait for it to exit, start it again (no live-restore: running containers are stopped) |
| `kill9_scheduler` | `kill -9` |
| `kill9_reconciler` | `kill -9` of the process on the pseudo-terminal |
| `kill9_control_plane` | `kill -9` of the worker; its tool containers are not touched |
| `pause_container` | `docker pause` of a running tool container of the soak (waits up to 5 minutes for one), unpaused 20-90 s later |

**Recovery** of a fault is the slowest of four moments after it was applied: all three services
alive with the database and Docker reachable; a reconciler pass; an ALLOW proposal created after the
fault recorded as succeeded; a HUMAN_APPROVAL proposal recorded after the fault (so: dispatched by the
scheduler). A recovery that is not complete after 20 minutes is a finding.

## 3. Invariants, every 15 minutes and at the end

Fixed before the first run. A failure is a **finding**: the soak stops (exit 3), the state is written
down as it is, and nothing is repaired or relaxed.

1. **Coherence.** `assert_coherent` (`tests/test_pipeline_stages.py`) on a repeatable-read snapshot of
   every engagement of the soak.
2. **No capability on an abandoned proposal**, in SQL, over every row.
3. **I7, no run twice.** In the database: no proposal and no capability with two runs that ran
   (`refusal_code IS NULL`). In Docker (the witness): no run id with more than one tool container
   created, and no proposal with more than one.
4. **Residue does not grow.** The *floor* (the smallest value in each 15-minute window) of the number
   of containers, exited tool containers, proxies, sandbox networks and credential/TLS files in the
   temp directory must not have risen in each of the last three windows (45 minutes). The count itself
   goes up and down with the traffic; a leak is a floor that climbs. Evidence files are kept by design
   (nothing prunes them) and are reported, not judged. After the drain (below) nothing of the soak may
   remain in Docker.
5. **No connection leak.** The same floor rule for the connections to Postgres of each process
   incarnation (by pid) and for all backends of the database; and no transaction `idle in transaction`
   for more than a minute.
6. **Audit matches state** (`scripts/soak/audit_pairs.py`, definitions in its docstring). Every state
   row has its audit event, always (`record_audit` is written before the stage commits, so a state
   with no record is never legal). An audit event with no state row, or two events for one subject, is
   legal only inside the window of a fault that kills a writer (`kill9_control_plane`,
   `kill9_scheduler`, `postgres_restart`, `docker_restart`; from its start to five minutes after it
   ended), and is listed with the fault. The reconciler's own proposal transitions are one transaction
   with their records: no window. A difference must persist over three observations five seconds apart.
7. **Unresolved reconciler intents** (`unresolved_reconciler_intents`): listed for a person, never
   judged -- an announcement with no result is a process that died in between, and the product says
   nothing repairs it.

Also a finding: a service that exits with no fault that explains it (the worker is never explained by
a fault: it must survive them), a service that exits four times in two minutes, the database or Docker
not back after five minutes, a worker exception that is not a database or Docker failure.

## 3a. How an exit is read, the resource caps, the hourly sample point (added after the pilots, before the four hours)

**Exits.** A service that stops is classified by the conductor: a `kill -9` it sent; a documented code *after a fault that
explains it* (`postgres_restart`: 4 "database lost" or 6 "lock lost"; `docker_restart`: 5 "Docker lost"); anything else is
`unexplained` and a finding. Since F1 (5.107) exit 5 *means* what it says -- the reconciler's `_translate` returns it only for a daemon
that cannot be spoken to or answers 5xx; an object that vanished while it listed is dropped, a 4xx that reaches the top is exit 1 -- so
an exit 5 with no restart of `dockerd` in force is a real finding and is not explained away. The worker is never explained by a fault.

**Caps** (`CAPS` in `conductor.py`, fixed before the run; a breach is a finding and stops the run): resident memory 512 MB for the
scheduler and the reconciler, 1 GB for the worker and the conductor; 1,024 descriptors and 20 connections to Postgres per process;
80 backends in the database; 150 containers of the soak and 20 sandbox networks; the run directory 2 GB, `events.jsonl` 512 MB; 2 GB
free on `/`.

**The hourly sample point** (`hourly.jsonl`, one record at the start, each full hour and the end): per process RSS, descriptors,
threads and connections; `dockerd`, `containerd` and Postgres resident memory; backends by role; containers, networks, temp files and
evidence files; rows and megabytes of `action_proposals`, `tool_runs`, `capabilities`, `approvals`, `evidence` and `audit_log`;
the size of the run directory and the free disk; faults so far by kind. The report prints them as a table, and the per-incarnation
trends (first, last, maximum, slope) from the one-minute samples beside it.

**All six kinds** are drawn from a shuffled bag (every kind before any is repeated), so a four-hour run with a fault every 10-20
minutes (12 to 24 faults) injects each kind at least twice; the report has a table of how many of each were applied and took
effect (a pause with no running container to pause is "could not be applied" and says so), and names any kind that never took effect.

## 4. The end

After the time is up the injector and the worker stop; the scheduler, the reconciler and the approver
go on for up to 45 minutes until every proposal is terminal, no run is in flight and no container of the
soak is left (the retention is 5 minutes, `unknown_outcome` about 21). The final check then adds:
nothing of the soak remains in Docker, no credential or TLS file, every proposal terminal. The
enrollments are withdrawn and what is stuck is moved to a terminal state; rows are never deleted.

## 5. Limits, stated

* The faults are applied to a single host. Postgres and Docker are restarted; a network partition, a
  full disk, a skewed clock and an out-of-memory kill are not injected.
* The witness loses the events of the seconds in which the Docker daemon is down; the database half of
  I7 does not.
* The workload does not start an egress proxy; the proxy and file switches of the reconciler are enabled
  and have nothing to act on.
* Memory and connection **trends** are reported (per process incarnation: first, last, maximum, slope)
  but only the connection counts are judged. There is no threshold for memory, because none was set
  before the run.
* The 15-minute windows give the rising-floor rule its first verdict after an hour (four windows).
