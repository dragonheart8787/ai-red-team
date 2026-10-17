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
`unexplained` and a finding. Since F1 (5.107) and F3 (5.109) exit 5 *means* what it says in both services -- they share one classification
(`control_plane/docker_health.py`), which returns it only for a daemon that cannot be spoken to or answers 5xx; an object that vanished while it listed is dropped, a 4xx that reaches the top is exit 1 -- so
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

## 3b. What is read after the run, and what is known before it (added after F3, before the four hours)

The checks above are questions fixed in advance. Two sections of the report ask the run what it
contains instead; neither judges or stops anything.

**Logs, classified after the run** (`scripts/soak/logscan.py`; `python -m scripts.soak.logscan RUN_DIR`
reruns it). Every warning and error in the services' logs, the Docker daemon's log (`/tmp/dockerd.log`)
and the Postgres server log between the first and the last event of the run is normalised (ids,
numbers, addresses, hashes replaced) and grouped by source, level and shape. A group is `explained`
only if *every* occurrence lies inside a fault's window (from its start to its recovery plus 60 s;
600 s if it never recovered); that says *when*, never *why*. A group with one occurrence outside every
window is `not_explained`; a source with no timestamps (the services' logs) is `untimed`. All three
classes are printed with counts, the fault kinds that cover them, first and last time, and raw samples.
The report then states, in prose, what each unexplained group is -- after reading it.

**Observed, and not covered by any check** (`not_covered` in `report.py`). Each item says what was
looked at, so that an empty item is an answer: log groups not explained; reconciler actions whose
outcome was not `done`; reconciler passes that were limited, held back or truncated; exit codes of tool
containers that died; gaps in the sampler; recoveries slower than twice their kind's median; the
approver's counts and errors; runs by refusal code and status; denied proposals without provenance.
A person then adds what they saw while reading, under the heading *Reviewer's notes* in the report.

**Known before the run** (so that it is not discovered as a surprise, and not "fixed" to make the
report quiet):

* The approver of this harness denies a proposal through `tests.helpers.committing_scope`, an
  **autocommit** connection. `deny_approval` takes a savepoint to record provenance, and on an
  autocommit connection Postgres answers `SAVEPOINT can only be used in transaction blocks`; the
  product catches `SQLAlchemyError`, logs "provenance for denied ... was not recorded" and goes on.
  So in a soak every denied `HUMAN_APPROVAL` proposal has **no provenance**, and the Postgres log has
  one such `ERROR` per denial (8 of 8 in pilot 4). It is a property of the harness's connection, not
  evidence about the product's own path (which runs inside `engagement_scope`'s transaction); the soak
  therefore does not exercise that path. The report counts the denials and the missing provenance.
  ACCEPTANCE 5.110 pins both halves with tests (`tests/test_deny_provenance_connection.py`).
* The Postgres server log is shared with everything else on the machine. Nothing else may run during a
  soak (no tests, no mutation sweep, no drills); the scan is cut by the run's own start and end, so a
  line from outside it is not read, but one from inside it that came from something else would be.

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

## 6. Interrupted runs: what happened on 2026-10-16/17, and the rule since

**A run that stops without ending itself is marked *interrupted*. It is not resumed, not joined to
another run, and not counted.** The verdict is read from the run directory by
`python -m scripts.soak.heartbeat RUN_DIR` (`clean`, `running`, `interrupted`,
`interrupted_host_restart`, `no_heartbeat`); the conductor rewrites `RUN_DIR/heartbeat.json` every
30 s (pid, host boot id, kernel, host uptime, phase, last sample) and puts the host's identity in
`soak.setup`. After the interrupted attempt 1, at most **two re-runs** are made in one environment; if both are
interrupted the soak is moved to a scheduled workflow on a CI runner and not retried by hand.

**Attempt 1 -- interrupted by a real host event.** Started 2026-10-16 about 02:31 UTC from commit
99ad336 (CI green), seed `d66`, 4 h. The last event in `events.jsonl` is a `reconciler.pass` at
02:37:58; there is no `FINDING`, no `soak.stopping`, no `soak.teardown`. At 03:24:11 the host reported
`up 0 min` with no process of the soak, Postgres and Docker not running; the files of the run were
still on disk. No fault had been injected yet (the first is drawn 10-20 minutes in), so nothing in the
run's own data points at the product. Roughly 6.5 minutes of a 4-hour run: **no result, none counted.**

**What was done and what could not be.** The recovery steps asked for -- `assert_coherent` and a
reconciler dry-run over the stuck proposals and runs *before* touching anything, then
`reconciler --mode state-only` to close them, the enrollment withdrawn through the CLI, and the
checks (transitions = audit events, no schema difference, no abandoned proposal with a capability)
-- could not be done on that state, because it no longer existed when work resumed (next
paragraph). Nothing was edited by hand. The reconciler dry-run was run on the database that is
there, and its plan is empty (`{"summary": {}, "outcomes": {}}`, exit 0); the database holds 0
engagements, 0 proposals, 0 runs, 0 audit rows, 0 enrollments. That is what was verified, and it
says nothing about the state that was lost.

**The second event (2026-10-17 03:19 UTC): the machine was replaced, not restarted.** Observed
at 03:21: `uptime` 1-2 min; kernel `6.18.44-fc-v139` (the earlier boot was `v114`); a Firecracker
micro-VM (the kernel command line and the ACPI tables say so); the repository checkout's birth time
is 2026-10-16 02:29:17, the start of the session, and it was at a commit from before the session's
work (the pushed branch had everything); the Postgres data directory is from 2026-10-03 and holds
only the default databases; there is no `.venv`, no `.env`, no scratch directory (so no
`soak_main/` with its last resource sample), no `/var/lib/docker`, no Docker images, no `opa`;
`last -x` has no entry; journald has no files; the kernel log of this boot has no OOM kill, panic
or filesystem error; `/` is 24 % full. The environment was rebuilt from the repository
(`make setup`, `scripts/init_db.sh`, `dockerd`, the nmap image, OPA 1.9.0 -- 58/58).

**Cause: not determinable from inside the machine.** What the evidence supports: the root file
system was restored to an earlier image by the platform (a snapshot restore or a replaced VM);
nothing seen supports a cause inside the guest (no OOM, no panic, a disk with room). What it cannot
say: why, or when exactly -- the guest logs of the earlier boots are not on this disk. What was
*not* done and should have been: the last one-minute sample of attempt 1 (containers, networks,
memory, connections at the time it stopped) was not read before the disk was replaced; the counts of
containers and networks at that moment are therefore **unknown**. On the rebuilt machine there are
0 containers and 0 networks before the first image was built. The lesson is the heartbeat file and
a rule of this document: read the last sample and the kernel log of a stopped run *first*, before
any other step.


**Re-run 1 -- interrupted by a second host restart (2026-10-17).** Started 04:14:36 UTC from commit
51c87f8. Last heartbeat 04:20:07, last event 04:20:22, six minutes in, no fault yet injected and no
finding. At 04:33:36 the host reported `up 1 min`, a new boot id (`5ecd084d...` -> `54825409...`),
the same kernel (`6.18.44-fc-v139`), and **the disk intact** this time (checkout, `.venv`, `.env`, run
directory, Postgres and Docker storage). The previous boot had begun about 03:19:30, so it had lasted
about 61 minutes. Read first, before anything else (`docs/D66_SOAK_RERUN1_INTERRUPTED_2026-10-17/`):
the last sample (04:19:49) was ordinary -- resident memory 62-74 MB per process, at most 31
descriptors, 18 Postgres backends, none idle in a transaction, 1 running tool container, 0 exited,
3 sandbox networks; the kernel log of the new boot shows no OOM kill, panic or file-system error;
the disk is 33 % full, 15 GB free. **Cause: again not determinable from inside**; nothing points at the
soak or the product (the run had injected no fault). Two events of this kind in a day (02:38 and
04:20-04:33), one of which replaced the machine, make "the host is not stable for four hours" the
working conclusion, and it is a conclusion about the environment, not about the code. The run is
marked **interrupted**; it is not resumed, joined or counted. It is the first of the two re-runs.

**Recovery of re-run 1's state, in the order asked** (the state existed this time):
before any change, `assert_coherent` (175 proposals in 3 engagements), no capability on an abandoned
proposal, I7 in the database (153 runs), audit events = state transitions (proposal.submitted 175/175,
policy.decided 175/175, capability.issued 153/153, tool_run.started 153/153, tool_run.succeeded
152/152, tool_run.refused 1/1, evidence.recorded 152/152, approval.granted 43/43) and the unresolved-
intent list (0) all held, and a reconciler dry-run planned nothing. One proposal was open:
`awaiting_approval` (a person's, which the reconciler leaves alone by design,
D64 design: "`awaiting_approval` is a person's, not a fault; untouched"); `reconciler --mode
state-only` (the soak's switches, 901 s, 0 actions) left it as designed. It was then denied through the
operator CLI (`scripts/approvals.py deny`, the transactional path, so its provenance is recorded), the
three enrollments were withdrawn through `scripts/manage_scheduler_enrollment.py withdraw`, and the
baseline policy layer was retired with the same helper the soak's own teardown uses (there is no CLI
for the test baseline). No SQL was written. After: the same five checks hold, no enrollment is live,
no container exists, the three sandbox networks remain (kept by design, one per allowlist).
**Not done:** the "schema is identical" comparison of `scripts/check_reconciler_run.py` needs a
`before` snapshot taken before the reconciler ran and none was; what can be said is that Alembic is at
the head (`0026`) and no DDL ran.

**Re-run 2 -- interrupted by a third host restart (2026-10-17); both re-runs are used.** Started
04:52:06 UTC from commit eed3db6 (the tree of 51c87f8 plus evidence). Last heartbeat 04:58:07, last event
04:58:33 -- six minutes in again, no fault injected, no finding. At 05:38:45 the host reported `up 0 min`
and a new boot id (`54825409...` -> `5539106d...`), same kernel, disk intact. Read first
(`docs/D66_SOAK_RERUN2_INTERRUPTED_2026-10-17/`): the last sample (04:58:20) was ordinary again -- 63-76 MB
per process, at most 31 descriptors, 18 backends, no tool container running, 6 sandbox networks, 207
proposals terminal; the new boot's kernel log has no OOM kill, panic or file-system error. **Cause: not
determinable from inside.** The boot it died in had lasted about 26 minutes (heartbeat host uptime
1534 s).

**The three interruptions side by side** (UTC, 2026-10-16/17): the host stopped answering at ~02:38 and was
a fresh boot at 03:24 (a gap of at least 46 min); at ~04:20 and was a fresh boot by 04:33 (about 13 min);
at ~04:58 and was a fresh boot at 05:38 (about 40 min). The boots lasted: unknown, about 61 min, about 26
min. Each time the last sample was ordinary and the kernel log of the next boot was empty of faults; the
first interruption was followed by a replaced disk, the other two were not. Nothing seen ties them to the
soak (each came before the first fault could be injected), to a resource cap, or to the product. They
are a property of the environment, and a four-hour run cannot be completed in it. No claim is made
about *why* the host is restarted.

**Recovery of re-run 2's state** (same order, no SQL): the five checks held before any change (218
proposals, 188 runs, audit = transitions) and a dry-run planned nothing. Five proposals were open: three
`awaiting_approval` (a person's) and two `approved` with no run yet (the scheduler's to dispatch). The
reconciler in `state-only` (600 s, 0 actions) left all five, as designed. The two approved ones were
dispatched by the product's own scheduler run for 75 s (188 -> 190 runs, both `succeeded`); the three
waiting ones were denied with `scripts/approvals.py deny`; the enrollments were withdrawn with the CLI;
the baseline layer was retired with the soak teardown's helper. After: the same five checks hold, every
proposal is terminal, no run in flight, no live enrollment, no container.

**Where the soak goes now.** `.github/workflows/soak.yml` runs it on a GitHub-hosted runner: weekly
(Sunday 02:17 UTC) and on demand (`hours` input; 0.2 only tries the workflow). A local PostgreSQL, the
Docker daemon started by hand (so that the `docker_restart` fault can restart it; systemd's socket
activation is stopped), the nmap image, the pinned deadline helper; the conductor runs as root; the report
is the step summary and the run directory (minus the raw container evidence) is an artifact for 30 days.
**It has not been run.** Its first run is a smoke run (`hours` = 0.2) to see that the setup works on a
runner; the faults assume things about the machine that a runner may not grant (the `docker_restart` and
`postgres_restart` faults, resource caps tuned for this host), and what the first runs show about that is
the next finding, not a result about the product. There is no four-hour result in this repository yet.
