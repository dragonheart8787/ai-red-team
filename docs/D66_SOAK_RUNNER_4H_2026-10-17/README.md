# The four-hour soak on a GitHub runner, 2026-10-17

`soak.yml`, run **39017478408**, `hours` 4, requested by a push of `.github/soak-request.json`
(commit ffc87db of this branch, after the smoke run passed). Traffic and faults 08:29:30-12:29:30 UTC (exactly
4.0 h), drain to 12:41:50 (12 minutes: nothing in flight remained), job 08:28-12:42. **Outcome: no
finding.** Everything below is read from the run's own report and journal (artifact `soak-run`, Artifact ID
12101471388, 30 days), printed to a job log by `soak-report.yml` (run 39033689145) because the artifact
cannot be fetched from the development machine. Nothing was repaired, relaxed or re-run.

## What it did

| | |
|---|---|
| proposals | **7,634** (6,603 recorded/succeeded, 757 closed/decision_DENY, 251 closed/approval_denied, 8 recorded/unknown_outcome, 4 closed/docker_unreachable, 10 closed/dedup_hit, 1 recorded/failed) |
| runs | 6,616 (6,603 succeeded, 8 unknown_outcome, 5 failed) |
| tool containers created | **6,610**, none for the same run or proposal twice (I7 docker) |
| HUMAN_APPROVAL | 2,036 granted and dispatched by the scheduler, 251 denied |
| audit rows | 53,749; database 55.5 MB at the end |
| reconciler | 755 passes, none limited/held back/truncated; 8 `mark_unknown_outcome` and 8 `remove_container`, all `done`, 8 evidence archives |
| container exit codes | 0 x6,607, 143 x4 (the daemon's restarts), 137 x1 |

**Audit event types of the run, with their counts** (from the report; this is the list 5.113 refers to):
approval.denied 251, approval.granted 2,036, capability.issued 6,626, engagement.created 3,
evidence.recorded 6,604, policy.decided 7,634, policy_layer.published 3, policy_reviewer.opinion 7,634,
proposal.submitted 7,634, reconciler.action_intended 8, reconciler.container_removed 8,
reconciler.dispatch_unknown_outcome 8, reconciler.evidence_saved 8, scheduler.dispatched 2,036,
scope_object.registered 3, tool_run.failed 1, tool_run.refused 4, tool_run.started 6,616,
tool_run.succeeded 6,603. **There is no `run.late_result`** (the event of the late-result path, 5.74): the
run did not exercise it.

## Faults: 16, every kind at least twice, all took effect, none unrecovered

| fault | times | recovery s (min / median / max) |
|---|---|---|
| postgres_restart | 2 | 12 / 18 / 24 |
| docker_restart | 3 | 15 / 17 / 20 |
| kill9_scheduler | 3 | 12 / 16 / 22 |
| kill9_reconciler | 3 | 6 / 6 / 9 |
| kill9_control_plane | 3 | 12 / 12 / 18 |
| pause_container | 2 | 90 / 94 / 98 (bounded by the 75-89 s hold) |

Service exits, 19 in all: 9 `kill -9` from the injector; scheduler 3 and reconciler 2 with **exit 5**
after the three daemon restarts (the shared classification of 5.109, in a real run); scheduler 2 and
reconciler 2 with exit 6 after the two Postgres restarts; the worker once at the end. None unexplained.
"What needed a person": nothing.

## Checks: executions

16 executions of each check (coherence, capability-on-abandoned, I7 database, I7 docker, audit pairing,
residue, connection leak, unresolved intents, schema identity); the drain check once; residue and
connection-leak judged 13 of 16 (the first three cycles had fewer than four 15-minute windows); **none
with zero**; all passed. Schema identical to the start at all 16 (453 facts). Audit pairing at the end:
proposal.submitted 7,634/7,634, policy.decided 7,634/7,634, capability.issued 6,626/6,626,
tool_run.started 6,616/6,616, tool_run.succeeded 6,603/6,603.

## Residue and trends

* Containers: floors per 15-minute window never above 3, no run of rises; exited tool containers peak 4,
  0 after the drain; sandbox networks constant 3; proxies 0; credential/TLS files 0. Evidence files grow by
  design (2 per `unknown_outcome` run): 16.
* Resident memory per process incarnation: scheduler 72 -> 74 MB (slope <= 1.8 MB/h), reconciler 64 -> 65,
  worker 77 -> 78, **conductor 74.6 -> 109 MB over 251 minutes (7.5 MB/h; hourly 87, 94, 101, 110)** -- the
  one trend that is not flat; no threshold was set for memory (D66_SOAK.md 5) and none was judged. The
  conductor holds the journal's samples in memory; it is the harness, not the product.
* Descriptors at most 45 per process, connections to Postgres 3-8 per process, backends min 7 / median 15 /
  max 21 of 77, nothing idle in a transaction. Postgres 527-743 MB over its processes; dockerd 84-91 MB.
  Disk: run directory 10 MB; 86.8 GB free of 147 GB.

## Observed, and not covered by any check

1. **dockerd warns about the sandbox's own spelling, 13,224 times** (about twice per container):
   "Security options with `:` as a separator are deprecated ... use `=`". The sandbox passes
   `security_opt=["no-new-privileges:true"]` at two sites (`tool_gateway/sandbox.py` 732 and 1052). It
   works today; a Docker release that drops the old separator would refuse every run. -> ACCEPTANCE 5.114.
2. **`SAVEPOINT can only be used in transaction blocks`, 251 times** in the Postgres log -- exactly the 251
   denials; 251 of 251 denied proposals have no provenance. The harness approver's autocommit connection
   (5.110), not the product's path. Known before the run.
3. **One dockerd error outside any fault window:** 10:03:42 `failed sending message on channel ... containerd.sock.ttrpc ... broken pipe`, once, five minutes after the daemon restart of 09:58. Not
   explained; no run, container or check was affected that the report shows.
4. **10 capabilities issued for 10 requests that were then closed `dedup_hit`** (capability.issued 6,626
   against tool_run.started 6,616). The numbers coincide; the cause was not examined here.
5. **3 worker retries** ("Connection aborted, FileNotFoundError") at the daemon restarts of 09:58 and 10:39,
   by design; the retried requests were either resumed or closed as dedup hits, never run twice.
6. **A pause that could not be undone:** at 08:57:38 the paused container's unpause failed ("Not found")
   after 89 s -- the container was gone (its run's budget, then the reconciler). The fault still took effect
   and the system recovered in 98 s. dockerd logged "resuming exited container from paused state".
7. Unexplained log groups by the numbers: 3 groups, 13,476 lines = (1) 13,224 + (2) 251 + (3) 1; the
   untimed lines are the service exits listed above.

## What this run is not

A single run, on one runner kind, with the harness's workload (`network.scan`, no egress proxy, no
credentials), one seed. The faults are the six of D66_SOAK.md; no partition, full disk, skewed clock or OOM
kill. The smoke-only exemption of the residue check did not apply: `smoke.not_enforced` count 0.
