# F3 -- the Docker daemon dies under a dispatch in flight (ACCEPTANCE 5.109)

*Found by the soak pilots (`docs/D66_SOAK_PILOT_2026-10-15.md`), fixed and drilled on 2026-10-16.
Evidence: `docs/D66_F3_DOCKER_RESTART_DRILL_2026-10-16/` (`rounds.json`, `reconcile.json`, the
scheduler logs, the Docker events). Claims are tagged [R] read in code, [E] experiment, [D] derived.*

## What was wrong

`scheduler.service._translate` knew two causes (audit failure, lost database). A
`requests.ConnectionError(FileNotFoundError)` raised by `sandbox.run` while a dispatch was running
fell through to `unexpected_error`, exit 1, where the exit-code table says 5 (`docker_lost`) [R][E].
It is F1's mirror (5.107): the reconciler once called a vanished *object* "Docker lost"; the scheduler
called a lost *daemon* "unexpected". Both came from two services classifying Docker's exceptions each
on its own.

## The fix: one classification

`control_plane/docker_health.py` is the only place that decides what a Docker exception means:

| class | exceptions | what a service does |
|---|---|---|
| `GONE` | `NotFound` (404) | handled where the call is made; at the top of a service it is a defect |
| `LOST` | `requests` errors, builtin connection/timeout `OSError`, SDK errors with no HTTP answer, HTTP 5xx | `docker_lost`, exit 5 |
| `ANSWERED` | HTTP 4xx other than 404 | a defect, exit 1 |
| `None` | everything else, including host file-system errors outside a Docker error's chain | not Docker's |

The scheduler's and the reconciler's `_translate` both call `docker_health.is_lost`.
`tests/test_docker_health_structure.py` (AST) fails if either service imports `docker`/`requests`
exceptions or classifies them itself. `tests/test_docker_health.py` has the table, a check that both
services agree on it, and a scheduler test that raises the real exception chain mid-dispatch and
requires exit 5. Mutations: `D66-F3-*` in `scripts/mutations_d66.py`.

## The drill: ten restarts of the daemon under a dispatch [E]

`scripts/drill_scheduler_docker_restart.py run`: the product's `scripts/run_scheduler.py` dispatches
an approved proposal to a real container; the moment the container runs, `dockerd` gets SIGTERM, is
awaited, and is started again. Ten rounds, one engagement, ten proposals.

| | result (10 of 10 rounds) |
|---|---|
| scheduler exit | **5** in every round, 5.2-6.3 s after the daemon was told to stop |
| container after the daemon was back | `exited`, exit code **143** (SIGTERM); restart policy `no`; never running again by itself |
| proposal / run | stayed `dispatching` / `running` -- the scheduler does not touch them |

### How does the in-flight run end after the restart?

Not by the scheduler. A proposal in `dispatching` is never selected again: `decide.py` selects only
`pipeline_stage = 'approved'`, and counts `dispatching` as "stuck" for the summary [R]. The
reconciler ends it (run with the soak's switches `kill`, `container` and the soak's thresholds, on the
drill's engagement only, `reconcile.json`):

* all ten proposals went to `recorded` / `unknown_outcome` (run `unknown_outcome`), by
  `reconciler.dispatch_unknown_outcome`;
* **1336-1355 s** after the run started (median 1343 s); the threshold is B + P + Q = 130 + 915 + 300
  = 1345 s, plus the pass period [E];
* nine containers were then removed by the reconciler (`remove_container`, reason
  `run_unknown_outcome`, after the retention); the tenth was removed by the drill's `clean` because the
  reconciler was stopped as soon as all ten rows had left `dispatching` [E].

The 21-23 minutes are the price of not knowing: the product cannot tell a run whose process died from
one that is still working until B + P + Q has passed. That is the design (5.103/5.104), not a delay
this fix introduced.

### Can the same run be dispatched again when the container comes back to life (I7)?

No, in 10 of 10 rounds [E]. From round 6 on the dead container was started by hand
(`docker start`, status `running` afterwards in 5 of 5 rounds), then a new scheduler was left running
for 40 s. In every round, for the proposal:

| | counted | result |
|---|---|---|
| `scheduler.dispatched` audit records | 10 rounds | **1** each |
| `tool_runs` rows | 10 rounds | **1** each |
| containers created for the run (Docker events) | 10 rounds | **1** each |
| containers carrying the run's label afterwards | 10 rounds | **1** each |

Why: the second scheduler never selects the proposal (stage `dispatching`, not `approved`) [R]. This
drill shows that gate; it does not test any second line of defence behind it (that a selection of the
same proposal would be refused is not claimed here). The revived container is not adopted either: it
finished (`Exited (0)`) and was left for the reconciler's `unknown_outcome` path, which removed it.

## Not in the repository

The reconciler archived the inspect output and logs of the unknown-outcome containers it removed
(`evidence/`, mode 0700). That is raw container data (environment, tool output), so it was moved out
of the tree and is not committed; the drill's own records are.

## Limits

* The drill restarts the daemon once per dispatch, during the first 0.2-0.4 s of the container's life.
  A restart at another moment of the dispatch (before `create`, after the container exited and before
  the result was written) is covered by the unit tests and by the soak's random faults, not by this
  drill.
* `dockerd` runs without live-restore here: running containers are stopped. With live-restore the
  container would survive; the scheduler would still see the daemon vanish (exit 5), and the run would
  end in whatever way the container ends. Not drilled.
