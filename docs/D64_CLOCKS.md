# D64 — which clock judges what, and how far apart two of them may be

**Completion 3, item 6** (ACCEPTANCE 5.93). Claims are tagged **[E]** measured on this machine, **[R]** read from the code,
**[D]** deduced and not reproduced here.

A threshold in the reconciler is always a comparison between *two readings of a clock*. It is only meaningful if both
readings come from the same clock, or from clocks that are known to agree. This page lists every such comparison, names the
clock each side comes from, says what happens when they disagree, and gives the number the setting `RECONCILER_MAX_CLOCK_SKEW_S`
is derived from.

## 1. Every comparison, and the clock on each side

| # | What is judged | Left reading (clock) | Right reading (clock) | Where | When the two disagree |
|---|---|---|---|---|---|
| 1 | a proposal's age: `received`/`decided` past the grace, `dispatching` past `B+P+Q`, a lapsed lease, an expired approval | `stage_updated_at`, `lease_expires_at`, `valid_until` (**database**) | `now()` in the same statement (**database**) | `reconciler_stuck_proposals()`, `StuckRow.db_now_us` | They cannot: one clock. The host's clock is not an input — shown by moving it (`test_proposals_are_judged_by_the_databases_clock_alone…`) [R][E] |
| 2 | a tool container or proxy past its bound | `State.StartedAt` (**Docker daemon**) | `host_now_us`, read just after the listing (**host**) | `plan._overdue_tool`, `plan._proxy` | a skew of `s` moves the deadline by `s` — **guarded** (§3) |
| 3 | an exited container past its retention | `State.FinishedAt` / `Created` (**daemon**) | `host_now_us` (**host**) | `plan._at_rest` | as 2 — guarded |
| 4 | an idle network | `Created` (**daemon**), and the host time this process first saw it idle | `host_now_us` (**host**) | `plan._idle_network` | as 2 — guarded |
| 5 | a network that blocked a refused run | `last_used_us`, `last_conflict_us`, `db_now_us` (**database**, all three) | each other | `plan._conflict_blocker` | They cannot: one clock [R] |
| 6 | the daily cap on removals for a range conflict | the host time of each removal this process made | `host_now_us` (**host**, both) | `Reconciler.conflict_removals_24h` | One clock, but it can *step*: a host clock moved forward by more than 24 h forgets the removals. The other four conditions still hold; the memory is per process anyway |
| 7 | a credential or TLS file's age | `mtime` (**kernel of the machine the directory is on**) | `host_now_us` (**host**) | `plan._file`, `act_files` | Same kernel when the directory is local (the default, the temp dir). A network file system's `mtime` is the server's clock: **not guarded; unsupported** (§5) |
| 8 | waits, hold-backs, back-off, the failure summary, the verify wait | `time.monotonic()` | `time.monotonic()` | `service`, `act_docker` | Immune to steps by construction |

So exactly two pairs ever compare readings of *different* clocks: Docker's against the host's (2, 3, 4), and — only if the
directory is not local — the file system's against the host's (7).

## 2. What was measured on this machine [E]

`python -` with 50 readings each, 2026-10-14; the host is a Firecracker VM, clock source `tsc`, one kernel.

| pair | measured | how |
|---|---|---|
| host − Docker daemon | **+1.75 … +4.36 ms** (mean +3.3 ms); the `info` call takes 8.8 ms (median), 11.3 ms (worst) | `observe.docker_skew_us`: the host's time at the middle of one `info` call against `SystemTime` in the reply |
| host − database | **−0.46 … +0.03 ms**; round trip 0.25 ms (median) | the host's time around one `clock_timestamp()` |
| file `mtime` − userspace clock | the kernel's stamp is up to **3.8 ms earlier** than the userspace clock read just before the file was made, and never later than the clock read just after | `mkstemp`, `stat`: a coarse kernel timestamp (one 4 ms tick) |

Here the daemon, the database server and the file system share the host's kernel, so any difference is measurement error: the
reading's error is at most half the round trip (4.4 ms) and the readings above are inside it. The `SystemTime` field is in the
daemon's own zone (`Z` here); `observe.parse_rfc3339_us` reads `Z` and `±hh:mm`, tested with a daemon ten hours east.

**Where a real skew can come from [D]** — none of these exist on this machine and none was reproduced: a remote daemon
(`DOCKER_HOST=tcp://…`), a Docker Desktop / WSL2 virtual machine whose clock drifts while the laptop sleeps, a VM resumed from a
snapshot, an NTP step. They are why the guard exists; the test that stands in for them moves the *host's* clock by a day against a
real daemon (§3).

## 3. The guard

`RECONCILER_MAX_CLOCK_SKEW_S` (recommended 5; no default, like every threshold). Each pass measures the skew first
(`observe.docker_skew_us`); `plan` then does this:

* skew within the bound (`|skew| ≤ MAX_CLOCK_SKEW_S`): nothing changes;
* skew beyond it → **no kill, no removal of a container, proxy or network is asked for**, and the plan carries
  `report:docker_clock_skewed`;
* skew not measurable (no `info`, no `SystemTime`, a time that does not parse) → the same, as `report:docker_clock_unknown`.
  An unreadable clock is not a zero skew;
* proposal transitions and file unlinks are not held back: their clocks (1, 7) are not the daemon's.

The reports appear in the dry run's report lines, in the `planned` counts of `reconciler.started`, and in `--once` output.

**Derivation of the number.** The sensitive comparison is the kill: a container is killed when `now ≥ StartedAt + B + K`, `K =
KILL_MARGIN_S = 60` being the longest the control plane's own `kill()` may take. A host clock ahead of the daemon's by `s` makes
the reconciler kill `s` seconds early, so with `s ≤ K/4` it can never act before `B + 3K/4` — after the budget, and after the
in-container deadline (`B + slack`) and the control plane's own kill have had their chance. `load()` refuses a bound above a quarter
of the margin (`SKEW_FRACTION_OF_MARGIN`). Retention (24 h) and the network idle time (1 h) are three to five orders of magnitude
longer than the bound: for them any bound that protects the kill is far more than enough. 5 s is a thousand times the error
measured here and a twelfth of the margin.

**Evidence** (`tests/test_reconciler_clocks.py`): the bound is inclusive at exactly the limit and exclusive one microsecond
beyond; every Docker action kind is withheld, not only the kill; the reports that need no clock are still made; with a real daemon
and a host clock one day ahead, a running container that is a day overdue by that clock is asked to be killed when the bound is
widened past the day and is **not** asked for with the configured bound (`docker_clock_skewed`), while by an honest clock it is not
overdue at all.

## 4. What the database's clock does and does not promise

`now()` is the start of the *transaction*, and the pass reads the stuck proposals, the run states and the conflicts in one
transaction through the reader role, so `db_now_us` is as old as that read: milliseconds on a small database, 3.8 s for the 1,403
stuck rows of the first dry run [E]. Every proposal looks that much *younger* than it is, never older: an action is late by at most
that, never early. `stage_updated_at` is written by the same server's `now()`, so an error of the server's clock moves both sides of
the comparison together; only a *correction* of that clock between the write and the read shifts a proposal's apparent age, by the
size of the correction [D].

## 5. Limits, stated

* the skew is measured once per pass, before the containers are listed. A step in either clock *during* a pass is not seen until
  the next one; the act half re-inspects every object by full id, labels and state immediately before acting, but does not
  re-measure the clock;
* the bound protects Docker objects. A directory on a network file system (`--directory`) is outside it and unsupported;
* the memory of removals for a range conflict is per process and uses the host's wall clock (row 6);
* a clock that *steps backwards* during a long-running process makes `time.time()` readings non-monotonic; the only places that
  use wall time for an interval are rows 2–4 and 6, and a step of more than `MAX_CLOCK_SKEW_S` in the host's clock shows up at the
  next pass as a skew against the daemon, if the daemon did not step with it.
