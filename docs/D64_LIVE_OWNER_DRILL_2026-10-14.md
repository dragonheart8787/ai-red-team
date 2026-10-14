# The reconciler beside live control planes (2026-10-14)

**What this is.** `scripts/drill_reconciler_live_owner.py run`, on this machine's Docker and PostgreSQL, with the product's
own command line (`scripts/run_reconciler.py`, loop mode, on a pseudo-terminal, the phrase typed). It closes the gap the first
drill (`D64_DRILL_2026-10-14.md`, ACCEPTANCE 5.95) stated: that drill showed a container whose owner is alive and late left
alone at two moments (+45 s and +80 s) and did not show passes **through** the interval that matters. This one runs the
reconciler continuously through `[B, B + margin + 10 s]` while the owners are alive.

**Setup.** `B = 30 s` (every run budget), `margin = 60 s` (`RECONCILER_KILL_MARGIN_S`, `.env.example`'s value), so the
reconciler's bound for a container is `B + margin = 90 s` after its start and the interval is `[+30 s, +100 s]`. One
reconciler, `--mode state-only --interval 3 --enable kill`, limited with `--engagement` to the drill's three engagements (a wait
of 3 s after each pass; a pass takes about 2 s; so one pass roughly every 5 s). **Only `kill` is on** for this loop. Three tool
containers, each owned by a real sandbox run in a control-plane process of its own, with no in-container deadline (so the
host-side owner is the first line and the reconciler is the backstop), each running `ncat -l -v` so that its log is not empty:

| | the owner | what must happen |
|---|---|---|
| L1 | alive, healthy | killed by its owner at about `B`; the reconciler writes nothing |
| L2 | alive and **late**: stopped (SIGSTOP) at the start and continued 40 s later, ten seconds after the deadline | killed by its owner once it continues, inside the margin; the passes that run while it is overdue leave it alone |
| F | alive and **frozen**: stopped for good | killed by the reconciler, at the first pass at or after `B + margin`, and not before |

Docker's own `docker events` is recorded from before the first container; every pass is stamped with the moment its output
was seen; the state of each owner process is read from `/proc` once a second.

## What happened

```
B = 30 s, margin = 60 s, the reconciler's bound for a container is B + margin = 90 s after its start; a wait of 3 s after each pass; retention 45 s
the reconciler is passing (2 passes so far)
containers started at L1 +0.0s, L2 +0.6s, F +1.2s
the late owner (L2) continues at +40.6s, after 40 s stopped; its deadline passed at +30.6s
the reconciler stopped (exit 0) after 21 passes
waiting 33 s for the retention of F's corpse
Docker's own record (seconds after the first container started):
  +   -0.0  L1  create
  +    0.2  L1  start
  +    0.6  L2  create
  +    0.7  L2  start
  +    1.2  F   create
  +    1.4  F   start
  +   30.2  L1  kill signal 9
  +   30.3  L1  die
  +   30.3  L1  destroy
  +   40.7  L2  kill signal 9
  +   40.8  L2  die
  +   40.8  L2  destroy
  +   95.2  F   kill signal 9
  +   95.3  F   die
  +  150.1  F   destroy
  audit L1: []
  audit L2: []
  audit F: ['action_intended', 'container_killed', 'action_intended', 'evidence_saved', 'container_removed']
passes: 21 in all; 13 inside [B, B + margin + 10 s] = [+30, +100] s of the containers' start (a wait of 3 s after each pass, plus the pass itself); the longest gap in that interval is 5.5 s
  L1: killed at +30.2s of its life by a process that was 'S (sleeping)'; the reconciler's bound was +90s
  L2: killed at +40.1s of its life by a process that was 'T (stopped)' (continued at +40.6s); the reconciler's bound was +90s
  L2 was past its deadline for 10.1 s (inside the 60 s margin) when its owner killed it; 2 reconciler pass(es) ran while it was overdue and none acted
  F: killed at +94.0s of its life, its owner 'T (stopped)'; the reconciler's bound is +90s
  the first pass that planned a kill: +94.1s of F's life
  F's trail: ['action_intended', 'container_killed', 'action_intended', 'evidence_saved', 'container_removed']
  inspect_sha256 in the trail 87730216c5bd7f01...  sha256 of 9ce77a614a35ad... 87730216c5bd7f01...
  logs_sha256 in the trail da3687f7d214da22...  sha256 of 9ce77a614a35ad... da3687f7d214da22...
  files: ['9ce77a614a35ad....json', '9ce77a614a35ad....logs']
RESULT: OK
removed network cyberorch-allow-c2b99762f9ec
removed network cyberorch-allow-c57edec6248b
removed network cyberorch-allow-7e568a886bd5
closed 1 stuck proposal(s) the drill's engagements left
```

## Result

| | killed at (after its own start) | by | the owner at that moment | the reconciler's bound | audit trail |
|---|---:|---|---|---:|---|
| L1 | 30.0 s | its owner | running | 90 s | **no event** |
| L2 | 39.9 s | its owner (continued at +40.6 s; the container was 9.9 s past its deadline) | stopped until then | 90 s | **no event** |
| F | 93.8 s | **the reconciler** | **stopped (SIGSTOP) the whole time** | 90 s | intent, then `container_killed` |

* **The kills of L1 and L2 are the owners'**: the reconciler wrote no audit event for either engagement, no pass planned a
  kill for anything before the bound, and L2's kill came at the moment its owner was continued.
* **The kill of F is the reconciler's**: its owner was stopped, the kill came 3.8 s after the
  bound, at the first pass after it (the pass before it ran at +89.8 s,
  which was 1.6 s short of the bound), and
  there is an intent before it and a verified result after it.
* **The reconciler was running through the interval**: 21 passes in all, 13 inside `[+30 s, +100 s]`
  of the containers' start; the longest gap between consecutive passes around the interval was 5.5 s.

### The passes (seconds after the first container started)

| when | what the plan held | |
|---|---|---|
| +  -6.0 s | nothing |  |
| +  -0.7 s | nothing |  |
| +   5.2 s | nothing |  |
| +  10.5 s | nothing |  |
| +  15.7 s | nothing |  |
| +  20.8 s | nothing |  |
| +  26.2 s | nothing |  |
| +  31.5 s | nothing | in the interval |
| +  36.9 s | nothing | in the interval |
| +  42.1 s | nothing | in the interval |
| +  47.3 s | nothing | in the interval |
| +  52.4 s | nothing | in the interval |
| +  57.6 s | nothing | in the interval |
| +  63.0 s | nothing | in the interval |
| +  68.4 s | nothing | in the interval |
| +  73.9 s | nothing | in the interval |
| +  79.3 s | nothing | in the interval |
| +  84.7 s | nothing | in the interval |
| +  89.8 s | nothing | in the interval |
| +  95.3 s | kill_container:overran_deadline 1 | in the interval |
| + 100.6 s | nothing |  |

### Docker's own record of kills and removals

| when | container | what |
|---|---|---|
| +   30.2 s | L1 | kill (signal 9) |
| +   30.3 s | L1 | destroy |
| +   40.7 s | L2 | kill (signal 9) |
| +   40.8 s | L2 | destroy |
| +   95.2 s | F | kill (signal 9) |
| +  150.1 s | F | destroy |

### The audit trail (the reconciler's events; L1 and L2 have none)

| when (s after the first container started, database clock) | event | payload |
|---|---|---|
| +   95.2 s | action_intended | {"kind": "kill_container", "reason_code": "overran_deadline", "subject_id": "RUN-78332c2cd341"} |
| +   95.3 s | container_killed | {"reason_code": "overran_deadline", "run_id": "RUN-78332c2cd341"} |
| +  150.0 s | action_intended | {"kind": "remove_container", "reason_code": "run_unknown_outcome", "subject_id": "RUN-78332c2cd341"} |
| +  150.0 s | evidence_saved | {"container_id": "9ce77a614a35ad5386c6144fc3a4c9f8b6ebe265ad6d97e389525708c23659ec", "inspect_sha256": "87730216c5bd7f01ba79df6c711994bc724eca7aa1743810b7a9a76a56abe578", "logs_sha256": "da3687f7d214da22883b176f2aa7880c1865c8823aaffc045496f160a7f0dde3", "run_id": "RUN-78332c2cd341"} |
| +  150.1 s | container_removed | {"reason_code": "run_unknown_outcome", "run_id": "RUN-78332c2cd341"} |

## F's corpse: the retention and the evidence archive (ACCEPTANCE 5.97)

F's run was declared `unknown_outcome` by hand, with one `UPDATE`, as the reconciler would do after `B + P + Q` (a quarter of an
hour, which the drill does not wait for). The retention was 45 s (`RECONCILER_RETENTION_S`). With `container` enabled and
`--evidence-dir` given, on the product's command line:

| moment (after the container stopped) | what |
|---|---|
| 8.7 s | dry run: **nothing planned** for the container |
| 13.9 s | real pass: **nothing done**; the container is still there |
| after the retention | dry run: `remove_container`, reason `run_unknown_outcome`; real pass: **done** |

Before the removal, `<container id>.inspect.json` and `<container id>.logs` were written to the evidence directory (mode 0600,
the directory 0700), and the audit trail says only this:

* container `9ce77a614a35ad5386c6144fc3a4c9f8b6ebe265ad6d97e389525708c23659ec`
* `inspect_sha256 = 87730216c5bd7f01ba79df6c711994bc724eca7aa1743810b7a9a76a56abe578`
* `logs_sha256 = da3687f7d214da22883b176f2aa7880c1865c8823aaffc045496f160a7f0dde3`

Both are the SHA-256 of the files as read back from the disk, and are the hashes of the copies in `evidence/` beside this file
(`sha256sum evidence/*` reproduces them). The log holds what `ncat` said (`Ncat: Listening on 127.0.0.1:9999`). The trail's order
for F is: intent to kill, killed, intent to remove, evidence saved, removed.

## What this does not show

1. **One host, one daemon, three containers.** The loop was limited to the drill's engagements with `--engagement`; the
   whole-host behaviour with the switches on is what the first drill showed (negatives untouched through every pass).
2. **"Every five seconds" is a wait of 3 s plus a pass of about 2 s.** The measured gaps are in the table above; the reconciler's
   latency after a bound is the gap (here up to 5.5 s) plus the time the pass takes.
3. **The run of F was declared unknown by hand**, not by the reconciler's own `mark_unknown_outcome` (which waits `B + P + Q`).
   That transition was drilled in the first drill (phase G).
4. **L2's lateness depends on how the sandbox's wait resumes.** Here its owner killed the container the moment it continued, 10 s
   past the deadline; an earlier run of the same drill (its report step failed on a typing mistake of the script, after the
   events were recorded) had the same owner kill 40 s past the deadline, 70 s after the container started, with five passes
   running while it was overdue and none acting. Both are inside the 60 s margin; the margin is what the passes respected.
5. Only `kill` was enabled in the loop; `proxy` was drilled in the first drill and `container` here only for the corpse.

## Mistakes of the drill's own, found by running it

* **A stopped owner was not stopped.** The first two attempts had the frozen and the late owners killed at their own deadline
  like the healthy one. The environment this runs in continues the stopped processes of a tool call when the call ends; the
  drill must run in a session of its own (`setsid nohup ...`), as it did here. (The first drill's frozen owner was an orphan, which
  is why it stayed stopped.)
* A range left behind by an earlier attempt made the sandbox refuse the next one (`a network is kept by the engagement that made it`):
  the drill now takes a random free range and removes its networks and containers when it ends, whatever happened.
* The report step compared passes with a count that assumed a pass every 5 s exactly; a pass takes time. The check is now that
  the passes reach both ends of the interval with no gap longer than 6.5 s.
