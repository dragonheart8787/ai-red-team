# The whole chain, with nobody editing a state (2026-10-15)

**What this is.** `scripts/drill_reconciler_full_chain.py run`, on this machine's Docker and PostgreSQL, with the product's own command line
(`scripts/run_reconciler.py`, loop mode, `--enable kill --enable container --evidence-dir`, on a pseudo-terminal, the phrase typed). It
closes what the two earlier drills left out on purpose: the first (`D64_DRILL_2026-10-14.md`) made its rows by hand, the second
(`D64_LIVE_OWNER_DRILL_2026-10-14.md`) set a run to `unknown_outcome` with an `UPDATE` because the reconciler's own mark comes a quarter of an
hour after the stage and the drill did not wait for it. **This one waits (30 minutes), and nothing in the drill writes a row after its setup.**

**Setup.** One engagement, one scope object, a policy that lets the pipeline decide; all made through the product's functions. A real
control-plane process runs `propose_action` through the whole pipeline with the product's `DockerSandbox` — decision, capability,
`dispatching`, a `running` run row, a real container from the nmap image — except that the tool's command is `sleep 3600` and no deadline helper
is put in the container, so that it outlives its budget (`B` = 30 s). That process is then killed with `SIGKILL`, 0.6 s after the container
started. The thresholds are `.env.example`'s (margin 60 s, `P` 915 s, `Q` 300 s) except the **retention, 1,500 s**: longer than the quarter
of an hour before `unknown_outcome`, so that the order the design promises can be seen — the container is at rest (killed) long before its
run is declared unknown, and must be kept after that until the retention is over. The reconciler ran every ~32 s (a pass of ~2 s and a
`--interval` of 30), 51 passes.

**What happened** (Docker's own events and the audit trail; seconds after the container started; `docs/D64_FULL_CHAIN_DRILL_2026-10-15/`):

| at | who | what |
|---|---|---|
| +0.0 / +0.2 | the control plane | container created and started (`create`, `start`) |
| +0.6 | the drill | the control plane is killed: proposal `dispatching`, run `running` |
| +106.8 | the reconciler | `action_intended` then Docker `kill signal 9` then `container_killed` (`overran_deadline`): the first pass at or after `B` + margin = 90 s; the pass before it, at +73, left the container alone |
| +106.9 | Docker | `die` — the container is at rest from here; its run is still `running`, so the plan does nothing about it (the run may still be recording) |
| +1269.5 | the reconciler | `dispatch_unknown_outcome`: proposal `dispatching → recorded / unknown_outcome`, run `unknown_outcome`, **1,269.7 s after the stage was written** (due at `B + P + Q` = 1,245 s; the next pass was ≤ 32 s later) |
| +1269.5 … +1634 | the reconciler | every pass sees the container at rest with an unknown run **and the retention not yet over**: no removal planned |
| +1634.8 | the reconciler | `action_intended`, the inspect output and the logs written, `evidence_saved` (ids and two SHA-256), Docker `destroy`, `container_removed` (`run_unknown_outcome`) — **1,527.9 s after the container finished** (retention 1,500 s) |

**Checked by the drill, all true:** exactly one `kill` and one `destroy` for the container in Docker's record; the kill after the control
plane was dead and not before `B` + margin; the audit events, in order, are exactly `action_intended`, `container_killed`,
`dispatch_unknown_outcome`, `action_intended`, `evidence_saved`, `container_removed`; `evidence_saved` is not after the removal; the two files
`evidence/<engagement>/<container id>.inspect.json` (5,095 bytes) and `.logs` (0 bytes — `sleep` prints nothing; the empty file is the evidence
of that) exist with mode 0600 in a 0700 directory and their SHA-256 are the ones in the audit trail; the audit payload holds ids and hashes only;
the final state is proposal `recorded / unknown_outcome`, run `unknown_outcome`; `assert_coherent` holds on the engagement; no result of the
reconciler was `failed`; the reconciler stopped on `SIGTERM` with exit 0.

**Found on the way, not in the product.** The first attempt did not start: the drill's `propose_action` call named no network allowlist and
the sandbox then derives the target's own address, a `/32`, on which Docker can attach no container
("no available IPv4 addresses on this network's address pools"). The scheduler passes the whole scope block, and so does the drill now; the
first attempt's network was removed by hand and its proposal had closed itself. (The soak's worker had made the same omission and was
corrected before it ran.)

**What this does not show.** The retention was lengthened to make the order visible; at its default (a day) the same sequence takes a day.
The container was killed by the reconciler and not stopped by an in-container deadline because the drill removed the deadline on purpose; a
container with the helper in it would have ended by itself at 30 s and gone straight to "at rest". Only `kill` and `container` were on.
