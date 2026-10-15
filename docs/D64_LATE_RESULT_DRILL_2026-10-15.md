# The late result, on a real container (2026-10-15)

**What this is.** `scripts/drill_reconciler_late_result.py run`, on this machine's Docker and PostgreSQL. ACCEPTANCE 5.74 was found and fixed with a fake
container held open by a hook (22 tests, `tests/test_dispatch_late_result.py`). This is the same race with a **real** container and a **real**
control-plane process, for a result that arrives 70 seconds after the reconciler has declared the run unknown.

**Setup.** One engagement, a scope object over a `/29`, a policy that lets the pipeline decide. A control-plane process runs `propose_action`
through the whole pipeline with the product's own `DockerSandbox` and a real `nmap` run (budget `B` = 30 s, allowlist the scope block). As soon
as the tool container exists the process is stopped with `SIGSTOP`: the container goes on and ends by itself, and nobody is waiting for it. The
product's command line (`state-only`, **no switch enabled**, every ~30 s, limited to the drill's engagement) runs beside it with `.env.example`'s
thresholds (the product refuses a `P` or `Q` below the least the code implies, which is why this takes 21 minutes and not two) and a retention of
1,800 s, so that the container's output is still there when its owner comes back.

**What happened** (seconds after the stage `dispatching` was written; `docs/D64_LATE_RESULT_DRILL_2026-10-15/audit.json`):

| at | who | what |
|---|---|---|
| 0.0 | the control plane | `proposal.submitted`, `policy.decided`, `tool_run.started`; stopped with `SIGSTOP` |
| +1,255.8 | the reconciler | `dispatch_unknown_outcome`: proposal `dispatching → recorded / unknown_outcome`, run `unknown_outcome` (due at `B + P + Q` = 1,245 s) |
| +1,325.9 | the control plane | continued 70.0 s later: it finishes its run and records the result — `tool_run.succeeded` flagged `late_result`, and `run.late_result` naming the run and the proposal |

**Checked, all true:** the control plane exited 0 and returned `ALLOW` with its run; Docker created exactly one container for the engagement; there is
exactly one run for the proposal, `succeeded`, exit code 0, and one evidence row; the proposal ends `recorded / succeeded / succeeded` — the late
result **replaced** the unknown outcome, in one transaction, and stage detail and dispatch state agree; `run.late_result` is in the trail once, with
`run_id` and `proposal_id`; the reconciler's own `dispatch_unknown_outcome` record is still there, once, before it; `assert_coherent` holds; no
result of the reconciler was `failed`; it stopped on `SIGTERM` with exit 0 after 75 passes.

**What this does not show.** The owner's wait for its container was not cut short by the budget although more than the budget had passed while it was
stopped (it saw the container had exited and read its output); a control plane that had *died* and been replaced would not come back at all, and the
run would stay unknown (that is the common case, drilled in 5.103). The late result here is the owner's own, from the same process.
