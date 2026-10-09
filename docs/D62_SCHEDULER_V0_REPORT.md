# D62 — Scheduler v0 (D58-1/2/3/4): implementation report

Design and decisions: `docs/D62_SCHEDULER_V0_DESIGN.md` (read it for *why*). This is what was built, what
was measured, and what is still open.

## 1. What it does

`python scripts/run_scheduler.py` finds `approved`, not-yet-dispatched proposals in **enrolled** engagements
and calls `dispatch_approved` for each, one at a time. Level-triggered: every tick re-derives everything from
the database; nothing is cached (the policy is loaded by the execution step at the moment of dispatch).
Enrollment is `scripts/manage_scheduler_enrollment.py` (an operator's act, typed confirmation on a terminal).

Not done (named in the brief): planning (D58-12), the failure ladder (D58-6), the reconciler (D58-9), a
requeue sweeper, credential selection (D58-15/16), quotas (D58-13).

## 2. End-to-end evidence

`tests/test_scheduler_e2e.py` (real Docker, `cyberorch/nmap:local`): create_engagement → register scope →
enroll → `propose_action` (effective policy loaded from the database) → HUMAN_APPROVAL → real
`grant_approval` → **`Scheduler.tick()`** → tool ran in a container (`tool_runs` succeeded, exit 0), evidence
row written, `scheduler.dispatched` (actor `scheduler`) precedes `capability.issued`, and
`reconstruct_decision` returns the whole chain (`proposal.submitted … approval.granted,
scheduler.dispatched, capability.issued, tool_run.started, tool_run.succeeded, evidence.recorded`).

```
test_a_tick_dispatches_an_approved_proposal_and_a_real_container_runs_the_tool          PASSED
test_an_engagement_that_is_not_enrolled_is_never_touched                                 PASSED
test_withdrawing_an_enrollment_takes_effect_on_the_next_tick                             PASSED
test_a_paused_or_killed_engagement_is_deferred_once_not_per_tick[pause-engagement_paused] PASSED
test_a_paused_or_killed_engagement_is_deferred_once_not_per_tick[kill-engagement_killed]  PASSED
test_a_resumed_engagement_is_dispatched_and_the_resumption_is_recorded_once              PASSED
```

Full suite: **1691 passed** (13 m 54 s, serial). The scheduler's own files: 168 tests.

## 3. Roles and grants (complete list; `tests/test_scheduler_roles.py::GRANTS` enumerates every table and view)

| role | relation | privilege |
|---|---|---|
| `scheduler_reader` | `engagements` | SELECT (`engagement_id`, `status`, `kill_switch_engaged`) |
| | `scheduler_enrollment` | SELECT |
| | `scheduler_proposals` (view) | SELECT (`proposal_id`, `engagement_id`, `pipeline_stage`, `stage_updated_at`, `action_class`) |
| | `scheduler_state` | SELECT |
| `scheduler_admin` | `scheduler_enrollment` | SELECT, INSERT, UPDATE (`withdrawn_by`, `withdrawn_at`) |
| `scheduler_state_writer` | `scheduler_state` | SELECT, INSERT, UPDATE (`disposition`, `reason_code`, `since`) |

All three: LOGIN, NOSUPERUSER, NOBYPASSRLS. `cyberorch_app` has **no** grant on `scheduler_enrollment`,
`scheduler_state` or the view. The reader has no grant on `action_proposals`, `tasks`, `evidence`,
`credential_material`, `audit_log`, `approvals`, `capabilities`, `tool_runs`, `scope_registry`,
`policy_layers`; each is refused with "permission denied" on a real connection. Cross-engagement reads return
0 rows; a reader with no engagement bound sees no engagement data.

## 4. Mutations (each source or grant change was made, the scheduler tests run, then restored and re-run green)

| # | mutation | result |
|---|---|---|
| M1 | remove the lock (acquire returns True, `held()` True) | 3 red: second instance refused, killed lock connection, lock-lost exit code |
| M2 | enrollment read ignores withdrawal | red (29, mostly collateral: old withdrawn engagements get served); targeted: `test_withdrawing_an_enrollment…` |
| M3a | grant reader `SELECT (reason)` on `action_proposals` | 3 red (grant matrix, refused-list ×2) |
| M3b | grant reader `SELECT` on `audit_log` | 2 red |
| M3c | grant state writer `UPDATE (status)` on `engagements` | 1 red (grant matrix) |
| M4 | relax payload whitelist (accept any payload) | 19 red (extra keys, free text, enrollment audit) |
| M5 | a skip raises the exit-7 stop | 11 red incl. "skipped over many ticks" |
| M7 | skip recorded every tick | 5 red incl. "recorded once" |
| M8 | dispatch before recording the decision | 2 red (e2e ordering, audit-failure ⇒ no dispatch) |
| M9 | `deferred` every tick | 2 red |
| M10 | no reserved-address check | 3 red (real Docker: the container is attempted) |
| M11 | no Docker pre-check | red (`docker_lost` exit 5) |
| M12 | no lock check in `tick` | red (lock-lost tests) |
| M13 | `scheduler_state` CHECK without `IS NOT NULL` | 2 red (see §5) |
| M14 | a seventh skip code in the CHECK | 1 red (vocabulary equality) |

## 5. Findings during implementation

* **A CHECK passes on NULL.** The first version of the `scheduler_state` combination check accepted
  "skipped, no reason" (`NULL IN (…)` is NULL, and a CHECK passes on NULL). Found by the test for the closed
  skip vocabulary, fixed in migration 0019 (`reason_code IS NOT NULL` in each branch), mutation M13.
* A skipped proposal stays `approved` and is picked every tick. The exit-7 rule ("still approved after
  `dispatch_approved`") applies only to a proposal actually handed over; a skip `continue`s before it. The
  skip is recorded once (state row + `scheduler.skipped`); `TickReport.skipped` lists only new skips.
* Skip reasons are a six-code closed vocabulary in the database (`CHECK`) and in `vocab.SKIP_REASONS`; a test
  compares the literals in the constraints to the code, and tests that all six are accepted and that
  everything else (incl. NULL, defer codes, case/space variants) is refused.
* **Reserved addresses, on a real daemon:** a container pinned at the network, gateway or broadcast address of
  an internal bridge fails with "Address already in use"; a normal host starts
  (`test_docker_really_has_no_container_at_…`). A proposal targeting such an address is skipped
  `target_is_reserved_address` with no capability, run or container created (checked against the daemon's
  container list). Capacity re-measured: /32→0, /31→1, /30→1, /29→5, /28→13.
* The sandbox keeps its `cyberorch-allow-*` networks; a test that needs a fresh subnet uses its own.

## 6. Assumptions I made and you have not explicitly confirmed

* D-9: the `/27` cap for widening an `ip` scope, the widening itself, and the derivation table.
* D-7: the third role `scheduler_state_writer`.
Both are implemented as in the design note; reverting either is a migration and a table row in the tests.

## 7. Open / candidates

* `decision_reasons` has no vocabulary check; D58-12 will need one.
* `code.*` on private repos has the same credential-less limit as ACCEPTANCE 5.57.
* An `ip` scope's allowlist is a wider block than the authorized address (recorded as a widening); the clean
  fix is a `tool_gateway` change.
* Docker going away between the pre-check and `dispatch_approved` closes the proposal (needs D58-6's reopen).
* Raw errors after `start()` other than "never ran" remain unplaced.
* The v0 service does not reconnect or restart itself; a supervisor must not restart it blindly.
