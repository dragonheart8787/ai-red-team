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

Full suite: **1691 passed** (13 m 54 s, serial). The scheduler's own files: 168 tests (182 after §8).

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
| M14 | a sixth skip code in the CHECK | 1 red (vocabulary equality) |
| M15 | `ip` scopes widened to a block again (§8) | 24 red (the `ip` skip tests, incl. real Docker, and the derivation unit tests) |

## 5. Findings during implementation

* **A CHECK passes on NULL.** The first version of the `scheduler_state` combination check accepted
  "skipped, no reason" (`NULL IN (…)` is NULL, and a CHECK passes on NULL). Found by the test for the closed
  skip vocabulary, fixed in migration 0019 (`reason_code IS NOT NULL` in each branch), mutation M13.
* A skipped proposal stays `approved` and is picked every tick. The exit-7 rule ("still approved after
  `dispatch_approved`") applies only to a proposal actually handed over; a skip `continue`s before it. The
  skip is recorded once (state row + `scheduler.skipped`); `TickReport.skipped` lists only new skips.
* Skip reasons are a five-code closed vocabulary (six before §8) in the database (`CHECK`) and in `vocab.SKIP_REASONS`; a test
  compares the literals in the constraints to the code, and tests that all five are accepted and that
  everything else (incl. NULL, defer codes, case/space variants, the retired code) is refused.
* **Reserved addresses, on a real daemon:** a container pinned at the network, gateway or broadcast address of
  an internal bridge fails with "Address already in use"; a normal host starts
  (`test_docker_really_has_no_container_at_…`). A proposal targeting such an address is skipped
  `target_is_reserved_address` with no capability, run or container created (checked against the daemon's
  container list). Capacity re-measured: /32→0, /31→1, /30→1, /29→5, /28→13.
* The sandbox keeps its `cyberorch-allow-*` networks; a test that needs a fresh subnet uses its own.

## 6. Assumptions I made and you have not explicitly confirmed

* D-7: the third role `scheduler_state_writer` (implemented as in the design note).
* D-9 was first implemented with an `ip`-scope widening (a /29–/27 block); you decided against it, and it was
  removed (see §8). No assumption about it remains.

## 7. Open / candidates

* `decision_reasons` has no vocabulary check; D58-12 will need one.
* `code.*` on private repos has the same credential-less limit as ACCEPTANCE 5.57.
* **First deliverable after v0: separate the single-IP authorization from the Docker network range**
  (`tool_gateway`, `DockerSandbox.ensure_network`). Today an `ip` scope cannot run at all (one address fits no
  container, and widening the network would exceed the authorization), so it is skipped
  (`scope_narrower_than_sandbox_minimum`). The sandbox must be able to keep the authorized `/32` as what is
  checked and recorded, and choose its own pool for the network it creates.
* Docker going away between the pre-check and `dispatch_approved` closes the proposal (needs D58-6's reopen).
* Raw errors after `start()` other than "never ran" remain unplaced.
* The v0 service does not reconnect or restart itself; a supervisor must not restart it blindly.

## 8. Revision: `ip` scopes are skipped, not widened

* `allowlist.py` no longer derives a block: an `ip`-type scope is always skipped as
  `scope_narrower_than_sandbox_minimum` (any address, either family); `block_for_address` and the /27 cap are
  deleted. A `cidr` scope is still its own allowlist when it is a /29 or wider.
* `no_usable_block_for_address` is gone from `vocab.SKIP_REASONS` (five codes now). Migration 0019 (already
  pushed) is untouched; **0020** replaces the two `scheduler_state` CHECKs with the five-code versions. It first
  rewrites rows still holding the retired code to `scope_narrower_than_sandbox_minimum` (the code the scheduler
  now gives them) — with `FORCE ROW LEVEL SECURITY` switched off for that one statement, since the table's owner
  is otherwise blind to the rows. Checked locally: a seeded row with the old code was rewritten, upgrade and
  downgrade both work. A test requires the database to refuse the retired code.
* Tests: the "`.9` is widened to a /28" and "real-Docker `ip` scope dispatches" tests now assert a skip — no
  capability, no run, no container and no network created (the daemon's lists are unchanged), and
  `scheduler.skipped` recorded once over many ticks. Mutation **M15** (put the derivation back) turns 24 tests red.
