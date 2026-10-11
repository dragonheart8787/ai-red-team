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

## 4. Mutations (re-verified at D63 closeout 3; each run by `scripts/mutations_d62_d63.py`)

A mutation counts only if it compiled or ran, and the tests that went red went red **on an assertion** — not
because the mutation itself broke something (a syntax, SQL or import error). `scripts/mutation_check.py` enforces
that (ACCEPTANCE 5.70): it runs the tests unmutated first, applies the change, requires it to compile/import/run,
reads each failure's test name and the exception it died of, and calls the mutation valid only if none of the
failures is the mutation's own error and the named target tests are among the assertion failures. The figures below
are from that tool, on the final tree: the scheduler mutations run all nine `tests/test_scheduler_*.py` files (190
tests; the counts differ from the first report because the suite grew by `test_scheduler_actions.py`,
`test_scheduler_policy_change.py` and tighter assertions); the grant and CHECK mutations run
`test_scheduler_roles.py` (67 tests). All 16 are valid; none was red for a syntax, SQL or import reason.

| # | mutation | red (tests; how they failed) |
|---|---|---|
| M1 | no lock: `acquire` always succeeds, `held()` always true | **3** — `test_a_second_instance_is_refused_before_it_reads_anything` (`assert 0 == 2`), `test_a_killed_lock_connection_stops_dispatching` (did not raise `StopService`), `test_run_returns_the_lock_lost_exit_code` (`assert 0 == 6`) |
| M2 | enrollment read ignores withdrawal (the `withdrawn_at IS NULL` filter removed; the query still runs) | **5** — `test_withdrawing_an_enrollment_takes_effect_on_the_next_tick` (`assert 'PROP-…' not in ['PROP-…']`: its own proposal is dispatched) and four tests in `test_scheduler_actions` / `test_scheduler_service` that receive the leftovers of other tests' withdrawn engagements as dispatches (`assert 2 == 1`, `assert 0 == 1`, …). **Correction (D63):** the first report said "29 red"; that came from a malformed mutation (`SELECT DISTINCT … ORDER BY enrollment_id`, which Postgres rejects), so the tests were red because the query did not run. That figure is withdrawn. |
| M3a | grant the reader `SELECT (reason)` on `action_proposals` | **3** — the grant matrix (`assert {…} == {…}`) and `test_the_reader_is_refused_everything_it_was_not_granted` ×2 (did not raise `ProgrammingError`) |
| M3b | grant the reader `SELECT` on `audit_log` | **2** — the grant matrix; the refusal test (did not raise) |
| M3c | grant the state writer `UPDATE (status)` on `engagements` | **1** — the grant matrix |
| M4 | the audit payload whitelist is relaxed (any payload accepted) | **19** — `test_an_extra_key_is_refused_on_every_event` ×6, `test_a_value_that_is_not_an_id_or_a_closed_code_is_refused` ×10, the other-event-code test, the counter test (all "did not raise `PayloadRejected`"), and the enrollment-audit test (`assert 0 == 1`) |
| M5 | a skip raises the exit-7 stop | **15** — 5 on assertions (`assert 7 == 0`: the service stopped with code 7 where 0 was expected) and 10 that die of the `StopService: dispatch_did_not_advance` the mutation raises, which is the behaviour under test (the tool classifies it as the tested code's own refusal) |
| M7 | a skip is recorded every tick | **10** — `test_a_skipped_proposal_over_many_ticks_does_not_stop_the_service_and_is_recorded_once` ("`scheduler.skipped` was written 12 times over 12 ticks"), the `ip`-scope test ×4 (6 times over 6 ticks), the real-Docker `ip` test, the reserved-address test ×3, the "does not hide a dispatchable proposal" test. (The first re-run found this one red by `ValueError: too many values to unpack` — a test using unpacking as its count check; those two tests now `assert len(…) == 1` with a message, which is what the table shows.) |
| M8 | dispatch before the decision is recorded | **6** — `test_a_tick_dispatches_each_supported_action_to_its_own_tool` ×4 (`assert 57669 < 57665`: `scheduler.dispatched` was written after `capability.issued`), the e2e ordering test, `test_if_the_decision_cannot_be_audited_nothing_is_dispatched` (`assert 1 == 0`) |
| M9 | `deferred` recorded every tick | **2** — `test_a_paused_or_killed_engagement_is_deferred_once_not_per_tick` (paused, killed) |
| M10 | no reserved-address check | **7** — `test_a_target_on_the_network_gateway_or_broadcast_address_is_skipped` ×3, the closed-vocabulary test, and the real-Docker reserved-address test ×3 (the container is attempted) |
| M11 | no Docker pre-check | **1** — `test_an_unreachable_docker_stops_the_service_before_the_dispatch` (`assert 0 == 5`) |
| M12 | no lock check in `tick` | **2** — `test_a_killed_lock_connection_stops_dispatching`, `test_run_returns_the_lock_lost_exit_code` |
| M13 | `scheduler_state_check1` without `reason_code IS NOT NULL` in each branch (built from the live definition) | **2** — `test_a_skip_reason_outside_the_five_codes_is_refused_by_the_database` (did not raise `IntegrityError`), `test_the_vocabulary_in_the_constraints_is_the_vocabulary_in_the_code` ("no clause ties a skip to a non-NULL code") |
| M14 | one code more in the `skipped` branch than the vocabulary has (a sixth, with the five now in force) | **1** — `test_the_vocabulary_in_the_constraints_is_the_vocabulary_in_the_code` |
| M15 | `ip` scopes widened to a /28 again (§8) | **24** — `test_an_ip_scope_is_always_skipped_never_widened` ×18 (the derivation returns an allowlist, not the skip), the closed-vocabulary test, the four `ip` tick tests and the real-Docker `ip` test (a container is started) |

*Earlier scripts.* The first M13/M14 scripts carried a constraint text with the six-code vocabulary that migration
0020 later retired, and "a sixth skip code" was, when it was run, a seventh. Both were rebuilt from the live
definition (`pg_get_constraintdef`), which is why M14 now says what it does.

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

## 6. Decisions

None is left as an assumption. D-7 (the third role `scheduler_state_writer`) is **approved**. D-9 was first
implemented with an `ip`-scope widening (a /29–/27 block); the decision went the other way and it was removed
(see §8) — `ip` scopes are skipped.

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
