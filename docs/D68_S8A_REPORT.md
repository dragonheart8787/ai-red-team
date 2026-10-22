# D68 S8a -- P1 (`task_relation_enforce`) enabled for the observation period

Claims are tagged [R] read, [E] executed, [D] derived, [N] not established.
Records: `docs/D68_S7_BASELINE/s8a_effects.json` (checks 3 and 4), `docs/D68_S7_BASELINE/goal_class_probe/` is S7. The CI runs are named below; the soak's own artifact is in the run.
**S8b has not started.** Q1 is not enabled anywhere.

## 1. What "enabled" means here

The repository ships with the switch off everywhere; nothing in it turns it on. Enabling is an operator publishing a layer (`scripts/manage_global_policy.py`, audited). In this session no deployment exists, so P1 was enabled **in the soak** (a CI job on a fresh database, 4 h of traffic and faults) by a global baseline layer carrying `task_relation_enforce: true` published before its engagements were made, and retired at its end. The operator command for a deployment, for the reversible form (an overlay, section 5):

    python scripts/manage_global_policy.py publish --layer emergency_overlay --version <n> \
        --document '{"task_relation_enforce": true}' --actor <who>

## 2. Before the soak

* The gate the owner set: the DP-13 rule and the `code.secrets` investigation done, the full suite and CI green. [E] Local full suite 3956 passed, 0 failed, the same 24 environment errors as before; CI `test` runs #262, #263 and #264 (normal and enforced-ON jobs) success.
* **The enablement checks fire, in the real environment** [E]. `scripts/soak/negative_controls.py` runs in the soak job and makes each state the checks are for, then runs `scripts/s8_enablement_check.py` as a process and requires its verdict. In the smoke (soak run 8) and again in the 4 h run (run 9): **5 of 5 controls behaved as expected** --

  | state produced | verdict required, and got |
  |---|---|
  | P1 on, a task-bearing proposal decided and recorded | exit 0 |
  | Q1 switch on, no validator configured | exit 1, "no validator is configured" and "doing nothing" |
  | Q1 switch on, a backend named, no answer ever recorded | exit 1, "doing nothing" |
  | P1 on, the stored `plan_fit` gone | exit 1, "the comparison is not running" |
  | an engagement made before the layer was published (the switch does not reach it) | exit 1, "not true in the effective policy" |

  The first run of these locally had one control wrong (it retired a baseline and expected the engagement to lose the switch, which D54 prevents -- section 5); the control was corrected to the state that really exists.

## 3. The soak with P1 enforced (run 9, 2026-10-22 16:18-20:30 UTC) [E]

* Conductor exit 0, **findings 0**, heartbeat `clean`, `check_never_ran` none; the soak step 4 h 11 min, the drain clean (nothing of the soak left).
* **The P1 check** (`scripts/soak/checks.py::p1_enforcement`): executed 16 times, judged 16 times, every time ok -- "switch true in 3 engagements; **7778 of 7778 decided proposals carry a plan_fit**; no P1 escalation". It fails on a switch that does not reach an engagement, on proposals decided with nothing recorded, and on a `proposal_without_task` / `proposal_outside_task` reason on a workload whose every request names a task made from the request itself (the workload cannot earn one).
* **Faults** [E]: 16, all six kinds (postgres restart 2, docker restart 3, kill -9 of the scheduler 3, reconciler 3, control plane 3, pause of a container 2), none unrecovered; after each, an ALLOW proposal was recorded and a HUMAN_APPROVAL one dispatched by the scheduler -- the restart-against-waiting-approvals path this period existed to exercise, with the stored signal replayed at the approval re-derivation (`new_approval_reasons` not tripped).
* The ten other checks as in every soak: all 16 executions ok (the residue and connection-leak checks judged 14 of 16, as their windows allow).
* **Observed and not covered by any check, carried from earlier soaks:** `SAVEPOINT can only be used in transaction blocks` from Postgres (248 lines, 18 inside fault windows): ACCEPTANCE 5.110, unchanged.
* Smoke (run 8, 0.2 h): the same, 6 executions, 380 of 380 plan_fit, 14 faults.

## 4. Required checks of plan 8.1, each executed [E]

* **Item 2 (P1):** the switch is true in the effective policy of the engagements (3 of 3 in the soak, by `checks.p1_switches`, before traffic and in every cycle); the decisions after enabling carry a non-absent `plan_fit`; and a task-less proposal asks for a person with its own name -- `scripts/s8a_effects.py`: "task-bearing proposal: ALLOW; task-less proposal: HUMAN_APPROVAL [proposal_without_task]".
* **Item 3 (waiting approvals voided by the policy-version bump):** announced before: two approvals waiting, decided under policy version 46017. Enabling (an overlay) moved the version to 46018. Counted after: **2 of 2 decided under another version**; the one approved and dispatched was refused (`executed: false`, `failure: capability_refused`, `deny_reasons: [policy_version_changed]`). **Every approval waiting at the moment of enabling is void and its proposal has to be made again** (DP-10).
* **Item 4 (rollback tried once):** retiring the overlay: the switch read false in the engagement and the task-less proposal that had asked for a person was ALLOW again -- decisions returned to unchanged. **The same with a baseline did not return every engagement** (section 5).
* **Item 1 (S8b):** the enablement check and its controls exist and fire (section 2); it is run for Q1 at S8b.

## 5. What the rollback check found (a correction, not an incident)

The plan said "rollback at any time: publish a layer without the flag". It cannot: the switches are OR-merged and booleans only, so no layer turns off what another turned on [R: `merge.py`, `test_no_layer_can_turn_off_what_another_turned_on`]. What retiring does depends on the layer [E]:

| enabling layer | retired | effect |
|---|---|---|
| emergency overlay | by the platform owner | every engagement returns (switch false, task-less proposal ALLOW again) |
| baseline | by the platform owner | only engagements made **after** the retirement; one made while it was active keeps the switch (D54 freezes the baseline) |

So enabling through an **overlay** is the reversible form; through a **baseline** it is reversible only for later engagements. The plan's sentence is corrected (plan section 8) and the difference is ACCEPTANCE 5.124, a candidate. Which form the first enabling in a deployment takes is the operator's decision.

## 6. What this does not establish [N]

* P1 enforcement on **real** traffic: the soak's workload is synthetic, every request carries a task made from itself, so it exercises the replay, the faults and the recording, and cannot say how many real proposals would be sent to a person. The measured figures for that are the shadow runs: with the DP-13 rule and the Supervisor's prefix fix, 8 of 120 ALLOW decisions (6.7%, <= 12.6%) in the clean scale scenario for one planner model (`docs/D68_S7_P1_SCALE.md` section 7).
* One 4 h run on one runner; not a guarantee.
* The ip/url identity-form class (5.123) is not addressed: 3 of 149 proposals in the clean scenario.
